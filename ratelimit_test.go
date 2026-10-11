package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// bucketValue reads the current leaked value of one (name, limit) bucket.
// Only valid from the package's own tests.
func bucketValue(t *testing.T, name string, limit Limit) float64 {
	t.Helper()
	globalLimiter.mutex.Lock()
	defer globalLimiter.mutex.Unlock()
	rec := globalLimiter.records[bucketKey(name, limit)]
	if rec == nil {
		return 0
	}
	return rec.value
}

func expectHTTP429(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected an HTTP 429 panic, got none")
		}
		statusCode, ok := r.(interface{ StatusCode() int })
		if !ok {
			t.Fatalf("expected an HTTPError panic, got %T: %v", r, r)
		}
		if statusCode.StatusCode() != 429 {
			t.Fatalf("expected status 429, got %d", statusCode.StatusCode())
		}
	}()
	fn()
}

// AC1: existing single-limit API behaves exactly as before, including the
// strict value+cost < rate comparison (4 calls allowed at rate 5, the 5th
// denied).
func TestRateLimitAllowsSingleLimitBackwardCompat(t *testing.T) {
	name := "rlcompat:alice"

	for i := 1; i <= 4; i++ {
		if !RateLimitAllows(name, 1, 5, 10*time.Minute) {
			t.Fatalf("call %d: expected allowed", i)
		}
	}
	if RateLimitAllows(name, 1, 5, 10*time.Minute) {
		t.Fatal("call 5: expected denied by 5/10min limit")
	}

	AdvanceTime(10 * time.Minute)
	if !RateLimitAllows(name, 1, 5, 10*time.Minute) {
		t.Fatal("expected allowed after 10 minutes of leak")
	}
}

// AC2: several limits apply at once; the tightest binds first, and the
// others recover independently afterwards.
func TestRateLimitAllowsMultipleLimits(t *testing.T) {
	name := "rlmulti:bob"
	limits := []Limit{
		{Rate: 5, Period: time.Second},
		{Rate: 75, Period: time.Minute},
	}

	for i := 1; i <= 4; i++ {
		if !RateLimitAllowsMulti(name, 1, limits...) {
			t.Fatalf("call %d: expected allowed", i)
		}
	}
	if RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("call 5: expected denied by 5/second limit")
	}

	// all-or-nothing: the denied call must not have charged the
	// per-minute bucket
	if v := bucketValue(t, name, Limit{Rate: 75, Period: time.Minute}); v != 4 {
		t.Fatalf("per-minute bucket = %v, want 4 (denied call must not charge)", v)
	}

	AdvanceTime(2 * time.Second)
	if !RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("expected allowed once the per-second bucket drained")
	}
}

// AC3: a request denied by one limit must not consume budget on the others.
func TestMultiLimitDeniedRequestNotCharged(t *testing.T) {
	name := "rlcharge:carol"
	hourly := Limit{Rate: 100, Period: time.Hour}
	limits := []Limit{{Rate: 2, Period: time.Second}, hourly}

	if !RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("call 1: expected allowed")
	}
	if RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("call 2: expected denied by 2/second limit")
	}
	if v := bucketValue(t, name, hourly); v != 1 {
		t.Fatalf("hourly bucket = %v, want 1 (denied call must not charge)", v)
	}

	AdvanceTime(2 * time.Second)
	if !RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("call 3: expected allowed after per-second drain")
	}
	if v := bucketValue(t, name, hourly); v < 1.5 || v > 2.5 {
		t.Fatalf("hourly bucket = %v, want about 2 (exactly two charged calls)", v)
	}
}

// AC4: RateLimitCheckMulti never updates any bucket.
func TestRateLimitCheckMultiNoUpdate(t *testing.T) {
	name := "rlcheck:dave"
	limits := []Limit{{Rate: 2, Period: time.Minute}}

	for i := 0; i < 10; i++ {
		if !RateLimitCheckMulti(name, 1, limits...) {
			t.Fatalf("check %d: expected allowed", i)
		}
	}
	if HasRateLimit(name) {
		t.Fatal("expected no bucket activity after check-only calls")
	}
	if !RateLimitAllows(name, 1, 2, time.Minute) {
		t.Fatal("expected full single-limit budget after check-only calls")
	}
}

// AC5: HasRateLimit reports activity in any bucket under the name, and
// returns false again once every bucket has drained.
func TestHasRateLimitMultipleBuckets(t *testing.T) {
	name := "rlhas:eve"
	limits := []Limit{
		{Rate: 5, Period: time.Minute},
		{Rate: 100, Period: time.Hour},
	}

	if HasRateLimit(name) {
		t.Fatal("expected no activity for unknown name")
	}
	if !RateLimitAllowsMulti(name, 1, limits...) {
		t.Fatal("expected allowed")
	}
	if !HasRateLimit(name) {
		t.Fatal("expected activity after an allowed call")
	}

	AdvanceTime(2 * time.Hour)
	if HasRateLimit(name) {
		t.Fatal("expected no activity after all buckets drained")
	}
}

// AC6: DoRateLimitMulti denies with HTTP 429 when either the user or IP
// bucket violates any limit, and charges both keys only when all limits
// pass.
func TestDoRateLimitMultiTwoPhase(t *testing.T) {
	operation := "rltwophase"
	user := "frank"
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	limits := []Limit{{Rate: 2, Period: time.Minute}}

	if !DoRateLimitMulti(operation, req, user, limits...) {
		t.Fatal("call 1: expected allowed")
	}

	// rate 2 with cost 1 admits one call per window (strict <), so the
	// second call violates both the user and IP buckets
	expectHTTP429(t, func() {
		DoRateLimitMulti(operation, req, user, limits...)
	})

	// the denied second call must not have charged either key
	userKey := operation + ":" + user
	ipKey := operation + ":" + GetIPAddress(req)
	if v := bucketValue(t, userKey, limits[0]); v != 1 {
		t.Fatalf("user bucket = %v, want 1 (denied call must not charge)", v)
	}
	if v := bucketValue(t, ipKey, limits[0]); v != 1 {
		t.Fatalf("ip bucket = %v, want 1 (denied call must not charge)", v)
	}

	AdvanceTime(time.Minute)
	if !DoRateLimitMulti(operation, req, user, limits...) {
		t.Fatal("expected allowed after both buckets drained")
	}
}
