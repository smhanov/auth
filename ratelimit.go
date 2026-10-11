package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mutex   sync.Mutex
	records map[string]*rateRecord

	// the last time we checked for old records
	lastCheck float64
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{
		records: make(map[string]*rateRecord),
	}
}

type rateRecord struct {
	name   string
	rate   float64
	period float64
	at     float64
	value  float64
}

func (r *rateLimiter) removeExpired(now float64) {
	// only call when locked

	// ten minutes
	if now-r.lastCheck < 10*60 {
		return
	}

	for name, rec := range r.records {
		rec.update(now)
		if rec.value == 0 {
			delete(r.records, name)
		}
	}
}

func (r *rateLimiter) getRecord(name string, rate, period, now float64) *rateRecord {
	rec := r.records[name]
	if rec == nil {
		rec = &rateRecord{name: name, rate: rate, period: period, at: now}
		r.records[name] = rec
	} else {
		rec.update(now)
	}
	return rec
}

// Limit expresses a single rate limit: the maximum accumulated cost Rate
// allowed per Period.
type Limit struct {
	Rate   float64
	Period time.Duration
}

// bucketKey returns the map key for one (name, limit) bucket. The \x00
// separator cannot appear in operation names, user names, or IP addresses,
// so HasRateLimit can safely match on name + "\x00" as a prefix.
func bucketKey(name string, limit Limit) string {
	return name + "\x00" + strconv.FormatFloat(limit.Rate, 'g', -1, 64) +
		"\x00" + strconv.Itoa(int(limit.Period/time.Second))
}

func (r *rateLimiter) isAllowedMulti(name string, cost float64, limits []Limit, update bool) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := float64(now().Unix())
	r.removeExpired(now)

	type bucketRef struct {
		record *rateRecord
		limit  Limit
	}

	// check every limit before charging any bucket, so a request denied
	// by one limit does not consume budget on the others
	buckets := make([]bucketRef, 0, len(limits))
	allowed := true
	for _, limit := range limits {
		period := float64(limit.Period / time.Second)
		record := r.getRecord(bucketKey(name, limit), limit.Rate, period, now)
		buckets = append(buckets, bucketRef{record, limit})
		if record.value+cost >= record.rate {
			allowed = false
		}
	}

	if !allowed || !update {
		return allowed
	}
	for _, bucket := range buckets {
		bucket.record.value += cost
	}
	return true
}

func (r *rateLimiter) isAllowed(name string, cost, rate float64, periodTime time.Duration, update bool) bool {
	return r.isAllowedMulti(name, cost, []Limit{{Rate: rate, Period: periodTime}}, update)
}

func (r *rateLimiter) hasRecord(name string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	now := float64(now().Unix())
	prefix := name + "\x00"
	found := false
	for key, record := range r.records {
		if strings.HasPrefix(key, prefix) {
			record.update(now)
			if record.value > 0 {
				found = true
			}
		}
	}

	return found
}

func (record *rateRecord) update(now float64) {
	elapsed := now - record.at

	// leaky bucket algorithm
	record.value = math.Max(0, record.value-elapsed*record.rate/
		record.period)
	record.at = now
}

var globalLimiter *rateLimiter

func init() {
	globalLimiter = newRateLimiter()
}

// RateLimitAllows will return true if the given operation is allowed. Name is an
// arbitrary string that uniquely identifies the user and operation.
// cost is the cost of the operation, and rate is the max cost allowed in the
// given time period.
//
// Example: user 123 logs in, and the maximum attempts allowed are
// 5 in a 10 minute period.
//
//	if auth.RateLimitAllows(name, 1, 5, 10 * time.Minute) {
//	    // succeeded
//	}
func RateLimitAllows(name string, cost, rate float64, period time.Duration) bool {
	return globalLimiter.isAllowed(name, cost, rate, period, true)
}

// RateLimitCheck checks if the given operation would be allowed, but does not update
// it.
func RateLimitCheck(name string, cost, rate float64, period time.Duration) bool {
	return globalLimiter.isAllowed(name, cost, rate, period, false)
}

// RateLimitAllowsMulti will return true if the given operation is allowed
// under ALL of the given limits. Any number of limits may be given, for
// example 75 per minute and up to 5 per second:
//
//	auth.RateLimitAllowsMulti(name, 1,
//		auth.Limit{Rate: 75, Period: time.Minute},
//		auth.Limit{Rate: 5, Period: time.Second})
//
// If any limit is exceeded, the operation is denied and no bucket is
// charged.
func RateLimitAllowsMulti(name string, cost float64, limits ...Limit) bool {
	return globalLimiter.isAllowedMulti(name, cost, limits, true)
}

// RateLimitCheckMulti checks if the given operation would be allowed under
// ALL of the given limits, but does not update it.
func RateLimitCheckMulti(name string, cost float64, limits ...Limit) bool {
	return globalLimiter.isAllowedMulti(name, cost, limits, false)
}

// DoRateLimit will rate limit an operation on both the user and ip address.
// If it is not allowed, it will return false
// If it is allowed, it will then assume the operation was carried out and return true
func DoRateLimit(operation string, req *http.Request, user string, rate float64, period time.Duration) bool {
	return DoRateLimitMulti(operation, req, user, Limit{Rate: rate, Period: period})
}

// DoRateLimitMulti will rate limit an operation on both the user and ip
// address under ALL of the given limits.
// If it is not allowed, it will return false
// If it is allowed, it will then assume the operation was carried out and return true
func DoRateLimitMulti(operation string, req *http.Request, user string, limits ...Limit) bool {
	userlimit := operation + ":" + user
	iplimit := operation + ":" + GetIPAddress(req)

	if !globalLimiter.isAllowedMulti(userlimit, 1, limits, false) ||
		!globalLimiter.isAllowedMulti(iplimit, 1, limits, false) {
		HTTPPanic(429, "try again later")
	}

	globalLimiter.isAllowedMulti(userlimit, 1, limits, true)
	globalLimiter.isAllowedMulti(iplimit, 1, limits, true)
	return true
}

// HasRateLimit returns true if the bucket for the given operation has
// any attempts, regardless of wether they have reached the limit or not.
// When several limits are in force for the name, it returns true if any
// of them has activity.
func HasRateLimit(name string) bool {
	return globalLimiter.hasRecord(name)
}
