package auth

// Tests for SQLite lock-error handling: statement retry with backoff
// inside transactions, commit failures that must never be silently
// swallowed, and RecoverErrors mapping transient lock failures to a
// retryable 503 instead of a 500 with raw panic text.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// lockRetryResponseBody is the stable, retryable message that
// RecoverErrors must send when a panic was caused by a database lock.
const lockRetryResponseBody = "database is locked; please retry"

// The mattn/go-sqlite3 driver sets a default 5-second busy timeout on
// every connection, which would make the driver silently wait out short
// lock holds and hide the Go-level retry behavior under test. A short
// driver timeout makes lock errors surface promptly so the retry loop
// in userdb.go is what rides out the contention.
const testDsnSuffix = "?_busy_timeout=10"

// newFileDBHandler builds a handler over a file-backed SQLite database.
// Unlike ":memory:" databases, a file database can exhibit real
// cross-connection write contention, which these tests rely on.
func newFileDBHandler(t *testing.T) (handler http.Handler, db *sqlx.DB, path string) {
	t.Helper()

	path = filepath.Join(t.TempDir(), "lock-retry.db")
	db = sqlx.MustConnect("sqlite3", path+testDsnSuffix)
	t.Cleanup(func() { db.Close() })

	settings := DefaultSettings
	// A real hash (bcrypt) takes long enough to eat into the lock-hold
	// window; the first statement must reach the lock while it is held.
	settings.HashPasswordFn = func(password string) string {
		return "hashed:" + password
	}

	handler = New(NewUserDB(db), settings)
	return handler, db, path
}

// openBlocker opens a second, independent connection pool to the same
// database file, used to manufacture lock contention.
func openBlocker(t *testing.T, path string) *sql.DB {
	t.Helper()

	blocker, err := sql.Open("sqlite3", path+testDsnSuffix)
	if err != nil {
		t.Fatalf("could not open blocker connection: %v", err)
	}
	t.Cleanup(func() { blocker.Close() })
	return blocker
}

// acquireWriteLock takes the SQLite write lock (BEGIN IMMEDIATE plus a
// write) on a dedicated blocker connection. Release it with
// releaseWriteLock.
func acquireWriteLock(t *testing.T, blocker *sql.DB) *sql.Conn {
	t.Helper()

	ctx := context.Background()
	conn, err := blocker.Conn(ctx)
	if err != nil {
		t.Fatalf("could not get blocker connection: %v", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE failed: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		"INSERT INTO AuthSettings (key, value) VALUES ('blocker', 'held')"); err != nil {
		t.Fatalf("blocker write failed: %v", err)
	}
	return conn
}

// releaseWriteLock rolls back and closes a blocker connection from
// acquireWriteLock, letting competing writers proceed.
func releaseWriteLock(conn *sql.Conn) {
	conn.ExecContext(context.Background(), "ROLLBACK") //nolint:errcheck
	conn.Close()                                       //nolint:errcheck
}

// postUserCreate sends a POST /user/create through the handler and
// returns the response along with its body.
func postUserCreate(t *testing.T, handler http.Handler, email string) (*http.Response, string) {
	t.Helper()

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", "correct-password")

	req, err := http.NewRequest(http.MethodPost, "/user/create", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost"
	req.RemoteAddr = "127.0.0.1:60000"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read response body: %v", err)
	}
	return resp, string(body)
}

func hasSessionCookie(resp *http.Response) bool {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "session" {
			return true
		}
	}
	return false
}

// shortenLockRetryBudget tightens the package retry budget for the
// duration of a test, restoring the production defaults afterwards.
func shortenLockRetryBudget(t *testing.T, base time.Duration, retries int) {
	t.Helper()

	origBase, origRetries := lockRetryBaseDelay, lockRetryMaxRetries
	lockRetryBaseDelay, lockRetryMaxRetries = base, retries
	t.Cleanup(func() {
		lockRetryBaseDelay, lockRetryMaxRetries = origBase, origRetries
	})
}

// TestWithLockRetryRetriesThenSucceeds verifies that withLockRetry rides
// out a lock error that clears after a few attempts: the fn is retried
// with backoff and succeeds without panicking.
func TestWithLockRetryRetriesThenSucceeds(t *testing.T) {
	shortenLockRetryBudget(t, time.Millisecond, 5)

	lockErr := errors.New("database is locked (5) (SQLITE_BUSY)")
	calls := 0
	withLockRetry("unit test", func() error {
		calls++
		if calls < 3 {
			return lockErr
		}
		return nil
	})
	if calls != 3 {
		t.Errorf("expected success on the 3rd call after 2 lock failures, got %d calls", calls)
	}
}

// TestWithLockRetryPanicsAfterBudgetExhausted verifies that when the
// lock error never clears, withLockRetry gives up after the retry
// budget and panics with the underlying error (so RecoverErrors can
// map it to a retryable 503).
func TestWithLockRetryPanicsAfterBudgetExhausted(t *testing.T) {
	shortenLockRetryBudget(t, time.Millisecond, 2)

	sentinel := errors.New("database is locked (5) (SQLITE_BUSY)")
	calls := 0
	defer func() {
		if thing := recover(); thing == nil {
			t.Error("expected withLockRetry to panic when the lock never clears")
		} else if thing != sentinel {
			t.Errorf("panic carried %v (%T); want the underlying error", thing, thing)
		}
		if calls != 3 { // 2 retries + the final attempt
			t.Errorf("expected 3 calls (retries + final attempt), got %d", calls)
		}
	}()
	withLockRetry("unit test", func() error {
		calls++
		return sentinel
	})
}

// TestWithLockRetryNonLockErrorPanicsImmediately verifies the error
// contract is unchanged for non-lock errors: no retries, immediate
// panic with the error itself.
func TestWithLockRetryNonLockErrorPanicsImmediately(t *testing.T) {
	shortenLockRetryBudget(t, time.Millisecond, 5)

	sentinel := errors.New("no such table: Users")
	calls := 0
	defer func() {
		if thing := recover(); thing == nil {
			t.Error("expected withLockRetry to panic on a non-lock error")
		} else if thing != sentinel {
			t.Errorf("panic carried %v (%T); want the underlying error", thing, thing)
		}
		if calls != 1 {
			t.Errorf("expected exactly 1 call (no retries for non-lock errors), got %d", calls)
		}
	}()
	withLockRetry("unit test", func() error {
		calls++
		return sentinel
	})
}

// TestCommitOnFinishedTxIsToleratedNoOp verifies the idempotent
// double-commit contract: Commit on a transaction that is already
// finished (by an earlier Commit or a Rollback) returns sql.ErrTxDone
// from database/sql, which UserTx.Commit swallows instead of panicking.
func TestCommitOnFinishedTxIsToleratedNoOp(t *testing.T) {
	db := sqlx.MustConnect("sqlite3", ":memory:")
	t.Cleanup(func() { db.Close() })
	udb := NewUserDB(db)

	committed := udb.Begin(context.Background())
	committed.Commit()
	committed.Commit() // ErrTxDone: must be a tolerated no-op

	rolledBack := udb.Begin(context.Background())
	rolledBack.Rollback()
	rolledBack.Commit() // also done: tolerated no-op
}

// TestLockClearsWithinRetryBudgetAllowsCreate verifies that a competing
// writer holding BEGIN IMMEDIATE, which releases within the retry
// budget, does not fail the request: the concurrent POST /user/create
// succeeds once the lock clears, and the transaction is really
// committed.
func TestLockClearsWithinRetryBudgetAllowsCreate(t *testing.T) {
	handler, db, path := newFileDBHandler(t)
	blocker := openBlocker(t, path)

	conn := acquireWriteLock(t, blocker)

	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		releaseWriteLock(conn)
		close(released)
	}()

	resp, body := postUserCreate(t, handler, "lock-clears@example.com")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 once the lock cleared, got %d (%s)",
			resp.StatusCode, body)
	}
	<-released

	if !hasSessionCookie(resp) {
		t.Error("expected a session cookie for the created user")
	}

	var count int
	if err := db.Get(&count, "SELECT count(*) FROM Users WHERE email=$1",
		"lock-clears@example.com"); err != nil {
		t.Fatalf("could not verify the created user: %v", err)
	}
	if count != 1 {
		t.Errorf("expected the user to be committed after the lock cleared, found %d rows",
			count)
	}
}

// TestLockHeldPastRetryBudgetReturns503 verifies that when the write
// lock is held well past the retry budget, the response is a 503 with
// the stable retryable message — never 200 or 500 with raw error text —
// and never claims success for the lost transaction.
func TestLockHeldPastRetryBudgetReturns503(t *testing.T) {
	shortenLockRetryBudget(t, time.Millisecond, 2)

	handler, _, path := newFileDBHandler(t)
	blocker := openBlocker(t, path)

	conn := acquireWriteLock(t, blocker)
	defer releaseWriteLock(conn)

	resp, body := postUserCreate(t, handler, "lock-exhausted@example.com")

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when the lock persists past the retry budget, got %d (%s)",
			resp.StatusCode, body)
	}
	if body != lockRetryResponseBody {
		t.Errorf("expected stable body %q, got %q", lockRetryResponseBody, body)
	}
	if status := resp.Header.Get("Status"); status != lockRetryResponseBody {
		t.Errorf("expected Status header %q, got %q", lockRetryResponseBody, status)
	}
	if hasSessionCookie(resp) {
		t.Error("a session cookie must not be issued when the transaction was lost")
	}
}

// TestLockAtCommitIsNotSilentSuccess verifies that a commit failure is
// surfaced to the client. The blocker holds a read transaction open, so
// the handler's statements succeed but its COMMIT cannot upgrade to the
// exclusive lock. A lost transaction must produce a 503 with the stable
// message — not a success response with a session cookie for data that
// was never committed. This is the regression test for the old Commit
// retry loop, whose second attempt always saw sql.ErrTxDone and treated
// it as success.
func TestLockAtCommitIsNotSilentSuccess(t *testing.T) {
	shortenLockRetryBudget(t, time.Millisecond, 2)

	handler, _, path := newFileDBHandler(t)
	blocker := openBlocker(t, path)

	// A read transaction holds a SHARED lock, which lets the handler
	// write but blocks its COMMIT from taking the exclusive lock.
	btx, err := blocker.Begin()
	if err != nil {
		t.Fatalf("blocker Begin failed: %v", err)
	}
	rows, err := btx.Query("SELECT count(*) FROM Users")
	if err != nil {
		t.Fatalf("blocker read failed: %v", err)
	}
	for rows.Next() { // drain so the lock is acquired and held
	}
	rows.Close()

	resp, body := postUserCreate(t, handler, "commit-blocked@example.com")

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when the commit fails, got %d (%s)",
			resp.StatusCode, body)
	}
	if body != lockRetryResponseBody {
		t.Errorf("expected stable body %q, got %q", lockRetryResponseBody, body)
	}
	// The handler sets the session cookie header before Commit()
	// (auth.go SignInUser), but a 503 from a failed commit must not
	// carry it: the session was rolled back, so the cookie could never
	// authenticate.
	if hasSessionCookie(resp) {
		t.Error("a session cookie must not be sent when the commit failed")
	}

	// After the blocker lets go, the user must not exist: the failed
	// transaction has to be rolled back, not applied.
	btx.Rollback() //nolint:errcheck
	var count int
	if err := blocker.QueryRow("SELECT count(*) FROM Users WHERE email=$1",
		"commit-blocked@example.com").Scan(&count); err != nil {
		t.Fatalf("could not verify the user was not created: %v", err)
	}
	if count != 0 {
		t.Errorf("user was committed despite the failed Commit(), found %d rows", count)
	}
}

// TestSessionCookieDroppedWhenRequestPanicsBeforeResponse verifies the
// cookie-emission window around SignInUser: it sets the session cookie
// before the caller's tx.Commit(), so a request that fails after the
// cookie is set but before the response is written must not deliver
// it. The OnAuthEvent hook panics with a lock-shaped error exactly in
// that window, without needing file-database lock machinery; the
// create path (action "create", no panic) is the control showing that
// successful responses still carry the cookie.
func TestSessionCookieDroppedWhenRequestPanicsBeforeResponse(t *testing.T) {
	db := sqlx.MustConnect("sqlite3", ":memory:")
	t.Cleanup(func() { db.Close() })

	settings := DefaultSettings
	settings.HashPasswordFn = func(password string) string {
		return "hashed:" + password
	}
	settings.OnAuthEvent = func(tx Tx, action string, userid int64, info UserInfo) {
		if action == "auth" {
			panic(errors.New("database is locked (5) (SQLITE_BUSY)"))
		}
	}
	handler := New(NewUserDB(db), settings)

	// Control: the create path fires OnAuthEvent("create"), does not
	// panic, and its success response carries the session cookie.
	resp, body := postUserCreate(t, handler, "cookie-window@example.com")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on create, got %d (%s)", resp.StatusCode, body)
	}
	if !hasSessionCookie(resp) {
		t.Error("expected a session cookie on the successful create")
	}

	form := url.Values{}
	form.Set("email", "cookie-window@example.com")
	form.Set("password", "correct-password")

	req, err := http.NewRequest(http.MethodPost, "/user/auth", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost"
	req.RemoteAddr = "127.0.0.1:60000"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	resp = rec.Result()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read response body: %v", err)
	}
	body = string(bodyBytes)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for the lock-shaped panic, got %d (%s)",
			resp.StatusCode, body)
	}
	if hasSessionCookie(resp) {
		t.Error("a session cookie must not be sent for a request that failed before its response was written")
	}
}

// TestRecoverErrorsLockErrorPanicTo503 verifies that a handler panicking
// with a lock-shaped error gets a 503 with the stable retryable message.
func TestRecoverErrorsLockErrorPanicTo503(t *testing.T) {
	handler := RecoverErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(errors.New("database is locked"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for a lock-shaped panic, got %d (%s)",
			resp.StatusCode, body)
	}
	if string(body) != lockRetryResponseBody {
		t.Errorf("expected stable body %q, got %q", lockRetryResponseBody, body)
	}
	if status := resp.Header.Get("Status"); status != lockRetryResponseBody {
		t.Errorf("expected Status header %q, got %q", lockRetryResponseBody, status)
	}
}

// TestRecoverErrorsLockStringPanicTo503 is the same check for a panic
// value that is a plain string rather than an error.
func TestRecoverErrorsLockStringPanicTo503(t *testing.T) {
	handler := RecoverErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("SQLITE_BUSY: database is locked")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for a lock-shaped string panic, got %d (%s)",
			resp.StatusCode, body)
	}
	if string(body) != lockRetryResponseBody {
		t.Errorf("expected stable body %q, got %q", lockRetryResponseBody, body)
	}
}

// TestRecoverErrorsNonLockPanicStays500 verifies that non-lock panics
// keep surfacing as 500 with the error text, as before.
func TestRecoverErrorsNonLockPanicStays500(t *testing.T) {
	handler := RecoverErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(errors.New("boom"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 for a non-lock panic, got %d (%s)",
			resp.StatusCode, body)
	}
	if string(body) != "boom" {
		t.Errorf("expected body %q, got %q", "boom", body)
	}
	if status := resp.Header.Get("Status"); status != "boom" {
		t.Errorf("expected Status header %q, got %q", "boom", status)
	}
}
