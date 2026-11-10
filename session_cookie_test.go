package auth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// These tests mirror the external sign-in pattern documented in the
// package documentation: they call the package-level SignInUser directly
// from an application-defined handler rather than going through
// ServeHTTP, so the package's cookieGuard plays no part. The discipline
// being tested is the caller's — send the cookie only after the commit
// succeeded.

// commitLockDB wraps a UserDB so that Tx.Commit can be made to panic on
// demand with a lock-shaped error, simulating a commit that exhausted
// its retry budget. See MyDB in auth_test.go for the wrapping pattern.
type commitLockDB struct {
	auth.DB
	failCommit atomic.Bool
}

type commitLockTx struct {
	auth.Tx
	failCommit *atomic.Bool
}

func (db *commitLockDB) Begin(ctx context.Context) auth.Tx {
	return commitLockTx{Tx: db.DB.Begin(ctx), failCommit: &db.failCommit}
}

func (tx commitLockTx) Commit() {
	if tx.failCommit.Load() {
		panic(errors.New("database is locked (5) (SQLITE_BUSY)"))
	}
	tx.Tx.Commit()
}

// serveExternalSignIn runs an application-defined sign-in handler that
// follows the documented pattern: create the session with SignInUser,
// commit the transaction, and only then set the session cookie and send
// the response. A commit that panics unwinds through RecoverErrors
// before http.SetCookie is reached.
func serveExternalSignIn(t *testing.T, db auth.DB, email string) *http.Response {
	t.Helper()

	external := auth.RecoverErrors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := db.Begin(r.Context())
		defer tx.Rollback()

		userid := tx.GetUserByEmail(email)
		info, cookie := auth.SignInUser(db, tx, userid, false, auth.IsRequestSecure(r))
		tx.Commit()
		http.SetCookie(w, &cookie)
		auth.SendJSON(w, info)
	}))

	req, err := http.NewRequest("POST", "/external-signin", nil)
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}

	rec := httptest.NewRecorder()
	external.ServeHTTP(rec, req)
	return rec.Result()
}

// TestSignInUserFailedCommitSendsNoCookie verifies that the documented
// external pattern sends no session cookie when the commit fails with a
// database lock error: the caller had not yet reached http.SetCookie
// when the commit panicked, so the 503 from RecoverErrors carries no
// cookie for the rolled-back session.
func TestSignInUserFailedCommitSendsNoCookie(t *testing.T) {
	const email = "signinuser-lock@example.com"

	db := &commitLockDB{DB: auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))}
	client := newTestClient(auth.New(db, auth.DefaultSettings))

	client.do(t, testRequest{
		name: "create user and sign in",
		path: "/user/create",
		params: map[string]string{
			"email":    email,
			"password": "correct-password",
		},
		code: 200,
	})

	// From now on every commit panics with a lock error, as if the
	// retry budget was exhausted while committing the new session.
	db.failCommit.Store(true)

	resp := serveExternalSignIn(t, db, email)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when the commit fails, got %d", resp.StatusCode)
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("expected no Set-Cookie headers on the error response, got %v", cookies)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read response body: %v", err)
	}
	if string(body) != "database is locked; please retry" {
		t.Errorf("expected body 'database is locked; please retry', got %q", string(body))
	}
}

// TestSignInUserCookieAuthenticatesAfterCommit verifies the success path
// of the documented external pattern: the cookie returned by SignInUser
// authenticates against the package's own handler stack once the
// transaction holding the new session row has committed.
func TestSignInUserCookieAuthenticatesAfterCommit(t *testing.T) {
	const email = "signinuser-ok@example.com"

	db := auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	client := newTestClient(auth.New(db, auth.DefaultSettings))

	client.do(t, testRequest{
		name: "create user and sign in",
		path: "/user/create",
		params: map[string]string{
			"email":    email,
			"password": "correct-password",
		},
		code: 200,
	})

	resp := serveExternalSignIn(t, db, email)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from the external sign-in handler, got %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one Set-Cookie header, got %v", cookies)
	}
	if cookies[0].Name != "session" {
		t.Errorf("expected cookie name 'session', got %q", cookies[0].Name)
	}

	client.session = cookies[0].Value
	client.do(t, testRequest{
		name: "cookie from SignInUser authenticates after commit",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{
			"email":  email,
			"userid": 1.0,
		},
	})
}
