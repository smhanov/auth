package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// makePostRequest sends the parameters as a POST form body, presenting the
// client's current session cookie. Unlike makeRequest it does not adopt any
// session cookie from the response, so tests can verify that a specific,
// pre-existing session cookie still authenticates afterwards.
func (tc *testClient) makePostRequest(t *testing.T, path string, params map[string]string) *http.Response {
	t.Helper()

	data := url.Values{}
	for name, value := range params {
		data.Set(name, value)
	}

	t.Logf("    POST %s?%s", path, data.Encode())
	req, err := http.NewRequest("POST", path, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("could not create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost"
	req.RemoteAddr = tc.remoteAddr
	if tc.session != "" {
		req.Header.Set("Cookie", fmt.Sprintf("session=%s;", tc.session))
	}

	rec := httptest.NewRecorder()
	tc.server.ServeHTTP(rec, req)
	return rec.Result()
}

// TestWrongPasswordKeepsSession verifies that a failed password login does
// not destroy the caller's existing session: the pre-auth signOut must be
// rolled back along with the rest of the transaction.
func TestWrongPasswordKeepsSession(t *testing.T) {
	handler := auth.New(auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")), auth.DefaultSettings)
	client := newTestClient(handler)

	client.do(t, testRequest{
		name: "create user and sign in",
		path: "/user/create",
		params: map[string]string{
			"email":    "keepsession@example.com",
			"password": "correct-password",
		},
		code: 200,
	})

	if client.session == "" {
		t.Fatal("expected a session cookie after signing in")
	}

	resp := client.makePostRequest(t, "/user/auth", map[string]string{
		"email":    "keepsession@example.com",
		"password": "wrong-password",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong password, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Status") != "wrong password" {
		t.Errorf("expected status 'wrong password', got %q", resp.Header.Get("Status"))
	}

	client.do(t, testRequest{
		name: "original session still works after the failed login",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{
			"email":  "keepsession@example.com",
			"userid": 1.0,
		},
	})
}

// panicSignInDB wraps a UserDB so that Tx.SignIn can be made to panic on
// demand, simulating a database statement failure in the middle of a
// transaction. See MyDB in auth_test.go for the wrapping pattern.
type panicSignInDB struct {
	auth.DB
	failSignIn atomic.Bool
}

type panicSignInTx struct {
	auth.Tx
	failSignIn *atomic.Bool
}

func (db *panicSignInDB) Begin(ctx context.Context) auth.Tx {
	return panicSignInTx{Tx: db.DB.Begin(ctx), failSignIn: &db.failSignIn}
}

func (tx panicSignInTx) SignIn(userid int64, cookie string) {
	if tx.failSignIn.Load() {
		panic("simulated SignIn failure after signOut")
	}
	tx.Tx.SignIn(userid, cookie)
}

// TestPanicRollsBack verifies that a panic between Begin and the final
// Commit leaves no partial writes. The stubbed Tx.SignIn panics after the
// pre-auth signOut has already deleted the old session row, so the old
// session must still validate afterwards.
func TestPanicRollsBack(t *testing.T) {
	db := &panicSignInDB{DB: auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))}
	handler := auth.New(db, auth.DefaultSettings)
	client := newTestClient(handler)

	client.do(t, testRequest{
		name: "create user and sign in",
		path: "/user/create",
		params: map[string]string{
			"email":    "rollback@example.com",
			"password": "correct-password",
		},
		code: 200,
	})

	if client.session == "" {
		t.Fatal("expected a session cookie after signing in")
	}

	// From now on Tx.SignIn panics. The next /user/auth call runs signOut
	// (deleting the old session row) before the panic, so the transaction
	// must roll back for the old session to survive.
	db.failSignIn.Store(true)

	resp := client.makePostRequest(t, "/user/auth", map[string]string{
		"email":    "rollback@example.com",
		"password": "correct-password",
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 from the simulated panic, got %d", resp.StatusCode)
	}

	client.do(t, testRequest{
		name: "old session is still valid after the rolled-back transaction",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{
			"email":  "rollback@example.com",
			"userid": 1.0,
		},
	})
}

// Minimal identity provider metadata used by the SAML routing stub.
const testIDPMetadata = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// samlStubDB routes one email address to a SAML identity provider and counts
// explicit transaction commits. See MyDB in auth_test.go for the wrapping
// pattern.
type samlStubDB struct {
	auth.DB
	samlEmail string
	commits   int32
}

type samlStubTx struct {
	auth.Tx
	samlEmail string
	commits   *int32
}

func (db *samlStubDB) Begin(ctx context.Context) auth.Tx {
	return samlStubTx{Tx: db.DB.Begin(ctx), samlEmail: db.samlEmail, commits: &db.commits}
}

func (tx samlStubTx) GetSamlIdentityProviderForUser(email string) string {
	if email == tx.samlEmail {
		return testIDPMetadata
	}
	return ""
}

func (tx samlStubTx) Commit() {
	atomic.AddInt32(tx.commits, 1)
	tx.Tx.Commit()
}

// TestSamlRequiredPath verifies handleUserAuth's SAML early-return branch.
// With sso absent the handler returns the "sso required" error and the
// pre-auth signOut is rolled back (accepted behavior change: the existing
// session survives). With sso present the handler redirects to the identity
// provider and commits the pre-auth signOut on its early return path.
func TestSamlRequiredPath(t *testing.T) {
	const email = "samluser@example.com"

	db := &samlStubDB{
		DB:        auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")),
		samlEmail: email,
	}
	handler := auth.New(db, auth.DefaultSettings)
	client := newTestClient(handler)

	client.do(t, testRequest{
		name: "create user and sign in",
		path: "/user/create",
		params: map[string]string{
			"email":    email,
			"password": "correct-password",
		},
		code: 200,
	})

	if client.session == "" {
		t.Fatal("expected a session cookie after signing in")
	}

	resp := client.makePostRequest(t, "/user/auth", map[string]string{
		"email":    email,
		"password": "correct-password",
	})
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 for sso required, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Status") != "sso required" {
		t.Errorf("expected status 'sso required', got %q", resp.Header.Get("Status"))
	}

	client.do(t, testRequest{
		name: "session survives the sso-required response",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{
			"email":  email,
			"userid": 1.0,
		},
	})

	resp = client.makePostRequest(t, "/user/auth", map[string]string{
		"email": email,
		"sso":   "1",
	})
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 redirect to the identity provider, got %d", resp.StatusCode)
	}
	if location := resp.Header.Get("Location"); !strings.HasPrefix(location, "https://idp.example.com/sso") {
		t.Errorf("expected redirect to the identity provider, got %q", location)
	}
	if atomic.LoadInt32(&db.commits) == 0 {
		t.Error("expected the SAML early-return path to commit its transaction")
	}

	client.do(t, testRequest{
		name: "old session was signed out by the committed SAML redirect",
		path: "/user/get",
		code: 401,
	})
}
