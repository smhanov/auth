package auth_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
	"golang.org/x/oauth2"
)

// Compile-time guard: VerifyOauth must keep its (string, string) signature
// so existing consumers keep compiling.
var _ func(method, token string) (string, string) = auth.VerifyOauth

// startProviderMock points auth.TestURL at a server that answers every
// request with body. The legacy /user/auth oauth path and VerifyOauth
// contact exactly this URL for facebook, google, and apple tokens.
func startProviderMock(t *testing.T, body string) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	previous := auth.TestURL
	auth.TestURL = ts.URL
	t.Cleanup(func() {
		auth.TestURL = previous
		ts.Close()
	})
}

// newMemoryDB returns a UserDB backed by an in-memory SQLite database
// restricted to a single connection, so every transaction (handler and
// test) sees the same in-memory database.
func newMemoryDB(t *testing.T) *auth.UserDB {
	t.Helper()
	sqlxDB := sqlx.MustConnect("sqlite3", ":memory:")
	sqlxDB.SetMaxOpenConns(1)
	return auth.NewUserDB(sqlxDB)
}

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func readAllBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// userCount returns the number of rows in the users table.
func userCount(t *testing.T, db *auth.UserDB) int {
	t.Helper()
	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	var count int
	if err := utx.Tx.Get(&count, "SELECT count(*) FROM users"); err != nil {
		t.Fatal(err)
	}
	return count
}

// oauthRowUser returns the userid linked to (method, foreignID), or 0.
func oauthRowUser(t *testing.T, db *auth.UserDB, method, foreignID string) int64 {
	t.Helper()
	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	return utx.GetOauthUser(method, foreignID)
}

// createAccountThenSignOut creates a password user and signs out again.
func createAccountThenSignOut(t *testing.T, email string) (*auth.UserDB, *testClient, int64) {
	t.Helper()
	db := newMemoryDB(t)
	client := newTestClient(auth.New(db, auth.DefaultSettings))
	client.do(t,
		testRequest{
			name:   "Create account",
			path:   "/user/create",
			params: map[string]string{"email": email, "password": "password"},
			code:   200,
		},
		testRequest{
			name: "Sign out",
			path: "/user/signout",
			code: 200,
		},
	)
	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	victimID := utx.GetUserByEmail(email)
	if victimID == 0 {
		t.Fatalf("account %s was not created", email)
	}
	return db, client, victimID
}

// TestOauthUnverifiedEmailRejected mirrors the reported attack: an oauth
// identity carrying a victim's unverified email must not link to the
// victim's account, must not create any account, and must not sign in.
func TestOauthUnverifiedEmailRejected(t *testing.T) {
	db, client, victimID := createAccountThenSignOut(t, "victim@example.com")
	usersBefore := userCount(t, db)

	// Google's tokeninfo endpoint reports claims as JSON strings.
	startProviderMock(t, `{"sub":"attacker-sub-999","email":"victim@example.com","email_verified":"false"}`)

	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "google",
		"token":  "attacker-token",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body %s", resp.StatusCode, readAllBody(t, resp))
	}
	if got := resp.Header.Get("Status"); got != "provider email not verified" {
		t.Errorf("expected clear rejection message, got %q", got)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			t.Errorf("a session cookie was issued for a rejected sign-in")
		}
	}

	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows: an account was created from an unverified email", usersBefore, usersAfter)
	}
	if id := oauthRowUser(t, db, "google", "attacker-sub-999"); id != 0 {
		t.Errorf("oauth row created for attacker-sub-999 linked to userid %d", id)
	}
	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	if id := utx.GetUserByEmail("victim@example.com"); id != victimID {
		t.Errorf("victim@example.com now resolves to userid %d, want %d", id, victimID)
	}
}

// TestOauthVerifiedEmailStillLinks checks that the same attack payload with
// a provider-asserted verified email keeps working, and that the tokeninfo
// string-typed email_verified claim is parsed correctly.
func TestOauthVerifiedEmailStillLinks(t *testing.T) {
	db, client, victimID := createAccountThenSignOut(t, "victim@example.com")

	startProviderMock(t, `{"sub":"attacker-sub-999","email":"victim@example.com","email_verified":"true"}`)

	client.do(t, testRequest{
		name:   "Verified google email links to the victim account",
		path:   "/user/auth",
		params: map[string]string{"method": "google", "token": "attacker-token"},
		code:   200,
		json: map[string]interface{}{
			"email":   "victim@example.com",
			"userid":  float64(victimID),
			"methods": []string{"google"},
		},
	})

	if id := oauthRowUser(t, db, "google", "attacker-sub-999"); id != victimID {
		t.Errorf("oauth row for attacker-sub-999 linked to userid %d, want %d", id, victimID)
	}
}

// TestOauthEmptyEmailNeverLinks checks that a missing or empty provider
// email is never treated as a verified matchable address.
func TestOauthEmptyEmailNeverLinks(t *testing.T) {
	db, client, _ := createAccountThenSignOut(t, "victim@example.com")
	usersBefore := userCount(t, db)

	// Facebook's Graph API only returns email when confirmed; an absent
	// email means nothing was verified.
	startProviderMock(t, `{"id":"fb-000","name":"No Email"}`)

	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "facebook",
		"token":  "some-token",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for empty provider email, got %d", resp.StatusCode)
	}

	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows", usersBefore, usersAfter)
	}
	if id := oauthRowUser(t, db, "facebook", "fb-000"); id != 0 {
		t.Errorf("oauth row created for fb-000 despite the unverified empty email")
	}
}

// TestGoogleProviderUnverifiedEmailRejected checks the GoogleProvider
// callback flow: a real boolean email_verified=false from /userinfo is
// rejected with an error and no user row.
func TestGoogleProviderUnverifiedEmailRejected(t *testing.T) {
	db := newMemoryDB(t)
	settings := auth.DefaultSettings
	settings.GoogleClientID = "cid"
	settings.GoogleClientSecret = "csec"
	settings.GoogleRedirectURL = "/callback"
	h := auth.New(db, settings)

	loginReq := httptest.NewRequest("GET", "/user/oauth/login/google", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)

	var stateCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == "google_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie not set")
	}
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "token") {
			return jsonHTTPResponse(200, `{"access_token":"valid_token","token_type":"bearer","expires_in":3600}`), nil
		}
		if strings.Contains(req.URL.String(), "userinfo") {
			// /userinfo returns a real boolean email_verified.
			return jsonHTTPResponse(200, `{"sub":"999","name":"Evil","email":"victim@example.com","email_verified":false}`), nil
		}
		return nil, fmt.Errorf("unexpected request %s", req.URL)
	})

	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/google?state="+stateVal+"&code=fake", nil)
	callbackReq.AddCookie(stateCookie)
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
	callbackW := httptest.NewRecorder()
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	resp := callbackW.Result()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 from callback, got %d body %s", resp.StatusCode, callbackW.Body.String())
	}

	if users := userCount(t, db); users != 0 {
		t.Errorf("users table has %d rows; expected no user from an unverified google email", users)
	}
	if id := oauthRowUser(t, db, "google", "999"); id != 0 {
		t.Errorf("oauth row created for google sub 999")
	}
}

// customEmailProvider implements only OAuthProvider. It cannot report
// verification, so its email must never match or create accounts.
type customEmailProvider struct {
	providerName string
	foreignID    string
	email        string
}

func (p *customEmailProvider) Name() string  { return p.providerName }
func (p *customEmailProvider) UsePKCE() bool { return false }

func (p *customEmailProvider) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		RedirectURL:  "/callback",
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.example.com/auth",
			TokenURL: "https://provider.example.com/token",
		},
	}
}

func (p *customEmailProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
	return p.foreignID, p.email, nil
}

// customVerifiedEmailProvider additionally implements
// VerifiedIdentityProvider and reports a verified email.
type customVerifiedEmailProvider struct {
	customEmailProvider
}

func (p *customVerifiedEmailProvider) FetchVerifiedIdentity(ctx context.Context, client *http.Client) (string, string, bool, error) {
	return p.foreignID, p.email, true, nil
}

// runCustomProviderCallback drives login + callback for the given provider
// and returns the callback response.
func runCustomProviderCallback(t *testing.T, h http.Handler, provider auth.OAuthProvider) *http.Response {
	t.Helper()
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/"+provider.Name(), nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)

	var stateCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == provider.Name()+"_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie not set")
	}
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(200, `{"access_token":"valid_token","token_type":"bearer","expires_in":3600}`), nil
	})

	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/"+provider.Name()+"?state="+stateVal+"&code=fake", nil)
	callbackReq.AddCookie(stateCookie)
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
	callbackW := httptest.NewRecorder()
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	return callbackW.Result()
}

// TestCustomProviderWithoutVerificationFailsClosed: a provider that
// implements only FetchIdentity is treated as unverified, so its email is
// never used to match an existing account (AC fail-closed).
func TestCustomProviderWithoutVerificationFailsClosed(t *testing.T) {
	db, _, victimID := createAccountThenSignOut(t, "victim@example.com")
	usersBefore := userCount(t, db)

	settings := auth.DefaultSettings
	provider := &customEmailProvider{providerName: "customfetch", foreignID: "custom-sub-777", email: "victim@example.com"}
	settings.OAuthProviders = []auth.OAuthProvider{provider}
	h := auth.New(db, settings)

	resp := runCustomProviderCallback(t, h, provider)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a custom provider without a verification signal, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			t.Errorf("a session cookie was issued for a rejected custom provider sign-in")
		}
	}

	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows", usersBefore, usersAfter)
	}
	if id := oauthRowUser(t, db, "customfetch", "custom-sub-777"); id != 0 {
		t.Errorf("oauth row created for custom-sub-777 linked to userid %d (victim is %d)", id, victimID)
	}
}

// TestCustomProviderWithVerifiedIdentityLinks: implementing
// FetchVerifiedIdentity with verified=true restores email-based sign-in.
func TestCustomProviderWithVerifiedIdentityLinks(t *testing.T) {
	db := newMemoryDB(t)
	settings := auth.DefaultSettings
	provider := &customVerifiedEmailProvider{
		customEmailProvider{providerName: "customverified", foreignID: "custom-sub-888", email: "newperson@example.com"},
	}
	settings.OAuthProviders = []auth.OAuthProvider{provider}
	h := auth.New(db, settings)

	resp := runCustomProviderCallback(t, h, provider)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for a verified custom provider sign-in, got %d", resp.StatusCode)
	}

	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	userid := utx.GetUserByEmail("newperson@example.com")
	if userid == 0 {
		t.Fatal("user not created for the verified custom provider email")
	}
	if id := utx.GetOauthUser("customverified", "custom-sub-888"); id != userid {
		t.Errorf("oauth row for custom-sub-888 linked to userid %d, want %d", id, userid)
	}
}

// TestVerifyOauthRejectsUnverifiedEmail checks that the exported
// VerifyOauth keeps its signature but panics with an HTTP 401 error for an
// unverified provider email, while VerifyOauthVerified exposes the flag.
func TestVerifyOauthRejectsUnverifiedEmail(t *testing.T) {
	startProviderMock(t, `{"sub":"attacker-sub-999","email":"victim@example.com","email_verified":"false"}`)

	func() {
		defer func() {
			thing := recover()
			if thing == nil {
				t.Fatal("VerifyOauth returned normally instead of panicking on an unverified email")
			}
			herr, ok := thing.(auth.HTTPError)
			if !ok {
				t.Fatalf("panic value is not auth.HTTPError: %v", thing)
			}
			if herr.StatusCode() != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d", herr.StatusCode())
			}
			if herr.Error() != "provider email not verified" {
				t.Errorf("expected clear message, got %q", herr.Error())
			}
		}()
		auth.VerifyOauth("google", "tok")
	}()

	id, email, verified := auth.VerifyOauthVerified("google", "tok")
	if verified {
		t.Errorf("VerifyOauthVerified reported verified=true for an unverified email")
	}
	if id != "attacker-sub-999" || email != "victim@example.com" {
		t.Errorf("VerifyOauthVerified returned (%q, %q)", id, email)
	}
}

// TestVerifyOauthVerifiedEmailReturnsFlag checks the happy path of the
// exported verification API.
func TestVerifyOauthVerifiedEmailReturnsFlag(t *testing.T) {
	startProviderMock(t, `{"sub":"sub-1","email":"someone@example.com","email_verified":"true"}`)

	id, email := auth.VerifyOauth("google", "tok")
	if id != "sub-1" || email != "someone@example.com" {
		t.Errorf("VerifyOauth returned (%q, %q)", id, email)
	}

	id, email, verified := auth.VerifyOauthVerified("google", "tok")
	if !verified {
		t.Errorf("VerifyOauthVerified reported verified=false for a verified email")
	}
	if id != "sub-1" || email != "someone@example.com" {
		t.Errorf("VerifyOauthVerified returned (%q, %q)", id, email)
	}
}

// TestOauthAddUpdateEmailRequiresVerified checks that /user/oauth/add keeps
// linking authenticated identities but only honors update_email for a
// verified provider email.
func TestOauthAddUpdateEmailRequiresVerified(t *testing.T) {
	db := newMemoryDB(t)
	client := newTestClient(auth.New(db, auth.DefaultSettings))
	client.do(t, testRequest{
		name:   "Create account for linking",
		path:   "/user/create",
		params: map[string]string{"email": "adder@example.com", "password": "password"},
		code:   200,
	})

	// Facebook treats an empty email as unverified: update_email must be
	// refused, and the whole request rolls back.
	startProviderMock(t, `{"id":"fb-666","name":"No Email"}`)
	resp := client.makeRequest(t, "/user/oauth/add", map[string]string{
		"method":       "facebook",
		"token":        "tok",
		"update_email": "true",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for update_email with an unverified provider email, got %d", resp.StatusCode)
	}

	utx := db.Begin(context.Background()).(auth.UserTx)
	userid := utx.GetUserByEmail("adder@example.com")
	utx.Rollback()
	if userid == 0 {
		t.Fatal("account missing")
	}
	if id := oauthRowUser(t, db, "facebook", "fb-666"); id != 0 {
		t.Errorf("oauth row survived the rejected update_email")
	}
	utx = db.Begin(context.Background()).(auth.UserTx)
	if got := utx.GetEmail(userid); got != "adder@example.com" {
		t.Errorf("account email changed to %q by an unverified update_email", got)
	}
	utx.Rollback()

	// A returned email means confirmed for Facebook: update_email applies.
	startProviderMock(t, `{"id":"fb-777","name":"With Email","email":"confirmed@example.com"}`)
	client.do(t, testRequest{
		name:   "update_email with a verified provider email succeeds",
		path:   "/user/oauth/add",
		params: map[string]string{"method": "facebook", "token": "tok", "update_email": "true"},
		code:   200,
		json:   map[string]interface{}{"email": "confirmed@example.com"},
	})

	utx = db.Begin(context.Background()).(auth.UserTx)
	got := utx.GetEmail(userid)
	linked := utx.GetOauthUser("facebook", "fb-777")
	utx.Rollback()
	if got != "confirmed@example.com" {
		t.Errorf("account email is %q, want confirmed@example.com", got)
	}
	if linked != userid {
		t.Errorf("oauth row for fb-777 linked to userid %d, want %d", linked, userid)
	}
}
