package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smhanov/auth"
	"golang.org/x/oauth2"
)

// capturedEmail records one email dispatched through the SendEmailFn stub.
type capturedEmail struct {
	email string
	token string
}

// firstLinkSettings returns googleAuthSettings with a SendEmailFn stub and
// an OnAuthEvent recorder, so tests can observe the first-link notification.
func firstLinkSettings() (auth.Settings, *[]capturedEmail, *[]string) {
	settings := googleAuthSettings()
	emails := &[]capturedEmail{}
	actions := &[]string{}
	settings.SendEmailFn = func(email, token string) {
		*emails = append(*emails, capturedEmail{email: email, token: token})
	}
	settings.OnAuthEvent = func(tx auth.Tx, action string, userid int64, info auth.UserInfo) {
		*actions = append(*actions, action)
	}
	return settings, emails, actions
}

// storedPasswordFor returns the stored password for the given email.
func storedPasswordFor(t *testing.T, db *auth.UserDB, email string) string {
	t.Helper()
	utx := db.Begin(context.Background()).(auth.UserTx)
	defer utx.Rollback()
	_, password := utx.GetPassword(email)
	return password
}

// TestFirstOauthLinkClearsPassword is the pre-hijack regression test: an
// attacker registers victim@example.com with a password they know (this
// library never verifies email at signup). When the real owner later signs
// in through oauth with the same verified address, the link must silently
// disable the attacker's credential and session — no notification email is
// sent.
func TestFirstOauthLinkClearsPassword(t *testing.T) {
	settings, emails, actions := firstLinkSettings()
	db := newMemoryDB(t)
	server := auth.New(db, settings)
	attacker := newTestClient(server)

	attacker.do(t, testRequest{
		name:   "Attacker pre-creates the victim account",
		path:   "/user/create",
		params: map[string]string{"email": "victim@example.com", "password": "attacker-password"},
		code:   200,
	})
	oldSession := attacker.session
	if oldSession == "" {
		t.Fatal("no session after account creation")
	}

	utx := db.Begin(context.Background()).(auth.UserTx)
	victimID := utx.GetUserByEmail("victim@example.com")
	utx.Rollback()
	if victimID == 0 {
		t.Fatal("account missing")
	}

	// The real owner signs in with Google using the same verified address.
	linkActions := len(*actions)
	startProviderMock(t, googleTokenInfo("owner-sub-1", "victim@example.com", true, googleClientID, "accounts.google.com"))
	attacker.do(t, testRequest{
		name:   "Owner signs in with a verified google identity",
		path:   "/user/auth",
		params: map[string]string{"method": "google", "token": "owner-token"},
		code:   200,
		json: map[string]interface{}{
			"email":   "victim@example.com",
			"userid":  float64(victimID),
			"methods": []string{"google"},
		},
	})
	newSession := attacker.session
	if newSession == "" || newSession == oldSession {
		t.Fatalf("expected a fresh session after the link, got %q", newSession)
	}
	linkEmitted := (*actions)[linkActions:]

	// The stored password is gone and password login is rejected.
	if got := storedPasswordFor(t, db, "victim@example.com"); got != "" {
		t.Errorf("stored password survived the first oauth link")
	}
	attacker.do(t, testRequest{
		name:   "The attacker's old password no longer signs in",
		path:   "/user/auth",
		params: map[string]string{"email": "victim@example.com", "password": "attacker-password"},
		code:   401,
		status: "wrong password",
	})

	// The pre-link session is invalid; the oauth session works.
	ghost := newTestClient(server)
	ghost.session = oldSession
	if resp := ghost.makeRequest(t, "/user/get", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("pre-link session still valid after the link (status %d)", resp.StatusCode)
	}
	attacker.do(t, testRequest{
		name: "The oauth request's own session still works",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{"email": "victim@example.com"},
	})

	// The linking sign-in sends no email: the library stays silent and
	// exposes the "oauthlink" action for apps that want to notify.
	if len(*emails) != 0 {
		t.Errorf("reset emails sent during first-link: %v, want none", *emails)
	}

	// The app sees "oauthlink" followed by the sign-in event for the
	// linking request.
	if len(linkEmitted) != 2 || linkEmitted[0] != "oauthlink" || linkEmitted[1] != "auth" {
		t.Errorf("OnAuthEvent actions for the linking sign-in = %v, want [oauthlink auth]", linkEmitted)
	}
}

// TestFirstOauthLinkWithoutPasswordSendsNoEmail checks that linking to an
// account that has no password (created through oauth) clears nothing and
// sends no email.
func TestFirstOauthLinkWithoutPasswordSendsNoEmail(t *testing.T) {
	settings, emails, actions := firstLinkSettings()
	db := newMemoryDB(t)
	server := auth.New(db, settings)
	client := newTestClient(server)

	// The first identity creates the account with a null password.
	startProviderMock(t, googleTokenInfo("sub-first", "someone@example.com", true, googleClientID, "accounts.google.com"))
	client.do(t, testRequest{
		name:   "First google sign-in creates the account",
		path:   "/user/auth",
		params: map[string]string{"method": "google", "token": "tok-1"},
		code:   200,
	})

	utx := db.Begin(context.Background()).(auth.UserTx)
	userID := utx.GetUserByEmail("someone@example.com")
	utx.Rollback()

	// A second, different identity with the same verified email links to
	// the password-less account: no hardening, no email, no error.
	startProviderMock(t, googleTokenInfo("sub-second", "someone@example.com", true, googleClientID, "accounts.google.com"))
	client.do(t, testRequest{
		name:   "Second google identity links to the password-less account",
		path:   "/user/auth",
		params: map[string]string{"method": "google", "token": "tok-2"},
		code:   200,
		json:   map[string]interface{}{"userid": float64(userID)},
	})

	if len(*emails) != 0 {
		t.Errorf("reset emails sent: %v, want none", *emails)
	}
	if id := oauthRowUser(t, db, "google", "sub-second"); id != userID {
		t.Errorf("oauth row for sub-second linked to userid %d, want %d", id, userID)
	}
	if got := storedPasswordFor(t, db, "someone@example.com"); got != "" {
		t.Errorf("password-less account gained a stored password")
	}
	for _, action := range *actions {
		if action == "oauthlink" {
			t.Errorf("OnAuthEvent saw oauthlink for a password-less account")
		}
	}
}

// TestFirstOauthLinkUnverifiedEmailKeepsPassword checks the DoS variant: an
// oauth identity carrying the victim's address but not verified by the
// provider is rejected outright by the verified-email gate, and the stored
// password is untouched.
func TestFirstOauthLinkUnverifiedEmailKeepsPassword(t *testing.T) {
	settings, emails, _ := firstLinkSettings()
	db := newMemoryDB(t)
	server := auth.New(db, settings)
	client := newTestClient(server)

	client.do(t, testRequest{
		name:   "Create the account with a password",
		path:   "/user/create",
		params: map[string]string{"email": "victim@example.com", "password": "original-password"},
		code:   200,
	})
	client.do(t, testRequest{
		name: "Sign out",
		path: "/user/signout",
		code: 200,
	})

	startProviderMock(t, googleTokenInfo("attacker-sub-5", "victim@example.com", false, googleClientID, "accounts.google.com"))
	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "google",
		"token":  "tok",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unverified provider email, got %d body %s", resp.StatusCode, readAllBody(t, resp))
	}

	if len(*emails) != 0 {
		t.Errorf("reset emails sent: %v, want none", *emails)
	}
	if got := storedPasswordFor(t, db, "victim@example.com"); got == "" {
		t.Fatal("stored password was cleared by a rejected sign-in")
	}
	client.do(t, testRequest{
		name:   "The original password still signs in",
		path:   "/user/auth",
		params: map[string]string{"email": "victim@example.com", "password": "original-password"},
		code:   200,
	})
}

// TestOauthAddDoesNotClearPassword checks that explicit linking while
// authenticated never removes the stored password, even when the provider
// email matches the account.
func TestOauthAddDoesNotClearPassword(t *testing.T) {
	settings, emails, actions := firstLinkSettings()
	db := newMemoryDB(t)
	server := auth.New(db, settings)
	client := newTestClient(server)

	client.do(t, testRequest{
		name:   "Create the account",
		path:   "/user/create",
		params: map[string]string{"email": "linker@example.com", "password": "real-password"},
		code:   200,
	})

	startProviderMock(t, googleTokenInfo("link-sub", "linker@example.com", true, googleClientID, "accounts.google.com"))
	client.do(t, testRequest{
		name:   "Link google while signed in",
		path:   "/user/oauth/add",
		params: map[string]string{"method": "google", "token": "tok"},
		code:   200,
	})

	if len(*emails) != 0 {
		t.Errorf("reset emails sent: %v, want none", *emails)
	}
	if got := storedPasswordFor(t, db, "linker@example.com"); got == "" {
		t.Error("stored password cleared by /user/oauth/add")
	}
	if id := oauthRowUser(t, db, "google", "link-sub"); id == 0 {
		t.Error("oauth row missing after /user/oauth/add")
	}
	for _, action := range *actions {
		if action == "oauthlink" {
			t.Errorf("OnAuthEvent saw oauthlink for an explicit /user/oauth/add link")
		}
	}
	client.do(t, testRequest{
		name:   "The password still signs in",
		path:   "/user/auth",
		params: map[string]string{"email": "linker@example.com", "password": "real-password"},
		code:   200,
	})
}

// TestOAuthCallbackWithSessionDoesNotClearPassword checks the other explicit
// linking path: an oauth callback that arrives while already signed in
// attaches the identity and never touches the stored password.
func TestOAuthCallbackWithSessionDoesNotClearPassword(t *testing.T) {
	db := newMemoryDB(t)
	settings := auth.DefaultSettings
	var emails []capturedEmail
	settings.SendEmailFn = func(email, token string) {
		emails = append(emails, capturedEmail{email: email, token: token})
	}
	provider := &customVerifiedEmailProvider{
		customEmailProvider{providerName: "sessioncb", foreignID: "cb-sub-1", email: "owner@example.com"},
	}
	settings.OAuthProviders = []auth.OAuthProvider{provider}
	server := auth.New(db, settings)

	client := newTestClient(server)
	client.do(t, testRequest{
		name:   "Create the account",
		path:   "/user/create",
		params: map[string]string{"email": "owner@example.com", "password": "keep-me"},
		code:   200,
	})

	loginReq := httptest.NewRequest("GET", "/user/oauth/login/sessioncb", nil)
	loginW := httptest.NewRecorder()
	server.ServeHTTP(loginW, loginReq)

	var stateCookie *http.Cookie
	for _, c := range loginW.Result().Cookies() {
		if c.Name == "sessioncb_oauth_state" {
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

	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/sessioncb?state="+stateVal+"&code=fake", nil)
	// The authenticated session turns the callback into an explicit link.
	callbackReq.Header.Set("Cookie", "session="+client.session)
	callbackReq.AddCookie(stateCookie)
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
	callbackW := httptest.NewRecorder()
	server.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	resp := callbackW.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from the callback, got %d", resp.StatusCode)
	}

	if len(emails) != 0 {
		t.Errorf("reset emails sent: %v, want none", emails)
	}
	if got := storedPasswordFor(t, db, "owner@example.com"); got == "" {
		t.Error("stored password cleared by an authenticated callback link")
	}
	if id := oauthRowUser(t, db, "sessioncb", "cb-sub-1"); id == 0 {
		t.Error("oauth row missing after the authenticated callback link")
	}
	client.do(t, testRequest{
		name: "The original session still works",
		path: "/user/get",
		code: 200,
		json: map[string]interface{}{"email": "owner@example.com"},
	})
}
