package auth_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/smhanov/auth"
)

// googleClientID is the Google client ID configured on the handlers used
// in these tests. Mock tokeninfo responses must carry it as aud to be
// accepted.
const googleClientID = "my-app.apps.googleusercontent.com"

// googleAuthSettings returns DefaultSettings with the legacy
// method=google token path enabled.
func googleAuthSettings() auth.Settings {
	settings := auth.DefaultSettings
	settings.GoogleClientID = googleClientID
	return settings
}

// startProviderStatusMock points auth.TestURL at a server that answers
// every request with the given status and body.
func startProviderStatusMock(t *testing.T, status int, body string) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	previous := auth.TestURL
	auth.TestURL = ts.URL
	t.Cleanup(func() {
		auth.TestURL = previous
		ts.Close()
	})
}

// googleTokenInfo formats a tokeninfo response; the tokeninfo endpoint
// returns every claim as a JSON string.
func googleTokenInfo(sub, email string, emailVerified bool, aud, iss string) string {
	return fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":"%t","aud":%q,"iss":%q}`,
		sub, email, emailVerified, aud, iss)
}

// TestGoogleTokenAudienceRejected is the regression test for token replay:
// a valid Google ID token issued to a different OAuth client must not
// authenticate that Google user here, even with a verified email.
func TestGoogleTokenAudienceRejected(t *testing.T) {
	db := newMemoryDB(t)
	client := newTestClient(auth.New(db, googleAuthSettings()))
	usersBefore := userCount(t, db)

	startProviderStatusMock(t, http.StatusOK, googleTokenInfo(
		"foreign-sub-1", "victim@example.com", true,
		"someone-elses-app.apps.googleusercontent.com", "accounts.google.com"))

	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "google",
		"token":  "replayed-token",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body %s", resp.StatusCode, readAllBody(t, resp))
	}
	if got := resp.Header.Get("Status"); got != "invalid google token" {
		t.Errorf("expected an invalid google token message, got %q", got)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			t.Errorf("a session cookie was issued for a foreign-audience token")
		}
	}
	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows", usersBefore, usersAfter)
	}
	if id := oauthRowUser(t, db, "google", "foreign-sub-1"); id != 0 {
		t.Errorf("oauth row created for foreign-sub-1 despite the wrong aud")
	}
}

// TestGoogleTokenMatchingAudienceAccepted checks that a token issued for
// the configured client ID is accepted for both iss spellings the
// tokeninfo endpoint emits.
func TestGoogleTokenMatchingAudienceAccepted(t *testing.T) {
	for _, iss := range []string{"accounts.google.com", "https://accounts.google.com"} {
		t.Run(iss, func(t *testing.T) {
			db := newMemoryDB(t)
			client := newTestClient(auth.New(db, googleAuthSettings()))

			startProviderStatusMock(t, http.StatusOK, googleTokenInfo(
				"sub-42", "googleperson@example.com", true, googleClientID, iss))

			client.do(t, testRequest{
				name:   "google token with matching aud and iss accepted",
				path:   "/user/auth",
				params: map[string]string{"method": "google", "token": "tok"},
				code:   200,
				json: map[string]interface{}{
					"email":   "googleperson@example.com",
					"methods": []string{"google"},
				},
			})

			if id := oauthRowUser(t, db, "google", "sub-42"); id == 0 {
				t.Errorf("no oauth row linked for sub-42")
			}
		})
	}
}

// TestGoogleTokenIssuerRejected checks that a missing or foreign iss fails
// closed even when the aud matches.
func TestGoogleTokenIssuerRejected(t *testing.T) {
	for _, iss := range []string{"", "https://evil.example.com", "accounts.google.com.evil.example"} {
		t.Run(iss, func(t *testing.T) {
			db := newMemoryDB(t)
			client := newTestClient(auth.New(db, googleAuthSettings()))
			usersBefore := userCount(t, db)

			startProviderStatusMock(t, http.StatusOK, googleTokenInfo(
				"sub-43", "victim@example.com", true, googleClientID, iss))

			resp := client.makeRequest(t, "/user/auth", map[string]string{
				"method": "google",
				"token":  "tok",
			})
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected 401 for iss %q, got %d body %s", iss, resp.StatusCode, readAllBody(t, resp))
			}
			if usersAfter := userCount(t, db); usersAfter != usersBefore {
				t.Errorf("users table changed from %d to %d rows for iss %q", usersBefore, usersAfter, iss)
			}
		})
	}
}

// TestGoogleTokeninfoErrorFailsCleanly checks that a non-200 tokeninfo
// response fails the request instead of being decoded as an empty
// identity.
func TestGoogleTokeninfoErrorFailsCleanly(t *testing.T) {
	db := newMemoryDB(t)
	client := newTestClient(auth.New(db, googleAuthSettings()))
	usersBefore := userCount(t, db)

	startProviderStatusMock(t, http.StatusServiceUnavailable, `{"error":"backendError","error_description":"Backend Error"}`)

	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "google",
		"token":  "tok",
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body %s", resp.StatusCode, readAllBody(t, resp))
	}
	if got := resp.Header.Get("Status"); got != "oauth provider error" {
		t.Errorf("expected oauth provider error, got %q", got)
	}
	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows: an identity was decoded from an error body", usersBefore, usersAfter)
	}
	if id := oauthRowUser(t, db, "google", ""); id != 0 {
		t.Errorf("oauth row created for an empty foreign id")
	}
}

// TestGoogleAuthRequiresConfiguredClientID checks that method=google fails
// closed with a clear error when no client ID is configured.
func TestGoogleAuthRequiresConfiguredClientID(t *testing.T) {
	db := newMemoryDB(t)
	client := newTestClient(auth.New(db, auth.DefaultSettings))
	usersBefore := userCount(t, db)

	startProviderStatusMock(t, http.StatusOK, googleTokenInfo(
		"sub-7", "someone@example.com", true, googleClientID, "accounts.google.com"))

	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"method": "google",
		"token":  "tok",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body %s", resp.StatusCode, readAllBody(t, resp))
	}
	if got := resp.Header.Get("Status"); got != "google client id not configured" {
		t.Errorf("expected google client id not configured, got %q", got)
	}
	if usersAfter := userCount(t, db); usersAfter != usersBefore {
		t.Errorf("users table changed from %d to %d rows", usersBefore, usersAfter)
	}
}

// TestVerifyOauthGoogleRequiresHandler checks that the package-level
// helpers reject method=google with a 400 pointing at the handler-based
// path, because they have no client ID to verify the aud claim against.
// Facebook keeps working through the package-level helpers.
func TestVerifyOauthGoogleRequiresHandler(t *testing.T) {
	expectGooglePanic := func(t *testing.T, call func()) {
		t.Helper()
		defer func() {
			thing := recover()
			if thing == nil {
				t.Fatal("expected a panic for method=google without Handler settings")
			}
			herr, ok := thing.(auth.HTTPError)
			if !ok {
				t.Fatalf("panic value is not auth.HTTPError: %v", thing)
			}
			if herr.StatusCode() != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", herr.StatusCode())
			}
			if !strings.Contains(herr.Error(), "google client id not configured") {
				t.Errorf("expected a message directing to the handler path, got %q", herr.Error())
			}
		}()
		call()
	}

	expectGooglePanic(t, func() { auth.VerifyOauth("google", "tok") })
	expectGooglePanic(t, func() { auth.VerifyOauthVerified("google", "tok") })

	startProviderStatusMock(t, http.StatusOK, `{"id":"fb-9","name":"With Email","email":"fbperson@example.com"}`)
	id, email, verified := auth.VerifyOauthVerified("facebook", "tok")
	if !verified || id != "fb-9" || email != "fbperson@example.com" {
		t.Errorf("VerifyOauthVerified(facebook) returned (%q, %q, %v)", id, email, verified)
	}
	id, email = auth.VerifyOauth("facebook", "tok")
	if id != "fb-9" || email != "fbperson@example.com" {
		t.Errorf("VerifyOauth(facebook) returned (%q, %q)", id, email)
	}
}
