package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

func TestSanitizeRedirectTarget(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "/"},
		{name: "relative path", input: "/dashboard", want: "/dashboard"},
		{name: "path with query", input: "/dashboard?tab=1", want: "/dashboard?tab=1"},
		{name: "absolute url", input: "https://evil.com/phish", want: "/"},
		{name: "scheme relative", input: "//evil.com/phish", want: "/"},
		{name: "missing leading slash", input: "dashboard", want: "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRedirectTarget(tc.input); got != tc.want {
				t.Fatalf("sanitizeRedirectTarget(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestOAuthLoginRejectsExternalNext(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		cookieName string
		settings   func(*Settings)
	}{
		{
			name:       "google",
			path:       "/user/oauth/login/google?next=https://evil.com/phish",
			cookieName: "google_oauth_state",
			settings: func(s *Settings) {
				s.GoogleClientID = "cid"
				s.GoogleClientSecret = "secret"
			},
		},
		{
			name:       "facebook",
			path:       "/user/oauth/login/facebook?next=https://evil.com/phish",
			cookieName: "facebook_oauth_state",
			settings: func(s *Settings) {
				s.FacebookClientID = "cid"
				s.FacebookClientSecret = "secret"
			},
		},
		{
			name:       "twitter",
			path:       "/user/oauth/login/twitter?next=https://evil.com/phish",
			cookieName: "twitter_oauth_state",
			settings: func(s *Settings) {
				s.TwitterClientID = "cid"
				s.TwitterClientSecret = "secret"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
			settings := DefaultSettings
			tc.settings(&settings)

			h := New(db, settings)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			h.ServeHTTP(w, req)

			resp := w.Result()
			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("expected redirect, got %d", resp.StatusCode)
			}

			var stateCookie *http.Cookie
			for _, c := range resp.Cookies() {
				if c.Name == tc.cookieName {
					stateCookie = c
					break
				}
			}
			if stateCookie == nil {
				t.Fatalf("expected %s cookie", tc.cookieName)
			}

			parts := strings.Split(stateCookie.Value, "|")
			if got := parts[len(parts)-1]; got != "/" {
				t.Fatalf("expected sanitized redirect target '/', got %q", got)
			}
		})
	}
}

func TestSanitizeRefererReturnPath(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		referer string
		want    string
	}{
		{
			name:    "same-origin absolute referer",
			target:  "https://app.example.com/user/auth?sso=1",
			referer: "https://app.example.com/dashboard?tab=1",
			want:    "/dashboard?tab=1",
		},
		{
			name:    "same-origin relative referer",
			target:  "https://app.example.com/user/auth?sso=1",
			referer: "/settings",
			want:    "/settings",
		},
		{
			name:    "external referer",
			target:  "https://app.example.com/user/auth?sso=1",
			referer: "https://evil.com/phish",
			want:    "/",
		},
		{
			name:    "scheme-relative referer",
			target:  "https://app.example.com/user/auth?sso=1",
			referer: "//evil.com/phish",
			want:    "/",
		},
		{
			name:    "scheme mismatch referer",
			target:  "https://app.example.com/user/auth?sso=1",
			referer: "http://app.example.com/dashboard",
			want:    "/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.Header.Set("Referer", tc.referer)
			if got := sanitizeRefererReturnPath(req); got != tc.want {
				t.Fatalf("sanitizeRefererReturnPath(%q) = %q, want %q", tc.referer, got, tc.want)
			}
		})
	}
}
