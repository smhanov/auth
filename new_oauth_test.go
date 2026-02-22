package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"golang.org/x/oauth2"
)

func TestGoogleFlow(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.GoogleClientID = "cid"
	settings.GoogleClientSecret = "csec"
	settings.GoogleRedirectURL = "/callback" // Test relative path
	
	h := New(db, settings)

	// 1. Login Redirect
	req := httptest.NewRequest("GET", "/user/oauth/login/google?next=/home", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("Google Login: Expected redirect, got %d", resp.StatusCode)
	}
	
	cookies := resp.Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "google_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Google Login: State cookie not set")
	}
	
	// 2. Callback
	stateVal := strings.Split(stateCookie.Value, "|")[0]
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/google?state="+stateVal+"&code=fake", nil)
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "token") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "valid_token", "token_type": "bearer", "expires_in": 3600
					}`)),
				}, nil
			}
			if strings.Contains(req.URL.String(), "userinfo") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"sub": "12345", "name": "Google User", "email": "google@example.com"
					}`)),
				}, nil
			}
			return nil, nil
		},
	}
	
	client := &http.Client{Transport: mock}
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, client)
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	resp = callbackW.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Google Callback: Expected redirect 302, got %d. Body: %s", resp.StatusCode, callbackW.Body.String())
	}
	loc, _ := resp.Location()
	if loc.Path != "/home" {
		t.Errorf("Google: Expected redirect to /home, got %s", loc.Path)
	}

	tx := db.db.MustBegin()
	var count int
	err := tx.Get(&count, "SELECT count(*) FROM users WHERE email='google@example.com'")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Google User not created")
	}
	tx.Rollback()
}

func TestFacebookFlow(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.FacebookClientID = "cid"
	settings.FacebookClientSecret = "csec"
	settings.FacebookRedirectURL = "http://localhost/callback"
	
	h := New(db, settings)

	// 1. Login Redirect
	req := httptest.NewRequest("GET", "/user/oauth/login/facebook", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	
	// Check cookie
	cookies := w.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "facebook_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Facebook Login: State cookie not set")
	}

	stateVal := strings.Split(stateCookie.Value, "|")[0]
	
	// 2. Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/facebook?state="+stateVal+"&code=fake", nil)
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "access_token") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "valid_token", "token_type": "bearer", "expires_in": 3600
					}`)),
				}, nil
			}

			if strings.Contains(req.URL.String(), "me") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"id": "67890", "name": "FB User", "email": "fb@example.com"
					}`)),
				}, nil
			}
			return nil, nil
		},
	}
	
	client := &http.Client{Transport: mock}
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, client)
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	resp := callbackW.Result()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Facebook Callback: Expected redirect 302, got %d. Body: %s", resp.StatusCode, callbackW.Body.String())
	}
	
	tx := db.db.MustBegin()
	var count int
	err := tx.Get(&count, "SELECT count(*) FROM users WHERE email='fb@example.com'")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Facebook User not created")
	}
	tx.Rollback()
}
