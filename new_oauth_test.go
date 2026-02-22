package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	// Extract state from the redirect URL (no longer stored in cookies)
	loc, err := resp.Location()
	if err != nil {
		t.Fatal("Google Login: No redirect location")
	}
	stateVal := loc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("Google Login: No state in redirect URL")
	}

	// 2. Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/google?state="+url.QueryEscape(stateVal)+"&code=fake", nil)
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
	callbackLoc, _ := resp.Location()
	if callbackLoc.Path != "/home" {
		t.Errorf("Google: Expected redirect to /home, got %s", callbackLoc.Path)
	}

	tx := db.db.MustBegin()
	var count int
	err = tx.Get(&count, "SELECT count(*) FROM users WHERE email='google@example.com'")
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
	
	// Extract state from the redirect URL (no longer stored in cookies)
	fbResp := w.Result()
	fbLoc, err := fbResp.Location()
	if err != nil {
		t.Fatal("Facebook Login: No redirect location")
	}
	stateVal := fbLoc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("Facebook Login: No state in redirect URL")
	}

	// 2. Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/facebook?state="+url.QueryEscape(stateVal)+"&code=fake", nil)
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

	fbCallbackResp := callbackW.Result()
	if fbCallbackResp.StatusCode != http.StatusFound {
		t.Errorf("Facebook Callback: Expected redirect 302, got %d. Body: %s", fbCallbackResp.StatusCode, callbackW.Body.String())
	}
	
	tx := db.db.MustBegin()
	var count int
	err = tx.Get(&count, "SELECT count(*) FROM users WHERE email='fb@example.com'")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Facebook User not created")
	}
	tx.Rollback()
}
