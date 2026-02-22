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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

func TestTwitterLogin(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.TwitterClientID = "cid"
	settings.TwitterClientSecret = "csec"
	settings.TwitterRedirectURL = "http://localhost/callback"
	
	h := New(db, settings)

	req := httptest.NewRequest("GET", "/user/oauth/login/twitter", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("Expected redirect, got %d", resp.StatusCode)
	}

	loc, _ := resp.Location()
	if !strings.HasPrefix(loc.String(), "https://twitter.com/i/oauth2/authorize") {
		t.Errorf("Wrong redirect URL: %s", loc.String())
	}
	
	cookies := resp.Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "twitter_oauth_state" {
			stateCookie = c
			break
		}
	}
	
	if stateCookie == nil {
		t.Fatal("State cookie not set")
	}
}

type mockTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

func TestTwitterCallback(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.TwitterClientID = "cid"
	settings.TwitterClientSecret = "csec"
	settings.TwitterRedirectURL = "/callback" // Test relative path
	
	h := New(db, settings)

	// 1. Simulate Login to get cookie (with next)
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/twitter?next=/dashboard", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)
	
	cookies := loginW.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "twitter_oauth_state" {
			stateCookie = c
			break
		}
	}
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+stateVal+"&code=fakerequestcode", nil)
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	// Mock Transport
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://api.twitter.com/2/oauth2/token" {
				// Return fake token
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "valid_token",
						"token_type": "bearer",
						"expires_in": 3600
					}`)),
				}, nil
			}
			if req.URL.String() == "https://api.twitter.com/2/users/me" {
				// Return fake user
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"data": {
							"id": "12345",
							"name": "Test User",
							"username": "testuser"
						}
					}`)),
				}, nil
			}
			return nil, nil // Error
		},
	}
	
	client := &http.Client{Transport: mock}
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, client)
	
	// Inject mocked context
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))

	resp := callbackW.Result()
	if resp.StatusCode != http.StatusFound { // Redirect
		t.Errorf("Expected redirect after callback, got %d. Body: %s", resp.StatusCode, callbackW.Body.String())
	}
	loc, _ := resp.Location()
	if loc.Path != "/dashboard" {
		t.Errorf("Expected redirect to /dashboard, got %s", loc.Path)
	}
	
	// Verify user created
	tx := db.Begin(context.Background())
	uid := tx.GetOauthUser("twitter", "12345")
	if uid == 0 {
		t.Error("User was not created in DB")
	}
	// Check email
	_, password := tx.GetPassword("testuser@twitter.example.com")
	if password != "" {
		t.Error("Password should be empty/mismatched but account should exist")
	}
	tx.Rollback()
}
