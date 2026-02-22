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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

func TestTwitterLoginWithEmailScope(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.TwitterClientID = "cid"
	settings.TwitterClientSecret = "csec"
	settings.TwitterRedirectURL = "http://localhost/callback"
	settings.TwitterUseEmail = true
	
	h := New(db, settings)

	req := httptest.NewRequest("GET", "/user/oauth/login/twitter", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	resp := w.Result()
	loc, _ := resp.Location()
	
	// Parse URL and check scope param
	u, _ := url.Parse(loc.String())
	scope := u.Query().Get("scope")
	if !strings.Contains(scope, "users.email") {
		t.Errorf("Expected scope to contain users.email, got %s", scope)
	}
}

func TestTwitterCallbackWithEmail(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.TwitterClientID = "cid"
	settings.TwitterClientSecret = "csec"
	settings.TwitterRedirectURL = "/callback"
	settings.TwitterUseEmail = true
	
	h := New(db, settings)

	// 1. Simulate Login to get cookie
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/twitter", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)
	
	// Extract state from the redirect URL (server-side state, no cookies)
	eResp := loginW.Result()
	eLoc, err := eResp.Location()
	if err != nil {
		t.Fatal("No redirect location from Twitter login")
	}
	stateVal := eLoc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("No state in redirect URL")
	}

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+url.QueryEscape(stateVal)+"&code=fakerequestcode", nil)
	callbackW := httptest.NewRecorder()

	// Mock Transport
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://api.twitter.com/2/oauth2/token" {
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
			if req.URL.String() == "https://api.twitter.com/2/users/me?user.fields=confirmed_email" {
				// Return fake user with email
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"data": {
							"id": "12345",
							"name": "Test User",
							"username": "testuser",
							"confirmed_email": "realemail@example.com"
						}
					}`)),
				}, nil
			} else if req.URL.String() == "https://api.twitter.com/2/users/me" {
				t.Error("Did not expect call without params")
			}
			return nil, nil // Error
		},
	}
	
	client := &http.Client{Transport: mock}
	ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, client)
	
	// Inject mocked context
	h.ServeHTTP(callbackW, callbackReq.WithContext(ctx))
	
	// Verify user created with correct email
	tx := db.Begin(context.Background())
	uid := tx.GetUserByEmail("realemail@example.com")
	if uid == 0 {
		t.Error("User with real email was not created")
	}
	tx.Rollback()
}
