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

type reproMockTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *reproMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

func TestTwitterCallbackAuthHook(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.TwitterClientID = "cid"
	settings.TwitterClientSecret = "csec"
	settings.TwitterRedirectURL = "/callback" 
    
    var capturedAction string
    settings.OnAuthEvent = func(tx Tx, action string, userid int64, info UserInfo) {
        capturedAction = action
    }
	
	h := New(db, settings)

	// 1. Simulate Login to get cookie
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/twitter?next=/dashboard", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)
	
	// Extract state from the redirect URL (server-side state, no cookies)
	tResp := loginW.Result()
	tLoc, err := tResp.Location()
	if err != nil {
		t.Fatal("No redirect location from Twitter login")
	}
	stateVal := tLoc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("No state in redirect URL")
	}

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+url.QueryEscape(stateVal)+"&code=fakerequestcode", nil)
	callbackW := httptest.NewRecorder()

	// Mock Transport
	mock := &reproMockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "token") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "ACCESS_TOKEN",
						"token_type": "bearer",
						"expires_in": 3600
					}`)),
				}, nil
			}
            if strings.Contains(req.URL.String(), "users/me") {
                return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
                        "data": {
                            "id": "12345",
                            "name": "Test User",
                            "username": "testuser",
                            "confirmed_email": "test@example.com"
                        }
					}`)),
				}, nil
            }
            return &http.Response{StatusCode: 404}, nil
		},
	}
    
    ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
    callbackReq = callbackReq.WithContext(ctx)

    h.ServeHTTP(callbackW, callbackReq)
    
    if capturedAction != "create" {
        t.Errorf("OnAuthEvent action expected 'create', got '%s'", capturedAction)
    }

    // 3. Login again (existing user)
    capturedAction = ""
    // We can reuse the same mock since it returns the same user ID.
    // Need new login request sequence to get new state.
    
    // Login 2 ...
	loginReq2 := httptest.NewRequest("GET", "/user/oauth/login/twitter?next=/dashboard", nil)
	loginW2 := httptest.NewRecorder()
	h.ServeHTTP(loginW2, loginReq2)
	
	// Extract state from the redirect URL for second login
	tResp2 := loginW2.Result()
	tLoc2, err := tResp2.Location()
	if err != nil {
		t.Fatal("No redirect location from Twitter login 2")
	}
	stateVal2 := tLoc2.Query().Get("state")

	// Callback 2
	callbackReq2 := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+url.QueryEscape(stateVal2)+"&code=fakerequestcode2", nil)
	callbackW2 := httptest.NewRecorder()
    
    // Reuse context with mock
    ctx2 := context.WithValue(callbackReq2.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
    callbackReq2 = callbackReq2.WithContext(ctx2)
    
    h.ServeHTTP(callbackW2, callbackReq2)
    
    if capturedAction != "auth" {
        t.Errorf("Second OnAuthEvent action expected 'auth', got '%s'", capturedAction)
    }
}

func TestGoogleCallbackAuthHook(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.GoogleClientID = "cid"
	settings.GoogleClientSecret = "csec"
	settings.GoogleRedirectURL = "/callback" 
    
    var capturedAction string
    settings.OnAuthEvent = func(tx Tx, action string, userid int64, info UserInfo) {
        capturedAction = action
    }
	
	h := New(db, settings)

	// 1. Simulate Login to get cookie
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/google?next=/dashboard", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)
	
	// Extract state from the redirect URL (server-side state, no cookies)
	gResp := loginW.Result()
	gLoc, err := gResp.Location()
	if err != nil {
		t.Fatal("No redirect location from Google login")
	}
	stateVal := gLoc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("No state in redirect URL")
	}

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/google?state="+url.QueryEscape(stateVal)+"&code=fakerequestcode", nil)
	callbackW := httptest.NewRecorder()

	// Mock Transport
	mock := &reproMockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "token") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "ACCESS_TOKEN",
						"token_type": "bearer",
						"expires_in": 3600
					}`)),
				}, nil
			}
            if strings.Contains(req.URL.String(), "userinfo") {
                return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
                        "sub": "12345",
                        "name": "Test User",
                        "email": "test@example.com"
					}`)),
				}, nil
            }
            return &http.Response{StatusCode: 404}, nil
		},
	}
    
    ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
    callbackReq = callbackReq.WithContext(ctx)

    h.ServeHTTP(callbackW, callbackReq)
    
    if capturedAction != "create" {
        t.Errorf("OnAuthEvent action expected 'create', got '%s'", capturedAction)
    }
}

func TestFacebookCallbackAuthHook(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	settings := DefaultSettings
	settings.FacebookClientID = "cid"
	settings.FacebookClientSecret = "csec"
	settings.FacebookRedirectURL = "/callback" 
    
    var capturedAction string
    settings.OnAuthEvent = func(tx Tx, action string, userid int64, info UserInfo) {
        capturedAction = action
    }
	
	h := New(db, settings)

	// 1. Simulate Login to get cookie
	loginReq := httptest.NewRequest("GET", "/user/oauth/login/facebook?next=/dashboard", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)
	
	// Extract state from the redirect URL (server-side state, no cookies)
	fResp := loginW.Result()
	fLoc, err := fResp.Location()
	if err != nil {
		t.Fatal("No redirect location from Facebook login")
	}
	stateVal := fLoc.Query().Get("state")
	if stateVal == "" {
		t.Fatal("No state in redirect URL")
	}

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/facebook?state="+url.QueryEscape(stateVal)+"&code=fakerequestcode", nil)
	callbackW := httptest.NewRecorder()

	// Mock Transport
	mock := &reproMockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "token") {
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
						"access_token": "ACCESS_TOKEN",
						"token_type": "bearer",
						"expires_in": 3600
					}`)),
				}, nil
			}
            // Facebook graph api
            if strings.Contains(req.URL.String(), "facebook.com/me") {
                return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body: io.NopCloser(bytes.NewBufferString(`{
                        "id": "123456",
                        "name": "Test User",
                        "email": "test@example.com"
					}`)),
				}, nil
            }
            return &http.Response{StatusCode: 404}, nil
		},
	}
    
    ctx := context.WithValue(callbackReq.Context(), oauth2.HTTPClient, &http.Client{Transport: mock})
    callbackReq = callbackReq.WithContext(ctx)

    h.ServeHTTP(callbackW, callbackReq)
    
    if capturedAction != "create" {
        t.Errorf("OnAuthEvent action expected 'create', got '%s'", capturedAction)
    }
}
