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
	
	cookies := loginW.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "twitter_oauth_state" {
			stateCookie = c
			break
		}
	}
    if stateCookie == nil {
        t.Fatal("No state cookie")
    }
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+stateVal+"&code=fakerequestcode", nil)
	callbackReq.AddCookie(stateCookie)
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
	
	cookies2 := loginW2.Result().Cookies()
	var stateCookie2 *http.Cookie
	for _, c := range cookies2 {
		if c.Name == "twitter_oauth_state" {
			stateCookie2 = c
			break
		}
	}
	stateVal2 := strings.Split(stateCookie2.Value, "|")[0]

	// Callback 2
	callbackReq2 := httptest.NewRequest("GET", "/user/oauth/callback/twitter?state="+stateVal2+"&code=fakerequestcode2", nil)
	callbackReq2.AddCookie(stateCookie2)
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
	
	cookies := loginW.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "google_oauth_state" {
			stateCookie = c
			break
		}
	}
    if stateCookie == nil {
        t.Fatal("No state cookie")
    }
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/google?state="+stateVal+"&code=fakerequestcode", nil)
	callbackReq.AddCookie(stateCookie)
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
	
	cookies := loginW.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "facebook_oauth_state" {
			stateCookie = c
			break
		}
	}
    if stateCookie == nil {
        t.Fatal("No state cookie")
    }
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	// 2. Prepare Callback
	callbackReq := httptest.NewRequest("GET", "/user/oauth/callback/facebook?state="+stateVal+"&code=fakerequestcode", nil)
	callbackReq.AddCookie(stateCookie)
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
