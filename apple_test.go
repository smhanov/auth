package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
)

func appleTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func appleTestSettings(t *testing.T) Settings {
	t.Helper()
	settings := DefaultSettings
	settings.AppleClientID = "com.example.service"
	settings.AppleTeamID = "TEAMID123"
	settings.AppleKeyID = "KEYID123"
	settings.ApplePrivateKey = appleTestPrivateKeyPEM(t)
	return settings
}

func unsignedAppleIDToken(sub, email string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := map[string]string{"sub": sub}
	if email != "" {
		claims["email"] = email
	}
	payload, _ := json.Marshal(claims)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func TestAppleLogin(t *testing.T) {
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	h := New(db, appleTestSettings(t))

	req := httptest.NewRequest("GET", "/user/oauth/login/apple?next=/home", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("Apple Login: Expected redirect, got %d", resp.StatusCode)
	}

	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "appleid.apple.com" || loc.Path != "/auth/authorize" {
		t.Fatalf("Apple Login: unexpected redirect %s", loc)
	}
	q := loc.Query()
	if q.Get("client_id") != "com.example.service" {
		t.Errorf("client_id=%q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type=%q", q.Get("response_type"))
	}
	if q.Get("response_mode") != "form_post" {
		t.Errorf("response_mode=%q", q.Get("response_mode"))
	}
	if !strings.Contains(q.Get("scope"), "email") {
		t.Errorf("scope=%q", q.Get("scope"))
	}
	if q.Get("state") == "" {
		t.Error("missing state")
	}
	if q.Get("redirect_uri") != "http://example.com/user/oauth/callback/apple" {
		t.Errorf("redirect_uri=%q", q.Get("redirect_uri"))
	}

	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "apple_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Apple Login: State cookie not set")
	}
}

func TestAppleClientSecretJWT(t *testing.T) {
	p := &AppleProvider{
		ClientID:   "com.example.service",
		TeamID:     "TEAMID123",
		KeyID:      "KEYID123",
		PrivateKey: appleTestPrivateKeyPEM(t),
	}
	secret := p.OAuthConfig().ClientSecret
	if secret == "" {
		t.Fatal("empty client secret")
	}

	tok, _, err := new(jwt.Parser).ParseUnverified(secret, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Method != jwt.SigningMethodES256 {
		t.Errorf("alg=%v", tok.Method)
	}
	if tok.Header["kid"] != "KEYID123" {
		t.Errorf("kid=%v", tok.Header["kid"])
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != "TEAMID123" {
		t.Errorf("iss=%v", claims["iss"])
	}
	if claims["sub"] != "com.example.service" {
		t.Errorf("sub=%v", claims["sub"])
	}
	if claims["aud"] != "https://appleid.apple.com" {
		t.Errorf("aud=%v", claims["aud"])
	}
}

func TestAppleFlow(t *testing.T) {
	runAppleFlowTest(t, "001234.apple-user", "apple@example.com", "apple@example.com")
}

func TestAppleFlowMissingEmail(t *testing.T) {
	runAppleFlowTest(t, "001234.no-email", "", "001234.no-email@apple.example.com")
}

func runAppleFlowTest(t *testing.T, sub, tokenEmail, wantEmail string) {
	t.Helper()
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	h := New(db, appleTestSettings(t))

	req := httptest.NewRequest("GET", "/user/oauth/login/apple?next=/home", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "apple_oauth_state" {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("Apple Login: State cookie not set")
	}
	stateVal := strings.Split(stateCookie.Value, "|")[0]

	form := url.Values{}
	form.Set("state", stateVal)
	form.Set("code", "fake")
	callbackReq := httptest.NewRequest("POST", "/user/oauth/callback/apple", strings.NewReader(form.Encode()))
	callbackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	callbackReq.AddCookie(stateCookie)
	callbackW := httptest.NewRecorder()

	idToken := unsignedAppleIDToken(sub, tokenEmail)
	mock := &mockTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.String(), "appleid.apple.com/auth/token") {
				header := make(http.Header)
				header.Set("Content-Type", "application/json")
				body := `{"access_token":"valid_token","token_type":"bearer","id_token":"` + idToken + `"}`
				return &http.Response{
					StatusCode: 200,
					Header:     header,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
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
		t.Fatalf("Apple Callback: Expected redirect 302, got %d. Body: %s", resp.StatusCode, callbackW.Body.String())
	}
	loc, _ := resp.Location()
	if loc.Path != "/home" {
		t.Errorf("Apple: Expected redirect to /home, got %s", loc.Path)
	}

	tx := db.db.MustBegin()
	defer tx.Rollback()
	var count int
	err := tx.Get(&count, "SELECT count(*) FROM users WHERE email=?", wantEmail)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Apple user not created for %s", wantEmail)
	}
	err = tx.Get(&count, "SELECT count(*) FROM oauth WHERE method='apple' AND foreign_id=?", sub)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("Apple oauth row not created for %s", sub)
	}
}
