package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type appleIdentityEnv struct {
	key    *rsa.PrivateKey
	kid    string
	jwks   *httptest.Server
	bundle string
}

func setupAppleIdentity(t *testing.T) *appleIdentityEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-kid"
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwksJSON, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   n,
			"e":   e,
		}},
	})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
	t.Cleanup(func() {
		jwks.Close()
		appleJWKSFetchURL = appleJWKSURL
		resetAppleJWKSCache()
	})
	appleJWKSFetchURL = jwks.URL
	resetAppleJWKSCache()
	return &appleIdentityEnv{key: key, kid: kid, jwks: jwks, bundle: "com.example.app"}
}

func (e *appleIdentityEnv) token(t *testing.T, claims appleIDTokenClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = e.kid
	signed, err := tok.SignedString(e.key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (e *appleIdentityEnv) validClaims(sub, email string) appleIDTokenClaims {
	return appleIDTokenClaims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			Issuer:    appleIssuer,
			Audience:  e.bundle,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   sub,
		},
	}
}

func (e *appleIdentityEnv) handler(t *testing.T) (http.Handler, *UserDB) {
	t.Helper()
	settings := DefaultSettings
	settings.AppleBundleIDs = []string{e.bundle}
	db := NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))
	return New(db, settings), db
}

func appleFormRequest(method, path string, values url.Values, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(method, path+"?"+values.Encode(), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestAppleIdentityTokenAuth(t *testing.T) {
	env := setupAppleIdentity(t)
	h, db := env.handler(t)
	token := env.token(t, env.validClaims("001234.apple-user", "apple@example.com"))

	form := url.Values{}
	form.Set("method", "apple")
	form.Set("token", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appleFormRequest("POST", "/user/auth", form))

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", resp.StatusCode, w.Body.String())
	}
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("missing session cookie")
	}

	tx := db.db.MustBegin()
	defer tx.Rollback()
	var count int
	if err := tx.Get(&count, "SELECT count(*) FROM users WHERE email=?", "apple@example.com"); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("users count=%d", count)
	}
	if err := tx.Get(&count, "SELECT count(*) FROM oauth WHERE method='apple' AND foreign_id=?", "001234.apple-user"); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("oauth count=%d", count)
	}
}

func TestAppleIdentityTokenAuthMissingEmail(t *testing.T) {
	env := setupAppleIdentity(t)
	h, db := env.handler(t)
	token := env.token(t, env.validClaims("001234.no-email", ""))

	form := url.Values{}
	form.Set("method", "apple")
	form.Set("token", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appleFormRequest("POST", "/user/auth", form))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status %d body %s", w.Result().StatusCode, w.Body.String())
	}

	tx := db.db.MustBegin()
	defer tx.Rollback()
	var count int
	if err := tx.Get(&count, "SELECT count(*) FROM users WHERE email=?", "001234.no-email@apple.example.com"); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("users count=%d", count)
	}
}

func TestAppleIdentityTokenAdd(t *testing.T) {
	env := setupAppleIdentity(t)
	h, db := env.handler(t)

	create := url.Values{}
	create.Set("email", "existing@example.com")
	create.Set("password", "password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appleFormRequest("POST", "/user/create", create))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("create status %d", w.Result().StatusCode)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session" {
			session = c
			break
		}
	}
	if session == nil {
		t.Fatal("missing session")
	}

	token := env.token(t, env.validClaims("001234.link", "apple-link@example.com"))
	add := url.Values{}
	add.Set("method", "apple")
	add.Set("token", token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, appleFormRequest("POST", "/user/oauth/add", add, session))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("add status %d body %s", w.Result().StatusCode, w.Body.String())
	}

	tx := db.db.MustBegin()
	defer tx.Rollback()
	var userid int64
	if err := tx.Get(&userid, "SELECT userid FROM users WHERE email=?", "existing@example.com"); err != nil {
		t.Fatal(err)
	}
	var linked int64
	if err := tx.Get(&linked, "SELECT userid FROM oauth WHERE method='apple' AND foreign_id=?", "001234.link"); err != nil {
		t.Fatal(err)
	}
	if linked != userid {
		t.Fatalf("linked userid %d want %d", linked, userid)
	}
}

func TestAppleIdentityTokenRejects(t *testing.T) {
	env := setupAppleIdentity(t)
	h, db := env.handler(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
	}{
		{
			name: "wrong iss",
			token: env.token(t, appleIDTokenClaims{
				Email: "a@example.com",
				StandardClaims: jwt.StandardClaims{
					Issuer:    "https://evil.example",
					Audience:  env.bundle,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
					Subject:   "sub1",
				},
			}),
		},
		{
			name: "wrong aud",
			token: env.token(t, appleIDTokenClaims{
				Email: "a@example.com",
				StandardClaims: jwt.StandardClaims{
					Issuer:    appleIssuer,
					Audience:  "com.evil.app",
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
					Subject:   "sub1",
				},
			}),
		},
		{
			name: "expired",
			token: env.token(t, appleIDTokenClaims{
				Email: "a@example.com",
				StandardClaims: jwt.StandardClaims{
					Issuer:    appleIssuer,
					Audience:  env.bundle,
					ExpiresAt: time.Now().Add(-time.Hour).Unix(),
					Subject:   "sub1",
				},
			}),
		},
		{
			name: "unknown kid",
			token: func() string {
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, env.validClaims("sub1", "a@example.com"))
				tok.Header["kid"] = "missing-kid"
				signed, err := tok.SignedString(env.key)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			}(),
		},
		{
			name: "bad signature",
			token: func() string {
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, env.validClaims("sub1", "a@example.com"))
				tok.Header["kid"] = env.kid
				signed, err := tok.SignedString(otherKey)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			}(),
		},
		{
			name: "alg none",
			token: func() string {
				tok := jwt.NewWithClaims(jwt.SigningMethodNone, env.validClaims("sub1", "a@example.com"))
				tok.Header["kid"] = env.kid
				signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("method", "apple")
			form.Set("token", tc.token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, appleFormRequest("POST", "/user/auth", form))
			if w.Result().StatusCode < 400 {
				t.Fatalf("expected 4xx, got %d", w.Result().StatusCode)
			}
			tx := db.db.MustBegin()
			defer tx.Rollback()
			var count int
			if err := tx.Get(&count, "SELECT count(*) FROM users"); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("created %d users", count)
			}
		})
	}
}

func TestAppleIdentityTokenUnconfigured(t *testing.T) {
	h := New(NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")), DefaultSettings)
	form := url.Values{}
	form.Set("method", "apple")
	form.Set("token", "not-a-jwt")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, appleFormRequest("POST", "/user/auth", form))
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", w.Result().StatusCode)
	}
	if got := w.Result().Header.Get("status"); got != "invalid oauth method" {
		t.Fatalf("status header %q", got)
	}
}
