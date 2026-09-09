package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleAudience = "https://appleid.apple.com"
)

// AppleProvider implements OAuthProvider for Sign in with Apple.
type AppleProvider struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  string
	RedirectURL string
}

func (p *AppleProvider) Name() string { return "apple" }

func (p *AppleProvider) UsePKCE() bool { return false }

func (p *AppleProvider) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.clientSecret(),
		RedirectURL:  p.RedirectURL,
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  appleAuthURL,
			TokenURL: appleTokenURL,
		},
	}
}

func (p *AppleProvider) AuthCodeOptions() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_mode", "form_post"),
	}
}

func (p *AppleProvider) FetchIdentity(_ context.Context, _ *http.Client) (string, string, error) {
	return "", "", fmt.Errorf("apple has no userinfo endpoint; use FetchIdentityFromToken")
}

func (p *AppleProvider) FetchIdentityFromToken(_ context.Context, token *oauth2.Token) (string, string, error) {
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", "", fmt.Errorf("apple token response missing id_token")
	}

	sub, email, err := parseAppleIDToken(raw)
	if err != nil {
		return "", "", err
	}
	if email == "" {
		email = fmt.Sprintf("%s@apple.example.com", sub)
	}
	return sub, email, nil
}

func (p *AppleProvider) clientSecret() string {
	key, err := parseApplePrivateKey(p.PrivateKey)
	if err != nil {
		return ""
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": p.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"aud": appleAudience,
		"sub": p.ClientID,
	})
	tok.Header["kid"] = p.KeyID

	signed, err := tok.SignedString(key)
	if err != nil {
		return ""
	}
	return signed
}

func parseApplePrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("apple private key is empty")
	}

	block, _ := pem.Decode([]byte(raw))
	der := []byte(raw)
	if block != nil {
		der = block.Bytes
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse apple private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("apple private key is not ECDSA")
	}
	return ecKey, nil
}

func parseAppleIDToken(idToken string) (sub, email string, err error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid apple id_token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("invalid apple id_token payload: %w", err)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", fmt.Errorf("invalid apple id_token claims: %w", err)
	}
	if claims.Sub == "" {
		return "", "", fmt.Errorf("apple id_token missing sub")
	}
	return claims.Sub, claims.Email, nil
}
