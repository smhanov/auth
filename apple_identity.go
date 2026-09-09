package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const appleJWKSURL = "https://appleid.apple.com/auth/keys"
const appleIssuer = "https://appleid.apple.com"

var appleJWKSFetchURL = appleJWKSURL

type appleJWKSet struct {
	Keys []appleJWK `json:"keys"`
}

type appleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type appleIDTokenClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

var appleJWKSCache struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func verifyAppleIdentityToken(idToken string, audiences []string) (string, string) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Alg()}}
	claims := &appleIDTokenClaims{}
	tok, err := parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid")
		}
		key, err := applePublicKey(kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil || tok == nil || !tok.Valid {
		HTTPPanic(http.StatusBadRequest, "invalid apple identity token")
	}
	if claims.Issuer != appleIssuer {
		HTTPPanic(http.StatusBadRequest, "invalid apple identity token")
	}
	if !appleAudienceAllowed(claims.Audience, audiences) {
		HTTPPanic(http.StatusBadRequest, "invalid apple identity token")
	}
	if claims.Subject == "" {
		HTTPPanic(http.StatusBadRequest, "invalid apple identity token")
	}
	email := claims.Email
	if email == "" {
		email = fmt.Sprintf("%s@apple.example.com", claims.Subject)
	}
	return claims.Subject, email
}

func appleAudienceAllowed(tokenAud string, allowed []string) bool {
	for _, a := range allowed {
		if a == tokenAud {
			return true
		}
	}
	return false
}

func applePublicKey(kid string) (*rsa.PublicKey, error) {
	if key := appleCachedKey(kid); key != nil {
		return key, nil
	}
	if err := refreshAppleJWKS(false); err != nil {
		return nil, err
	}
	if key := appleCachedKey(kid); key != nil {
		return key, nil
	}
	if err := refreshAppleJWKS(true); err != nil {
		return nil, err
	}
	if key := appleCachedKey(kid); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("unknown apple kid")
}

func appleCachedKey(kid string) *rsa.PublicKey {
	appleJWKSCache.mu.Lock()
	defer appleJWKSCache.mu.Unlock()
	if appleJWKSCache.keys == nil {
		return nil
	}
	return appleJWKSCache.keys[kid]
}

func refreshAppleJWKS(force bool) error {
	appleJWKSCache.mu.Lock()
	if !force && time.Since(appleJWKSCache.fetched) < time.Hour && appleJWKSCache.keys != nil {
		appleJWKSCache.mu.Unlock()
		return nil
	}
	appleJWKSCache.mu.Unlock()

	resp, err := http.Get(appleJWKSFetchURL)
	if err != nil {
		return fmt.Errorf("apple jwks fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("apple jwks fetch status %s", resp.Status)
	}

	var set appleJWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("apple jwks decode failed: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(jwk.N, jwk.E)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = pub
	}

	appleJWKSCache.mu.Lock()
	appleJWKSCache.keys = keys
	appleJWKSCache.fetched = time.Now()
	appleJWKSCache.mu.Unlock()
	return nil
}

func rsaPublicKeyFromJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if n.Sign() <= 0 || e <= 0 {
		return nil, fmt.Errorf("invalid rsa jwk")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func resetAppleJWKSCache() {
	appleJWKSCache.mu.Lock()
	appleJWKSCache.keys = nil
	appleJWKSCache.fetched = time.Time{}
	appleJWKSCache.mu.Unlock()
}
