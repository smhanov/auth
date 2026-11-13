package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleProvider implements OAuthProvider for Google login.
type GoogleProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (p *GoogleProvider) Name() string { return "google" }

func (p *GoogleProvider) UsePKCE() bool { return true }

func (p *GoogleProvider) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func (p *GoogleProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
	id, email, _, err := p.fetchVerifiedIdentity(ctx, client)
	return id, email, err
}

// FetchVerifiedIdentity implements VerifiedIdentityProvider. Google's
// userinfo endpoint reports a real boolean email_verified; an unverified
// address is rejected outright.
func (p *GoogleProvider) FetchVerifiedIdentity(ctx context.Context, client *http.Client) (string, string, bool, error) {
	return p.fetchVerifiedIdentity(ctx, client)
}

func (p *GoogleProvider) fetchVerifiedIdentity(ctx context.Context, client *http.Client) (string, string, bool, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return "", "", false, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", false, fmt.Errorf("%s", formatOAuthProviderResponseError("Google API error", body, resp.Status))
	}

	var userResp struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return "", "", false, fmt.Errorf("failed to decode user info: %w", err)
	}

	if !userResp.EmailVerified {
		return "", "", false, fmt.Errorf("google email not verified")
	}

	return userResp.Sub, userResp.Email, true, nil
}
