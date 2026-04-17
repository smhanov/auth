package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// FacebookProvider implements OAuthProvider for Facebook login.
type FacebookProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (p *FacebookProvider) Name() string { return "facebook" }

func (p *FacebookProvider) UsePKCE() bool { return false }

func (p *FacebookProvider) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       []string{"email", "public_profile"},
		Endpoint:     facebook.Endpoint,
	}
}

func (p *FacebookProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
	resp, err := client.Get("https://graph.facebook.com/me?fields=id,name,email")
	if err != nil {
		return "", "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("%s", formatOAuthProviderResponseError("Facebook API error", body, resp.Status))
	}

	var userResp struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return "", "", fmt.Errorf("failed to decode user info: %w", err)
	}

	email := userResp.Email
	if email == "" {
		email = fmt.Sprintf("%s@facebook.example.com", userResp.ID)
	}

	return userResp.ID, email, nil
}
