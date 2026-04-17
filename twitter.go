package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// TwitterProvider implements OAuthProvider for Twitter (X) login.
type TwitterProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	UseEmail     bool
}

func (p *TwitterProvider) Name() string { return "twitter" }

func (p *TwitterProvider) UsePKCE() bool { return true }

func (p *TwitterProvider) OAuthConfig() *oauth2.Config {
	scopes := []string{"users.read", "tweet.read", "offline.access"}
	if p.UseEmail {
		scopes = append(scopes, "users.email")
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://twitter.com/i/oauth2/authorize",
			TokenURL: "https://api.twitter.com/2/oauth2/token",
		},
	}
}

func (p *TwitterProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
	fetchURL := "https://api.twitter.com/2/users/me"
	if p.UseEmail {
		fetchURL += "?user.fields=confirmed_email"
	}

	resp, err := client.Get(fetchURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read user info response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s", formatOAuthProviderResponseError("Twitter API error", body, resp.Status))
	}

	var userResp struct {
		Data struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			Username       string `json:"username"`
			ConfirmedEmail string `json:"confirmed_email"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &userResp); err != nil {
		return "", "", fmt.Errorf("failed to decode user info: %w", err)
	}

	var email string
	if p.UseEmail && userResp.Data.ConfirmedEmail != "" {
		email = userResp.Data.ConfirmedEmail
	} else {
		email = fmt.Sprintf("%s@twitter.example.com", userResp.Data.Username)
	}

	return userResp.Data.ID, email, nil
}
