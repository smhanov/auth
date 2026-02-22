package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	twitterAuthorizeURL = "https://twitter.com/i/oauth2/authorize"
	twitterTokenURL     = "https://api.twitter.com/2/oauth2/token"
	twitterUserURL      = "https://api.twitter.com/2/users/me"
)

func (a *Handler) getTwitterConfig(r *http.Request) *oauth2.Config {
	scopes := []string{"users.read", "tweet.read", "offline.access"}
	if a.settings.TwitterUseEmail {
		scopes = append(scopes, "users.email")
	}
	return &oauth2.Config{
		ClientID:     a.settings.TwitterClientID,
		ClientSecret: a.settings.TwitterClientSecret,
		RedirectURL:  resolveRedirectURL(a.settings.TwitterRedirectURL, r, "/user/oauth/callback/twitter"),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  twitterAuthorizeURL,
			TokenURL: twitterTokenURL,
		},
	}
}

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (a *Handler) handleTwitterLogin(w http.ResponseWriter, r *http.Request) {
	config := a.getTwitterConfig(r)

	// Generate state and PKCE verifier
	state, err := generateRandomString()
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to generate state")
	}

	verifier := oauth2.GenerateVerifier()
	next := r.FormValue("next")
	if next == "" {
		next = "/"
	}

	// Store verifier and next URL in memory, keyed by state token.
	storeOauthState("twitter", state, verifier, next)

	// Redirect to Twitter
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleTwitterCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		HTTPPanic(http.StatusBadRequest, "Missing state parameter")
	}

	// Retrieve verifier and next URL from in-memory storage
	verifier, next, err := loadOauthState("twitter", state)
	if err != nil {
		HTTPPanic(http.StatusBadRequest, "Invalid or expired sign-in session. Please try again.")
	}

	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	// Exchange code for token
	code := r.FormValue("code")
	if code == "" {
		HTTPPanic(http.StatusBadRequest, "Code missing")
	}

	config := a.getTwitterConfig(r)
	token, err := config.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Token exchange failed: %v", err)
	}

	// Fetch user info
	client := config.Client(r.Context(), token)

	fetchURL := twitterUserURL
	if a.settings.TwitterUseEmail {
		fetchURL += "?user.fields=confirmed_email"
	}

	resp, err := client.Get(fetchURL)
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to get user info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		HTTPPanic(http.StatusInternalServerError, "Twitter API error: %s", string(body))
	}

	var userResp struct {
		Data struct {
			ID             string `json:"id"`
			Name           string `json:"name"`
			Username       string `json:"username"`
			ConfirmedEmail string `json:"confirmed_email"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to decode user info")
	}

	// Handle existing session (link account) or new login
	currentUserID := CheckUserID(tx, r)

	var email string
	if a.settings.TwitterUseEmail && userResp.Data.ConfirmedEmail != "" {
		email = userResp.Data.ConfirmedEmail
	} else {
		email = fmt.Sprintf("%s@twitter.example.com", userResp.Data.Username)
	}

	var userid int64
	var created bool
	if currentUserID != 0 {
		existingID := tx.GetOauthUser("twitter", userResp.Data.ID)
		if existingID != 0 && existingID != currentUserID {
			HTTPPanic(http.StatusBadRequest, "Twitter account already linked to another user")
		}
		tx.AddOauthUser("twitter", userResp.Data.ID, currentUserID)
		userid = currentUserID
	} else {
		userid, created = signInOauth(tx, "twitter", userResp.Data.ID, email)
	}

	if currentUserID != 0 {
		tx.Commit()
		http.Redirect(w, r, next, http.StatusFound)
	} else {
		info := a.SignInUser(tx, w, userid, created, IsRequestSecure(r))

		if a.settings.OnAuthEvent != nil {
			action := "auth"
			if created {
				action = "create"
			}
			a.settings.OnAuthEvent(tx, action, userid, info)
		}

		tx.Commit()
		http.Redirect(w, r, next, http.StatusFound)
	}
}
