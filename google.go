package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleUserURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

func (a *Handler) getGoogleConfig(r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.settings.GoogleClientID,
		ClientSecret: a.settings.GoogleClientSecret,
		RedirectURL:  resolveRedirectURL(a.settings.GoogleRedirectURL, r, "/user/oauth/callback/google"),
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func (a *Handler) handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	config := a.getGoogleConfig(r)

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

	// Store verifier and next URL in memory keyed by state.
	// This avoids relying on cookies which can be blocked by browser
	// privacy settings, SameSite policies, or cookie partitioning.
	storeOauthState("google", state, verifier, next)

	// Redirect to Google
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		HTTPPanic(http.StatusBadRequest, "Missing state parameter")
	}

	// Retrieve verifier and next URL from in-memory storage
	verifier, next, err := loadOauthState("google", state)
	if err != nil {
		log.Printf("Google OAuth callback: %v (state=%q)", err, state)
		HTTPPanic(http.StatusBadRequest, "Invalid or expired sign-in session. Please try again.")
	}

	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	// Exchange code for token
	code := r.FormValue("code")
	if code == "" {
		HTTPPanic(http.StatusBadRequest, "Code missing")
	}

	config := a.getGoogleConfig(r)
	token, err := config.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Token exchange failed: %v", err)
	}

	// Fetch user info
	client := config.Client(r.Context(), token)
	resp, err := client.Get(googleUserURL)
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to get user info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		HTTPPanic(http.StatusInternalServerError, "Google API error: %s", string(body))
	}

	var userResp struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to decode user info")
	}

	// Handle existing session (link account) or new login
	currentUserID := CheckUserID(tx, r)

	var userid int64
	var created bool
	if currentUserID != 0 {
		// Link account
		existingID := tx.GetOauthUser("google", userResp.Sub)
		if existingID != 0 && existingID != currentUserID {
			HTTPPanic(http.StatusBadRequest, "Google account already linked to another user")
		}
		tx.AddOauthUser("google", userResp.Sub, currentUserID)
		userid = currentUserID
	} else {
		// Delegate to signInOauth logic
		userid, created = signInOauth(tx, "google", userResp.Sub, userResp.Email)
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
