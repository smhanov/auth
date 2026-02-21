package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

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

	// Store state and verifier in a short-lived cookie
	cookieValue := fmt.Sprintf("%s|%s|%s", state, verifier, next)
	http.SetCookie(w, &http.Cookie{
		Name:     "google_oauth_state",
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to Google
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state
	cookie, err := r.Cookie("google_oauth_state")
	if err != nil {
		log.Printf("Google OAuth callback: state cookie missing (err=%v, cookies=%v)", err, r.Cookies())
		HTTPPanic(http.StatusBadRequest, "State cookie missing. Please try signing in again.")
	}

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 2 {
		HTTPPanic(http.StatusBadRequest, "Invalid state cookie")
	}
	expectedState := parts[0]
	verifier := parts[1]
	next := "/"
	if len(parts) >= 3 {
		next = parts[2]
	}

	state := r.FormValue("state")
	if state != expectedState {
		log.Printf("Google OAuth callback: state mismatch (expected=%q, got=%q)", expectedState, state)
		HTTPPanic(http.StatusBadRequest, "Invalid state param. Please try signing in again.")
	}

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

	// Process user
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

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

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "google_oauth_state",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	
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
