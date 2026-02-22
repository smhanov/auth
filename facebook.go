package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

const (
	facebookUserURL = "https://graph.facebook.com/me?fields=id,name,email"
)

func (a *Handler) getFacebookConfig(r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.settings.FacebookClientID,
		ClientSecret: a.settings.FacebookClientSecret,
		RedirectURL:  resolveRedirectURL(a.settings.FacebookRedirectURL, r, "/user/oauth/callback/facebook"),
		Scopes:       []string{"email", "public_profile"},
		Endpoint:     facebook.Endpoint,
	}
}

func (a *Handler) handleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	config := a.getFacebookConfig(r)

	state, err := generateRandomString()
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to generate state")
	}

	next := r.FormValue("next")
	if next == "" {
		next = "/"
	}

	// Store state and next URL in memory.
	// Facebook doesn't use PKCE so verifier is empty.
	storeOauthState("facebook", state, "", next)

	// Redirect to Facebook
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state == "" {
		HTTPPanic(http.StatusBadRequest, "Missing state parameter")
	}

	// Retrieve next URL from in-memory storage
	_, next, err := loadOauthState("facebook", state)
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

	config := a.getFacebookConfig(r)
	token, err := config.Exchange(r.Context(), code)
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Token exchange failed: %v", err)
	}

	// Fetch user info
	client := config.Client(r.Context(), token)
	resp, err := client.Get(facebookUserURL)
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to get user info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		HTTPPanic(http.StatusInternalServerError, "Facebook API error: %s", string(body))
	}

	var userResp struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to decode user info")
	}

	// Handle existing session (link account) or new login
	currentUserID := CheckUserID(tx, r)

	email := userResp.Email
	if email == "" {
		email = fmt.Sprintf("%s@facebook.example.com", userResp.ID)
	}

	var userid int64
	var created bool
	if currentUserID != 0 {
		existingID := tx.GetOauthUser("facebook", userResp.ID)
		if existingID != 0 && existingID != currentUserID {
			HTTPPanic(http.StatusBadRequest, "Facebook account already linked to another user")
		}
		tx.AddOauthUser("facebook", userResp.ID, currentUserID)
		userid = currentUserID
	} else {
		userid, created = signInOauth(tx, "facebook", userResp.ID, email)
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
