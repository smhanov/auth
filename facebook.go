package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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

	// Generate state (reuse helper from twitter.go if available, or duplicate logic if needed)
	state, err := generateRandomString()
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to generate state")
	}

	// Facebook flow (standard server-side flow)
	// We'll use state for CSRF protection.
	next := r.FormValue("next")
	if next == "" {
		next = "/"
	}
	
	// Store state in cookie
	cookieValue := fmt.Sprintf("%s|%s", state, next)
	http.SetCookie(w, &http.Cookie{
		Name:     "facebook_oauth_state",
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
	})

	// Redirect to Facebook
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state
	cookie, err := r.Cookie("facebook_oauth_state")
	if err != nil {
		HTTPPanic(http.StatusBadRequest, "State cookie missing")
	}

	parts := strings.Split(cookie.Value, "|")
	expectedState := ""
	next := "/"

	if len(parts) == 2 {
		expectedState = parts[0]
		next = parts[1]
	} else {
		expectedState = cookie.Value
	}

	state := r.FormValue("state")
	if state != expectedState {
		HTTPPanic(http.StatusBadRequest, "Invalid state param")
	}

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
	// Facebook API requires appsecret_proof if enforced, or just access_token
	// The library handles access_token.
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

	// Process user
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	// Handle existing session (link account) or new login
	currentUserID := CheckUserID(tx, r)
	
	// Delegate to signInOauth logic
	// Note: Facebook might not return email if user declined or phone number account.
	// signInOauth needs an email to potentially match to existing user or create one.
	// If email is empty, we might have issues creating a user if expected unique email.
	// The library logic in signInOauth creates user with empty string email?
	// Verified: tx.CreatePasswordUser(email, "") -> INSERT ...
	// If email is empty string "", and unique constraint on email... might fail if multiple empty emails?
	// Postgres Schema has UNIQUE(email). SQLite Schema has email TEXT UNIQUE NOT NULL.
	// So we need an email.
	
	email := userResp.Email
	if email == "" {
		// Fallback email generator
		email = fmt.Sprintf("%s@facebook.example.com", userResp.ID)
	}

	var userid int64
	var created bool
	if currentUserID != 0 {
		// Link account
		existingID := tx.GetOauthUser("facebook", userResp.ID)
		if existingID != 0 && existingID != currentUserID {
			HTTPPanic(http.StatusBadRequest, "Facebook account already linked to another user")
		}
		tx.AddOauthUser("facebook", userResp.ID, currentUserID)
		userid = currentUserID
	} else {
		// Delegate to signInOauth logic
		userid, created = signInOauth(tx, "facebook", userResp.ID, email)
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "facebook_oauth_state",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
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
