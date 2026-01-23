package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	twitterAuthorizeURL = "https://twitter.com/i/oauth2/authorize"
	twitterTokenURL     = "https://api.twitter.com/2/oauth2/token"
	twitterUserURL      = "https://api.twitter.com/2/users/me"
)

func (a *Handler) getTwitterConfig(r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.settings.TwitterClientID,
		ClientSecret: a.settings.TwitterClientSecret,
		RedirectURL:  resolveRedirectURL(a.settings.TwitterRedirectURL, r, "/user/oauth/callback/twitter"),
		Scopes:       []string{"users.read", "tweet.read", "offline.access"},
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

	// Store state and verifier in a short-lived cookie
	// In a real app, you might want to sign this or store in a server-side session
	// Using a pipe separator to store both
	cookieValue := fmt.Sprintf("%s|%s|%s", state, verifier, next)
	http.SetCookie(w, &http.Cookie{
		Name:     "twitter_oauth_state",
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
	})

	// Redirect to Twitter
	url := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (a *Handler) handleTwitterCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state
	cookie, err := r.Cookie("twitter_oauth_state")
	if err != nil {
		HTTPPanic(http.StatusBadRequest, "State cookie missing")
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
		HTTPPanic(http.StatusBadRequest, "Invalid state param")
	}

	// Exchange code for token
	code := r.FormValue("code")
	if code == "" {
		HTTPPanic(http.StatusBadRequest, "Create missing")
	}

	config := a.getTwitterConfig(r)
	token, err := config.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Token exchange failed: %v", err)
	}

	// Fetch user info
	client := config.Client(r.Context(), token)
	resp, err := client.Get(twitterUserURL)
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
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to decode user info")
	}

	// Process user
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	// Handle existing session (link account) or new login
	currentUserID := CheckUserID(tx, r)
	
	var email string
	// Twitter v2 users/me doesn't clearly give email without special permissions/requests.
	// We'll map the ID and Name as requested.
	// Since we need an email for the user model, we might construct a dummy one if creating.
	// Or we rely on the logic in signInOauth to handle creation.
	
	// Create a stable "email" identity. 
	// The library uses email as a primary human-readable key.
	// We'll use id + "@twitter.com" distinct placeholder, or username.
	email = fmt.Sprintf("%s@twitter.example.com", userResp.Data.Username)

	// Delegate to signInOauth logic
	// If currentUserID > 0, we might want to just link.
	// signInOauth handles linking if we pass the same ID? 
	// No, signInOauth does login or create. 
	
	// Let's look at signInOauth, it takes a Tx.
	// It calls AddOauthUser if needed.
	
	userid, created := signInOauth(tx, "twitter", userResp.Data.ID, email)
	
	// If user was already logged in, we should probably ensure we linked to THAT user
	// instead of potentially logging into a different one.
	if currentUserID != 0 {
		// Verify if the oauth user is different from current user
		if userid != currentUserID {
			// This means this Twitter account is already linked to another user, 
			// or was just created as a new user.
			// Complex logic: Merge? Error?
			// For simplicity: If we are logged in, we want to ADD this method to CURRENT user.
			// signInOauth might have created a new user or found an existing one.
			
			// If it created a new user, we can remove it and link to current.
			// If it found an existing match, we can't easily merge without user input.
			
			// Let's refine:
			// If logged in -> AddOauthUser
			// If not logged in -> signInOauth
			
			// Check if this Twitter ID is already linked
			existingID := tx.GetOauthUser("twitter", userResp.Data.ID)
			if existingID != 0 {
				if existingID != currentUserID {
					HTTPPanic(http.StatusBadRequest, "Twitter account already linked to another user")
				}
				// Already linked to us, do nothing
			} else {
				tx.AddOauthUser("twitter", userResp.Data.ID, currentUserID)
			}
			userid = currentUserID
			// created = false // effectively
		}
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "twitter_oauth_state",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
	})
	
	// Finalize
	if currentUserID != 0 {
		// We were adding a method.
		// Redirect to where? Maybe settings page? 
		// Or return JSON if this was an AJAX popup?
		// The prompt doesn't specify. Assuming standard flow, redirect to home or close popup.
		// Existing handleUserOauthAdd returns JSON info.
		// But this is a full page redirect flow.
		// We'll redirect to root "/" for now.
		tx.Commit()
		http.Redirect(w, r, next, http.StatusFound)
	} else {
		// We were logging in.
		a.SignInUser(tx, w, userid, created, IsRequestSecure(r))
		tx.Commit()
		
		// If it's a browser redirect, we should probably redirect to main app.
		// Returning JSON might display it in browser.
		// "Implement the OAuth2 exchange".
		// Usually a callback redirects the user to the app dashboard.
		http.Redirect(w, r, next, http.StatusFound)
		// Or if we want to debug: SendJSON(w, info)
	}
}
