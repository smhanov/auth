package auth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// OAuthProvider defines the interface for pluggable OAuth providers.
// Implement this interface to add support for additional OAuth providers
// beyond the built-in Google, Facebook, and Twitter providers.
//
// Each provider handles the server-side OAuth2 authorization code flow:
//   - Login: redirects the user to the provider's authorization page
//   - Callback: exchanges the authorization code for a token and fetches user identity
//
// Example implementation for GitHub:
//
//	type GitHubProvider struct {
//	    ClientID     string
//	    ClientSecret string
//	    RedirectURL  string
//	}
//
//	func (p *GitHubProvider) Name() string { return "github" }
//	func (p *GitHubProvider) UsePKCE() bool { return false }
//
//	func (p *GitHubProvider) OAuthConfig() *oauth2.Config {
//	    return &oauth2.Config{
//	        ClientID:     p.ClientID,
//	        ClientSecret: p.ClientSecret,
//	        RedirectURL:  p.RedirectURL,
//	        Scopes:       []string{"user:email"},
//	        Endpoint: oauth2.Endpoint{
//	            AuthURL:  "https://github.com/login/oauth/authorize",
//	            TokenURL: "https://github.com/login/oauth/access_token",
//	        },
//	    }
//	}
//
//	func (p *GitHubProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
//	    resp, err := client.Get("https://api.github.com/user")
//	    // ... parse response to extract id and email ...
//	    return id, email, nil
//	}
type OAuthProvider interface {
	// Name returns the unique provider name (e.g., "github", "google").
	// This is used for URL routing (/user/oauth/login/{name} and
	// /user/oauth/callback/{name}) and for storing OAuth linkage in the database.
	Name() string

	// OAuthConfig returns the OAuth2 configuration for this provider.
	// The RedirectURL field may be:
	//   - Empty: defaults to /user/oauth/callback/{name}, resolved against the request
	//   - A relative path (e.g., "/callback"): resolved against the request host/scheme
	//   - An absolute URL: used as-is
	OAuthConfig() *oauth2.Config

	// UsePKCE returns whether this provider should use PKCE (Proof Key for Code Exchange).
	// PKCE adds an extra layer of security to the authorization code flow.
	// Most modern providers support PKCE; set to true unless the provider doesn't support it.
	UsePKCE() bool

	// FetchIdentity uses the authenticated OAuth2 client (which already has a valid token)
	// to retrieve the user's provider-specific ID and email address.
	// The id should be stable and unique for each user on the provider.
	// The email is used to match or create local user accounts.
	// If the provider doesn't return an email, generate a placeholder
	// (e.g., "{id}@provider.example.com").
	FetchIdentity(ctx context.Context, client *http.Client) (id string, email string, err error)
}

// resolveOAuthConfig creates a copy of the provider's OAuth config with the
// RedirectURL resolved against the current request.
func (a *Handler) resolveOAuthConfig(provider OAuthProvider, r *http.Request) *oauth2.Config {
	cfg := *provider.OAuthConfig() // shallow copy
	cfg.RedirectURL = resolveRedirectURL(cfg.RedirectURL, r, "/user/oauth/callback/"+provider.Name())
	return &cfg
}

// handleOAuthLogin is the generic login handler for all OAuth providers.
// It generates state (and optionally PKCE verifier), stores them in a cookie,
// and redirects the user to the provider's authorization page.
func (a *Handler) handleOAuthLogin(provider OAuthProvider, w http.ResponseWriter, r *http.Request) {
	config := a.resolveOAuthConfig(provider, r)

	state, err := generateRandomString()
	if err != nil {
		HTTPPanic(http.StatusInternalServerError, "Failed to generate state")
	}

	next := sanitizeRedirectTarget(r.FormValue("next"))

	var cookieValue string
	var authOpts []oauth2.AuthCodeOption

	if provider.UsePKCE() {
		verifier := oauth2.GenerateVerifier()
		cookieValue = fmt.Sprintf("%s|%s|%s", state, verifier, next)
		authOpts = append(authOpts, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	} else {
		cookieValue = fmt.Sprintf("%s|%s", state, next)
		authOpts = append(authOpts, oauth2.AccessTypeOffline)
	}

	cookieName := provider.Name() + "_oauth_state"
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   IsRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	url := config.AuthCodeURL(state, authOpts...)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// handleOAuthCallback is the generic callback handler for all OAuth providers.
// It validates state, exchanges the authorization code for a token,
// fetches user identity, and signs in or creates the user.
func (a *Handler) handleOAuthCallback(provider OAuthProvider, w http.ResponseWriter, r *http.Request) {
	cookieName := provider.Name() + "_oauth_state"
	providerName := provider.Name()

	// Read and validate state cookie
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		log.Printf("OAuth %s callback: state cookie missing (err=%v, cookies=%v)", providerName, err, r.Cookies())
		HTTPPanic(http.StatusBadRequest, "State cookie missing. Please try signing in again.")
	}

	parts := strings.Split(cookie.Value, "|")

	var expectedState, verifier, next string

	if provider.UsePKCE() {
		if len(parts) < 2 {
			HTTPPanic(http.StatusBadRequest, "Invalid state cookie")
		}
		expectedState = parts[0]
		verifier = parts[1]
		next = "/"
		if len(parts) >= 3 {
			next = sanitizeRedirectTarget(parts[2])
		}
	} else {
		expectedState = parts[0]
		next = "/"
		if len(parts) >= 2 {
			next = sanitizeRedirectTarget(parts[1])
		}
	}

	state := r.FormValue("state")
	if state != expectedState {
		log.Printf("OAuth %s callback: state mismatch (expected=%q, got=%q)", providerName, expectedState, state)
		HTTPPanic(http.StatusBadRequest, "Invalid state param. Please try signing in again.")
	}

	// Exchange code for token
	code := r.FormValue("code")
	if code == "" {
		HTTPPanic(http.StatusBadRequest, "Code missing")
	}

	config := a.resolveOAuthConfig(provider, r)

	var exchangeOpts []oauth2.AuthCodeOption
	if provider.UsePKCE() {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
	}

	token, err := config.Exchange(r.Context(), code, exchangeOpts...)
	if err != nil {
		HTTPPanic(http.StatusBadGateway, "%s", formatOAuthProviderError(
			fmt.Sprintf("%s token exchange failed", providerName), err))
	}

	// Fetch user identity
	client := config.Client(r.Context(), token)

	foreignID, email, err := provider.FetchIdentity(r.Context(), client)
	if err != nil {
		HTTPPanic(http.StatusBadGateway, "Failed to get user info from %s: %v", providerName, err)
	}

	// Process user
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	currentUserID := CheckUserID(tx, r)

	var userid int64
	var created bool
	if currentUserID != 0 {
		// Link account to existing user
		existingID := tx.GetOauthUser(providerName, foreignID)
		if existingID != 0 && existingID != currentUserID {
			HTTPPanic(http.StatusBadRequest, "%s account already linked to another user", providerName)
		}
		tx.AddOauthUser(providerName, foreignID, currentUserID)
		userid = currentUserID
	} else {
		// Sign in or create user
		userid, created = signInOauth(tx, providerName, foreignID, email)
	}

	// Clear the state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
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
