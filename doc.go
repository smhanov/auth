/*
Package auth provides a complete, self-hosted user authentication system for Go web applications.

It includes:
  - Email/Password authentication
  - OAuth2 login (Google, Facebook, Twitter)
  - SAML 2.0 support for Enterprise SSO
  - User session management via HTTP cookies
  - Password reset flows via Email
  - Automatic database schema management

# Quick Start

This example shows how to set up the authentication server with a SQLite database.

	package main

	import (
		"log"
		"net/http"

		"github.com/jmoiron/sqlx"
		_ "github.com/mattn/go-sqlite3"
		"github.com/smhanov/auth"
	)

	func main() {
		// 1. Connect to the database
		db, err := sqlx.Open("sqlite3", "users.db")
		if err != nil {
			log.Fatal(err)
		}

		// 2. Configure auth settings
		settings := auth.DefaultSettings
		settings.SMTPServer = "smtp.gmail.com:587"
		settings.SMTPUser = "example@gmail.com"
		settings.SMTPPassword = "app-password"
		settings.EmailFrom = "MyApp <support@myapp.com>"

		// 3. Create the handler
		// NewUserDB will automatically create necessary tables
		authHandler := auth.New(auth.NewUserDB(db), settings)

		// 4. Mount the handler
		// The endpoints will be available under /user/...
		http.Handle("/user/", authHandler)

		log.Println("Listening on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}

# Authentication Primer

If you are unfamiliar with the different authentication methods, here is a guide on when to use what.

1. OAuth 2.0 (Social Login)

OAuth is the industry standard for letting users sign in with their existing accounts (Google, Facebook, Twitter).
This reduces friction as users don't need to create a new password for your site.

  - How it works: Your app redirects the user to the provider (e.g., Google). The user consents, and Google redirects them back to your site with a token.
  - Use case: Consumer-facing applications.

2. SAML 2.0 (Enterprise SSO)

SAML is an XML-based standard used by large enterprises. It allows companies to manage their employees' access to your software centrally.
Instead of creating 100 accounts on your site, the company connects their Identity Provider (IdP) like Okta or Active Directory to your app.

  - How it works: Your app redirects the employee to their company login page. After successful login, the company sends a signed XML "Assertion" to your app.
  - Use case: B2B software selling to large organizations.

# OAuth Configuration

To enable OAuth login with social providers, configure the following settings in the Settings struct:

1. Twitter

  - TwitterClientID: Your Twitter OAuth 2.0 Client ID from the Twitter Developer Portal.
  - TwitterClientSecret: Your Twitter OAuth 2.0 Client Secret.
  - TwitterRedirectURL: Optional override for the callback URL. In most cases, leave this blank to use the default `{scheme}://{server}/user/oauth/callback/twitter`, derived from the HTTP request.
  - TwitterUseEmail: Set to true to request the user's email address during authentication. This requires the users.email scope and will fetch the email from the /2/users/me endpoint with user.fields=confirmed_email.

2. Google

  - GoogleClientID: Your Google OAuth 2.0 Client ID.
  - GoogleClientSecret: Your Google OAuth 2.0 Client Secret.
  - GoogleRedirectURL: Optional override for the callback URL. In most cases, leave this blank to use the default `{scheme}://{server}/user/oauth/callback/google`, derived from the HTTP request.

3. Facebook

  - FacebookClientID: Your Facebook OAuth 2.0 App ID.
  - FacebookClientSecret: Your Facebook OAuth 2.0 App Secret.
  - FacebookRedirectURL: Optional override for the callback URL. In most cases, leave this blank to use the default `{scheme}://{server}/user/oauth/callback/facebook`, derived from the HTTP request.

When using this default callback URL behavior behind a proxy, ensure both `X-Forwarded-Proto` and `X-Forwarded-Host` are set correctly.

# Tutorials & Usage

Authentication Endpoints:

The following endpoints are exposed by the handler:

  - POST /user/create        - Create a new account (email, password)
  - POST /user/auth          - Sign in (email, password)
  - GET  /user/signout       - Sign out the current user
  - GET  /user/get           - Get current user info (JSON)
  - POST /user/forgotpassword - Request a password reset email
  - POST /user/resetpassword  - Reset password using token

1. Email and Password Authentication

To sign up a new user, send a POST request:

	POST /user/create
	Form Data:
		email: user@example.com
		password: secret-password
		signin: 1  (Optional: set to 1 to auto-login after creation)

To sign in:

	POST /user/auth
	Form Data:
		email: user@example.com
		password: secret-password

The server responds with a JSON object containing user info and sets a `session` cookie.

2. OAuth Interaction (Google, Facebook, Twitter)

To enable OAuth, configure the Client ID and Secret in your Settings. In most cases, leave `*RedirectURL` blank so the callback URL is automatically derived as `{scheme}://{server}/user/oauth/callback/{provider}` from the HTTP request:

	settings.GoogleClientID = "YOUR_CLIENT_ID"
	settings.GoogleClientSecret = "YOUR_CLIENT_SECRET"
	// settings.GoogleRedirectURL = "" // recommended in most deployments

If you are behind a reverse proxy, ensure `X-Forwarded-Proto` and `X-Forwarded-Host` are set so scheme and host are detected correctly.

Start the login flow by sending the user to the login URL.

Redirect Parameters:
You can control where the user is sent after a successful login using the `next` query parameter.

	<a href="/user/oauth/login/google?next=/dashboard">Login with Google</a>

If `next` is omitted, the user is redirected to `/`.

3. SAML Interaction

SAML requires a certificate and private key to sign requests. If columns `certificate` and `privatekey` are missing in the database, the library generates them automatically.

Your Service Provider (SP) Metadata is available at:

	GET /user/saml/metadata

Provide this URL (or the XML content) to your customer's IT department to configure their IdP.
The Assertion Consumer Service (ACS) URL they will need is:

	POST /user/saml/acs

4. Database Integration

The package includes a default `UserDB` based on `sqlx` which supports SQLite and PostgreSQL.
It handles user storage, session tracking, and OAuth linkage internally.
You can wrap or replace `NewUserDB` if you need custom data storage.

# Advanced Customization

1. Customizing User Information with GetInfo

By default, the system returns basic user info (userid, email, settings, and OAuth methods).
To customize the information returned to clients, override the GetInfo method.

Example:

	type MyDB struct {
		*auth.UserDB
	}

	type CustomUserInfo struct {
		UserID     int64    `json:"userid"`
		Email      string   `json:"email"`
		Name       string   `json:"name"`
		AvatarURL  string   `json:"avatar_url"`
		Premium    bool     `json:"premium"`
		Methods    []string `json:"methods"`
		NewAccount bool     `json:"newAccount"`
	}

	func (db *MyDB) GetInfo(tx auth.Tx, userid int64, newAccount bool) auth.UserInfo {
		// Access the underlying sqlx transaction
		utx := tx.(*auth.UserTx)

		var info CustomUserInfo
		err := utx.Tx.Get(&info, `
			SELECT u.userid, u.email, p.name, p.avatar_url, p.premium
			FROM users u
			LEFT JOIN user_profiles p ON u.userid = p.userid
			WHERE u.userid = $1
		`, userid)
		if err != nil {
			panic(err)
		}

		info.Methods = utx.GetOauthMethods(userid)
		info.NewAccount = newAccount

		return info
	}

	// Create the handler with your custom DB
	authHandler := auth.New(&MyDB{auth.NewUserDB(db)}, settings)

Important: The GetInfo method is called after successful authentication, account creation, and password resets. It returns the data that will be sent to the client as JSON.

2. Event Hooks with OnAuthEvent

To perform actions when users authenticate (e.g., logging, analytics, welcome emails), use the OnAuthEvent callback:

	settings.OnAuthEvent = func(tx auth.Tx, action string, userid int64, info auth.UserInfo) {
		switch action {
		case "create":
			// User just created an account
			log.Printf("New user created: %d", userid)
			// Send welcome email, create user profile, etc.

		case "auth":
			// User signed in
			log.Printf("User %d signed in", userid)
			// Update last login timestamp, analytics, etc.

		case "resetpassword":
			// User reset their password
			log.Printf("User %d reset password", userid)
			// Send security notification email
		}

		// You can access the database within the transaction
		utx := tx.(*auth.UserTx)
		utx.Tx.Exec(`UPDATE users SET last_login = NOW() WHERE userid = $1`, userid)
	}

Note: The callback is executed within the same database transaction as the authentication. If you panic or the transaction fails, the authentication will be rolled back. For async operations (like sending emails), consider using a goroutine.

3. Updating User Information

To update a user's email or password, send a POST request to `/user/update`:

Update Email Only:

	POST /user/update
	Form Data:
		email: newemail@example.com

	Requires: User must be signed in (have valid session cookie)

Update Password Only:

	POST /user/update
	Form Data:
		password: new-secret-password

	Requires: User must be signed in (have valid session cookie)

Update Both:

	POST /user/update
	Form Data:
		email: newemail@example.com
		password: new-secret-password

	Requires: User must be signed in (have valid session cookie)

If neither email nor password is provided, the request returns a 400 error.
Email addresses are automatically converted to lowercase.

4. Adding OAuth Methods to Existing Accounts

Users can link OAuth providers to their existing accounts:

	POST /user/oauth/add
	Form Data:
		method: google       (or "facebook", "twitter")
		token: oauth-token   (from OAuth flow)
		update_email: true   (Optional: update user's email to OAuth email)

	Requires: User must be signed in

This is useful when:
  - A user initially created an account with email/password and now wants to link Google
  - A user wants to link multiple OAuth providers to one account

To remove an OAuth method:

	POST /user/oauth/remove
	Form Data:
		method: google

	Requires: User must be signed in

5. SAML Identity Provider Selection

For enterprise applications where different users authenticate with different SAML providers, override GetSamlIdentityProviderForUser:

	type MyDB struct {
		*auth.UserDB
	}

	type MyTx struct {
		auth.Tx
	}

	func (db *MyDB) Begin(ctx context.Context) auth.Tx {
		return &MyTx{db.UserDB.Begin(ctx)}
	}

	func (tx *MyTx) GetSamlIdentityProviderForUser(email string) string {
		// Route by email domain
		if strings.HasSuffix(email, "@company1.com") {
			return tx.GetSamlIdentityProviderByID("https://company1.okta.com")
		}
		if strings.HasSuffix(email, "@company2.com") {
			return tx.GetSamlIdentityProviderByID("https://company2-idp.com")
		}

		// Return empty string for non-SAML users (will use regular auth)
		return ""
	}

Before using SAML, register the Identity Provider metadata:

	// Fetch and register IDP metadata (do this once, not on every startup)
	tx := db.Begin(context.Background())
	defer tx.Rollback()

	idpMetadataXML := fetchFromURL("https://company.okta.com/metadata")
	idpID := auth.GetSamlID(idpMetadataXML)
	tx.AddSamlIdentityProviderMetadata(idpID, idpMetadataXML)

	tx.Commit()

See example_saml_test.go for a complete working example.

# Common Pitfalls

1. Session Cookies and HTTPS

Session cookies are automatically set to "Secure" when the request comes over HTTPS (checked via `auth.IsRequestSecure(r)`).
If you're behind a reverse proxy (nginx, CloudFlare, etc.), make sure it sets `X-Forwarded-Proto` correctly. If you rely on default OAuth callback URL deduction, also set `X-Forwarded-Host`.

2. Email Case Sensitivity

All email addresses are automatically converted to lowercase before storage and comparison.
Don't manually lowercase emails in your client code - the server handles this.

3. OAuth Redirect URLs

In most cases, leave `GoogleRedirectURL`, `FacebookRedirectURL`, and `TwitterRedirectURL` blank.
When blank, the library uses `{scheme}://{server}/user/oauth/callback/{provider}`, where scheme and server are automatically deduced from the HTTP request.
If your app runs behind a reverse proxy, ensure `X-Forwarded-Proto` and `X-Forwarded-Host` are set correctly so the derived URL matches what you register with each provider.
OAuth redirect URLs registered with providers must still match exactly (including protocol and port) the URL your deployment will generate.

4. Password Reset Token Expiry

Password reset tokens expire after a set period (default implementation doesn't specify, but typically 1-24 hours).
Tokens are single-use - once used successfully, they're deleted from the database.

5. CORS and Cookies

If your frontend is on a different domain than your auth server, you need to:
  - Use the `auth.CORS()` wrapper: `http.Handle("/user/", auth.CORS(authHandler))`
  - Configure your frontend to send credentials: `fetch(url, {credentials: 'include'})`
  - Ensure both domains are over HTTPS in production

6. Transaction Management

When calling `auth.SignInUser()` or other database operations directly:
  - Always defer `tx.Rollback()` immediately after creating the transaction
  - Only call `tx.Commit()` after all operations succeed
  - Don't call both Commit and Rollback - Rollback is safe to call even after Commit

Example:

	tx := db.Begin(context.Background())
	defer tx.Rollback()  // Safe to call even if we Commit

	// ... do work ...

	info := authHandler.SignInUser(tx, w, userid, false, auth.IsRequestSecure(r))
	tx.Commit()
	auth.SendJSON(w, info)
*/
package auth
