/*
Package auth provides a complete user authentication system for Go web applications.

Quick Start:

    package main

    import (
        "log"
        "net/http"
        "github.com/jmoiron/sqlx"
        _ "github.com/mattn/go-sqlite3"
        "github.com/smhanov/auth"
    )

    func main() {
        // Open database connection
        db, err := sqlx.Open("sqlite3", "users.db")
        if err != nil {
            log.Fatal(err)
        }

        // Configure authentication settings
        settings := auth.DefaultSettings
        settings.SMTPServer = "smtp.gmail.com:587"
        settings.SMTPUser = "your-email@gmail.com"
        settings.SMTPPassword = "your-app-password"
        settings.EmailFrom = "Your App <your-email@gmail.com>"
        settings.ForgotPasswordSubject = "Password Reset Request"
        settings.ForgotPasswordBody = "Click here to reset your password: ${TOKEN}"

        // Create the auth handler
        authHandler := auth.New(auth.NewUserDB(db), settings)

        // Mount the auth endpoints at /user/
        http.Handle("/user/", authHandler)
        log.Fatal(http.ListenAndServe(":8080", nil))
    }

Features:

1. Email/Password Authentication
   - Create accounts with email/password
   - Sign in with email/password
   - Password reset via email
   - Change email/password
   - Rate limiting on authentication attempts

2. OAuth Support
   - Facebook authentication
   - Google authentication 
   - Link multiple auth methods to one account

3. SAML Single Sign-On
   - Support for enterprise SSO
   - Multiple identity providers
   - Automatic metadata handling

4. Customizable User Info
   You can override the GetInfo method to return custom user information:

    type MyDB struct {
        *auth.UserDB
    }

    type CustomUserInfo struct {
        UserID    int64  `json:"userid"`
        Email     string `json:"email"` 
        Name      string `json:"name"`
        AvatarURL string `json:"avatar_url"`
    }

    func (db *MyDB) GetInfo(tx auth.Tx, userid int64, newAccount bool) auth.UserInfo {
        // Query additional user data from your database
        var info CustomUserInfo
        err := tx.(*auth.UserTx).Tx.Get(&info, 
            `SELECT userid, email, name, avatar_url 
             FROM users WHERE userid = ?`, userid)
        if err != nil {
            panic(err)
        }
        return info
    }

    // Use your custom DB:
    authHandler := auth.New(&MyDB{auth.NewUserDB(db)}, settings)

API Endpoints:

POST /user/auth
- Sign in with email/password: email=user@example.com&password=secret
- Sign in with OAuth: method=facebook&token=oauth-token
- Sign in with SAML: email=user@company.com&sso=1

POST /user/create
- Create account: email=user@example.com&password=secret
- Optional signin=0 to create without signing in

GET /user/get
- Get current user info
- Returns 401 if not signed in

POST /user/signout
- Sign out current user

POST /user/update
- Update email: email=new@example.com
- Update password: password=newpassword

POST /user/oauth/add
- Add OAuth method: method=facebook&token=oauth-token
- Optional update_email=true to update email

POST /user/oauth/remove
- Remove OAuth method: method=facebook

POST /user/forgotpassword
- Request password reset: email=user@example.com

POST /user/resetpassword
- Reset password: token=reset-token&password=newpassword

GET /user/saml/metadata
- Get SAML service provider metadata

POST /user/saml/acs
- SAML assertion consumer service endpoint

Database Schema:
The package automatically creates these tables:
- Users: Basic user info and credentials
- Sessions: Active login sessions
- OAuth: Linked OAuth accounts
- PasswordResetTokens: Password reset tokens
- AuthSettings: Configuration settings

See schema.go for complete table definitions.

Security Features:
- Passwords hashed with bcrypt
- Rate limiting on authentication attempts
- CSRF protection
- Secure session cookies
- SQL injection protection via sqlx
*/
package auth
