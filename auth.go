package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Settings is the settings for the auth package
type Settings struct {
	// SMTP Server and port
	SMTPServer   string
	SMTPUser     string
	SMTPPassword string

	// Eg. "My web site <example@example.com>"
	EmailFrom             string
	ForgotPasswordSubject string
	ForgotPasswordBody    string

	// Alternatively, you can use this to send email
	SendEmailFn func(email string, url string)

	// Optionally override password hash from bcrypt default. You may override HashPassword,
	// or both. If you override HashPassword but not CompareHashedPassword, then
	// a CompareHashPasswordFn will be created based on HashPasswordFn.
	HashPasswordFn          func(password string) string
	CompareHashedPasswordFn func(hashedRealPassword, candidatePassword string) error
}

// DefaultSettings provide some reasonable defaults
var DefaultSettings = Settings{
	ForgotPasswordSubject: `Password reset`,
	ForgotPasswordBody:    `To reset your password, go to ${URL}`,
}

// ErrorDuplicateUser indicates that a user cannot be created because
// the email already exists. It should be used instead of the cryptic
// user database constraint validation error.
var ErrorDuplicateUser = errors.New("Duplicate user")

// ErrorUnauthorized is used when the user is not signed in, but is
// required to be for the operation.
var ErrorUnauthorized = errors.New("not signed in")

// UserInfo contains whatever information
// you need about the user for your application.
// It is returned to the javascript code
// for successful authentication requests.
type UserInfo interface{}

// DB is all the operations needed from the database.
// You can use the built-in userdb provided by this package
// and override one or more operations.
//
// Any errors should be expressed through panic.
type DB interface {
	Begin(ctx context.Context) Tx
}

// Tx is a database transaction that has methods for
// user authentication. Any error should be communicated
// by panic()
type Tx interface {
	Commit()
	Rollback()

	AddOauthUser(method string, foreignid string, userid int64)
	CreatePasswordUser(email string, password string) int64
	CreatePasswordResetToken(userid int64, token string, expiry int64)
	GetID(cookie string) int64
	GetInfo(userid int64, newAccount bool) UserInfo
	GetOauthMethods(userid int64) []string
	GetOauthUser(method string, foreignid string) int64
	GetPassword(email string) (int64, string)
	GetUserByEmail(email string) int64
	GetUserByPasswordResetToken(token string) int64
	RemoveOauthMethod(userid int64, method string)
	SignIn(userid int64, cookie string)
	SignOut(userid int64, cookie string)
	UpdateEmail(userid int64, email string)
	UpdatePassword(userid int64, password string)
}

// Handler is an HTTP Handler that will perform user authentication
// and management.
type Handler struct {
	settings Settings
	db       DB
}

func (a *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.ReplaceAll(r.URL.Path, "/users/", "/user/")

	switch p {
	case "/user/auth":
		a.handleUserAuth(w, r)
	case "/user/create":
		a.handleUserCreate(w, r)
	case "/user/get":
		a.handleUserGet(w, r)
	case "/user/signout":
		a.handleUserSignout(w, r)
	case "/user/update":
		a.handleUserUpdate(w, r)
	case "/user/oauth/remove":
		a.handleUserOauthRemove(w, r)
	case "/user/oauth/add":
		a.handleUserOauthAdd(w, r)
	case "/user/forgotpassword":
		a.handleUserForgotPassword(w, r)
	case "/user/resetpassword":
		a.handleUserResetPassword(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (a *Handler) handleUserGet(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	info := tx.GetInfo(GetUserID(tx, r), false)
	tx.Commit()

	SendJSON(w, info)
}

func (a *Handler) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if thing := recover(); thing != nil {
			message := fmt.Sprintf("%v", thing)
			if strings.Index(message, "UNIQUE") >= 0 {
				HTTPPanic(http.StatusBadRequest, "email already exists")
			}
			panic(thing)
		}
	}()

	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	if email == "" || strings.Index(email, "@") == -1 {
		HTTPPanic(http.StatusBadRequest, "not an email address")
	}

	if password == "" {
		HTTPPanic(http.StatusBadRequest, "blank password")
	}

	userid := tx.CreatePasswordUser(email, a.settings.HashPasswordFn(password))
	var info UserInfo
	if r.FormValue("signin") != "0" {
		info = SignInUser(tx, w, userid, true, IsRequestSecure(r))
	} else {
		info = tx.GetInfo(userid, true)
	}
	tx.Commit()
	SendJSON(w, info)
}

// GetUserID returns the userid. It panics with an HttpError if the
// user is not signed in.
func GetUserID(tx Tx, r *http.Request) int64 {
	userid := CheckUserID(tx, r)

	if userid == 0 {
		HTTPPanic(http.StatusUnauthorized, "Not signed in.")
	}

	return userid
}

// CheckUserID returns the userid if the user is signed in,
// or 0
func CheckUserID(tx Tx, r *http.Request) int64 {
	cookie, err := r.Cookie("session")

	var userid int64
	if err == nil {
		userid = tx.GetID(cookie.Value)
	}
	return userid
}

func signOut(tx Tx, req *http.Request) {
	cookie, _ := req.Cookie("session")
	if cookie != nil {
		userid := tx.GetID(cookie.Value)
		if userid > 0 {
			tx.SignOut(userid, cookie.Value)
		}
	}
}

func (a *Handler) handleUserSignout(w http.ResponseWriter, req *http.Request) {
	tx := a.db.Begin(req.Context())
	defer tx.Rollback()

	signOut(tx, req)
	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

// IsRequestSecure returns true if the request used the HTTPS protocol.
// It also checks for appropriate Forwarding headers.
func IsRequestSecure(r *http.Request) bool {
	return strings.ToLower(r.URL.Scheme) == "https" ||
		strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" ||
		strings.Index(r.Header.Get("Forwarded"), "proto=https") >= 0
}

// SignInUser performs the final steps of signing in an authenticated user,
// including creating a session. It returns the info structure that should be
// sent. You should first commit the transaction and then send this structure,
// perhaps using the SendJSON helper.
//
// Secure should be set to true if the http request was sent over HTTPs, to restrict
// usage of the cookie to https only.
//
// Example:
// info := auth.SignInUser(tx, w, userid, false, auth.IsRequestSecure(r))
// tx.Commit()
// auth.SendJSON(w, info)
func SignInUser(tx Tx, w http.ResponseWriter, userid int64, newAccount bool, secure bool) UserInfo {
	cookie := MakeCookie()
	tx.SignIn(userid, cookie)

	info := tx.GetInfo(userid, newAccount)

	expiration := time.Now().Add(30 * 24 * time.Hour)
	cookieVal := http.Cookie{
		Name:     "session",
		Value:    cookie,
		Path:     "/",
		Expires:  expiration,
		Secure:   secure,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookieVal)
	return info
}

func (a *Handler) handleUserAuth(w http.ResponseWriter, req *http.Request) {
	username := strings.TrimSpace(strings.ToLower(req.FormValue("email")))
	password := req.FormValue("password")
	method := req.FormValue("method")
	token := req.FormValue("token")

	tx := a.db.Begin(req.Context())
	defer tx.Commit() // so signout works below.
	signOut(tx, req)

	var userid int64
	var err error
	var created bool

	if method != "" {
		foreignID, foreignEmail := VerifyOauth(method, token)
		userid, created = signInOauth(tx, "facebook", foreignID, foreignEmail)
	} else {
		var realPassword string
		userid, realPassword = tx.GetPassword(username)
		if userid == 0 {
			HTTPPanic(http.StatusUnauthorized, "no user with that email exists")
		}

		err = a.settings.CompareHashedPasswordFn(realPassword, password)

		if err != nil {
			HTTPPanic(http.StatusUnauthorized, "wrong password")
		}
	}

	info := SignInUser(tx, w, userid, created, IsRequestSecure(req))
	tx.Commit()
	SendJSON(w, info)
}

func (a *Handler) handleUserUpdate(w http.ResponseWriter, req *http.Request) {
	tx := a.db.Begin(req.Context())
	defer tx.Rollback()

	userid := GetUserID(tx, req)
	email := strings.ToLower(req.FormValue("email"))
	password := req.FormValue("password")

	if email == "" && password == "" || email != "" && strings.Index(email, "@") < 0 {
		HTTPPanic(400, "not an email address")
	}

	if email != "" {
		tx.UpdateEmail(userid, email)
	}

	if password != "" {
		tx.UpdatePassword(userid, a.settings.HashPasswordFn(password))
	}

	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

func (a *Handler) handleUserOauthRemove(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	method := r.FormValue("method")
	if method == "" {
		HTTPPanic(400, "Missing method parameter")
	}

	tx.RemoveOauthMethod(GetUserID(tx, r), method)

	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

func (a *Handler) handleUserOauthAdd(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	method := r.FormValue("method")
	token := r.FormValue("token")
	updateEmail := r.FormValue("update_email")
	userid := GetUserID(tx, r)
	if method == "" {
		HTTPPanic(400, "Missing method parameter")
	}

	foreignID, email := VerifyOauth(method, token)
	tx.AddOauthUser(method, foreignID, userid)

	if updateEmail == "true" {
		tx.UpdateEmail(userid, strings.ToLower(email))
	}

	info := tx.GetInfo(userid, false)

	tx.Commit()

	SendJSON(w, info)
}

func (a *Handler) handleUserForgotPassword(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	email := r.FormValue("email")
	url := r.FormValue("url")

	if strings.Index(email, "@") < 0 {
		HTTPPanic(400, "please enter an email address")
	}

	userid := tx.GetUserByEmail(email)

	if userid == 0 {
		HTTPPanic(400, "email has no existing account")
	}

	if strings.Index(url, "${TOKEN}") < 0 {
		HTTPPanic(400, "url must contain ${TOKEN}")
	}

	token := MakeCookie()
	tx.CreatePasswordResetToken(userid, token, time.Now().Unix()+5*24*60*60)

	url = strings.Replace(url, "${TOKEN}", token, -1)
	tx.Commit()

	a.settings.SendEmailFn(email, url)
}

func (a *Handler) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin(r.Context())
	defer tx.Rollback()

	password := r.FormValue("password")

	if password == "" {
		HTTPPanic(400, "blank password")
	}

	userid := tx.GetUserByPasswordResetToken(r.FormValue("token"))
	if userid == 0 {
		HTTPPanic(401, "expired token")
	}

	tx.UpdatePassword(userid, a.settings.HashPasswordFn(password))
	info := SignInUser(tx, w, userid, false, IsRequestSecure(r))
	tx.Commit()
	SendJSON(w, info)
}

// New creates a new Handler
func New(db DB, settings Settings) http.Handler {

	if settings.SendEmailFn == nil {
		settings.SendEmailFn = func(addr string, url string) {
			sendEmail(settings, addr, url)
		}
	}

	if settings.HashPasswordFn == nil {
		settings.HashPasswordFn = HashPassword

		if settings.CompareHashedPasswordFn == nil {
			settings.CompareHashedPasswordFn = CompareHashedPassword
		}

		// HashPasswordFn is specified. Create a compare func if unspecified.
	} else if settings.CompareHashedPasswordFn == nil {
		settings.CompareHashedPasswordFn = func(hashedRealPassword string, candidatePassword string) error {
			hashedCandidate := settings.HashPasswordFn(candidatePassword)

			if hashedCandidate != hashedRealPassword {
				return errors.New("passwords do not match")
			}

			return nil
		}
	}

	return RecoverErrors(&Handler{settings, db})
}
