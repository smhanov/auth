package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
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
	Begin() Tx
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
	switch r.URL.Path {
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
	tx := a.db.Begin()
	defer tx.Rollback()

	SendJSON(w, tx.GetInfo(a.getUserID(tx, r), false))
}

func (a *Handler) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if thing := recover(); thing != nil {
			message := fmt.Sprintf("%v", thing)
			if strings.Index(message, "UNIQUE") >= 0 {
				thing = newErrorF(http.StatusBadRequest, "email already exists")
			}
			panic(thing)
		}
	}()

	tx := a.db.Begin()
	defer tx.Rollback()

	email := strings.ToLower(r.FormValue("email"))
	password := r.FormValue("password")

	if email == "" || strings.Index(email, "@") == -1 {
		panic(newErrorF(http.StatusBadRequest, "not an email address"))
	}

	if password == "" {
		panic(newErrorF(http.StatusBadRequest, "blank password"))
	}

	userid := tx.CreatePasswordUser(email, HashPassword(password))

	SignInUser(tx, w, userid, true)
}

func (a *Handler) getUserID(tx Tx, r *http.Request) int64 {
	cookie, err := r.Cookie("session")

	var userid int64
	if err == nil {
		userid = tx.GetID(cookie.Value)
	}

	if userid == 0 {
		panic(newErrorF(http.StatusUnauthorized, "Not signed in."))
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
	tx := a.db.Begin()
	defer tx.Rollback()

	signOut(tx, req)
	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

// SignInUser performs the final steps of signing in an authenticated user,
// including creating a session and outputing the user info structure as JSON.
// It also commits the transaction.
func SignInUser(tx Tx, w http.ResponseWriter, userid int64, newAccount bool) {
	cookie := MakeCookie()
	tx.SignIn(userid, cookie)

	info := tx.GetInfo(userid, newAccount)

	expiration := time.Now().Add(30 * 24 * time.Hour)
	cookieVal := http.Cookie{Name: "session", Value: cookie,
		Path: "/", Expires: expiration}
	http.SetCookie(w, &cookieVal)

	tx.Commit()

	SendJSON(w, info)
}

func (a *Handler) handleUserAuth(w http.ResponseWriter, req *http.Request) {
	username := strings.ToLower(req.FormValue("email"))
	password := req.FormValue("password")
	method := req.FormValue("method")
	token := req.FormValue("token")

	tx := a.db.Begin()
	defer tx.Commit()
	signOut(tx, req)

	var userid int64
	var err error
	var created bool

	if method != "" {
		foreignID, foreignEmail := doOauth(method, token)
		userid, created = signInOauth(tx, "facebook", foreignID, foreignEmail)
	} else {
		var realPassword string
		userid, realPassword = tx.GetPassword(username)
		if userid == 0 {
			panic(newErrorF(http.StatusUnauthorized, "no user with that email exists"))
		}

		err = bcrypt.CompareHashAndPassword([]byte(realPassword), []byte(password))

		if err != nil {
			panic(newErrorF(http.StatusUnauthorized, "wrong password"))
		}
	}

	SignInUser(tx, w, userid, created)
}

func (a *Handler) handleUserUpdate(w http.ResponseWriter, req *http.Request) {
	tx := a.db.Begin()
	defer tx.Rollback()

	userid := a.getUserID(tx, req)
	email := strings.ToLower(req.FormValue("email"))
	password := req.FormValue("password")

	if email == "" && password == "" || email != "" && strings.Index(email, "@") < 0 {
		panic(newErrorF(400, "not an email address"))
	}

	if email != "" {
		tx.UpdateEmail(userid, email)
	}

	if password != "" {
		tx.UpdatePassword(userid, HashPassword(password))
	}

	tx.Commit()
	w.WriteHeader(http.StatusOK)
}

func (a *Handler) handleUserOauthRemove(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin()
	defer tx.Rollback()

	method := r.FormValue("method")
	if method == "" {
		panic(newErrorF(400, "Missing method parameter"))
	}

	tx.RemoveOauthMethod(a.getUserID(tx, r), method)

	tx.Commit()
}

func (a *Handler) handleUserOauthAdd(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin()
	defer tx.Rollback()

	method := r.FormValue("method")
	token := r.FormValue("token")
	updateEmail := r.FormValue("update_email")
	userid := a.getUserID(tx, r)
	if method == "" {
		panic(newErrorF(400, "Missing method parameter"))
	}

	foreignID, email := doOauth(method, token)
	tx.AddOauthUser(method, foreignID, userid)

	if updateEmail == "true" {
		tx.UpdateEmail(userid, strings.ToLower(email))
	}

	info := tx.GetInfo(userid, false)

	tx.Commit()

	SendJSON(w, info)
}

func (a *Handler) handleUserForgotPassword(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin()
	defer tx.Rollback()

	email := r.FormValue("email")
	url := r.FormValue("url")

	if strings.Index(email, "@") < 0 {
		panic(newErrorF(400, "please enter an email address"))
	}

	userid := tx.GetUserByEmail(email)

	if userid == 0 {
		panic(newErrorF(400, "email has no existing account"))
	}

	if strings.Index(url, "${TOKEN}") < 0 {
		panic(newErrorF(400, "url must contain ${TOKEN}"))
	}

	token := MakeCookie()
	tx.CreatePasswordResetToken(userid, token, time.Now().Unix()+5*24*60*60)

	url = strings.Replace(url, "${TOKEN}", token, -1)

	a.settings.SendEmailFn(email, url)

	tx.Commit()
}

func (a *Handler) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	tx := a.db.Begin()
	defer tx.Rollback()

	userid := tx.GetUserByPasswordResetToken(r.FormValue("token"))

	if userid == 0 {
		panic(newErrorF(401, "expired token"))
	}

	password := r.FormValue("password")

	if password == "" {
		panic(newErrorF(400, "blank password"))
	}

	tx.UpdatePassword(userid, HashPassword(password))
	SignInUser(tx, w, userid, false)
}

// New creates a new Handler
func New(db DB, settings Settings) http.Handler {

	if settings.SendEmailFn == nil {
		settings.SendEmailFn = func(addr string, url string) {
			sendEmail(settings, addr, url)
		}
	}

	return recoverErrors(&Handler{settings, db})
}
