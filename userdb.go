package auth

import (
	"context"
	"database/sql"
	"log"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// UserDB is a database that handles user authentication
type UserDB struct {
	db *sqlx.DB
}

// UserTx wraps a database transaction
type UserTx struct {
	Tx *sqlx.Tx
}

// NewUserDB returns a new user database
func NewUserDB(db *sqlx.DB) *UserDB {
	udb := &UserDB{db}
	udb.createTables()
	return udb
}

// GetInfo implements the DB interface by delegating to the transaction
func (db *UserDB) GetInfo(tx Tx, userid int64, newAccount bool) UserInfo {
	return tx.GetInfo(userid, newAccount)
}

func (db *UserDB) createTables() {
	var err error
	if db.db.DriverName() == "postgres" {
		_, err = db.db.Exec(schemaPostgres)
	} else {
		_, err = db.db.Exec(schemaSqlite)
	}
	if err != nil {
		panic(err)
	}
}

// Retry tuning for SQLite lock errors, applied by withLockRetry. These
// are package-level so that tests can shorten the retry budget; the
// defaults keep the historical Begin() behavior (5 retries, 10 ms base,
// about 310 ms of worst-case waiting).
var (
	lockRetryBaseDelay  = 10 * time.Millisecond
	lockRetryMaxRetries = 5
)

// withLockRetry runs fn, retrying SQLite lock errors with exponential
// backoff and jitter. SQLite can return "database is locked" under
// concurrent write load; a failed statement does not abort the
// transaction, so retrying it is safe.
//
// It returns when fn succeeds. Non-lock errors panic immediately; a
// lock error that persists after the retry budget is exhausted panics
// with the underlying error. RecoverErrors maps such panics to a
// retryable 503.
func withLockRetry(what string, fn func() error) {
	for attempt := 0; attempt < lockRetryMaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return
		}
		if !isLockError(err) {
			panic(err)
		}
		log.Printf("auth: database locked on %s, retry %d/%d: %v",
			what, attempt+1, lockRetryMaxRetries, err)
		time.Sleep(lockRetryDelay(attempt))
	}

	// Final attempt, after the retry budget is spent.
	if err := fn(); err != nil {
		log.Printf("auth: %s failed after %d retries: %v",
			what, lockRetryMaxRetries, err)
		panic(err)
	}
}

// lockRetryDelay returns the exponential backoff delay, with jitter,
// to apply before the given retry attempt.
func lockRetryDelay(attempt int) time.Duration {
	delay := lockRetryBaseDelay * time.Duration(1<<uint(attempt))
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(half)))
}

// Begin begins a transaction with retry logic for database lock errors.
// SQLite can return "database is locked" under concurrent write load.
// We retry with exponential backoff before panicking.
func (db *UserDB) Begin(ctx context.Context) Tx {
	var tx *sqlx.Tx
	withLockRetry("Begin()", func() error {
		var err error
		tx, err = db.db.BeginTxx(ctx, nil)
		return err
	})
	return UserTx{tx}
}

// Commit commits the transaction.
//
// A failed commit cannot be retried through the same Tx: database/sql
// marks the transaction done and hands its connection back *before*
// attempting the real commit, so a second call would only return
// sql.ErrTxDone — masking the failure as success. We therefore make a
// single real attempt. ErrTxDone is tolerated as an idempotent
// double-commit (the transaction was already finished, e.g. by a
// Rollback or an earlier Commit); any other error panics with the
// underlying error, which RecoverErrors maps to a retryable 503 for
// SQLite lock failures.
func (tx UserTx) Commit() {
	err := tx.Tx.Commit()
	if err == nil || err == sql.ErrTxDone {
		return
	}
	panic(err)
}

// isLockError checks if an error is a SQLite database lock error.
func isLockError(err error) bool {
	if err == nil {
		return false
	}
	return isLockErrorMessage(err.Error())
}

// isLockErrorMessage checks whether a message looks like a SQLite
// database lock error.
func isLockErrorMessage(msg string) bool {
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "SQLITE_LOCKED")
}

// The retry wrappers below run every statement inside the transaction
// through withLockRetry, so transient SQLite lock errors are retried
// with backoff before panicking. Non-lock errors still panic
// immediately, preserving the panic-based error contract of Tx. On
// non-SQLite databases isLockError never matches, so the wrappers are
// pass-through.

// execWithRetry executes a statement that does not return rows.
func (tx UserTx) execWithRetry(query string, args ...interface{}) sql.Result {
	var res sql.Result
	withLockRetry("Exec()", func() error {
		var err error
		res, err = tx.Tx.Exec(query, args...)
		return err
	})
	return res
}

// queryWithRetry executes a statement that returns rows.
func (tx UserTx) queryWithRetry(query string, args ...interface{}) *sql.Rows {
	var rows *sql.Rows
	withLockRetry("Query()", func() error {
		var err error
		rows, err = tx.Tx.Query(query, args...)
		return err
	})
	return rows
}

// getWithRetry executes a single-row query into dest.
func (tx UserTx) getWithRetry(dest interface{}, query string, args ...interface{}) {
	withLockRetry("Get()", func() error {
		return tx.Tx.Get(dest, query, args...)
	})
}

// selectWithRetry executes a multi-row query into dest.
func (tx UserTx) selectWithRetry(dest interface{}, query string, args ...interface{}) {
	withLockRetry("Select()", func() error {
		return tx.Tx.Select(dest, query, args...)
	})
}

// Rollback aborts a DB transaction
func (tx UserTx) Rollback() {
	tx.Tx.Rollback()
}

// GetID returns the userid associated with the cookie value,
// or 0 if no user is signed in with that cookie.
func (tx UserTx) GetID(cookie string) int64 {
	query := `
		SELECT userid
		FROM sessions
		WHERE cookie=$1`

	rows := tx.queryWithRetry(query, cookie)

	defer rows.Close()

	var userid int64
	for rows.Next() {
		err := rows.Scan(&userid)
		if err != nil {
			panic(err)
		}
	}

	return userid
}

// GetEmail returns the email address for the given userid.
func (tx UserTx) GetEmail(userid int64) string {
	query := `
		SELECT email
		FROM users
		WHERE userid=$1`

	var email string
	tx.getWithRetry(&email, query, userid)

	return email
}

// GetInfo by default returns a structure containing the user's userid,
// email, and settings.
func (tx UserTx) GetInfo(userid int64, newAccount bool) UserInfo {
	type info struct {
		Userid     int64    `json:"userid"`
		Email      string   `json:"email"`
		Settings   string   `json:"settings"`
		Methods    []string `json:"methods"`
		NewAccount bool     `json:"newAccount"`
	}

	query := `
		SELECT userid, email, settings
		FROM users
		WHERE userid=$1`

	var i info
	tx.getWithRetry(&i, query, userid)

	i.Methods = tx.GetOauthMethods(userid)
	i.NewAccount = newAccount
	if i.Methods == nil {
		i.Methods = make([]string, 0)
	}

	return i
}

// CreatePasswordUser creates a user with the given email and password
// The email is already in lower case and the password is already hashed.
func (tx UserTx) CreatePasswordUser(email string, password string) int64 {
	now := now().Unix()
	var id int64

	if tx.Tx.DriverName() == "postgres" {
		withLockRetry("QueryRow()", func() error {
			return tx.Tx.QueryRow(`INSERT INTO Users (email, password, settings, created, lastSeen) 
			VALUES ($1, $2, $3, $4, $5) RETURNING userid`, email, password, "", now, now).Scan(&id)
		})
	} else {
		res := tx.execWithRetry(`INSERT INTO Users (email, password, settings, created, lastSeen) 
			VALUES ($1, $2, $3, $4, $5)`,
			email, password, "", now, now)

		var err error
		id, err = res.LastInsertId()
		if err != nil {
			panic(err)
		}
	}

	return id
}

// SignIn creates a session with the given cookie and signs the user in.
func (tx UserTx) SignIn(userid int64, cookie string) {
	now := now().Unix()

	tx.execWithRetry("INSERT INTO Sessions (cookie, userid, lastUsed) VALUES ($1, $2, $3)",
		cookie, userid, now)

	tx.execWithRetry("UPDATE Users SET lastSeen=$1 WHERE userid=$2",
		now, userid)

	tx.performMaintenance()
}

func (tx UserTx) performMaintenance() {
	now := now().Unix()
	before := now - 30*24*60*60

	tx.execWithRetry("DELETE FROM Sessions WHERE lastUsed < $1", before)
	tx.execWithRetry("DELETE FROM PasswordResetTokens WHERE expiry < $1", now)
}

// SignOut deletes session information corresponding to the given cookie
func (tx UserTx) SignOut(userid int64, cookie string) {
	tx.execWithRetry("DELETE FROM Sessions WHERE cookie=$1",
		cookie)
}

// DeleteSessions invalidates all sessions for the given user.
func (tx UserTx) DeleteSessions(userid int64) {
	tx.execWithRetry("DELETE FROM Sessions WHERE userid=$1", userid)
}

// GetPassword searches for the salted hashed password for the given email
// address. The email is assumed to be already in all lower case.
// It also returns the userid. If not found, userid will be 0
func (tx UserTx) GetPassword(email string) (int64, string) {
	var rows *sql.Rows
	rows = tx.queryWithRetry("SELECT userid, password FROM Users WHERE email=$1",
		email)

	var userid int64
	var password string

	defer rows.Close()
	for rows.Next() {
		rows.Scan(&userid, &password)
	}

	return userid, password
}

// AddOauthUser marks the given OAUTH identify as belonging to this user.
func (tx UserTx) AddOauthUser(method string, foreignID string, userid int64) {
	tx.execWithRetry("DELETE FROM Oauth WHERE method=$1 AND foreign_id=$2",
		method, foreignID)

	tx.execWithRetry(`INSERT INTO Oauth (method, foreign_id, userid) VALUES
		($1, $2, $3)`, method, foreignID, userid)
}

// GetOauthUser returns the userid assocaited with the given foreign identity,
// or 0 if none exists.
func (tx UserTx) GetOauthUser(method string, foreignID string) int64 {
	rows := tx.queryWithRetry(`SELECT userid FROM Oauth 
		WHERE method=$1 AND foreign_id=$2`, method, foreignID)

	var userid int64

	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&userid)
		if err != nil {
			panic(err)
		}
	}

	return userid
}

// GetUserByEmail finds the userid associated with the email,
// or returns 0 if none exists.
func (tx UserTx) GetUserByEmail(email string) int64 {
	rows := tx.queryWithRetry(`SELECT userid FROM users WHERE email=$1`, email)
	defer rows.Close()

	var userid int64
	for rows.Next() {
		err := rows.Scan(&userid)
		if err != nil {
			panic(err)
		}
	}

	return userid
}

// UpdateEmail changes the given user's email. Email must be in lower case already.
func (tx UserTx) UpdateEmail(userid int64, email string) {
	tx.execWithRetry("UPDATE Users SET email=$1 WHERE userid=$2",
		email, userid)
}

// UpdatePassword changes the given user's password. Password must be already hashed.
func (tx UserTx) UpdatePassword(userid int64, password string) {
	tx.execWithRetry("UPDATE Users SET password=$1 WHERE userid=$2",
		password, userid)
}

// RemoveOauthMethod removes the given method from the user's account
func (tx UserTx) RemoveOauthMethod(userid int64, method string) {
	tx.execWithRetry("DELETE FROM Oauth WHERE userid=$1 AND method=$2",
		userid, method)
}

// GetOauthMethods returns the oauth methods associated with the given user
func (tx UserTx) GetOauthMethods(userid int64) []string {
	var methods []string
	tx.selectWithRetry(&methods,
		`SELECT method FROM Oauth WHERE userid=$1 ORDER BY method`, userid)
	return methods
}

// CreatePasswordResetToken creates the password reset token with the
// given expiry date in seconds
func (tx UserTx) CreatePasswordResetToken(userid int64, token string, expiry int64) {
	tx.execWithRetry(`INSERT INTO PasswordResetTokens (userid, token, expiry)
		VALUES ($1, $2, $3)`, userid, token, expiry)
}

// GetUserByPasswordResetToken finds the given userid from the token if not expired.
// If not found, return 0. If found, then remove all tokens from that user.
func (tx UserTx) GetUserByPasswordResetToken(token string) int64 {
	var userid int64

	// sql.ErrNoRows means the token was not found; treat it as success
	// so the retry wrapper does not panic on it.
	withLockRetry("Get()", func() error {
		err := tx.Tx.Get(&userid, `SELECT userid FROM PasswordResetTokens WHERE token=$1 AND expiry >= $2`, token,
			now().Unix())
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})

	if userid != 0 {
		tx.execWithRetry(`DELETE FROM PasswordResetTokens WHERE userid=$1`, userid)
	}

	return userid
}

// GetValue should look up the given value. If not present return
// the empty string.
func (tx UserTx) GetValue(key string) string {
	rows := tx.queryWithRetry("SELECT value FROM AuthSettings WHERE key=$1",
		key)

	var value string

	defer rows.Close()
	for rows.Next() {
		rows.Scan(&value)
	}
	return value
}

// SetValue should set the given value in the database.
func (tx UserTx) SetValue(key, value string) {
	tx.execWithRetry("DELETE FROM AuthSettings WHERE key=$1",
		key)

	tx.execWithRetry(`INSERT INTO AuthSettings (key, value) VALUES
		($1, $2)`, key, value)
}

// GetSamlIdentityProviderForUser returns the SAML provider metadata for a
// given user. The choice of which provider to use for the email address
// is entirely contained in this method.
// You will have to override the DB interface to implement this
// in your app, maybe distinguishing based on their email domain.
// If this method returns the empty string, normal authentication
// is done. Otherwise, the browser is redirected to the identity provider's
// sign in page.
func (tx UserTx) GetSamlIdentityProviderForUser(email string) string {
	return ""
}

// GetSamlIdentityProviderByID will return the XML Metadata file
// for the given identity provider, which has previously been added
// with AddSamlIdentityProviderMetadata
func (tx UserTx) GetSamlIdentityProviderByID(id string) string {
	return tx.GetValue("provider:" + id)
}

// AddSamlIdentityProviderMetadata adds the meta data for the given
// identity provider to the database. The id should be the one
// returned by GetSamlID(xml)
func (tx UserTx) AddSamlIdentityProviderMetadata(id, xml string) {
	tx.SetValue("provider:"+id, xml)
}
