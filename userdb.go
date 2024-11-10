package auth

import (
	"context"
	"database/sql"
	"log"

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

// Begin begins a transaction
func (db *UserDB) Begin(ctx context.Context) Tx {
	return UserTx{db.db.MustBegin()}
}

// Commit commits a DB transaction
func (tx UserTx) Commit() {
	err := tx.Tx.Commit()
	if err != nil && err != sql.ErrTxDone {
		log.Panic(err)
	}
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

	rows, err := tx.Tx.Query(query, cookie)
	if err != nil {
		panic(err)
	}

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
	err := tx.Tx.Get(&i, query, userid)
	if err != nil {
		panic(err)
	}

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
	var err error
	var id int64

	if tx.Tx.DriverName() == "postgres" {
		err = tx.Tx.QueryRow(`INSERT INTO Users (email, password, settings, created, lastSeen) 
			VALUES ($1, $2, $3, $4, $5) RETURNING userid`, email, password, "", now, now).Scan(&id)
	} else {
		var res sql.Result
		res, err = tx.Tx.Exec(`INSERT INTO Users (email, password, settings, created, lastSeen) 
			VALUES ($1, $2, $3, $4, $5)`,
			email, password, "", now, now)

		if err != nil {
			panic(err)
		}
		id, err = res.LastInsertId()
	}

	if err != nil {
		panic(err)
	}

	return id
}

// SignIn creates a session with the given cookie and signs the user in.
func (tx UserTx) SignIn(userid int64, cookie string) {
	now := now().Unix()

	tx.Tx.MustExec("INSERT INTO Sessions (cookie, userid, lastUsed) VALUES ($1, $2, $3)",
		cookie, userid, now)

	tx.Tx.MustExec("UPDATE Users SET lastSeen=$1 WHERE userid=$2",
		now, userid)

	tx.performMaintenance()
}

func (tx UserTx) performMaintenance() {
	now := now().Unix()
	before := now - 30*24*60*60

	tx.Tx.MustExec("DELETE FROM Sessions WHERE lastUsed < $1", before)
	tx.Tx.MustExec("DELETE FROM PasswordResetTokens WHERE expiry < $1", now-5*24*60*60)
}

// SignOut deletes session information corresponding to the given cookie
func (tx UserTx) SignOut(userid int64, cookie string) {
	tx.Tx.MustExec("DELETE FROM Sessions WHERE cookie=$1",
		cookie)
}

// GetPassword searches for the salted hashed password for the given email
// address. The email is assumed to be already in all lower case.
// It also returns the userid. If not found, userid will be 0
func (tx UserTx) GetPassword(email string) (int64, string) {
	var rows *sql.Rows
	var err error
	rows, err = tx.Tx.Query("SELECT userid, password FROM Users WHERE email=$1",
		email)

	if err != nil {
		panic(err)
	}

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
	_, err := tx.Tx.Exec("DELETE FROM Oauth WHERE method=$1 AND foreign_id=$2",
		method, foreignID)
	if err != nil {
		panic(err)
	}

	_, err = tx.Tx.Exec(`INSERT INTO Oauth (method, foreign_id, userid) VALUES
		($1, $2, $3)`, method, foreignID, userid)

	if err != nil {
		panic(err)
	}
}

// GetOauthUser returns the userid assocaited with the given foreign identity,
// or 0 if none exists.
func (tx UserTx) GetOauthUser(method string, foreignID string) int64 {
	rows, err := tx.Tx.Query(`SELECT userid FROM Oauth 
		WHERE method=$1 AND foreign_id=$2`, method, foreignID)

	if err != nil {
		panic(err)
	}

	var userid int64

	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			panic(err)
		}
	}

	return userid
}

// GetUserByEmail finds the userid associated with the email,
// or returns 0 if none exists.
func (tx UserTx) GetUserByEmail(email string) int64 {
	rows, err := tx.Tx.Query(`SELECT userid FROM users WHERE email=$1`, email)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var userid int64
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			panic(err)
		}
	}

	return userid
}

// UpdateEmail changes the given user's email. Email must be in lower case already.
func (tx UserTx) UpdateEmail(userid int64, email string) {
	tx.Tx.MustExec("UPDATE Users SET email=$1 WHERE userid=$2",
		email, userid)
}

// UpdatePassword changes the given user's password. Password must be already hashed.
func (tx UserTx) UpdatePassword(userid int64, password string) {
	tx.Tx.MustExec("UPDATE Users SET password=$1 WHERE userid=$2",
		password, userid)
}

// RemoveOauthMethod removes the given method from the user's account
func (tx UserTx) RemoveOauthMethod(userid int64, method string) {
	tx.Tx.MustExec("DELETE FROM Oauth WHERE userid=$1 AND method=$2",
		userid, method)
}

// GetOauthMethods returns the oauth methods associated with the given user
func (tx UserTx) GetOauthMethods(userid int64) []string {
	var methods []string
	err := tx.Tx.Select(&methods,
		`SELECT method FROM Oauth WHERE userid=$1 ORDER BY method`, userid)
	if err != nil {
		panic(err)
	}
	return methods
}

// CreatePasswordResetToken creates the password reset token with the
// given expiry date in seconds
func (tx UserTx) CreatePasswordResetToken(userid int64, token string, expiry int64) {
	tx.Tx.MustExec(`INSERT INTO PasswordResetTokens (userid, token, expiry)
		VALUES ($1, $2, $3)`, userid, token, expiry)
}

// GetUserByPasswordResetToken finds the given userid from the token if not expired.
// If not found, return 0. If found, then remove all tokens from that user.
func (tx UserTx) GetUserByPasswordResetToken(token string) int64 {
	var userid int64

	err := tx.Tx.Get(&userid, `SELECT userid FROM PasswordResetTokens WHERE token=$1 AND expiry >= $2`, token,
		now().Unix()-5*24*60*60)
	if err != nil && err != sql.ErrNoRows {
		panic(err)
	}

	if userid != 0 {
		tx.Tx.MustExec(`DELETE FROM PasswordResetTokens WHERE userid=$1`, userid)
	}

	return userid
}

// GetValue should look up the given value. If not present return
// the empty string.
func (tx UserTx) GetValue(key string) string {
	rows, err := tx.Tx.Query("SELECT value FROM AuthSettings WHERE key=$1",
		key)

	if err != nil {
		panic(err)
	}

	var value string

	defer rows.Close()
	for rows.Next() {
		rows.Scan(&value)
	}
	return value
}

// SetValue should set the given value in the database.
func (tx UserTx) SetValue(key, value string) {
	_, err := tx.Tx.Exec("DELETE FROM AuthSettings WHERE key=$1",
		key)
	if err != nil {
		panic(err)
	}

	_, err = tx.Tx.Exec(`INSERT INTO AuthSettings (key, value) VALUES
		($1, $2)`, key, value)

	if err != nil {
		panic(err)
	}
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
