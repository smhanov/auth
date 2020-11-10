package auth

const schemaSqlite = `
CREATE TABLE IF NOT EXISTS Users (
    userid INTEGER PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
	password TEXT,
	settings TEXT,
	created INTEGER NOT NULL,
	lastSeen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS Sessions (
    cookie TEXT PRIMARY KEY,
	userid INTEGER,
	lastUsed INTEGER NOT NULL,
    FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE
);	

CREATE TABLE IF NOT EXISTS oauth (
	method TEXT NOT NULL,
	foreign_id TEXT NOT NULL,
	token TEXT,
	userid INTEGER NOT NULL,
	FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE,
	UNIQUE(method, foreign_id)
);

CREATE TABLE IF NOT EXISTS PasswordResetTokens (
    token TEXT NOT NULL,
	userid INTEGER NOT NULL,
	expiry INTEGER NOT NULL,
    FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE
);	

CREATE TABLE IF NOT EXISTS AuthSettings (
	key TEXT NOT NULL,
	value TEXT NOT NULL
);
`

const schemaPostgres = `
CREATE TABLE IF NOT EXISTS Users (
    userid BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
	password TEXT,
	settings TEXT,
	created BIGINT NOT NULL,
	lastSeen BIGINT NOT NULL,
	UNIQUE(email)
);

CREATE TABLE IF NOT EXISTS Sessions (
    cookie TEXT PRIMARY KEY,
	userid BIGINT,
	lastUsed BIGINT NOT NULL,
    FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE
);	

CREATE TABLE IF NOT EXISTS oauth (
	method TEXT NOT NULL,
	foreign_id TEXT NOT NULL,
	token TEXT,
	userid BIGINT NOT NULL,
	FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE,
	UNIQUE(method, foreign_id)
);

CREATE TABLE IF NOT EXISTS PasswordResetTokens (
    token TEXT NOT NULL,
	userid BIGINT NOT NULL,
	expiry BIGINT NOT NULL,
    FOREIGN KEY (userid) REFERENCES Users ON DELETE CASCADE
);	

CREATE TABLE IF NOT EXISTS AuthSettings (
	key TEXT NOT NULL,
	value TEXT NOT NULL
);
`
