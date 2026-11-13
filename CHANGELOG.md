# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-13

First semver release of `github.com/smhanov/auth`. The package has been in
active use across smhanov and ArchieOS projects since 2019; this is the first
versioned (tagged) release.

### Capabilities
- Email/password authentication with secure session management and password hashing.
- OAuth 2.0 login for Google, Facebook, Twitter, and Apple (web and native
  identity tokens), plus a pluggable `OAuthProvider` interface for adding your
  own (GitHub, GitLab, etc.).
- Enterprise SAML SSO.
- Built-in rate limiting.
- Pluggable storage via `sqlx` — SQLite and PostgreSQL.
- Ready-to-use flows for password reset, email update, and account creation.

### Fixed
- Hardened SAML assertion handling: malformed client-triggerable input
  (bad base64, unparseable XML, missing `SAMLResponse`, missing `Issuer`,
  rejected assertions) now returns stable `400`/`401` responses instead of
  panicking or echoing raw library errors. `GetSamlID` fails with a typed,
  prefixed error. See `325b2e1`.

### Notes
- Requires Go 1.26.0 or later (see `go.mod`).
- Licensed under the MIT License.
