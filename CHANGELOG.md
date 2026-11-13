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
- OAuth sign-ins no longer match or create accounts by an email the provider
  has not verified. Previously, an OAuth identity carrying a victim's
  unverified email address could be used to take over the victim's account
  (the account-linking bug class behind CVE-2026-53516 and similar reports).
  Sign-ins relying on an unverified provider email are now rejected with 401,
  no session is issued, and no `oauth` row is created. Google (tokeninfo
  string claims and userinfo booleans), Apple identity tokens, Facebook
  (confirmed addresses only, per Meta's Graph API), and Twitter
  (`confirmed_email`) all check their provider verification signal. Custom
  `OAuthProvider` implementations are treated as unverified and fail closed
  unless they implement the new optional `VerifiedIdentityProvider`
  interface; `VerifyOauth` keeps its v1.0.0 signature but now panics with an
  HTTP 401 error on an unverified email — use the new `VerifyOauthVerified`
  to read the verification flag instead. Also, `POST /user/oauth/add` with
  `update_email=true` only honors a verified provider email.
- Google ID tokens presented to the legacy token path (`POST /user/auth` and
  `POST /user/oauth/add` with `method=google`) are now bound to this
  deployment: the token's `aud` claim must equal the configured
  `GoogleClientID` and its `iss` must be `accounts.google.com` or
  `https://accounts.google.com`, or the request fails with 401 ("invalid
  google token"). Previously, any valid Google ID token issued to *any*
  OAuth client could be replayed to sign in as that Google user.
  Migration: deployments that used only this legacy path must set
  `GoogleClientID` in Settings — requests fail with 400 ("google client id
  not configured") until they do — or migrate to the
  `/user/oauth/login/google` redirect flow, which binds the token to your
  client through the authorization-code exchange. The package-level
  `VerifyOauth` and `VerifyOauthVerified` no longer accept `method=google`
  (400) because they have no client ID to check the token against; use the
  Handler endpoints instead. Also, a non-200 response from a provider
  endpoint now fails the request with 502 ("oauth provider error") instead
  of being decoded into an empty identity.
- Hardened SAML assertion handling: malformed client-triggerable input
  (bad base64, unparseable XML, missing `SAMLResponse`, missing `Issuer`,
  rejected assertions) now returns stable `400`/`401` responses instead of
  panicking or echoing raw library errors. `GetSamlID` fails with a typed,
  prefixed error. See `325b2e1`.

### Notes
- Requires Go 1.26.0 or later (see `go.mod`).
- Licensed under the MIT License.
