# auth

Package `auth` provides a complete, self-hosted user authentication system for Go web applications.

[![Go Reference](https://pkg.go.dev/badge/github.com/smhanov/auth.svg)](https://pkg.go.dev/github.com/smhanov/auth)

## Overview

This library aims to provide "boring" but essential user authentication infrastructure, saving you from rewriting the same login logic for every project. It is designed to be dropped into your existing web application with minimal configuration.

## Key Benefits

- **Comprehensive**: Handles Email/Password, OAuth (Google, Facebook, Twitter), and Enterprise SAML SSO out of the box.
- **Extensible**: Pluggable OAuth provider API lets you add any OAuth2 provider (GitHub, GitLab, etc.) with a simple interface.
- **Secure**: Includes built-in rate limiting, secure session management, and password hashing standards.
- **Self-Hosted**: You own your data. Supports SQLite and PostgreSQL via `sqlx`.
- **Complete Flows**: Includes ready-to-use flows for password resets, email updates, and account creation.

## Adding Custom OAuth Providers

Implement the `OAuthProvider` interface to add any OAuth2 provider:

```go
type GitHubProvider struct {
    ClientID, ClientSecret string
}

func (p *GitHubProvider) Name() string              { return "github" }
func (p *GitHubProvider) UsePKCE() bool             { return false }
func (p *GitHubProvider) OAuthConfig() *oauth2.Config {
    return &oauth2.Config{
        ClientID:     p.ClientID,
        ClientSecret: p.ClientSecret,
        Scopes:       []string{"user:email"},
        Endpoint: oauth2.Endpoint{
            AuthURL:  "https://github.com/login/oauth/authorize",
            TokenURL: "https://github.com/login/oauth/access_token",
        },
    }
}
func (p *GitHubProvider) FetchIdentity(ctx context.Context, client *http.Client) (string, string, error) {
    // Use client to call provider API and return (userID, email, error)
}
```

Register it in settings:

```go
settings.OAuthProviders = []auth.OAuthProvider{
    &GitHubProvider{ClientID: "...", ClientSecret: "..."},
}
```

Routes are automatically created: `/user/oauth/login/github` and `/user/oauth/callback/github`.

## Documentation

For full documentation, tutorials, and API reference, please visit the official Go docs:

**[https://pkg.go.dev/github.com/smhanov/auth](https://pkg.go.dev/github.com/smhanov/auth)**

## Installation

```shell
go get github.com/smhanov/auth
```

## Acknowledgements

Audited by [codepathfinder.dev](https://codepathfinder.dev). Trace vulnerabilities across your codebase.
