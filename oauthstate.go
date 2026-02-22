package auth

import (
	"fmt"
	"sync"
	"time"
)

// oauthStateEntry holds the OAuth flow data stored in memory, keyed by state token.
type oauthStateEntry struct {
	Verifier  string
	Next      string
	CreatedAt time.Time
}

var (
	oauthStates   = make(map[string]oauthStateEntry)
	oauthStatesMu sync.Mutex
)

const oauthStateTTL = 10 * time.Minute

func oauthStateKey(provider, state string) string {
	return provider + ":" + state
}

// storeOauthState saves the OAuth verifier and next URL in memory,
// keyed by the provider name and state token. Expired entries from
// abandoned flows are cleaned up lazily on each call.
func storeOauthState(provider, state, verifier, next string) {
	oauthStatesMu.Lock()
	defer oauthStatesMu.Unlock()

	// Lazily clean up expired entries
	now := time.Now()
	for k, v := range oauthStates {
		if now.Sub(v.CreatedAt) > oauthStateTTL {
			delete(oauthStates, k)
		}
	}

	oauthStates[oauthStateKey(provider, state)] = oauthStateEntry{
		Verifier:  verifier,
		Next:      next,
		CreatedAt: now,
	}
}

// loadOauthState retrieves and removes the OAuth verifier and next URL
// for the given provider and state token. Returns an error if the state
// is not found or has expired.
func loadOauthState(provider, state string) (verifier string, next string, err error) {
	oauthStatesMu.Lock()
	defer oauthStatesMu.Unlock()

	key := oauthStateKey(provider, state)
	entry, ok := oauthStates[key]
	if !ok {
		return "", "", fmt.Errorf("oauth state not found for provider %s", provider)
	}

	// Delete after reading (one-time use)
	delete(oauthStates, key)

	// Reject expired state
	if time.Since(entry.CreatedAt) > oauthStateTTL {
		return "", "", fmt.Errorf("oauth state expired for provider %s", provider)
	}

	next = entry.Next
	if next == "" {
		next = "/"
	}

	return entry.Verifier, next, nil
}
