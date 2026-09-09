package auth_test

import (
	"log"
	"net/http"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// Example_apple shows Sign in with Apple using env credentials.
//
// Apple rejects http://localhost return URLs. Use a public HTTPS tunnel and
// register the exact callback https://<host>/user/oauth/callback/apple on the
// Services ID Return URLs. Set APPLE_REDIRECT_URL to that callback if it
// cannot be derived from the request.
//
// Load credentials from the environment (Services ID, Team ID, Key ID, and
// .p8 private key). With 1Password CLI, inject them rather than committing
// secrets, for example:
//
//	export APPLE_CLIENT_ID="$(op read op://...)"
//	export APPLE_TEAM_ID="$(op read op://...)"
//	export APPLE_KEY_ID="$(op read op://...)"
//	export APPLE_PRIVATE_KEY="$(op read op://...)"
//	export APPLE_REDIRECT_URL="https://<host>/user/oauth/callback/apple"
//	go test -run Example_apple
//
// or `op run --env-file=... -- go test -run Example_apple`.
func Example_apple() {
	rawdb, err := sqlx.Open("sqlite3", "mydatabase.db")
	if err != nil {
		log.Panic(err)
	}

	settings := auth.DefaultSettings
	settings.AppleClientID = os.Getenv("APPLE_CLIENT_ID")
	settings.AppleTeamID = os.Getenv("APPLE_TEAM_ID")
	settings.AppleKeyID = os.Getenv("APPLE_KEY_ID")
	settings.ApplePrivateKey = os.Getenv("APPLE_PRIVATE_KEY")
	settings.AppleRedirectURL = os.Getenv("APPLE_REDIRECT_URL")

	http.Handle("/user/", auth.New(auth.NewUserDB(rawdb), settings))
	http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/user/get", http.StatusFound)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(appleExamplePage))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

const appleExamplePage = `<!DOCTYPE html>
<html>
<body>
<a href="/user/oauth/login/apple?next=/">Sign in with Apple</a>
<p><a href="/me">Me</a></p>
</body>
</html>`
