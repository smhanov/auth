package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"runtime/debug"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type httpError struct {
	status  int
	message string
}

func (h httpError) String() string {
	return h.message
}

func newErrorF(status int, fmtStr string, args ...interface{}) httpError {
	return httpError{status, fmt.Sprintf(fmtStr, args...)}
}

// SendJSON will write a json response
// You don't need to use this but it's handy to have!
func SendJSON(w http.ResponseWriter, thing interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(thing)
}

// SendError writes an error as a status to the output
// You don't need to use this but it's handy to have!
func SendError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Status", err.Error())
	w.WriteHeader(status)
}

// CORS wraps an HTTP request handler, adding appropriate cors headers.
// If CORS is desired, you can wrap the handler with it.
func CORS(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers",
				"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Status, Content-Type, Content-Length")
		}
		// Stop here if its Preflighted OPTIONS request
		if r.Method == "OPTIONS" {
			return
		}

		fn.ServeHTTP(w, r)
	}
}

func recoverErrors(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if thing := recover(); thing != nil {
				code := http.StatusInternalServerError
				status := "Internal server error"
				switch v := thing.(type) {
				case httpError:
					code = v.status
					status = v.message
				case error:
					status = v.Error()
					log.Println(debug.Stack())
				}
				w.Header().Set("Status", status)
				w.WriteHeader(code)
			}
		}()

		fn.ServeHTTP(w, r)
	}
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// MakeCookie generates a long random string suitable for use as a session cookie
func MakeCookie() string {
	return stringWithCharset(64, charset)
}

// HashPassword computes the salted, hashed password using bcypt.
// Panics on error.
func HashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}

	return string(hash)
}

// CompareHashedPassword compares the hashed password with the one the user entered (unhashed).
// It returns no error if the passwords match. The default implementation uses
// bcrypt.CompareHashAndPassword
func CompareHashedPassword(hashedPassword, candidatePassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(candidatePassword))
}
