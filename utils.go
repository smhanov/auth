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

// HTTPError is an error that should be communicated to the user through
// an http status code.
type HTTPError interface {
	Error() string
	StatusCode() int
}

type httpError struct {
	status  int
	message string
}

func (h httpError) Error() string {
	return h.message
}

func (h httpError) StatusCode() int {
	return h.status
}

// HTTPPanic will cause a panic with an HTTPError. This is expected to be
// recovered at a higher level, for example using the RecoverErrors
// middleware so the error is returned to the client.
func HTTPPanic(status int, fmtStr string, args ...interface{}) HTTPError {
	panic(httpError{status, fmt.Sprintf(fmtStr, args...)})
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

// RecoverErrors will wrap an HTTP handler. When a panic occurs, it will
// print the stack to the log. Secondly, it will return the internal server error
// with the status header equal to the error string.
func RecoverErrors(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if thing := recover(); thing != nil {
				code := http.StatusInternalServerError
				status := "Internal server error"
				dopanic := true
				switch v := thing.(type) {
				case HTTPError:
					code = v.StatusCode()
					status = v.Error()
					dopanic = false
				case error:
					status = v.Error()
					log.Println(debug.Stack())
				}
				w.Header().Set("Status", status)
				w.WriteHeader(code)
				if dopanic {
					panic(thing)
				}
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
