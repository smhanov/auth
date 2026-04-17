package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
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

// SendJSON will write a json response and set the appropriate content-type
// header. You don't need to use this but it's handy to have!
func SendJSON(w http.ResponseWriter, thing interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(thing)
}

// SendError writes an error as a status to the output
// You don't need to use this but it's handy to have!
func SendError(w http.ResponseWriter, status int, err error) {
	writeErrorResponse(w, status, err.Error())
}

// CORS wraps an HTTP request handler, adding CORS headers only for the
// explicitly allowed origins.
//
// Origins must be fully qualified values such as "https://app.example.com".
// If you need the previous permissive behavior that reflects any Origin,
// use UnsafeCORS instead.
func CORS(fn http.Handler, allowedOrigins []string) http.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		allowed[origin] = struct{}{}
	}

	if len(allowed) == 0 {
		panic("auth.CORS requires at least one allowed origin; use auth.UnsafeCORS to allow any origin")
	}

	return corsHandler(fn, func(origin string) bool {
		_, ok := allowed[origin]
		return ok
	})
}

// UnsafeCORS wraps an HTTP request handler and reflects any Origin.
//
// This matches the package's previous CORS behavior and should only be used
// when you intentionally want to trust every calling origin.
func UnsafeCORS(fn http.Handler) http.HandlerFunc {
	return corsHandler(fn, func(string) bool { return true })
}

func corsHandler(fn http.Handler, originAllowed func(string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			addVaryHeader(w.Header(), "Origin")
			addVaryHeader(w.Header(), "Access-Control-Request-Method")
			addVaryHeader(w.Header(), "Access-Control-Request-Headers")

			if !originAllowed(origin) {
				writeErrorResponse(w, http.StatusForbidden, "origin not allowed")
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers",
				"Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Status, Content-Type, Content-Length")
		}
		// Stop here if its Preflighted OPTIONS request
		if r.Method == http.MethodOptions {
			return
		}

		fn.ServeHTTP(w, r)
	}
}

func addVaryHeader(headers http.Header, value string) {
	for _, existing := range headers.Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			if strings.TrimSpace(part) == value {
				return
			}
		}
	}
	headers.Add("Vary", value)
}

// RecoverErrors will wrap an HTTP handler. When a panic occurs, it will
// print the stack to the log. Secondly, it will return the error text in both
// the response header and response body so callers can read it reliably.
func RecoverErrors(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if thing := recover(); thing != nil {
				code := http.StatusInternalServerError
				status := "Internal server error"
				switch v := thing.(type) {
				case HTTPError:
					code = v.StatusCode()
					status = v.Error()
				default:
					status = fmt.Sprintf("%v", thing)
					log.Printf("%v", thing)
					log.Println(string(debug.Stack()))
				}
				writeErrorResponse(w, code, status)
			}
		}()

		fn.ServeHTTP(w, r)
	}
}

func writeErrorResponse(w http.ResponseWriter, statusCode int, status string) {
	if status == "" {
		status = http.StatusText(statusCode)
	}

	w.Header().Set("Status", sanitizeHeaderValue(status))
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(statusCode)
	fmt.Fprint(w, status)
}

func sanitizeHeaderValue(value string) string {
	value = strings.NewReplacer("\r", " ", "\n", " ").Replace(value)
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}

func formatOAuthProviderError(prefix string, err error) string {
	if retrieveErr, ok := err.(*oauth2.RetrieveError); ok {
		return formatOAuthProviderResponseError(prefix, retrieveErr.Body, err.Error())
	}

	return fmt.Sprintf("%s: %v", prefix, err)
}

func formatOAuthProviderResponseError(prefix string, body []byte, fallback string) string {
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		if fallback == "" {
			return prefix
		}
		return fmt.Sprintf("%s: %s", prefix, fallback)
	}

	var payload struct {
		Detail           string `json:"detail"`
		ErrorDescription string `json:"error_description"`
		Error            string `json:"error"`
		Message          string `json:"message"`
		Title            string `json:"title"`
		Reason           string `json:"reason"`
		Errors           []struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &payload); err == nil {
		detail := firstNonEmpty(
			payload.Detail,
			payload.ErrorDescription,
			payload.Message,
			payload.Error,
		)
		if detail == "" {
			for _, item := range payload.Errors {
				detail = firstNonEmpty(item.Detail, item.Message)
				if detail != "" {
					break
				}
			}
		}

		if detail != "" {
			if payload.Title != "" && !strings.Contains(detail, payload.Title) {
				detail = payload.Title + ": " + detail
			}
			if payload.Reason != "" && !strings.Contains(detail, payload.Reason) {
				detail += " (reason: " + payload.Reason + ")"
			}
			return fmt.Sprintf("%s: %s", prefix, detail)
		}
	}

	return fmt.Sprintf("%s: %s", prefix, bodyText)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		b[i] = charset[n.Int64()]
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
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

// AdvanceTime is used during testing to simulate time passing
func AdvanceTime(amount time.Duration) {
	timeOffset += amount
}

var timeOffset time.Duration

func now() time.Time {
	return time.Now().Add(timeOffset)
}

// GetHost returns the host of the request, taking into account
// x-forwarded-host headers. May include the port as well.
func GetHost(request *http.Request) string {
	forwardedHost := request.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" {
		return forwardedHost
	}
	return request.Host
}

// GetRequestIP returns the Ip address of the request, taking into account
// x-forwarded-for headers.
func GetIPAddress(request *http.Request) string {
	ipAddress := request.RemoteAddr
	xForwardedFor := request.Header.Get("x-forwarded-for")
	if xForwardedFor != "" {
		ipAddress = xForwardedFor
	}

	colon := strings.LastIndex(ipAddress, ":")
	if colon >= 0 {
		ipAddress = ipAddress[:colon]
	}

	return ipAddress
}

func resolveRedirectURL(configuredURL string, r *http.Request, defaultPath string) string {
	if configuredURL == "" {
		configuredURL = defaultPath
	}
	if strings.HasPrefix(configuredURL, "/") {
		scheme := "http"
		if IsRequestSecure(r) {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s%s", scheme, GetHost(r), configuredURL)
	}
	return configuredURL
}

func sanitizeRedirectTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	return target
}

func sanitizeRefererReturnPath(r *http.Request) string {
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return "/"
	}

	u, err := url.Parse(referer)
	if err != nil {
		return "/"
	}

	if u.IsAbs() {
		if !sameRequestOrigin(r, u) {
			return "/"
		}
	} else if u.Host != "" || u.Scheme != "" {
		return "/"
	}

	target := u.Path
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}

	return sanitizeRedirectTarget(target)
}

func sameRequestOrigin(r *http.Request, u *url.URL) bool {
	return strings.EqualFold(u.Scheme, requestScheme(r)) && strings.EqualFold(u.Host, GetHost(r))
}

func requestScheme(r *http.Request) string {
	if IsRequestSecure(r) {
		return "https"
	}
	return "http"
}
