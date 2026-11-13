package auth

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// TestURL if set, will be used instead of an oauth provider like
// facebook to make requests.
var TestURL string

type facebookResponse struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    string `json:"id"`
}

type googleResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	// The tokeninfo endpoint returns every claim as a JSON string,
	// unlike /userinfo which returns a real boolean for email_verified.
	// See https://developers.google.com/identity/openid-connect/openid-connect#obtainidtoken.
	EmailVerified string `json:"email_verified"`
	Audience      string `json:"aud"`
	Issuer        string `json:"iss"`
}

func getURL(url string) string {
	if TestURL != "" {
		return TestURL
	}
	return url
}

func httpRequest(url string, params map[string]string, jsonResult interface{}) {
	client := &http.Client{}

	r, _ := http.NewRequest("GET", url, nil)
	q := r.URL.Query()
	for key, value := range params {
		q.Add(key, value)
	}
	r.URL.RawQuery = q.Encode()

	resp, err := client.Do(r)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		b, err := io.ReadAll(resp.Body)
		log.Printf("Response: %v", b)
		if err != nil {
			panic(err)
		}
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(jsonResult)
	if err != nil {
		panic(err)
	}
}

// VerifyOauth contacts the oauth provider, specified with
// method, and retrieves the foriegn user id and foreign
// email of the user from the token.
// Returns the foriegn id and email, which can then be used
// to sign in the user.
// Valid methods are: "facebook", "google". Apple identity tokens
// require Handler settings; use POST /user/auth with method=apple.
//
// The provider must assert that the email address is verified
// (for example Google's email_verified claim): if it does not,
// VerifyOauth panics with an HTTP 401 error and the email must not
// be used to match or create local accounts. Use VerifyOauthVerified
// to get the verification flag instead of the panic.
func VerifyOauth(method, token string) (string, string) {
	foreignID, email, verified := verifyOauth(method, token, nil)
	if !verified {
		HTTPPanic(http.StatusUnauthorized, "provider email not verified")
	}
	return foreignID, email
}

// VerifyOauthVerified is like VerifyOauth but does not panic on an
// unverified provider email. It returns the foreign id and email along
// with whether the provider asserted the email is verified. Only use the
// returned email to match or create accounts when verified is true.
func VerifyOauthVerified(method, token string) (string, string, bool) {
	return verifyOauth(method, token, nil)
}

func (a *Handler) verifyOauth(method, token string) (string, string, bool) {
	return verifyOauth(method, token, a.appleAudiences())
}

func (a *Handler) appleAudiences() []string {
	seen := make(map[string]struct{})
	var audiences []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		audiences = append(audiences, id)
	}
	add(a.settings.AppleClientID)
	for _, id := range a.settings.AppleBundleIDs {
		add(id)
	}
	return audiences
}

// verifyOauth verifies an oauth token and returns the foreign user id,
// the foreign email, and whether the provider asserts that the email
// is verified. The email may only be used as an account key when the
// verified flag is true.
func verifyOauth(method, token string, appleAudiences []string) (string, string, bool) {
	switch method {
	case "facebook":
		var data facebookResponse
		url := getURL("https://graph.facebook.com/v3.2/me")
		httpRequest(url, map[string]string{
			"access_token": token,
			"fields":       "name,email",
		}, &data)

		// Meta's Graph API only returns the email field when the address
		// is confirmed, and there is no separate email_verified flag, so
		// presence of the email is the verification signal. A missing or
		// empty email is not verified and must never be matched.
		return data.ID, data.Email, data.Email != ""
	case "google":
		var data googleResponse
		url := getURL("https://www.googleapis.com/oauth2/v3/tokeninfo")
		httpRequest(url, map[string]string{
			"id_token": token,
		}, &data)

		// tokeninfo returns claims as JSON strings ("true"/"false"),
		// unlike /userinfo which returns a real boolean.
		return data.Sub, data.Email, data.EmailVerified == "true"
	case "apple":
		if len(appleAudiences) == 0 {
			HTTPPanic(400, "invalid oauth method")
		}
		return verifyAppleIdentityToken(token, appleAudiences)
	}

	HTTPPanic(400, "invalid oauth method")
	return "", "", false
}

func signInOauth(tx Tx, method string, foreignID string, email string, emailVerified bool) (int64, bool) {

	// Never use an email the provider has not verified as an account
	// key: an attacker controlling an oauth identity that carries a
	// victim's unverified address must not gain access to the victim's
	// account, and the address must not be baked into a new account.
	if !emailVerified {
		HTTPPanic(http.StatusUnauthorized, "provider email not verified")
	}

	email = strings.ToLower(email)
	emailUserID := tx.GetUserByEmail(email)
	created := false

	// try to get the userid from oauth db
	oauthUserID := tx.GetOauthUser(method, foreignID)

	var userid int64

	// There are two userids:
	// emailUserId: The id from the user with the same email as the oauth user
	// oauthUserId: Userid from oauth sign in

	// use the oauth userid if present.
	// otherwise use the emailUserId if present.
	// otherwise, create a new user.

	// if no userid exists in oauth,
	if oauthUserID != 0 {
		userid = oauthUserID
	} else if emailUserID != 0 {
		userid = emailUserID
	} else {
		// create a new user with null password and the given email
		userid = tx.CreatePasswordUser(email, "")
		created = true
	}

	if oauthUserID == 0 {
		// create oauth entry
		tx.AddOauthUser(method, foreignID, userid)
	}

	return userid, created
}
