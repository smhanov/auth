package auth

import (
	"encoding/json"
	"io/ioutil"
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
		b, err := ioutil.ReadAll(resp.Body)
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
// Valid methods are: "facebook", "google"
func VerifyOauth(method, token string) (string, string) {
	switch method {
	case "facebook":
		var data facebookResponse
		url := getURL("https://graph.facebook.com/v3.2/me")
		// connect to me api to get email and foreign id
		httpRequest(url, map[string]string{
			"access_token": token,
			"fields":       "name,email",
		}, &data)

		return data.ID, data.Email
	case "google":
		var data googleResponse
		url := getURL("https://www.googleapis.com/oauth2/v3/tokeninfo")

		// connect to me api to get email and foreign id
		httpRequest(url, map[string]string{
			"id_token": token,
		}, &data)

		return data.Sub, data.Email
	}

	HTTPPanic(400, "invalid oauth method")
	return "", ""
}

func signInOauth(tx Tx, method string, foreignID string, email string) (int64, bool) {

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
