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

func getURL(url string) string {
	if TestURL != "" {
		return TestURL
	}
	return url
}

func doOauth(method, token string) (string, string) {

	if method == "facebook" {
		// connect to me api to get email and foreign id
		url := getURL("https://graph.facebook.com/v3.2/me")

		client := &http.Client{}

		r, err := http.NewRequest("GET", url, nil)
		q := r.URL.Query()
		q.Add("access_token", token)
		q.Add("fields", "name,email")
		r.URL.RawQuery = q.Encode()

		resp, err := client.Do(r)

		if resp.StatusCode != 200 {

			b, _ := ioutil.ReadAll(resp.Body)
			log.Printf("Response: %v", b)

			if err != nil {
				panic(newErrorF(401, "Unauthorized"))
			}
		}

		decoder := json.NewDecoder(resp.Body)

		var data facebookResponse

		err = decoder.Decode(&data)
		if err != nil {
			panic(err)
		}

		return data.ID, data.Email
	}

	panic(newErrorF(400, "invalid oauth method"))
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
