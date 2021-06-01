package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// ---------------------------------
// Just test if it is possible to override the getuserinfo function
type MyDB struct {
	db *auth.UserDB
}

type MyTx struct {
	auth.Tx
}

func (db MyDB) Begin(ctx context.Context) auth.Tx {
	return MyTx{db.db.Begin(ctx)}
}

func (tx MyTx) GetUserInfo() auth.UserInfo {
	return 7
}

//lint:ignore U1000 ...
func justTestCompile() {
	db := MyDB{auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:"))}

	settings := auth.DefaultSettings

	// configure how to send password reset emails
	settings.SMTPServer = "smtp.gmail.com:587"
	settings.ForgotPasswordSubject = "Password reset from awesomepeaches.com"
	settings.ForgotPasswordBody = "Please go to this url to reset your password:\n\n   ${URL}"
	settings.EmailFrom = "support@awesomepeaches.com"
	auth.New(db, settings)
}

type testRequest struct {
	name string

	// request
	path   string
	params map[string]string

	//response
	code int
	json map[string]interface{}

	// status field of header
	status string
}

var passwordToken string

func TestStuff(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := strings.Split(r.FormValue("access_token"), ":")
		io.WriteString(w,
			fmt.Sprintf(`{"name": "%s", "email": "%s", "id": "fbuser%s"}`,
				values[1], values[2], r.FormValue("access_token")))
	}))

	auth.TestURL = ts.URL

	trs := []testRequest{
		{
			name: "Get with no cookie should result in 401",
			path: "/user/get",
			code: 401,
		},
		{
			name: "create user with invalid email should result in 400",
			path: "/user/create",
			params: map[string]string{
				"email":    "steve",
				"password": "password",
			},
			code:   400,
			status: "not an email address",
		},
		{
			name: "create user with empty email should result in 400",
			path: "/user/create",
			params: map[string]string{
				"email":    "",
				"password": "password",
			},
			code:   400,
			status: "not an email address",
		},
		{
			name: "create user with empty password should result in 400",
			path: "/user/create",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "",
			},
			code:   400,
			status: "blank password",
		},
		{
			name: "create user should succeed",
			path: "/user/create",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example@example.com",
				"userid":   1.0,
				"settings": "",
			},
		},
		{
			name: "create duplicate user have appropriate error message",
			path: "/user/create",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "password",
			},
			code:   400,
			status: "email already exists",
		},
		{
			name: "create a different user should succeed",
			path: "/user/create",
			params: map[string]string{
				"email":    " example2@example.com  ", // note spaces!! They should be removed.
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example2@example.com",
				"userid":   2.0,
				"settings": "",
			},
		},
		{
			name: "user/get should succeed",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":    "example2@example.com",
				"userid":   2.0,
				"settings": "",
			},
		},
		{
			name: "sign out should succeed",
			path: "/user/signout",
			code: 200,
		},
		{
			name: "sign out when not signed in should succeed",
			path: "/user/signout",
			code: 200,
		},
		{
			name: "After signing out, user/get should fail",
			path: "/user/get",
			code: 401,
		},
		{
			name: "Sign in should fail with wrong email, with appropriate error message",
			path: "/user/auth",
			params: map[string]string{
				"email":    "example3@example.com",
				"password": "password",
			},
			code:   401,
			status: "no user with that email exists",
		},
		{
			name: "Sign in should fail with wrong password, with appropriate error message",
			path: "/user/auth",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "password2",
			},
			code:   401,
			status: "wrong password",
		},
		{
			name: "Sign in should otherwise succeed",
			path: "/user/auth",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example@example.com",
				"userid":   1.0,
				"settings": "",
			},
		},
		{
			name: "Sign in with uppercase / spaces in email should succeed",
			path: "/user/auth",
			params: map[string]string{
				"email":    "Example@example.com ",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example@example.com",
				"userid":   1.0,
				"settings": "",
			},
		},
		{
			name: "After signing in, user/get should succeed",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":    "example@example.com",
				"userid":   1.0,
				"settings": "",
			},
		},
		{
			name: "Authenticate existing user with NEW facebook id should succeed",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Example User 2:example2@example.com",
			},
			json: map[string]interface{}{
				"email":    "example2@example.com",
				"userid":   2.0,
				"settings": "",
				"methods":  []string{"facebook"},
			},
		},

		{
			name: "After signing in with facebook, user/get should succeed",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email": "example2@example.com",
			},
		},

		{
			name: "",
			path: "/user/signout",
			code: 200,
		},

		{
			name: "Authenticate existing user with known facebook id should succeed",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Example User 2:example2@example.com",
			},
			json: map[string]interface{}{
				"email":    "example2@example.com",
				"userid":   2.0,
				"settings": "",
			},
		},

		{
			name: "Create a NEW user with NEW facebook id should succeed",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Example User 3:example3@example.com",
			},
			json: map[string]interface{}{
				"email":    "example3@example.com",
				"userid":   3.0,
				"settings": "",
			},
		},

		{
			name: "Update email / password should succeed",
			path: "/user/update",
			code: 200,
			params: map[string]string{
				"email":    "example3-updated@example.com",
				"password": "password",
			},
		},

		{
			name: "Auth with new email password should succeed",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"email":    "example3-updated@example.com",
				"password": "password",
			},
		},

		{
			name: "Can change only the password if desired",
			path: "/user/update",
			code: 200,
			params: map[string]string{
				"password": "password2",
			},
		},

		{
			name: "Auth with old password should fail",
			path: "/user/auth",
			code: 401,
			params: map[string]string{
				"email":    "example3-updated@example.com",
				"password": "password",
			},
		},

		{
			name: "After a failed authentication, any previous user should be signed out",
			path: "/user/get",
			code: 401,
		},

		{
			name: "Sign in as existing user with existing FB but different email should succeed",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Example User 3:example3@example.com",
			},
			json: map[string]interface{}{
				"email":    "example3-updated@example.com",
				"userid":   3.0,
				"settings": "",
			},
		},

		{
			name: "Update email to blank should give appropriate error",
			path: "/user/update",
			code: 400,
			params: map[string]string{
				"email": "",
			},
			status: "not an email address",
		},

		{
			name: "Update email to invalid should give appropriate error",
			path: "/user/update",
			code: 400,
			params: map[string]string{
				"email": "test",
			},
			status: "not an email address",
		},

		{
			name: "Remove OAuth method should work",
			path: "/user/oauth/remove",
			code: 200,
			params: map[string]string{
				"method": "facebook",
			},
		},

		{
			name: "After removing oauth method and having different email, FB signin creates a new user",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Example User 3:example3@example.com",
			},
			json: map[string]interface{}{
				"email":    "example3@example.com",
				"userid":   4.0,
				"settings": "",
			},
		},

		{
			name: "create new user for next test",
			path: "/user/create",
			params: map[string]string{
				"email":    "example5@example.com",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example5@example.com",
				"userid":   5.0,
				"settings": "",
				"methods":  []string{},
			},
		},

		{
			name: "Can add an oauth method",
			path: "/user/oauth/add",
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Mr Five:fivejives@example.com",
			},
			code: 200,
		},

		{
			name: "After adding an oauth method, we can authenticate with it",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Mr Five:fivejives@example.com",
			},
			json: map[string]interface{}{
				"email":   "example5@example.com",
				"userid":  5.0,
				"methods": []string{"facebook"},
			},
		},

		{
			name: "create user for next test",
			path: "/user/create",
			params: map[string]string{
				"email":    "example6@example.com",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":    "example6@example.com",
				"userid":   6.0,
				"settings": "",
			},
		},

		{
			name: "User 6 adds user 5's oauth credentials",
			path: "/user/oauth/add",
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Mr Five:fivejives@example.com",
			},
			code: 200,
		},

		{
			name: "getUser shows user 6 now has facebook",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":   "example6@example.com",
				"userid":  6.0,
				"methods": []string{"facebook"},
			},
		},

		{
			name: "Signing in with user 5's facebook now authenticates user 6",
			path: "/user/auth",
			code: 200,
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Mr Five:fivejives@example.com",
			},
			json: map[string]interface{}{
				"email":   "example6@example.com",
				"userid":  6.0,
				"methods": []string{"facebook"},
			},
		},

		{
			name: "Adding credentials a second time succeeds, does nothing",
			path: "/user/oauth/add",
			params: map[string]string{
				"method": "facebook",
				"token":  "facebook:Mr Five:fivejives@example.com",
			},
			code: 200,
		},

		{
			name: "Adding credentials with the update_email flag changes the email address of the account",
			path: "/user/oauth/add",
			params: map[string]string{
				"method":       "facebook",
				"token":        "facebook:Mr Five:fivejives@example.com",
				"update_email": "true",
			},
			code: 200,
			json: map[string]interface{}{
				"email": "fivejives@example.com",
			},
		},

		{
			name: "User 6 can now sign in with that email",
			path: "/user/auth",
			params: map[string]string{
				"email":    "fivejives@example.com",
				"password": "password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":   "fivejives@example.com",
				"userid":  6.0,
				"methods": []string{"facebook"},
			},
		},

		{
			name: "Forgot password with no email has sensible message",
			path: "/user/forgotpassword",
			params: map[string]string{
				"email": "blah",
			},
			code:   400,
			status: "please enter an email address",
		},

		{
			name: "Forgot password with non-existing email has sensible message",
			path: "/user/forgotpassword",
			code: 400,
			params: map[string]string{
				"email": "blah@blah.com",
			},
			status: "email has no existing account",
		},

		{
			name: "Forgot password with existing email works",
			path: "/user/forgotpassword",
			code: 200,
			params: map[string]string{
				"email": "example@example.com",
			},
		},
	}

	handler := auth.New(auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")),
		auth.Settings{
			SendEmailFn: func(email, token string) {
				t.Logf("Password reset email sent; token=%s", token)
				passwordToken = token
			},
		})
	client := newTestClient(handler)
	client.do(t, trs...)

	client.do(t, []testRequest{{
		name: "password reset with no password has error",
		path: "/user/resetpassword",
		code: 400,
		params: map[string]string{
			"token":    passwordToken,
			"password": "",
		},
		status: "blank password",
	}, {
		name: "password reset with invalid token has error",
		path: "/user/resetpassword",
		code: 401,
		params: map[string]string{
			"token":    "blah",
			"password": "newpassword",
		},
		status: "expired token",
	}, {
		name: "password reset success",
		path: "/user/resetpassword",
		code: 200,
		params: map[string]string{
			"token":    passwordToken,
			"password": "newpassword",
		},
		json: map[string]interface{}{
			"email":    "example@example.com",
			"userid":   1.0,
			"settings": "",
		},
	},

		{
			name: "after password reset we are signed in",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":  "example@example.com",
				"userid": 1.0,
			},
		},

		{
			name: "Sign in with new password works",
			path: "/user/auth",
			params: map[string]string{
				"email":    "example@example.com",
				"password": "newpassword",
			},
			code: 200,
			json: map[string]interface{}{
				"email":  "example@example.com",
				"userid": 1.0,
			},
		},
		{
			name: "Create a new user without signing in",
			path: "/user/create",
			params: map[string]string{
				"email":    "example4@example.com",
				"password": "password",
				"signin":   "0",
			},
			code: 200,
			json: map[string]interface{}{
				"email": "example4@example.com",
			},
		},
		{
			name: "after creating user with signin=0, we are still signed in as original user",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email": "example@example.com",
			},
		},
	}...,
	)

	auth.AdvanceTime(1 * time.Hour)

	// bad password attempts are rate limited
	t.Logf("Bad password attempts should be rate limited.")
	passed := false
	for i := 0; i < 100; i++ {
		resp := client.makeRequest(t, "/user/auth", map[string]string{
			"email":    "example@example.com",
			"password": "badpassword",
		})

		if resp.StatusCode == 429 {
			t.Logf("    Rate limited after %d attempts", i+1)
			passed = true
			break
		} else if resp.StatusCode != 401 {
			t.Errorf("    Received invalid response %v", resp.StatusCode)
		}
	}

	if !passed {
		t.Errorf("FAIL: Password cracking attempts are not rate-limited.")
	}

	// wait 5 minutes and try again
	t.Logf("After waiting period, password attempts are allowed again")
	auth.AdvanceTime(5 * time.Minute)
	resp := client.makeRequest(t, "/user/auth", map[string]string{
		"email":    "example@example.com",
		"password": "badpassword",
	})
	if resp.StatusCode != 401 {
		t.Errorf("FAIL: After waiting period, got status code %v", resp.StatusCode)
	}

	// Wait an hour and start the next test.
	auth.AdvanceTime(60 * time.Minute)
	t.Logf("Email guessing attempts are rate limited.")

	passed = false
	for i := 0; i < 100; i++ {
		resp := client.makeRequest(t, "/user/auth", map[string]string{
			"email":    fmt.Sprintf("nobody%d@doesntexist.com", i),
			"password": "badpassword",
		})

		if resp.StatusCode == 429 {
			t.Logf("    Rate limited after %d attempts", i+1)
			passed = true
			break
		} else if resp.StatusCode != 401 {
			t.Errorf("    Received invalid response %v", resp.StatusCode)
		}
	}

	if !passed {
		t.Errorf("FAIL: Email guessing attempts are not rate-limited.")
	}

	// Wait an hour and start the next test.
	auth.AdvanceTime(60 * time.Minute)
	t.Logf("Forgot password requests are rate limited.")

	passed = false
	for i := 0; i < 10; i++ {
		resp := client.makeRequest(t, "/user/forgotpassword", map[string]string{
			"email": "example@example.com",
		})

		if resp.StatusCode == 429 {
			t.Logf("    Rate limited after %d attempts", i+1)
			passed = true
			break
		} else if resp.StatusCode != 200 {
			t.Errorf("    Received invalid response %v", resp.StatusCode)
		}
	}

	if !passed {
		t.Errorf("FAIL: Email guessing attempts are not rate-limited.")
	}

}

type testClient struct {
	session string
	server  http.Handler
}

func newTestClient(server http.Handler) *testClient {
	return &testClient{server: server}
}

func (tc *testClient) do(t *testing.T, trs ...testRequest) {
	for _, tr := range trs {
		if tr.name != "" {
			t.Logf("%s:", tr.name)
		}
		resp := tc.makeRequest(t, tr.path, tr.params)

		if resp.StatusCode != tr.code {
			t.Errorf("*** Expected status code %v but got %v", tr.code, resp.StatusCode)
			t.Errorf("    Status: %s", resp.Header.Get("status"))
			t.FailNow()
		}

		if tr.status != "" {
			if resp.Header.Get("status") != tr.status {
				t.Errorf("*** Expected status messsage '%s' but got '%s'", tr.status, resp.Header.Get("status"))
			}
		}

		if tr.json != nil {
			decoder := json.NewDecoder(resp.Body)

			data := make(map[string]interface{})
			err := decoder.Decode(&data)
			if err != nil {
				t.Logf("Error decoding JSON")
				panic(err)
			}

			for key, value := range tr.json {
				result := data[key]
				if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", value) {
					t.Errorf("*** Expected '%v'='%v' in json result, but got '%v'", key, value, result)
				}
			}
		}

	}

}

func (tc *testClient) makeRequest(t *testing.T, path string, params map[string]string) *http.Response {
	data := url.Values{}
	for name, value := range params {
		data.Set(name, value)
	}

	t.Logf("    %s", path+"?"+data.Encode())
	req, _ := http.NewRequest("GET", path+"?"+data.Encode(), nil)
	req.RemoteAddr = "10.0.0.1"
	rec := httptest.NewRecorder()

	if tc.session != "" {
		req.Header.Set("Cookie", fmt.Sprintf("session=%s;", tc.session))
	}

	tc.server.ServeHTTP(rec, req)

	resp := rec.Result()

	for _, cookie := range resp.Cookies() {
		tc.session = cookie.Value
	}

	return resp
}
