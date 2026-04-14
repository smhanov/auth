package auth_test

import (
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

func TestPasswordChangeInvalidatesExistingSessions(t *testing.T) {
	handler := auth.New(auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")), auth.DefaultSettings)

	owner := newTestClient(handler)
	owner.do(t,
		testRequest{
			name: "create user",
			path: "/user/create",
			params: map[string]string{
				"email":    "session-update@example.com",
				"password": "old-password",
			},
			code: 200,
		},
	)

	stolenSession := owner.session
	attacker := newTestClient(handler)
	attacker.session = stolenSession

	owner.do(t,
		testRequest{
			name: "change password",
			path: "/user/update",
			params: map[string]string{
				"password": "new-password",
			},
			code: 200,
		},
	)

	if owner.session == "" || owner.session == stolenSession {
		t.Fatalf("expected password change to issue a fresh session cookie")
	}

	owner.do(t,
		testRequest{
			name: "current request remains signed in with fresh session",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":  "session-update@example.com",
				"userid": 1.0,
			},
		},
	)

	attacker.do(t,
		testRequest{
			name: "stolen session is invalidated",
			path: "/user/get",
			code: 401,
		},
	)

	login := newTestClient(handler)
	login.do(t,
		testRequest{
			name: "old password no longer works",
			path: "/user/auth",
			params: map[string]string{
				"email":    "session-update@example.com",
				"password": "old-password",
			},
			code: 401,
		},
		testRequest{
			name: "new password works",
			path: "/user/auth",
			params: map[string]string{
				"email":    "session-update@example.com",
				"password": "new-password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":  "session-update@example.com",
				"userid": 1.0,
			},
		},
	)
}

func TestPasswordResetInvalidatesExistingSessions(t *testing.T) {
	var passwordToken string
	handler := auth.New(
		auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")),
		auth.Settings{
			SendEmailFn: func(email, token string) {
				passwordToken = token
			},
		},
	)

	owner := newTestClient(handler)
	owner.do(t,
		testRequest{
			name: "create reset user",
			path: "/user/create",
			params: map[string]string{
				"email":    "session-reset@example.com",
				"password": "old-password",
			},
			code: 200,
		},
	)

	stolenSession := owner.session
	attacker := newTestClient(handler)
	attacker.session = stolenSession

	owner.do(t,
		testRequest{
			name: "request reset token",
			path: "/user/forgotpassword",
			params: map[string]string{
				"email": "session-reset@example.com",
			},
			code: 200,
		},
	)

	if passwordToken == "" {
		t.Fatalf("expected password reset token to be issued")
	}

	resetClient := newTestClient(handler)
	resetClient.do(t,
		testRequest{
			name: "reset password",
			path: "/user/resetpassword",
			params: map[string]string{
				"token":    passwordToken,
				"password": "new-password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":  "session-reset@example.com",
				"userid": 1.0,
			},
		},
	)

	if resetClient.session == "" || resetClient.session == stolenSession {
		t.Fatalf("expected password reset to issue a fresh session cookie")
	}

	resetClient.do(t,
		testRequest{
			name: "reset request gets the new session",
			path: "/user/get",
			code: 200,
			json: map[string]interface{}{
				"email":  "session-reset@example.com",
				"userid": 1.0,
			},
		},
	)

	attacker.do(t,
		testRequest{
			name: "stolen session is invalid after reset",
			path: "/user/get",
			code: 401,
		},
	)

	login := newTestClient(handler)
	login.do(t,
		testRequest{
			name: "old password fails after reset",
			path: "/user/auth",
			params: map[string]string{
				"email":    "session-reset@example.com",
				"password": "old-password",
			},
			code: 401,
		},
		testRequest{
			name: "new password works after reset",
			path: "/user/auth",
			params: map[string]string{
				"email":    "session-reset@example.com",
				"password": "new-password",
			},
			code: 200,
			json: map[string]interface{}{
				"email":  "session-reset@example.com",
				"userid": 1.0,
			},
		},
	)
}