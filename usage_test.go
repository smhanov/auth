package auth_test

import (
	"log"
	"net/http"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

func Example() {
	// configure how to send password reset emails

	settings := auth.DefaultSettings
	settings.SMTPServer = "smtp.gmail.com:587"
	settings.SMTPUser = "support@awesomepeaches.com"
	settings.SMTPPassword = "awernmx32hdkssk2mssxx" // app password from google
	settings.ForgotPasswordSubject = "Password reset from awesomepeaches.com"
	settings.ForgotPasswordBody = "Please go to this url to reset your password:\n\n   ${URL}"
	settings.EmailFrom = "support@awesomepeaches.com"

	db, err := sqlx.Open("sqlite3", "mydatabase.db")
	if err != nil {
		log.Panic(err)
	}

	http.Handle("/user/", auth.New(auth.NewUserDB(db), settings))

	log.Fatal(http.ListenAndServe(":8080", nil))
}
