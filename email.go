package auth

import (
	"log"
	"net/smtp"
	"net/textproto"
	"strings"

	"github.com/jordan-wright/email"
)

func sendEmail(settings Settings, addr string, url string) {
	e := &email.Email{
		To:      []string{addr},
		From:    settings.EmailFrom,
		Subject: settings.ForgotPasswordSubject,
		Text:    []byte(strings.Replace(settings.ForgotPasswordBody, "${URL}", url, -1)),
		Headers: textproto.MIMEHeader{},
	}

	log.Printf("Sending email using %s:%s", settings.SMTPUser, settings.SMTPPassword)
	err := e.Send(settings.SMTPServer, smtp.PlainAuth("", settings.SMTPUser, settings.SMTPPassword,
		strings.Split(settings.SMTPServer, ":")[0]))
	if err != nil {
		log.Printf("Error sending email:")
		log.Panic(err)
	}
}
