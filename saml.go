package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"

	"encoding/pem"
	"encoding/xml"
	"errors"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

func (a *Handler) initSaml(db DB) {
	// check if we support V2
	tx := db.Begin(a.settings.DefaultContext)
	defer tx.Commit()

	privatekey := tx.GetValue("privatekey")
	certificate := tx.GetValue("certificate")

	if privatekey == "" || certificate == "" {
		log.Printf("No privatekey/certificate in database. Generating a pair")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Panic(err)
		}

		var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(key)
		privateKeyBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}

		var buffer bytes.Buffer
		err = pem.Encode(&buffer, privateKeyBlock)
		if err != nil {
			log.Panic(err)
		}

		privatekey = buffer.String()
		//log.Printf("Encoded as %s", privatekey)
		tx.SetValue("privatekey", privatekey)

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
			},
			NotBefore: now(),
			NotAfter:  now().Add(time.Hour * 24 * 365 * 25),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}
		buffer.Reset()
		pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		certificate = buffer.String()
		//log.Printf("Encoded as %s", certificate)
		tx.SetValue("certificate", certificate)

	}

	privateKey, err := parseRsaPrivateKeyFromPemStr(privatekey)
	if err != nil {
		log.Panic(err)
	}

	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		log.Panicf("Could not parse certificate block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Panic(err)

	}

	a.privateKey = privateKey
	a.certificate = cert

}

func (a *Handler) newSamlSP(req *http.Request, metadataXML string) *samlsp.Middleware {
	var ed *saml.EntityDescriptor
	var err error

	url := *req.URL

	if req.Host != "" {
		url.Host = req.Host
	}

	forwarded := req.Header.Get("X-Forwarded-Host")
	if forwarded != "" {
		url.Host = forwarded
	}

	url.Scheme = "http"
	url.Path = "/user/"
	url.RawQuery = ""

	if IsRequestSecure(req) {
		url.Scheme = "https"
	}

	if metadataXML != "" {
		ed, err = samlsp.ParseMetadata([]byte(metadataXML))
		if err != nil {
			panic(err) // TODO handle error
		}
	}

	m, err := samlsp.New(samlsp.Options{
		URL:               url,
		Key:               a.privateKey,
		Certificate:       a.certificate,
		IDPMetadata:       ed,
		AllowIDPInitiated: true,
	})

	if err != nil {
		log.Panic(err)
	}

	return m
}

func (a *Handler) handleSaml(tx Tx, w http.ResponseWriter, req *http.Request, email, metadataXML string) {
	sp := a.newSamlSP(req, metadataXML)

	returnTo := req.Header.Get("Referer")
	if returnTo == "" {
		returnTo = "/"
	}
	// store the referrer as a cookie in the return-to url
	http.SetCookie(w, &http.Cookie{
		Name:     "saml_return_to",
		Value:    returnTo,
		Expires:  now().Add(24 * time.Hour),
		Path:     "/",
		Secure:   IsRequestSecure(req),
		HttpOnly: true,
	})
	sp.HandleStartAuthFlow(w, req)
}

func parseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (a *Handler) handleSamlMetadata(w http.ResponseWriter, req *http.Request) {
	m := a.newSamlSP(req, "")
	buf, _ := xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", "attachment; filename=\"service-provider-metadata.xml\"")
	w.Write(buf)
}

/*func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "  ")
	return string(s)
}*/

func (a *Handler) handleSamlACS(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	tx := a.db.Begin(r.Context())
	defer tx.Commit()

	issuer := getIssuer(r)
	xml := tx.GetSamlIdentityProviderByID(issuer)
	if xml == "" {
		HTTPPanic(400, "SAML Request is missing Issuer information")
	}

	m := a.newSamlSP(r, xml)

	possibleRequestIDs := []string{}
	if m.ServiceProvider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := m.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := m.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		error2 := err.(*saml.InvalidResponseError)
		log.Printf("Error2: %v", error2.PrivateErr)
		log.Printf("Response: %v", error2.Response)
		log.Panic(err)
	}

	//log.Printf("Assertion: %v", prettyPrint(assertion))
	var email string
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			for _, value := range attr.Values {
				if !isEmail(value.Value) {
					continue
				}

				// check if it matches an email address.
				if attr.FriendlyName == "mail" ||
					attr.Name == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" {
					email = value.Value
				}
			}
		}
	}

	if isEmail(assertion.Subject.NameID.Value) {
		email = assertion.Subject.NameID.Value
	}

	if email == "" {
		log.Printf("Cannot find email in SAML response")
		HTTPPanic(400, "Cannot find email in SAML response")
	}

	userid := tx.GetUserByEmail(email)

	created := false
	if userid == 0 {
		log.Printf("Create saml user %s", email)
		userid = tx.CreatePasswordUser(email, "")
		created = true
	} else {
		log.Printf("Sign in saml user %s", email)
	}

	returnTo := "/"
	if cookie, err := r.Cookie("saml_return_to"); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     "saml_return_to",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
			Secure:   IsRequestSecure(r),
		})
		returnTo = cookie.Value
	}
	SignInUser(tx, w, userid, created, IsRequestSecure(r))
	http.Redirect(w, r, returnTo, http.StatusSeeOther) // code 303 changes redirect to a GET request.
}

func isEmail(input string) bool {
	at := strings.Index(input, "@")
	dot := strings.LastIndex(input, ".")
	return at > 0 && dot > at
}

// GetSamlID returns the entity ID  contained within the XML for the
// given identity provider.
func GetSamlID(xml string) string {
	descriptor, err := samlsp.ParseMetadata([]byte(xml))
	if err != nil {
		log.Panic(err)
	}

	return descriptor.EntityID
}

func getIssuer(req *http.Request) string {
	decodedResponseXML, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))

	if err != nil {
		log.Panic(err)
	}

	resp := saml.Response{}
	if err = xml.Unmarshal([]byte(decodedResponseXML), &resp); err != nil {
		log.Panic(err)
	}

	return resp.Issuer.Value
}
