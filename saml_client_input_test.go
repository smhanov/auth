package auth_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/smhanov/auth"
)

// samlAcsResponse wraps raw XML (or raw parameter text) as the value a
// client posts in the SAMLResponse form parameter.
func samlAcsParam(raw string) *string {
	return &raw
}

// assertSamlErrorResponse checks that an assertion-consumer-service error
// response is deliberate: the exact expected status code, the exact stable
// message in both the Status header and the body (so no internal error
// text can leak), and no redirect or cookies.
func assertSamlErrorResponse(t *testing.T, resp *http.Response, wantStatus int, wantMessage string) {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Errorf("expected status code %d, got %d", wantStatus, resp.StatusCode)
	}
	if status := resp.Header.Get("Status"); status != wantMessage {
		t.Errorf("expected Status header %q, got %q", wantMessage, status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("could not read response body: %v", err)
	}
	if string(body) != wantMessage {
		t.Errorf("expected body %q, got %q", wantMessage, string(body))
	}
	if location := resp.Header.Get("Location"); location != "" {
		t.Errorf("expected no Location header on the error response, got %q", location)
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("expected no Set-Cookie headers on the error response, got %v", cookies)
	}
}

// TestSamlAcsMalformedClientResponses verifies that every malformed shape
// of the client-controlled SAMLResponse parameter produces a deliberate
// 400 with a stable message instead of a 500 carrying raw internal error
// text (base64 failures, xml parser errors, "EOF") or a nil-pointer
// panic. The real in-memory database has no registered providers, so
// responses without an issuer (or with an unknown one) must hit the
// existing missing-issuer 400.
func TestSamlAcsMalformedClientResponses(t *testing.T) {
	handler := auth.New(auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")), auth.DefaultSettings)
	client := newTestClient(handler)

	b64 := func(s string) *string { return samlAcsParam(base64.StdEncoding.EncodeToString([]byte(s))) }

	responseWithoutIssuer := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>`
	responseWithUnknownIssuer := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Issuer>https://unknown.example.com/metadata</saml:Issuer></samlp:Response>`

	tests := []struct {
		name         string
		samlResponse *string
		wantMessage  string
	}{
		{
			name:         "missing SAMLResponse parameter",
			samlResponse: nil,
			wantMessage:  "Malformed SAML response",
		},
		{
			name:         "empty SAMLResponse parameter",
			samlResponse: samlAcsParam(""),
			wantMessage:  "Malformed SAML response",
		},
		{
			name:         "invalid base64",
			samlResponse: samlAcsParam("!!! not base64 !!!"),
			wantMessage:  "Malformed SAML response",
		},
		{
			name:         "valid base64 of malformed xml",
			samlResponse: samlAcsParam(base64.StdEncoding.EncodeToString([]byte("<samlp:Resp"))),
			wantMessage:  "Malformed SAML response",
		},
		{
			name:         "valid xml with wrong root element",
			samlResponse: b64("<foo/>"),
			wantMessage:  "Malformed SAML response",
		},
		{
			name:         "response without an issuer element",
			samlResponse: b64(responseWithoutIssuer),
			wantMessage:  "SAML Request is missing Issuer information",
		},
		{
			name:         "response with an unknown issuer",
			samlResponse: b64(responseWithUnknownIssuer),
			wantMessage:  "SAML Request is missing Issuer information",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]string{}
			if tt.samlResponse != nil {
				params["SAMLResponse"] = *tt.samlResponse
			}
			resp := client.makePostRequest(t, "/user/saml/acs", params)
			assertSamlErrorResponse(t, resp, http.StatusBadRequest, tt.wantMessage)
		})
	}
}

// TestSamlAcsRejectedResponse verifies that a well-formed SAML response
// from a known identity provider that fails ParseResponse validation (an
// unsigned response cannot pass) yields a deliberate 401 with a stable
// message, while the validation detail stays in the server log. Before
// the fix this path returned a 500 whose assertion on the error type was
// unchecked.
func TestSamlAcsRejectedResponse(t *testing.T) {
	db := &samlStubDB{
		DB: auth.NewUserDB(sqlx.MustConnect("sqlite3", ":memory:")),
	}
	handler := auth.New(db, auth.DefaultSettings)
	client := newTestClient(handler)

	// The stub resolves any issuer to valid identity provider metadata,
	// so this unsigned response reaches ParseResponse and is rejected
	// there.
	responseXML := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:Issuer>https://idp.example.com/metadata</saml:Issuer></samlp:Response>`

	resp := client.makePostRequest(t, "/user/saml/acs", map[string]string{
		"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(responseXML)),
	})
	assertSamlErrorResponse(t, resp, http.StatusUnauthorized, "Invalid SAML response")
}
