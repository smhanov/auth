package auth_test

import (
	"strings"
	"testing"

	"github.com/smhanov/auth"
)

// TestGetSamlIDValidMetadata verifies that GetSamlID extracts the
// entity ID from valid identity provider metadata, for use as the
// registration id with AddSamlIdentityProviderMetadata.
func TestGetSamlIDValidMetadata(t *testing.T) {
	// testIDPMetadata is the shared fixture from tx_discipline_test.go.
	got := auth.GetSamlID(testIDPMetadata)
	if got != "https://idp.example.com/metadata" {
		t.Errorf("expected entity ID %q, got %q",
			"https://idp.example.com/metadata", got)
	}
}

// TestGetSamlIDInvalidMetadataPanics verifies the documented contract
// for unparseable metadata: GetSamlID panics with an error value (not a
// log.Panic string) whose message starts with a stable prefix and
// carries the underlying cause, so setup code that recovers can inspect
// it and developers can see why their metadata was rejected.
func TestGetSamlIDInvalidMetadataPanics(t *testing.T) {
	tests := []struct {
		name     string
		metadata string
	}{
		{
			name:     "empty string",
			metadata: "",
		},
		{
			name:     "not xml",
			metadata: "this is not xml",
		},
		{
			name:     "wrong root element",
			metadata: `<foo/>`,
		},
		{
			name: "entities descriptor without an idp",
			metadata: `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
				`</EntitiesDescriptor>`,
		},
	}

	const prefix = "auth: cannot parse SAML identity provider metadata: "

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				thing := recover()
				if thing == nil {
					t.Fatalf("expected a panic for metadata %q", test.metadata)
				}
				err, ok := thing.(error)
				if !ok {
					t.Fatalf("expected the panic value to be an error, got %T: %v",
						thing, thing)
				}
				message := err.Error()
				if !strings.HasPrefix(message, prefix) {
					t.Errorf("expected message to start with %q, got %q",
						prefix, message)
				}
				if cause := strings.TrimPrefix(message, prefix); cause == "" {
					t.Errorf("expected the message to carry the underlying cause after the prefix, got %q",
						message)
				}
			}()

			auth.GetSamlID(test.metadata)
		})
	}
}
