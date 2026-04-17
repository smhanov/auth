package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/smhanov/auth"
)

func TestCORSAllowsConfiguredOrigin(t *testing.T) {
	called := false
	handler := auth.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), []string{"https://app.example.com"})

	req := httptest.NewRequest(http.MethodGet, "/user/get", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Fatal("expected wrapped handler to be called")
	}
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected allowed origin header to be reflected, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("expected credentials header to be true, got %q", got)
	}
	if got := w.Header().Values("Vary"); len(got) == 0 {
		t.Fatal("expected Vary header to be set")
	}
}

func TestCORSRejectsDisallowedOrigin(t *testing.T) {
	called := false
	handler := auth.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), []string{"https://app.example.com"})

	req := httptest.NewRequest(http.MethodGet, "/user/get", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Fatal("expected disallowed origin request to be blocked before reaching handler")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("expected no allow-origin header for rejected origin, got %q", got)
	}
}

func TestUnsafeCORSAllowsAnyOrigin(t *testing.T) {
	handler := auth.UnsafeCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/user/get", nil)
	req.Header.Set("Origin", "https://anywhere.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://anywhere.example.com" {
		t.Fatalf("expected origin to be reflected, got %q", got)
	}
}

func TestCORSPanicsWithoutAllowedOrigins(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected CORS to panic when no origins are configured")
		}
	}()

	auth.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil)
}
