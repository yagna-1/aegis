package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yagna-1/aegis/internal/audit"
	"github.com/yagna-1/aegis/internal/config"
)

func TestProxyRejectsCallerAuthHeaders(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	log, err := audit.New("")
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	cfg := &config.Config{
		Allowlist: []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{
			"127.0.0.1": {
				Header:   "Authorization",
				Template: "Bearer ${MY_TOKEN}",
			},
		},
	}
	srv := New(cfg, log)

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("X-Aegis-Target", upstream.URL+"/repos")
	req.Header.Set("Authorization", "Bearer caller-supplied")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
	if upstreamCalled {
		t.Fatal("upstream should not be called when auth header is caller-supplied")
	}
}

func TestProxyFailsClosedOnMissingCredential(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	log, err := audit.New("")
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	cfg := &config.Config{
		Allowlist: []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{
			"127.0.0.1": {
				Header:   "Authorization",
				Template: "Bearer ${MISSING_TOKEN}",
			},
		},
	}
	srv := New(cfg, log)

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("X-Aegis-Target", upstream.URL+"/repos")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, rr.Code)
	}
	if upstreamCalled {
		t.Fatal("upstream should not be called when credential resolution fails")
	}
}

func TestProxyInjectsCredentialWhenPresent(t *testing.T) {
	t.Setenv("MY_TOKEN", "real-token")

	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	log, err := audit.New("")
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}

	cfg := &config.Config{
		Allowlist: []string{"127.0.0.1"},
		Credentials: map[string]config.Credential{
			"127.0.0.1": {
				Header:   "Authorization",
				Template: "Bearer ${MY_TOKEN}",
			},
		},
	}
	srv := New(cfg, log)

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("X-Aegis-Target", upstream.URL+"/repos")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if gotAuth != "Bearer real-token" {
		t.Fatalf("unexpected Authorization header: %q", gotAuth)
	}
}

