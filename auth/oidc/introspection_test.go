package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenIntrospection(t *testing.T) {
	key := testKey(t)
	jwks := testJWKS(t, publicKey(key, "current"))
	var server *httptest.Server
	var mode atomic.Value
	mode.Store("active")
	now := time.Now().Truncate(time.Second)
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth2/authorize",
				"token_endpoint": server.URL + "/oauth2/token", "introspection_endpoint": server.URL + "/oauth2/introspect", "jwks_uri": server.URL + "/oauth2/jwks",
				"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/oauth2/jwks":
			_, _ = w.Write(jwks)
		case "/oauth2/introspect":
			id, secret, ok := r.BasicAuth()
			if !ok || id != testClient || secret != "test-client-secret" || r.ParseForm() != nil || r.Form.Get("token") != "opaque-token" || r.Form.Get("token_type_hint") != "access_token" {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			switch mode.Load().(string) {
			case "inactive":
				_ = json.NewEncoder(w).Encode(map[string]bool{"active": false})
			case "wrong client":
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "client_id": "other", "sub": "opaque-subject", "sid": "session-id", "token_type": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
			case "expired":
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "client_id": testClient, "sub": "opaque-subject", "sid": "session-id", "token_type": "Bearer", "iat": now.Add(-10 * time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix()})
			case "oversized":
				_, _ = w.Write([]byte(strings.Repeat("x", maxIntrospectionResponseBytes+1)))
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "client_id": testClient, "sub": "opaque-subject", "sid": "session-id", "scope": "openid", "token_type": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configuration, err := Discover(t.Context(), server.URL, testClient, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	introspector, err := NewTokenIntrospector(configuration, testClient, "test-client-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	introspector.now = func() time.Time { return now }
	status, err := introspector.Introspect(t.Context(), "opaque-token")
	if err != nil || !status.Active || status.Subject != "opaque-subject" || status.SessionID != "session-id" || status.Scope != "openid" {
		t.Fatalf("unexpected active status: %+v, %v", status, err)
	}
	mode.Store("inactive")
	status, err = introspector.Introspect(t.Context(), "opaque-token")
	if err != nil || status.Active || status.Subject != "" {
		t.Fatalf("unexpected inactive status: %+v, %v", status, err)
	}
	for _, failure := range []string{"wrong client", "expired", "oversized"} {
		t.Run(failure, func(t *testing.T) {
			mode.Store(failure)
			if _, err := introspector.Introspect(t.Context(), "opaque-token"); !errors.Is(err, ErrIntrospectionFailed) {
				t.Fatalf("accepted %s response: %v", failure, err)
			}
		})
	}
}

func TestTokenIntrospectorRequiresVettedEndpoint(t *testing.T) {
	verifier, err := NewVerifier(testIssuer, testClient, testJWKS(t, publicKey(testKey(t), "current")))
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"", "http://identity.example.test/introspect", "https://evil.example.test/introspect"} {
		configuration := &Configuration{IntrospectionEndpoint: endpoint, Verifier: verifier}
		if _, err := NewTokenIntrospector(configuration, testClient, "secret", nil); err == nil {
			t.Fatalf("accepted untrusted introspection endpoint %q", endpoint)
		}
	}
}
