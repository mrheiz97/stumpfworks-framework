package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoverIdentityCompatibleProvider(t *testing.T) {
	key := testKey(t)
	jwks := testJWKS(t, publicKey(key, "current"))
	var server *httptest.Server
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
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configuration, err := Discover(t.Context(), server.URL, testClient, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if configuration.AuthorizationEndpoint != server.URL+"/oauth2/authorize" || configuration.TokenEndpoint != server.URL+"/oauth2/token" || configuration.IntrospectionEndpoint != server.URL+"/oauth2/introspect" {
		t.Fatalf("bad endpoints: %+v", configuration)
	}
	now := time.Now()
	token := signToken(t, key, "current", map[string]any{"iss": server.URL, "sub": "opaque-subject", "aud": testClient, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": "nonce-1"})
	if _, err := configuration.Verifier.VerifyIDToken(token, "nonce-1"); err != nil {
		t.Fatalf("discovered verifier rejected token: %v", err)
	}
}

func TestDiscoverRejectsUntrustedMetadataAndRedirects(t *testing.T) {
	key := testKey(t)
	jwks := testJWKS(t, publicKey(key, "current"))
	var server *httptest.Server
	var mode atomic.Value
	mode.Store("")
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentMode := mode.Load().(string)
		if r.URL.Path == "/oauth2/jwks" {
			if currentMode == "oversized jwks" {
				_, _ = w.Write([]byte(strings.Repeat("x", maxJWKSBytes+1)))
				return
			}
			_, _ = w.Write(jwks)
			return
		}
		if currentMode == "redirect" {
			http.Redirect(w, r, server.URL+"/other", http.StatusFound)
			return
		}
		if currentMode == "oversized metadata" {
			_, _ = w.Write([]byte(strings.Repeat("x", maxMetadataBytes+1)))
			return
		}
		meta := map[string]any{
			"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth2/authorize",
			"token_endpoint": server.URL + "/oauth2/token", "jwks_uri": server.URL + "/oauth2/jwks",
			"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		switch currentMode {
		case "wrong issuer":
			meta["issuer"] = "https://evil.example.test"
		case "foreign JWKS":
			meta["jwks_uri"] = "https://evil.example.test/jwks"
		case "http token":
			meta["token_endpoint"] = "http://identity.example.test/token"
		case "foreign introspection":
			meta["introspection_endpoint"] = "https://evil.example.test/introspect"
		case "empty-query token":
			meta["token_endpoint"] = server.URL + "/oauth2/token?"
		case "missing PKCE":
			meta["code_challenge_methods_supported"] = []string{"plain"}
		case "wrong algorithm":
			meta["id_token_signing_alg_values_supported"] = []string{"HS256"}
		}
		_ = json.NewEncoder(w).Encode(meta)
	}))
	defer server.Close()
	for _, testMode := range []string{"wrong issuer", "foreign JWKS", "http token", "foreign introspection", "empty-query token", "missing PKCE", "wrong algorithm", "redirect", "oversized metadata", "oversized jwks"} {
		t.Run(testMode, func(t *testing.T) {
			mode.Store(testMode)
			if _, err := Discover(t.Context(), server.URL, testClient, server.Client()); err == nil {
				t.Fatal("accepted untrusted discovery result")
			}
		})
	}
}

func TestDiscoverRejectsInvalidContextAndIssuer(t *testing.T) {
	if _, err := Discover(nil, testIssuer, testClient, nil); err == nil {
		t.Fatal("accepted nil context")
	}
	if _, err := Discover(context.Background(), "http://identity.example.test", testClient, nil); err == nil {
		t.Fatal("accepted HTTP issuer")
	}
	if _, err := Discover(context.Background(), "https://identity.example.test?", testClient, nil); err == nil {
		t.Fatal("accepted issuer with an empty query marker")
	}
}
