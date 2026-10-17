package oidc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfidentialCodeFlow(t *testing.T) {
	key := testKey(t)
	jwks := testJWKS(t, publicKey(key, "current"))
	var server *httptest.Server
	var expectedChallenge atomic.Value
	var expectedNonce atomic.Value
	var tokenCalls atomic.Int32
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/oauth2/authorize",
				"token_endpoint": server.URL + "/oauth2/token", "jwks_uri": server.URL + "/oauth2/jwks",
				"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/oauth2/jwks":
			_, _ = w.Write(jwks)
		case "/oauth2/token":
			tokenCalls.Add(1)
			id, secret, ok := r.BasicAuth()
			if !ok || id != testClient || secret != "test-client-secret" || r.ParseForm() != nil || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "one-use-code" || r.Form.Get("redirect_uri") != "https://access.example.test/callback" {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != expectedChallenge.Load().(string) {
				http.Error(w, "invalid PKCE", http.StatusBadRequest)
				return
			}
			now := time.Now()
			claims := map[string]any{"iss": server.URL, "sub": "opaque-subject", "aud": testClient, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": expectedNonce.Load().(string)}
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signToken(t, key, "current", claims), "access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 300})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	configuration, err := Discover(t.Context(), server.URL, testClient, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewLoginClient(configuration, testClient, "test-client-secret", "https://access.example.test/callback", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	address, transaction, err := client.Begin()
	if err != nil {
		t.Fatal(err)
	}
	authorizeURL, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeURL.Query()
	if authorizeURL.Path != "/oauth2/authorize" || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("scope") != "openid" || query.Get("state") != transaction.State() || query.Get("nonce") == "" {
		t.Fatalf("invalid authorization URL: %s", address)
	}
	expectedChallenge.Store(query.Get("code_challenge"))
	expectedNonce.Store(query.Get("nonce"))
	codec, err := NewTransactionCodec(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := codec.Seal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err = codec.Open(client, sealed)
	if err != nil {
		t.Fatal(err)
	}
	callback := url.Values{"state": {transaction.State()}, "code": {"one-use-code"}}
	refreshedClient, err := NewLoginClient(configuration, testClient, "test-client-secret", "https://access.example.test/callback", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshedClient.Complete(t.Context(), transaction, callback); !errors.Is(err, ErrLoginFailed) || tokenCalls.Load() != 0 {
		t.Fatal("different client snapshot consumed transaction")
	}
	client.configuration.validUntil = time.Now().Add(-time.Second)
	if _, _, err := client.Begin(); !errors.Is(err, ErrStaleConfiguration) {
		t.Fatal("stale snapshot began a new login")
	}
	result, err := transaction.CompleteWithToken(t.Context(), callback)
	if err != nil || result.Identity != (Identity{Issuer: server.URL, Subject: "opaque-subject"}) || result.AccessToken != "opaque-access-token" || result.ExpiresIn != 5*time.Minute {
		t.Fatalf("unexpected login result: %+v, %v", result, err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls: %d", tokenCalls.Load())
	}
	if _, err := transaction.Complete(t.Context(), callback); !errors.Is(err, ErrLoginFailed) || tokenCalls.Load() != 1 {
		t.Fatal("transaction replay succeeded")
	}
}

func TestCallbackFailsClosedBeforeTokenExchange(t *testing.T) {
	key := testKey(t)
	verifier, err := NewVerifier(testIssuer, testClient, testJWKS(t, publicKey(key, "current")))
	if err != nil {
		t.Fatal(err)
	}
	configuration := &Configuration{AuthorizationEndpoint: testIssuer + "/authorize", TokenEndpoint: testIssuer + "/token", Verifier: verifier}
	client, err := NewLoginClient(configuration, testClient, "secret", "https://access.example.test/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	configuration.AuthorizationEndpoint = "https://evil.example.test/authorize"
	address, _, err := client.Begin()
	if err != nil || !strings.HasPrefix(address, testIssuer) {
		t.Fatal("client followed mutated configuration")
	}
	for name, callback := range map[string]url.Values{
		"wrong state":    {"state": {"wrong"}, "code": {"code"}},
		"missing code":   {"state": {"placeholder"}},
		"duplicate code": {"state": {"placeholder"}, "code": {"a", "b"}},
		"provider error": {"state": {"placeholder"}, "code": {"code"}, "error": {"access_denied"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, transaction, err := client.Begin()
			if err != nil {
				t.Fatal(err)
			}
			if callback.Get("state") == "placeholder" {
				callback.Set("state", transaction.State())
			}
			if _, err := client.Complete(t.Context(), transaction, callback); !errors.Is(err, ErrLoginFailed) {
				t.Fatalf("accepted invalid callback: %v", err)
			}
			if _, err := client.Complete(t.Context(), transaction, callback); !errors.Is(err, ErrLoginFailed) {
				t.Fatal("failed callback was reusable")
			}
		})
	}
	_, expired, err := client.Begin()
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return expired.createdAt.Add(transactionLifetime + time.Second) }
	if _, err := client.Complete(t.Context(), expired, url.Values{"state": {expired.State()}, "code": {"code"}}); !errors.Is(err, ErrLoginFailed) {
		t.Fatal("accepted expired transaction")
	}
}

func TestLoginClientRejectsEmptyQueryMarkerOnRedirect(t *testing.T) {
	client := testLoginClient(t)
	if _, err := NewLoginClient(client.configuration, testClient, "secret", "https://access.example.test/callback?", nil); err == nil {
		t.Fatal("accepted redirect URI with an empty query marker")
	}
}

func TestNilTransactionCannotComplete(t *testing.T) {
	if _, err := (*Transaction)(nil).Complete(t.Context(), url.Values{}); !errors.Is(err, ErrLoginFailed) {
		t.Fatal("nil transaction accepted")
	}
}
