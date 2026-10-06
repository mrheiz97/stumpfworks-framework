package contract

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/mrheiz97/stumpfworks-framework/auth/oidc"
)

// TestIdentityDiscovery is opt-in. It checks the real provider's public OIDC
// contract without exchanging an authorization code or creating a session.
func TestIdentityDiscovery(t *testing.T) {
	issuer := os.Getenv("SWF_TEST_IDENTITY_ISSUER")
	clientID := os.Getenv("SWF_TEST_IDENTITY_CLIENT_ID")
	if issuer == "" && clientID == "" {
		t.Skip("set SWF_TEST_IDENTITY_ISSUER and SWF_TEST_IDENTITY_CLIENT_ID for the live contract test")
	}
	if issuer == "" || clientID == "" {
		t.Fatal("both SWF_TEST_IDENTITY_ISSUER and SWF_TEST_IDENTITY_CLIENT_ID are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if path := os.Getenv("SWF_TEST_IDENTITY_CA_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			t.Fatal(err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("CA file contains no certificates")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	configuration, err := oidc.Discover(context.Background(), issuer, clientID, client)
	if err != nil {
		t.Fatalf("Identity discovery/JWKS contract failed: %v", err)
	}
	if configuration.AuthorizationEndpoint == "" || configuration.TokenEndpoint == "" || configuration.Verifier == nil {
		t.Fatal("Identity returned incomplete OIDC configuration")
	}
	// A login start needs neither a real secret nor a browser visit. The actual
	// code exchange and account/session checks remain a separate acceptance test.
	login, err := oidc.NewLoginClient(configuration, clientID, "contract-test-placeholder", "https://access.example.test/api/v1/auth/oidc/callback", client)
	if err != nil {
		t.Fatalf("Identity configuration cannot initialize login client: %v", err)
	}
	address, transaction, err := login.Begin()
	if err != nil {
		t.Fatalf("login start failed: %v", err)
	}
	parsed, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if transaction.State() == "" || query.Get("state") != transaction.State() || query.Get("code_challenge_method") != "S256" || query.Get("nonce") == "" {
		t.Fatal("login start omitted state, PKCE S256, or nonce")
	}
}
