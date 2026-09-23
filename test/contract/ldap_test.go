package contract

import (
	"context"
	"crypto/x509"
	"os"
	"testing"
	"time"

	directoryldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
)

// TestLDAPReadOnly requires deliberate opt-in and injected service credentials.
// It never prints endpoint, credentials or returned directory attributes.
func TestLDAPReadOnly(t *testing.T) {
	if os.Getenv("SWF_TEST_LDAP_ENABLED") != "1" {
		t.Skip("read-only LDAP contract test not enabled")
	}
	for _, name := range []string{"SWF_TEST_LDAP_URL", "SWF_TEST_LDAP_BASE_DN", "SWF_TEST_LDAP_BIND_DN", "SWF_TEST_LDAP_BIND_PASSWORD", "SWF_TEST_LDAP_USERNAME"} {
		if os.Getenv(name) == "" {
			t.Fatalf("required test setting missing: %s", name)
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal("system CA pool unavailable")
	}
	if path := os.Getenv("SWF_TEST_LDAP_CA_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			t.Fatal("test directory CA could not be loaded")
		}
	}
	reader, err := directoryldap.New(directoryldap.Config{
		URL: os.Getenv("SWF_TEST_LDAP_URL"), BaseDN: os.Getenv("SWF_TEST_LDAP_BASE_DN"),
		BindDN: os.Getenv("SWF_TEST_LDAP_BIND_DN"), BindPassword: os.Getenv("SWF_TEST_LDAP_BIND_PASSWORD"),
		Roots: roots, Timeout: 8 * time.Second,
	})
	if err != nil {
		t.Fatal("test directory configuration invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, err := reader.GetUser(ctx, os.Getenv("SWF_TEST_LDAP_USERNAME"))
	if err != nil {
		t.Fatal("read-only directory lookup failed")
	}
	if user == nil || user.Username == "" || user.DN == "" {
		t.Fatal("directory result missing required attributes")
	}
}
