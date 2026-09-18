package ldap

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig(endpoint string) Config {
	return Config{URL: endpoint, BaseDN: "dc=example,dc=test", BindDN: "cn=reader,dc=example,dc=test", BindPassword: "not-a-real-secret"}
}

func TestConfiguration(t *testing.T) {
	for _, endpoint := range []string{"ldap://example.test", "ldaps://user:pass@example.test", "ldaps://example.test/base", "ldaps://example.test?", "ldaps://example.test#x", "ldaps://example.test:99999"} {
		if _, err := New(testConfig(endpoint)); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	c := testConfig("ldaps://example.test")
	c.BindPassword = ""
	if _, err := New(c); err == nil {
		t.Fatal("anonymous bind accepted")
	}
	c = testConfig("ldaps://example.test")
	c.Timeout = time.Minute
	if _, err := New(c); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
}

func TestEscapedFilter(t *testing.T) {
	filter := userFilter("*)(|(objectClass=*))")
	if strings.Contains(filter, "sAMAccountName=*)") || !strings.Contains(filter, `\2a\29\28`) {
		t.Fatal("unescaped filter input")
	}
}

func TestInputBounds(t *testing.T) {
	for _, field := range []string{"URL", "BaseDN", "BindDN", "BindPassword"} {
		c := testConfig("ldaps://example.test")
		oversized := strings.Repeat("x", 4097)
		switch field {
		case "URL":
			c.URL = oversized
		case "BaseDN":
			c.BaseDN = oversized
		case "BindDN":
			c.BindDN = oversized
		case "BindPassword":
			c.BindPassword = oversized
		}
		if _, err := New(c); err == nil {
			t.Fatal("oversized directory configuration accepted")
		}
	}
	r, err := New(testConfig("ldaps://127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", strings.Repeat(" ", 257) + "alice", string([]byte{0xff}), "alice\x00"} {
		if _, err := r.GetUser(context.Background(), name); err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid username reached network lookup")
		}
	}
}

func TestCancellation(t *testing.T) {
	reader, _ := New(testConfig("ldaps://127.0.0.1:1"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.GetUser(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestRejectUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	reader, _ := New(testConfig(strings.Replace(server.URL, "https://", "ldaps://", 1)))
	if _, err := reader.GetUser(context.Background(), "alice"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestInboundBudget(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = server.Write([]byte("12345")) }()
	bounded := &boundedConn{Conn: client, remaining: 4}
	buffer := make([]byte, 10)
	n, err := bounded.Read(buffer)
	if err != nil || n != 4 {
		t.Fatalf("read %d, %v", n, err)
	}
	if _, err := bounded.Read(buffer); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("response budget not enforced")
	}
}

func TestCancellationDuringLDAPBind(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := testConfig(strings.Replace(server.URL, "https://", "ldaps://", 1))
	c.Roots = roots
	reader, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = reader.GetUser(ctx, "alice")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancellation did not close pending LDAP operation")
	}
}
