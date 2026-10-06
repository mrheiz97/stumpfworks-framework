package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func protocolFixture(t *testing.T, count int, referral bool) (*Reader, func()) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		reply := func(id interface{}, op *ber.Packet) {
			message := ber.NewSequence("")
			message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			message.AppendChild(op)
			_, _ = conn.Write(message.Bytes())
		}
		result := func(tag ber.Tag) *ber.Packet {
			p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
			p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
			return p
		}
		reply(request.Children[0].Value, result(1))
		request, err = ber.ReadPacket(conn)
		if err != nil {
			return
		}
		id := request.Children[0].Value
		if referral {
			p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 19, nil, "")
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "ldaps://untrusted.test", ""))
			reply(id, p)
		}
		for i := 0; i < count; i++ {
			p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=alice,dc=example,dc=test", ""))
			attrs := ber.NewSequence("")
			attr := ber.NewSequence("")
			attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "sAMAccountName", ""))
			values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "alice", ""))
			attr.AppendChild(values)
			attrs.AppendChild(attr)
			p.AppendChild(attrs)
			reply(id, p)
		}
		reply(id, result(5))
	}()
	c := testConfig("ldaps://" + listener.Addr().String())
	c.Roots = roots
	reader, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return reader, func() { _ = listener.Close(); <-done }
}

func TestLDAPProtocolResults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		referral bool
		want     error
	}{{"one", 1, false, nil}, {"missing", 0, false, ErrNotFound}, {"duplicate", 2, false, ErrAmbiguous}, {"referral", 1, true, ErrUnavailable}} {
		t.Run(tc.name, func(t *testing.T) {
			reader, closeFixture := protocolFixture(t, tc.count, tc.referral)
			defer closeFixture()
			user, err := reader.GetUser(context.Background(), "alice")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if tc.want == nil && (user.Username != "alice" || user.DisplayName != "alice") {
				t.Fatal("incorrect user projection")
			}
		})
	}
}
