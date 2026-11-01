package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
)

func TestVerificationInputBounds(t *testing.T) {
	leaf, _, o := fixture(t)
	oversized := &x509.Certificate{Raw: make([]byte, maxCertificateBytes+1)}
	for _, c := range []*x509.Certificate{nil, {}, oversized, {Raw: []byte("invalid certificate DER")}} {
		if _, err := VerifyIssued(c, o); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid certificate input accepted", err)
		}
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, VerifiedChains: [][]*x509.Certificate{{c}}}
		if _, err := VerifiedPeer(state, o.PeerOptions); err == nil {
			t.Fatal("invalid peer input accepted")
		}
	}
	o.ExpectedPublicKeyDER = make([]byte, maxCertificateBytes+1)
	if _, err := VerifyIssued(leaf, o); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("oversized public key accepted", err)
	}
	if _, err := metadata(&x509.Certificate{DNSNames: make([]string, maxIdentities+1)}); !errors.Is(err, ErrCertificateRejected) {
		t.Fatal("unbounded SAN metadata accepted", err)
	}
}
