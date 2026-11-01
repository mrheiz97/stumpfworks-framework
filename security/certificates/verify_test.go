package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func fixture(t *testing.T) (*x509.Certificate, *x509.Certificate, IssuedOptions) {
	t.Helper()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("urn:example:device:one")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}, DNSNames: []string{"device.example.test"}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, ca, IssuedOptions{PeerOptions: PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth}, Roots: roots, ExpectedPublicKeyDER: public, PinnedRoot: ca}
}
func TestVerifiedPeerAndIssued(t *testing.T) {
	leaf, ca, o := fixture(t)
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	for _, now := range []time.Time{leaf.NotBefore, o.Now, leaf.NotAfter} {
		o.Now = now
		m, err := VerifiedPeer(state, o.PeerOptions)
		if err != nil || m.Serial != "2a" || len(m.FingerprintSHA256) != 64 || m.URIs[0] != "urn:example:device:one" {
			t.Fatal("peer verification failed", err)
		}
		if _, err = VerifyIssued(leaf, o); err != nil {
			t.Fatal("issued verification failed", err)
		}
	}
	m, _ := VerifyIssued(leaf, o)
	m.URIs[0] = "changed"
	again, _ := VerifyIssued(leaf, o)
	if again.URIs[0] != "urn:example:device:one" {
		t.Fatal("metadata aliases another result")
	}
	// Parsed mutable fields cannot override signed DER.
	altered := *leaf
	altered.DNSNames = []string{"attacker.example.test"}
	server := o
	server.Usage = x509.ExtKeyUsageServerAuth
	server.DNSName = "attacker.example.test"
	if _, err := VerifyIssued(&altered, server); err == nil {
		t.Fatal("unsigned field mutation trusted")
	}
	server.DNSName = "device.example.test"
	if _, err := VerifyIssued(leaf, server); err != nil {
		t.Fatal(err)
	}
}
func TestIssuedRejectsInvalidContexts(t *testing.T) {
	leaf, _, base := fixture(t)
	_, other, otherOptions := fixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*IssuedOptions)
		want   error
	}{
		{"missing roots", func(o *IssuedOptions) { o.Roots = nil }, ErrInvalidInput},
		{"empty roots", func(o *IssuedOptions) { o.Roots = x509.NewCertPool() }, ErrCertificateRejected},
		{"wrong root", func(o *IssuedOptions) { o.Roots = otherOptions.Roots; o.PinnedRoot = nil }, ErrCertificateRejected},
		{"wrong pin", func(o *IssuedOptions) { o.PinnedRoot = other }, ErrPinMismatch},
		{"wrong key", func(o *IssuedOptions) { o.ExpectedPublicKeyDER = otherOptions.ExpectedPublicKeyDER }, ErrKeyMismatch},
		{"missing key", func(o *IssuedOptions) { o.ExpectedPublicKeyDER = nil }, ErrInvalidInput},
		{"private key rejected", func(o *IssuedOptions) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			o.ExpectedPublicKeyDER, _ = x509.MarshalPKCS8PrivateKey(key)
		}, ErrInvalidInput},
		{"PEM is not DER", func(o *IssuedOptions) {
			o.ExpectedPublicKeyDER = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: o.ExpectedPublicKeyDER})
		}, ErrInvalidInput},
		{"zero clock", func(o *IssuedOptions) { o.Now = time.Time{} }, ErrInvalidInput},
		{"implicit any usage", func(o *IssuedOptions) { o.Usage = x509.ExtKeyUsageAny }, ErrInvalidInput},
		{"unsupported usage", func(o *IssuedOptions) { o.Usage = x509.ExtKeyUsageCodeSigning }, ErrInvalidInput},
		{"expired", func(o *IssuedOptions) { o.Now = leaf.NotAfter.Add(time.Nanosecond) }, ErrCertificateRejected},
		{"not valid yet", func(o *IssuedOptions) { o.Now = leaf.NotBefore.Add(-time.Nanosecond) }, ErrCertificateRejected},
		{"server requires name", func(o *IssuedOptions) { o.Usage = x509.ExtKeyUsageServerAuth }, ErrInvalidInput},
		{"wrong hostname", func(o *IssuedOptions) { o.Usage = x509.ExtKeyUsageServerAuth; o.DNSName = "other.example.test" }, ErrCertificateRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mutate(&o)
			m, err := VerifyIssued(leaf, o)
			if !errors.Is(err, tc.want) || m.Serial != "" {
				t.Fatal("unexpected rejection", err)
			}
		})
	}
	if _, err := VerifyIssued(nil, base); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil leaf accepted")
	}
}
func TestPeerRequiresMatchingTLSEvidence(t *testing.T) {
	leaf, _, o := fixture(t)
	other, _, _ := fixture(t)
	for _, state := range []*tls.ConnectionState{nil, {}, {PeerCertificates: []*x509.Certificate{nil}}, {PeerCertificates: []*x509.Certificate{leaf}}, {PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{nil}}}, {PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{other}}}} {
		if _, err := VerifiedPeer(state, o.PeerOptions); !errors.Is(err, ErrUnverifiedPeer) {
			t.Fatal("unverified evidence accepted", err)
		}
	}
}
