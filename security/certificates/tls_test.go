package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func authority(t *testing.T, now time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if parent == nil {
		parent = c
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, c, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}
func leafPair(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("urn:another:service:certificate")
	c := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"device.example.test"}, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func TestRealMutualTLSVerification(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	ca, key := authority(t, now, nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, err := VerifiedPeer(r.TLS, PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth})
		if err != nil || len(m.URIs) != 1 || m.URIs[0] != "urn:another:service:certificate" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(204)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Time: func() time.Time { return now }, Certificates: []tls.Certificate{leafPair(t, now, ca, key, x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	other, otherKey := authority(t, now, nil, nil)
	for _, tc := range []struct {
		name        string
		certificate *tls.Certificate
		ok          bool
	}{
		{name: "valid", certificate: pairPointer(leafPair(t, now, ca, key, x509.ExtKeyUsageClientAuth)), ok: true},
		{name: "missing"},
		{name: "wrong CA", certificate: pairPointer(leafPair(t, now, other, otherKey, x509.ExtKeyUsageClientAuth))},
		{name: "wrong EKU", certificate: pairPointer(leafPair(t, now, ca, key, x509.ExtKeyUsageServerAuth))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "device.example.test", Time: func() time.Time { return now }}
			if tc.certificate != nil {
				cfg.Certificates = []tls.Certificate{*tc.certificate}
			}
			tr := &http.Transport{TLSClientConfig: cfg}
			defer tr.CloseIdleConnections()
			hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			r, err := hc.Get(server.URL)
			if !tc.ok {
				if err == nil {
					r.Body.Close()
					t.Fatal("invalid mTLS credential accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			if r.StatusCode != 204 {
				t.Fatal(r.StatusCode)
			}
		})
	}
}
func pairPointer(c tls.Certificate) *tls.Certificate { return &c }

func TestIntermediateChainAndRootPin(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	root, key := authority(t, now, nil, nil)
	intermediate, intermediateKey := authority(t, now, root, key)
	pair := leafPair(t, now, intermediate, intermediateKey, x509.ExtKeyUsageClientAuth)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	o := IssuedOptions{PeerOptions: PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth}, Roots: roots, Intermediates: intermediates, ExpectedPublicKeyDER: public, PinnedRoot: root}
	if _, err = VerifyIssued(leaf, o); err != nil {
		t.Fatal(err)
	}
	o.PinnedRoot = intermediate
	if _, err = VerifyIssued(leaf, o); err != ErrPinMismatch {
		t.Fatal("intermediate treated as verified root", err)
	}
	o.PinnedRoot = root
	o.Intermediates = nil
	if _, err = VerifyIssued(leaf, o); err == nil {
		t.Fatal("missing chain fetched or inferred")
	}
}
