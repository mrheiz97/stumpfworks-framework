package certificates_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/mrheiz97/stumpfworks-framework/internal/testutil/certificatecontract"
	"github.com/mrheiz97/stumpfworks-framework/security/certificates"
)

const contractURI = "urn:example:device:contract-device"

// These are test-only consumer adapters. Namespace, SAN shape, expiry metadata
// and CA bootstrap decisions deliberately do not enter the framework runtime.
func strictDeviceProfile(m certificates.Metadata) bool {
	return len(m.URIs) == 1 && m.URIs[0] == contractURI && len(m.DNSNames) == 0 && len(m.EmailAddresses) == 0 && len(m.IPAddresses) == 0
}

func TestPreparedPeerConsumerContract(t *testing.T) {
	certificatecontract.RunPeer(t, func(s *tls.ConnectionState, now time.Time) (certificatecontract.Peer, error) {
		if s != nil && len(s.PeerCertificates) > 0 && s.PeerCertificates[0] != nil {
			for _, u := range s.PeerCertificates[0].URIs {
				if u == nil {
					return certificatecontract.Peer{}, certificates.ErrInvalidInput
				}
			}
		}
		m, err := certificates.VerifiedPeer(s, certificates.PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth})
		if err != nil {
			return certificatecontract.Peer{}, err
		}
		if !strictDeviceProfile(m) {
			return certificatecontract.Peer{}, certificates.ErrCertificateRejected
		}
		return certificatecontract.Peer{URI: m.URIs[0], Serial: m.Serial, FingerprintSHA256: m.FingerprintSHA256}, nil
	}, contractURI)
}
func singleCertificate(raw []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, certificates.ErrInvalidInput
	}
	return x509.ParseCertificate(b.Bytes)
}
func TestPreparedIssuedConsumerContract(t *testing.T) {
	certificatecontract.RunIssued(t, func(v certificatecontract.IssuedInput, now time.Time) error {
		if v.Key == nil {
			return certificates.ErrInvalidInput
		}
		leaf, err := singleCertificate(v.CertificatePEM)
		if err != nil {
			return err
		}
		root, err := singleCertificate(v.CAPEM)
		if err != nil || !root.IsCA {
			return certificates.ErrInvalidInput
		}
		var pin *x509.Certificate
		if len(v.PinnedCAPEM) > 0 {
			pin, err = singleCertificate(v.PinnedCAPEM)
			if err != nil {
				return err
			}
		}
		public, err := x509.MarshalPKIXPublicKey(&v.Key.PublicKey)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		m, err := certificates.VerifyIssued(leaf, certificates.IssuedOptions{PeerOptions: certificates.PeerOptions{Now: now, Usage: x509.ExtKeyUsageClientAuth}, Roots: roots, ExpectedPublicKeyDER: public, PinnedRoot: pin})
		if err != nil {
			return err
		}
		if !strictDeviceProfile(m) || !m.NotAfter.Equal(v.ExpiresAt) {
			return certificates.ErrCertificateRejected
		}
		return nil
	}, contractURI)
}
