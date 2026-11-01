// Package certificates provides pure, policy-neutral X509 verification helpers.
// It performs no network, file, signing, revocation, or application authorization
// operations. Callers own trust establishment and certificate identity policy.
package certificates

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrInvalidInput        = errors.New("invalid certificate verification input")
	ErrUnverifiedPeer      = errors.New("peer certificate is not TLS verified")
	ErrCertificateRejected = errors.New("certificate verification rejected")
	ErrKeyMismatch         = errors.New("certificate public key mismatch")
	ErrPinMismatch         = errors.New("certificate root pin mismatch")
)

const maxCertificateBytes = 1 << 20
const maxIdentities = 128

// Metadata owns its slices; mutating it cannot alter the input or later results.
// Serial and fingerprint are public metadata, not recommended log/metric labels.
type Metadata struct {
	FingerprintSHA256, Serial                   string
	NotBefore, NotAfter                         time.Time
	URIs, DNSNames, EmailAddresses, IPAddresses []string
}

// PeerOptions requires an explicit clock and ClientAuth or ServerAuth usage.
// ServerAuth additionally requires DNSName for hostname verification.
type PeerOptions struct {
	Now     time.Time
	Usage   x509.ExtKeyUsage
	DNSName string
}

// IssuedOptions never accepts a private key. ExpectedPublicKeyDER is a PKIX
// public key, not a certificate or PKCS8 private key. Roots must be explicit:
// nil never falls back to the operating system's trust store.
type IssuedOptions struct {
	PeerOptions
	Roots, Intermediates *x509.CertPool
	ExpectedPublicKeyDER []byte
	// PinnedRoot, when present, must match the DER of the final certificate in
	// at least one verified chain. Pinning does not establish trust by itself.
	PinnedRoot *x509.Certificate
}

// VerifiedPeer consumes evidence from a verified crypto/tls handshake. It does
// not build/reverify chains or establish trust from a manually populated state.
// The explicit clock checks leaf freshness, not revocation or current CA policy.
func VerifiedPeer(state *tls.ConnectionState, o PeerOptions) (Metadata, error) {
	if !validOptions(o) {
		return Metadata{}, ErrInvalidInput
	}
	if state == nil || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil {
		return Metadata{}, ErrUnverifiedPeer
	}
	if !bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw) {
		return Metadata{}, ErrUnverifiedPeer
	}
	leaf, err := canonical(state.PeerCertificates[0])
	if err != nil {
		return Metadata{}, err
	}
	if !validLeaf(leaf, o) {
		return Metadata{}, ErrCertificateRejected
	}
	return metadata(leaf)
}

// VerifyIssued verifies a leaf using explicit roots and the Go X509 verifier,
// required explicit EKU, public-key binding and optional verified-root pin.
// It does not infer identity from a common name or enforce a URI namespace.
func VerifyIssued(certificate *x509.Certificate, o IssuedOptions) (Metadata, error) {
	if !validOptions(o.PeerOptions) || o.Roots == nil || len(o.ExpectedPublicKeyDER) == 0 || len(o.ExpectedPublicKeyDER) > maxCertificateBytes {
		return Metadata{}, ErrInvalidInput
	}
	expected, err := x509.ParsePKIXPublicKey(o.ExpectedPublicKeyDER)
	if err != nil {
		return Metadata{}, ErrInvalidInput
	}
	expectedDER, err := x509.MarshalPKIXPublicKey(expected)
	if err != nil {
		return Metadata{}, ErrInvalidInput
	}
	leaf, err := canonical(certificate)
	if err != nil {
		return Metadata{}, err
	}
	if !validLeaf(leaf, o.PeerOptions) {
		return Metadata{}, ErrCertificateRejected
	}
	actualDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return Metadata{}, ErrCertificateRejected
	}
	if subtle.ConstantTimeCompare(actualDER, expectedDER) != 1 {
		return Metadata{}, ErrKeyMismatch
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: o.Roots, Intermediates: o.Intermediates, CurrentTime: o.Now, KeyUsages: []x509.ExtKeyUsage{o.Usage}, DNSName: o.DNSName})
	if err != nil {
		return Metadata{}, ErrCertificateRejected
	}
	if o.PinnedRoot != nil {
		pin, err := canonical(o.PinnedRoot)
		if err != nil {
			return Metadata{}, ErrInvalidInput
		}
		want := sha256.Sum256(pin.Raw)
		matches := false
		for _, chain := range chains {
			if len(chain) == 0 {
				continue
			}
			got := sha256.Sum256(chain[len(chain)-1].Raw)
			matches = matches || subtle.ConstantTimeCompare(got[:], want[:]) == 1
		}
		if !matches {
			return Metadata{}, ErrPinMismatch
		}
	}
	return metadata(leaf)
}

func validOptions(o PeerOptions) bool {
	return !o.Now.IsZero() && (o.Usage == x509.ExtKeyUsageClientAuth || o.Usage == x509.ExtKeyUsageServerAuth) && (o.Usage != x509.ExtKeyUsageServerAuth || o.DNSName != "")
}
func canonical(c *x509.Certificate) (*x509.Certificate, error) {
	if c == nil || len(c.Raw) == 0 || len(c.Raw) > maxCertificateBytes {
		return nil, ErrInvalidInput
	}
	leaf, err := x509.ParseCertificate(c.Raw)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return leaf, nil
}
func validLeaf(c *x509.Certificate, o PeerOptions) bool {
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || o.Now.Before(c.NotBefore) || o.Now.After(c.NotAfter) {
		return false
	}
	explicit := false
	for _, usage := range c.ExtKeyUsage {
		explicit = explicit || usage == o.Usage
	}
	if !explicit {
		return false
	}
	return o.DNSName == "" || c.VerifyHostname(o.DNSName) == nil
}
func metadata(c *x509.Certificate) (Metadata, error) {
	if len(c.URIs)+len(c.DNSNames)+len(c.EmailAddresses)+len(c.IPAddresses) > maxIdentities {
		return Metadata{}, ErrCertificateRejected
	}
	sum := sha256.Sum256(c.Raw)
	m := Metadata{FingerprintSHA256: hex.EncodeToString(sum[:]), Serial: c.SerialNumber.Text(16), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), DNSNames: append([]string(nil), c.DNSNames...), EmailAddresses: append([]string(nil), c.EmailAddresses...)}
	for _, uri := range c.URIs {
		if uri == nil {
			return Metadata{}, ErrCertificateRejected
		}
		m.URIs = append(m.URIs, uri.String())
	}
	for _, ip := range c.IPAddresses {
		m.IPAddresses = append(m.IPAddresses, ip.String())
	}
	return m, nil
}
