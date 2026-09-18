// Package ldap provides bounded, read-only Active Directory lookups over LDAPS.
// Authentication policy, group-to-role mapping and directory writes belong to consumers.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ldaplib "github.com/go-ldap/ldap/v3"
)

var (
	ErrUnavailable = errors.New("directory unavailable")
	ErrNotFound    = errors.New("directory user not found")
	ErrAmbiguous   = errors.New("directory lookup ambiguous")
)

type Config struct {
	URL, BaseDN, BindDN, BindPassword string
	Roots                             *x509.CertPool
	Timeout                           time.Duration
}

type User struct{ Username, DisplayName, DN, Mail string }

type Reader struct {
	config            Config
	address, hostname string
}

// A lookup cannot consume unlimited directory response data. This budget is
// per connection, including bind and search, without changing BER globals.
type boundedConn struct {
	net.Conn
	remaining int
}

func (c *boundedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func New(config Config) (*Reader, error) {
	if len(config.URL) > 2048 || len(config.BaseDN) > 4096 || len(config.BindDN) > 4096 || len(config.BindPassword) > 4096 {
		return nil, errors.New("directory configuration exceeds size limits")
	}
	u, err := url.Parse(config.URL)
	if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("directory requires an LDAPS host URL")
	}
	port := u.Port()
	if port == "" {
		port = "636"
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("invalid directory port")
	}
	if config.BaseDN == "" || config.BindDN == "" || config.BindPassword == "" {
		return nil, errors.New("directory requires base DN and service credentials")
	}
	if _, err := ldaplib.ParseDN(config.BaseDN); err != nil {
		return nil, errors.New("invalid directory base DN")
	}
	if config.Timeout == 0 {
		config.Timeout = 8 * time.Second
	}
	if config.Timeout < time.Second || config.Timeout > 30*time.Second {
		return nil, errors.New("directory timeout must be 1..30 seconds")
	}
	if config.Roots != nil {
		config.Roots = config.Roots.Clone()
	}
	return &Reader{config: config, address: net.JoinHostPort(u.Hostname(), port), hostname: u.Hostname()}, nil
}

func userFilter(username string) string {
	return "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(sAMAccountName=" + ldaplib.EscapeFilter(username) + "))"
}

// GetUser returns one enabled AD/Samba-AD user. Referrals are never followed.
// Each call owns its connection and closes it on cancellation or deadline.
func (r *Reader) GetUser(ctx context.Context, username string) (*User, error) {
	if ctx == nil {
		return nil, errors.New("directory context required")
	}
	if len(username) > 256 || !utf8.ValidString(username) {
		return nil, errors.New("invalid directory username")
	}
	username = strings.TrimSpace(username)
	if username == "" || strings.ContainsRune(username, 0) {
		return nil, errors.New("invalid directory username")
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: r.config.Timeout}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: r.hostname, RootCAs: r.config.Roots}}
	raw, err := dialer.DialContext(ctx, "tcp", r.address)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	conn := ldaplib.NewConn(&framedConn{Conn: &boundedConn{Conn: raw, remaining: 1 << 20}}, true)
	conn.Start()
	defer conn.Close()
	conn.SetTimeout(r.config.Timeout)
	if err := conn.Bind(r.config.BindDN, r.config.BindPassword); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	result, err := conn.Search(ldaplib.NewSearchRequest(r.config.BaseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 2, int(r.config.Timeout.Seconds()), false, userFilter(username), []string{"sAMAccountName", "displayName", "mail"}, nil))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(result.Referrals) > 0 {
		return nil, ErrUnavailable
	}
	if len(result.Entries) == 0 {
		return nil, ErrNotFound
	}
	if len(result.Entries) != 1 {
		return nil, ErrAmbiguous
	}
	entry := result.Entries[0]
	user := &User{Username: entry.GetAttributeValue("sAMAccountName"), DisplayName: entry.GetAttributeValue("displayName"), Mail: entry.GetAttributeValue("mail"), DN: entry.DN}
	if user.Username == "" {
		return nil, ErrUnavailable
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	return user, nil
}
