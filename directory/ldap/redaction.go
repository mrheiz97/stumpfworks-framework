package ldap

import "log/slog"

// Secret-bearing configuration is intentionally opaque to common formatting
// and JSON logging. Explicit field extraction is still the caller's duty:
// never attach credentials, raw config, or private user records to logs.
func (Config) String() string               { return "LDAP configuration [REDACTED]" }
func (c Config) GoString() string           { return c.String() }
func (c Config) LogValue() slog.Value       { return slog.StringValue(c.String()) }
func (Config) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }

func (*Reader) String() string         { return "LDAP reader [REDACTED]" }
func (r *Reader) GoString() string     { return r.String() }
func (r *Reader) LogValue() slog.Value { return slog.StringValue(r.String()) }
