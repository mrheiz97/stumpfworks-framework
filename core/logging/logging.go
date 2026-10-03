// Package logging configures structured application logging.
package logging

import (
	"io"
	"log/slog"

	"github.com/mrheiz97/stumpfworks-framework/security"
)

const redacted = "[REDACTED]"

// NewJSON creates a JSON logger. Callers must not attach secrets as attributes.
func NewJSON(output io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level, ReplaceAttr: redactAttr}))
}

func redactAttr(_ []string, attr slog.Attr) slog.Attr {
	if security.IsSensitiveKey(attr.Key) {
		return slog.String(attr.Key, redacted)
	}
	return attr
}
