// Package problem writes RFC 9457 compatible HTTP problem details.
package problem

import (
	"encoding/json"
	"net/http"

	coreerrors "github.com/mrheiz97/stumpfworks-framework/core/errors"
)

// Details is the stable public error representation.
type Details struct {
	Type          string       `json:"type"`
	Title         string       `json:"title"`
	Status        int          `json:"status"`
	Code          string       `json:"code,omitempty"`
	CorrelationID string       `json:"correlation_id,omitempty"`
	Errors        []FieldError `json:"errors,omitempty"`
}

// WriteError maps a coded application error to a safe problem response. The
// internal cause is intentionally ignored.
func WriteError(w http.ResponseWriter, status int, err error) {
	details := Details{Status: status}
	if coded, ok := coreerrors.As(err); ok {
		details.Code = coded.Code
		details.Title = coded.Public
	}
	Write(w, details)
}

// FieldError identifies one invalid input without exposing internal errors.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// Write sends a problem response and never exposes an internal error value.
func Write(w http.ResponseWriter, details Details) {
	if details.Status < 400 || details.Status > 599 {
		details = Details{Type: "about:blank", Title: http.StatusText(http.StatusInternalServerError), Status: http.StatusInternalServerError, Code: "internal_error", CorrelationID: details.CorrelationID}
	}
	if details.Type == "" {
		details.Type = "about:blank"
	}
	if details.Title == "" {
		details.Title = http.StatusText(details.Status)
	}
	if details.CorrelationID == "" {
		details.CorrelationID = w.Header().Get("X-Request-ID")
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(details.Status)
	_ = json.NewEncoder(w).Encode(details)
}
