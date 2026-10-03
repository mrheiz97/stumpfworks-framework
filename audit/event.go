// Package audit defines security-relevant, append-only audit events.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/mrheiz97/stumpfworks-framework/security"
)

// Result describes the outcome of an audited action.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
	ResultDenied  Result = "denied"
)

// Event is an immutable fact supplied to a Store. Metadata must already be
// privacy-reviewed and must not contain credentials or unrestricted payloads.
type Event struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	Actor         string         `json:"actor"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Result        Result         `json:"result"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// Validate checks the stable audit envelope.
func (e Event) Validate() error {
	if e.ID == "" {
		return errors.New("audit event ID is required")
	}
	if e.Timestamp.IsZero() {
		return errors.New("audit event timestamp is required")
	}
	if e.Actor == "" {
		return errors.New("audit actor is required")
	}
	if e.Action == "" {
		return errors.New("audit action is required")
	}
	if e.Resource == "" {
		return errors.New("audit resource is required")
	}
	switch e.Result {
	case ResultSuccess, ResultFailure, ResultDenied:
	default:
		return errors.New("audit result is invalid")
	}
	if err := validateMetadata(e.Metadata); err != nil {
		return err
	}
	return nil
}

func validateMetadata(metadata map[string]any) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return errors.New("audit metadata must be valid JSON")
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return errors.New("audit metadata must be valid JSON")
	}
	return inspectMetadata(value, 0)
}

func inspectMetadata(value any, depth int) error {
	if depth > 16 {
		return errors.New("audit metadata is nested too deeply")
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if security.IsSensitiveKey(key) {
				return errors.New("audit metadata contains a sensitive field")
			}
			if err := inspectMetadata(child, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := inspectMetadata(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Store appends immutable audit events.
type Store interface {
	Append(context.Context, Event) error
}
