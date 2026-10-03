// Package postgres persists audit events in PostgreSQL.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mrheiz97/stumpfworks-framework/audit"
)

// Store is an append-only PostgreSQL audit store.
type Store struct{ pool *pgxpool.Pool }

// New creates a store around an existing application pool.
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	return &Store{pool: pool}, nil
}

// Append validates and inserts one event. Duplicate IDs are rejected by the schema.
func (s *Store) Append(ctx context.Context, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate audit event: %w", err)
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO swf_audit_events (id, occurred_at, actor, action, resource, result, correlation_id, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, event.ID, event.Timestamp, event.Actor, event.Action, event.Resource, event.Result, event.CorrelationID, metadata)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}
