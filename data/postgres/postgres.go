// Package postgres manages the shared PostgreSQL connection lifecycle.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures a connection pool. URL may contain credentials and must
// never be logged.
type Options struct {
	URL             string
	MaxConnections  int32
	MinConnections  int32
	ConnectTimeout  time.Duration
	MaxMessageBytes int
	AllowInsecure   bool
}

// Pool wraps pgxpool with a deliberately small framework API.
type Pool struct{ pool *pgxpool.Pool }

// Stats is a credential-free snapshot suitable for bounded operational metrics.
type Stats struct {
	AcquiredConnections     int32
	ConstructingConnections int32
	IdleConnections         int32
	MaxConnections          int32
	TotalConnections        int32
	AcquireCount            int64
	CanceledAcquireCount    int64
	EmptyAcquireCount       int64
	NewConnectionsCount     int64
	AcquireDuration         time.Duration
}

// Open parses the configuration, creates the pool, and verifies connectivity.
func Open(ctx context.Context, options Options) (*Pool, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	config, err := pgxpool.ParseConfig(options.URL)
	if err != nil {
		return nil, errors.New("parse PostgreSQL configuration")
	}
	if !options.AllowInsecure && permitsPlaintext(config) {
		return nil, errors.New("PostgreSQL TLS is required; explicitly allow insecure connections only for trusted local development")
	}
	config.MaxConns = options.MaxConnections
	config.MinConns = options.MinConnections
	config.ConnConfig.ConnectTimeout = options.ConnectTimeout
	config.ConnConfig.MaxProtocolMessageBodyLen = options.MaxMessageBytes
	connectCtx, cancel := context.WithTimeout(ctx, options.ConnectTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(connectCtx, config)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	return &Pool{pool: pool}, nil
}

func (o Options) validate() error {
	if o.URL == "" {
		return errors.New("PostgreSQL URL is required")
	}
	if o.MaxConnections <= 0 {
		return errors.New("PostgreSQL max connections must be positive")
	}
	if o.MinConnections < 0 || o.MinConnections > o.MaxConnections {
		return errors.New("PostgreSQL min connections must be between zero and max connections")
	}
	if o.ConnectTimeout <= 0 {
		return errors.New("PostgreSQL connect timeout must be positive")
	}
	if o.MaxMessageBytes <= 0 {
		return errors.New("PostgreSQL max message bytes must be positive")
	}
	return nil
}

func permitsPlaintext(config *pgxpool.Config) bool {
	if config.ConnConfig.TLSConfig == nil {
		return true
	}
	for _, fallback := range config.ConnConfig.Fallbacks {
		if fallback.TLSConfig == nil {
			return true
		}
	}
	return false
}

// Ping implements a health readiness check.
func (p *Pool) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// Close releases all pool resources.
func (p *Pool) Close() { p.pool.Close() }

// Native exposes pgxpool only for adapters that need transactions or queries.
func (p *Pool) Native() *pgxpool.Pool { return p.pool }

// Stats returns a point-in-time snapshot without exposing connection strings,
// SQL text, database names, users, or query parameters.
func (p *Pool) Stats() Stats {
	stat := p.pool.Stat()
	return Stats{
		AcquiredConnections: stat.AcquiredConns(), ConstructingConnections: stat.ConstructingConns(),
		IdleConnections: stat.IdleConns(), MaxConnections: stat.MaxConns(), TotalConnections: stat.TotalConns(),
		AcquireCount: stat.AcquireCount(), CanceledAcquireCount: stat.CanceledAcquireCount(),
		EmptyAcquireCount: stat.EmptyAcquireCount(), NewConnectionsCount: stat.NewConnsCount(),
		AcquireDuration: stat.AcquireDuration(),
	}
}

// WithinTransaction executes work in a transaction, rolls back on errors or
// panics, and commits only after the callback succeeds.
func (p *Pool) WithinTransaction(ctx context.Context, work func(pgx.Tx) error) error {
	if work == nil {
		return errors.New("transaction callback is required")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	if err := work(tx); err != nil {
		return fmt.Errorf("transaction callback: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
