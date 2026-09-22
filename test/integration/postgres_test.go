//go:build integration

package integration_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TheRealHZL/stumpfworks-framework/audit"
	auditpostgres "github.com/TheRealHZL/stumpfworks-framework/audit/postgres"
	"github.com/TheRealHZL/stumpfworks-framework/data/migrate"
	frameworkpostgres "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	frameworkmetrics "github.com/TheRealHZL/stumpfworks-framework/web/metrics"
	"github.com/jackc/pgx/v5"
)

func TestPostgresPoolMetricsFromRealPool(t *testing.T) {
	url := os.Getenv("SWF_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("SWF_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := frameworkpostgres.Open(ctx, frameworkpostgres.Options{URL: url, MaxConnections: 4, MinConnections: 0, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	connection, err := pool.Native().Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	registry := frameworkmetrics.New()
	registry.RegisterPostgresPool(pool)
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, `swf_postgres_connections{state="acquired"} 1`) || !strings.Contains(body, `swf_postgres_connections{state="max"} 4`) {
		t.Fatalf("unexpected real pool metrics: %s", body)
	}
	for _, forbidden := range []string{"swf-test-only", "postgres://", "database=", "query="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("pool exposition leaked %q", forbidden)
		}
	}
}

func TestPostgresMigrationsAndAudit(t *testing.T) {
	url := os.Getenv("SWF_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("SWF_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := frameworkpostgres.Open(ctx, frameworkpostgres.Options{URL: url, MaxConnections: 4, MinConnections: 0, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Native().Exec(ctx, `DROP TABLE IF EXISTS swf_audit_events, swf_schema_migrations`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	migrations, err := auditpostgres.Migrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	if err := migrate.Apply(ctx, pool.Native(), migrations); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store, err := auditpostgres.New(pool.Native())
	if err != nil {
		t.Fatal(err)
	}
	event := audit.Event{ID: "integration-event-1", Timestamp: time.Now().UTC(), Actor: "test:runner", Action: "integration.verify", Resource: "database:test", Result: audit.ResultSuccess, CorrelationID: "test-request"}
	if err := store.Append(ctx, event); err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	var count int
	if err := pool.Native().QueryRow(ctx, `SELECT count(*) FROM swf_audit_events WHERE id=$1`, event.ID).Scan(&count); err != nil {
		t.Fatalf("query audit event: %v", err)
	}
	if count != 1 {
		t.Fatalf("event count %d", count)
	}
	if err := migrate.Apply(ctx, pool.Native(), migrations); err != nil {
		t.Fatalf("idempotent migration run: %v", err)
	}
}

func TestTransactionRollback(t *testing.T) {
	url := os.Getenv("SWF_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("SWF_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := frameworkpostgres.Open(ctx, frameworkpostgres.Options{URL: url, MaxConnections: 2, MinConnections: 0, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Native().Exec(ctx, `CREATE TABLE IF NOT EXISTS swf_transaction_test (id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Native().Exec(ctx, `TRUNCATE swf_transaction_test`); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("rollback")
	err = pool.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO swf_transaction_test (id) VALUES ('rolled-back')`); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error lost: %v", err)
	}
	var count int
	if err := pool.Native().QueryRow(ctx, `SELECT count(*) FROM swf_transaction_test`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rollback left %d rows", count)
	}
}

func TestConcurrentMigrationRunners(t *testing.T) {
	url := os.Getenv("SWF_TEST_POSTGRES_URL")
	if url == "" {
		t.Skip("SWF_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := frameworkpostgres.Open(ctx, frameworkpostgres.Options{URL: url, MaxConnections: 4, MinConnections: 0, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Native().Exec(ctx, `DROP TABLE IF EXISTS swf_audit_events, swf_schema_migrations`); err != nil {
		t.Fatal(err)
	}
	migrations, err := auditpostgres.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	errorsCh := make(chan error, 2)
	var runners sync.WaitGroup
	for range 2 {
		runners.Add(1)
		go func() { defer runners.Done(); errorsCh <- migrate.Apply(ctx, pool.Native(), migrations) }()
	}
	runners.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent migration failed: %v", err)
		}
	}
	var count int
	if err := pool.Native().QueryRow(ctx, `SELECT count(*) FROM swf_schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(migrations) {
		t.Fatalf("migration count=%d want=%d", count, len(migrations))
	}
}
