//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/mrheiz97/stumpfworks-framework/auth/oidc"
	frameworkpostgres "github.com/mrheiz97/stumpfworks-framework/data/postgres"
)

func TestOIDCSealedPostgresAttemptIsBrowserBoundAndOneUse(t *testing.T) {
	address := os.Getenv("SWF_TEST_POSTGRES_URL")
	if address == "" {
		t.Skip("SWF_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := frameworkpostgres.Open(ctx, frameworkpostgres.Options{URL: address, MaxConnections: 4, MinConnections: 0, ConnectTimeout: 5 * time.Second, MaxMessageBytes: 16 << 20, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: "test", Algorithm: string(jose.RS256), Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://identity.example.test"
	verifier, err := oidc.NewVerifier(issuer, "test-access", jwks)
	if err != nil {
		t.Fatal(err)
	}
	client, err := oidc.NewLoginClient(&oidc.Configuration{AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", Verifier: verifier}, "test-access", "test-secret", "https://access.example.test/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, transaction, err := client.Begin()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := oidc.NewBrowserBinding()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	codec, err := oidc.NewTransactionCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := codec.Seal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	stateDigest := sha256.Sum256([]byte(transaction.State()))
	bindingDigest := sha256.Sum256([]byte(binding))
	wrongDigest := sha256.Sum256([]byte("wrong browser"))

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	// The random suffix is locally generated hex, never a user-controlled SQL identifier.
	table := "swf_oidc_contract_" + hex.EncodeToString(suffix)
	if _, err := pool.Native().Exec(ctx, "CREATE TABLE "+table+" (state_digest bytea PRIMARY KEY, browser_digest bytea NOT NULL, sealed bytea NOT NULL, expires_at timestamptz NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := pool.Native().Exec(cleanupCtx, "DROP TABLE "+table); err != nil {
			t.Errorf("remove contract table: %v", err)
		}
	}()
	if _, err := pool.Native().Exec(ctx, "INSERT INTO "+table+" (state_digest,browser_digest,sealed,expires_at) VALUES ($1,$2,$3,now()+interval '5 minutes')", stateDigest[:], bindingDigest[:], sealed); err != nil {
		t.Fatal(err)
	}
	take := "DELETE FROM " + table + " WHERE state_digest=$1 AND browser_digest=$2 AND expires_at>now() RETURNING sealed"
	var record []byte
	if err := pool.Native().QueryRow(ctx, take, stateDigest[:], wrongDigest[:]).Scan(&record); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong browser consumed attempt: %v", err)
	}

	type result struct {
		record []byte
		err    error
	}
	results := make(chan result, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() {
			var found []byte
			err := pool.Native().QueryRow(ctx, take, stateDigest[:], bindingDigest[:]).Scan(&found)
			results <- result{record: found, err: err}
		})
	}
	group.Wait()
	close(results)
	successes := 0
	for outcome := range results {
		if errors.Is(outcome.err, pgx.ErrNoRows) {
			continue
		}
		if outcome.err != nil {
			t.Fatal(outcome.err)
		}
		restored, err := codec.Open(client, outcome.record)
		if err != nil || restored.State() != transaction.State() {
			t.Fatalf("stored transaction did not restore: %v", err)
		}
		successes++
	}
	if successes != 1 {
		t.Fatalf("concurrent callbacks took transaction %d times", successes)
	}
}
