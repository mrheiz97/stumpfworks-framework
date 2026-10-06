package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigurationCacheRefreshRotationAndExpiry(t *testing.T) {
	oldKey := testKey(t)
	newKey := testKey(t)
	var activeKeys atomic.Value
	activeKeys.Store(testJWKS(t, publicKey(oldKey, "old")))
	var broken atomic.Bool
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks",
				"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			_, _ = w.Write(activeKeys.Load().([]byte))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	cache, err := NewConfigurationCache(server.URL, testClient, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Current(); !errors.Is(err, ErrStaleConfiguration) {
		t.Fatal("empty cache accepted")
	}
	if status := cache.Status(); status.Fresh || !status.LastSuccessfulRefresh.IsZero() || !status.ExpiresAt.IsZero() {
		t.Fatalf("empty cache reported healthy status: %+v", status)
	}
	clock := time.Now()
	cache.now = func() time.Time { return clock }
	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, err := cache.Current()
	if err != nil {
		t.Fatal(err)
	}
	initialStatus := cache.Status()
	if !initialStatus.Fresh || !initialStatus.LastSuccessfulRefresh.Equal(clock) || !initialStatus.ExpiresAt.Equal(clock.Add(time.Minute)) {
		t.Fatalf("wrong fresh cache status: %+v", initialStatus)
	}
	loginClient, err := NewLoginClient(first, testClient, "test-secret", "https://access.example.test/callback", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	loginClient.now = func() time.Time { return clock }
	oldToken := signToken(t, oldKey, "old", map[string]any{"iss": server.URL, "sub": "subject", "aud": testClient, "iat": clock.Unix(), "exp": clock.Add(5 * time.Minute).Unix(), "nonce": "nonce"})
	if _, err := first.Verifier.VerifyIDToken(oldToken, "nonce"); err != nil {
		t.Fatal(err)
	}
	first.TokenEndpoint = "https://evil.example.test/token"
	second, err := cache.Current()
	if err != nil || second.TokenEndpoint != server.URL+"/token" {
		t.Fatal("caller mutation altered cache")
	}
	// A safe issuer rotation overlaps old and new signing keys. Pending logins
	// may still receive an ID token signed with the old key during this window.
	activeKeys.Store(testJWKS(t, publicKey(oldKey, "old"), publicKey(newKey, "new")))
	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	overlap, err := cache.Current()
	if err != nil {
		t.Fatal(err)
	}
	newToken := signToken(t, newKey, "new", map[string]any{"iss": server.URL, "sub": "subject", "aud": testClient, "iat": clock.Unix(), "exp": clock.Add(5 * time.Minute).Unix(), "nonce": "nonce"})
	for name, token := range map[string]string{"pending old-key login": oldToken, "new-key login": newToken} {
		if _, err := overlap.Verifier.VerifyIDToken(token, "nonce"); err != nil {
			t.Fatalf("%s rejected during key overlap: %v", name, err)
		}
	}
	activeKeys.Store(testJWKS(t, publicKey(newKey, "new")))
	broken.Store(true)
	if err := cache.Refresh(t.Context()); err == nil {
		t.Fatal("failed refresh accepted")
	}
	if status := cache.Status(); !status.Fresh || !status.LastSuccessfulRefresh.Equal(initialStatus.LastSuccessfulRefresh) || !status.ExpiresAt.Equal(initialStatus.ExpiresAt) {
		t.Fatalf("failed refresh extended or discarded freshness: %+v", status)
	}
	clock = clock.Add(30 * time.Second)
	if _, err := cache.Current(); err != nil {
		t.Fatalf("valid key window discarded early: %v", err)
	}
	if _, _, err := loginClient.Begin(); err != nil {
		t.Fatalf("fresh client rejected: %v", err)
	}
	clock = clock.Add(30 * time.Second)
	if _, err := cache.Current(); !errors.Is(err, ErrStaleConfiguration) {
		t.Fatal("stale keys accepted after failed refresh")
	}
	if status := cache.Status(); status.Fresh || !status.ExpiresAt.Equal(initialStatus.ExpiresAt) {
		t.Fatalf("stale cache reported fresh or moved deadline: %+v", status)
	}
	if _, _, err := loginClient.Begin(); !errors.Is(err, ErrStaleConfiguration) {
		t.Fatal("reused login client accepted stale keys")
	}
	broken.Store(false)
	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotated, err := cache.Current()
	if err != nil {
		t.Fatal(err)
	}
	newToken = signToken(t, newKey, "new", map[string]any{"iss": server.URL, "sub": "subject", "aud": testClient, "iat": clock.Unix(), "exp": clock.Add(5 * time.Minute).Unix(), "nonce": "nonce"})
	rotated.Verifier.now = func() time.Time { return clock }
	if _, err := rotated.Verifier.VerifyIDToken(newToken, "nonce"); err != nil {
		t.Fatalf("rotated key rejected: %v", err)
	}
	if _, err := rotated.Verifier.VerifyIDToken(oldToken, "nonce"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("removed key still accepted in new snapshot")
	}
	if err := cache.Run(t.Context(), time.Millisecond, func(error, CacheStatus) {}); err == nil {
		t.Fatal("accepted refresh loop faster than one second")
	}
	if err := cache.Run(t.Context(), time.Minute, func(error, CacheStatus) {}); err == nil {
		t.Fatal("accepted refresh interval longer than half the cache age")
	}
	ticks := make(chan time.Time)
	type refreshEvent struct {
		err    error
		status CacheStatus
	}
	events := make(chan refreshEvent, 3)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- cache.runRefreshLoop(ctx, ticks, func(err error, status CacheStatus) {
			events <- refreshEvent{err: err, status: status}
		})
	}()
	awaitEvent := func() refreshEvent {
		t.Helper()
		select {
		case event := <-events:
			return event
		case <-time.After(5 * time.Second):
			t.Fatal("refresh loop did not report")
			return refreshEvent{}
		}
	}
	if event := awaitEvent(); event.err != nil || !event.status.Fresh {
		t.Fatalf("initial loop refresh failed: %+v", event)
	}
	lastSuccess := cache.Status().LastSuccessfulRefresh
	broken.Store(true)
	ticks <- time.Now()
	if event := awaitEvent(); event.err == nil || !event.status.LastSuccessfulRefresh.Equal(lastSuccess) {
		t.Fatalf("failed loop refresh was not reported or advanced freshness: %+v", event)
	}
	broken.Store(false)
	clock = clock.Add(time.Second)
	ticks <- time.Now()
	if event := awaitEvent(); event.err != nil || !event.status.Fresh || !event.status.LastSuccessfulRefresh.Equal(clock) {
		t.Fatalf("loop did not recover after outage: %+v", event)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh loop did not stop on cancellation: %v", err)
	}
}

func TestConfigurationCacheRejectsInvalidPolicy(t *testing.T) {
	for _, age := range []time.Duration{0, time.Second, time.Hour + time.Second} {
		if _, err := NewConfigurationCache(testIssuer, testClient, nil, age); err == nil {
			t.Fatalf("accepted invalid max age %s", age)
		}
	}
	if _, err := (*ConfigurationCache)(nil).Current(); !errors.Is(err, ErrStaleConfiguration) {
		t.Fatal("nil cache accepted")
	}
	if status := (*ConfigurationCache)(nil).Status(); status.Fresh {
		t.Fatal("nil cache reported fresh")
	}
}
