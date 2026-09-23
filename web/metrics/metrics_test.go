package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
)

func TestMetricsUseRoutePatternAndBoundedMethod(t *testing.T) {
	registry := New()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := registry.Middleware(mux)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/users/private-id?token=private", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("UNUSUAL-METHOD", "/users/private-id", nil))
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("unexpected exposition response: %d, %q", response.Code, response.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, `swf_http_requests_total{method="GET",route="GET /users/{id}",status="204"} 1`) {
		t.Fatalf("missing registered route: %s", body)
	}
	if !strings.Contains(body, `swf_http_requests_total{method="OTHER",route="unmatched",status="405"} 1`) {
		t.Fatalf("missing bounded unknown method: %s", body)
	}
	if strings.Contains(body, "private-id") || strings.Contains(body, "token=private") || strings.Contains(body, "UNUSUAL-METHOD") {
		t.Fatalf("request data exposed: %s", body)
	}
	if !strings.Contains(body, `le="+Inf"} 1`) {
		t.Fatal("missing infinite histogram bucket")
	}
}

type fakePostgresStats struct{ stats frameworkpg.Stats }

func (f fakePostgresStats) Stats() frameworkpg.Stats { return f.stats }

func TestPostgresMetricsContainOnlyBoundedPoolState(t *testing.T) {
	registry := New()
	registry.mu.Lock()
	registry.postgres = fakePostgresStats{stats: frameworkpg.Stats{
		AcquiredConnections: 2, IdleConnections: 3, MaxConnections: 10, TotalConnections: 5,
		AcquireCount: 20, CanceledAcquireCount: 1, EmptyAcquireCount: 4,
		NewConnectionsCount: 6, AcquireDuration: 1500 * time.Millisecond,
	}}
	registry.mu.Unlock()
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`swf_postgres_connections{state="acquired"} 2`, `swf_postgres_connections{state="idle"} 3`,
		`swf_postgres_acquire_canceled_total 1`, `swf_postgres_acquire_duration_seconds_total 1.5`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"database=", "user=", "query=", "host="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("pool metrics exposed %q", forbidden)
		}
	}
}

func TestLDAPMetricsUseOnlyBoundedOutcomeLabels(t *testing.T) {
	registry := New()
	observer := registry.LDAPObserver()
	observer.ObserveLDAPLookup(frameworkldap.LookupObservation{Outcome: frameworkldap.OutcomeSuccess, Stage: frameworkldap.StageResult, Duration: 125 * time.Millisecond})
	observer.ObserveLDAPLookup(frameworkldap.LookupObservation{Outcome: frameworkldap.LookupOutcome("private-user@example.test"), Stage: frameworkldap.LookupStage("private-server"), Duration: -time.Second})
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`swf_directory_lookups_total{outcome="success",stage="result"} 1`,
		`swf_directory_lookups_total{outcome="unavailable",stage="result"} 1`,
		`swf_directory_lookup_duration_seconds_count{outcome="success",stage="result"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing directory metric %q: %s", expected, body)
		}
	}
	if strings.Contains(body, "private-user") || strings.Contains(body, "private-server") {
		t.Fatal("unbounded directory outcome exposed")
	}
}

func TestMetricsConcurrentRequestsAndScrapes(t *testing.T) {
	registry := New()
	handler := registry.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
			registry.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/metrics", nil))
		})
	}
	group.Wait()
	response := httptest.NewRecorder()
	registry.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), `swf_http_requests_total{method="POST",route="unmatched",status="202"} 100`) {
		t.Fatalf("unexpected request count: %s", response.Body.String())
	}
}

func TestMetricLabelEscaping(t *testing.T) {
	got := (key{method: "GET", route: "a\"b\\c\nd", status: 200}).text()
	if got != `{method="GET",route="a\"b\\c\nd",status="200"}` {
		t.Fatalf("unexpected escaped label: %q", got)
	}
}
