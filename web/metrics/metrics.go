// Package metrics provides opt-in, Prometheus-compatible HTTP observations.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	frameworkpg "github.com/TheRealHZL/stumpfworks-framework/data/postgres"
	frameworkldap "github.com/TheRealHZL/stumpfworks-framework/directory/ldap"
)

var buckets = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type key struct {
	method string
	route  string
	status int
}

type observation struct {
	count   uint64
	sum     float64
	buckets [len(buckets)]uint64
}

// Registry owns one application's HTTP metrics. Do not register its Handler on
// a public listener without authentication or network-level access control.
type Registry struct {
	mu        sync.Mutex
	data      map[key]observation
	directory map[directoryKey]observation
	postgres  postgresStatsSource
}

type postgresStatsSource interface{ Stats() frameworkpg.Stats }

type directoryKey struct {
	outcome frameworkldap.LookupOutcome
	stage   frameworkldap.LookupStage
}

// New creates an empty, application-scoped registry.
func New() *Registry {
	return &Registry{data: make(map[key]observation), directory: make(map[directoryKey]observation)}
}

// RegisterPostgresPool adds credential-free pool statistics to this registry.
// Passing nil removes a previously registered source.
func (registry *Registry) RegisterPostgresPool(pool *frameworkpg.Pool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.postgres = pool
}

type ldapObserver struct{ registry *Registry }

// LDAPObserver connects the directory reader to this registry without adding
// user-controlled or identity-bearing labels.
func (registry *Registry) LDAPObserver() frameworkldap.Observer {
	return ldapObserver{registry: registry}
}

func (observer ldapObserver) ObserveLDAPLookup(item frameworkldap.LookupObservation) {
	outcome := boundedLDAPOutcome(item.Outcome)
	stage := boundedLDAPStage(item.Stage)
	seconds := item.Duration.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	observer.registry.mu.Lock()
	defer observer.registry.mu.Unlock()
	label := directoryKey{outcome: outcome, stage: stage}
	value := observer.registry.directory[label]
	value.count++
	value.sum += seconds
	for index, upper := range buckets {
		if seconds <= upper {
			value.buckets[index]++
		}
	}
	observer.registry.directory[label] = value
}

func boundedLDAPStage(stage frameworkldap.LookupStage) frameworkldap.LookupStage {
	switch stage {
	case frameworkldap.StageValidation, frameworkldap.StageConnect, frameworkldap.StageBind,
		frameworkldap.StageSearch, frameworkldap.StageResult:
		return stage
	default:
		return frameworkldap.StageResult
	}
}

func boundedLDAPOutcome(outcome frameworkldap.LookupOutcome) frameworkldap.LookupOutcome {
	switch outcome {
	case frameworkldap.OutcomeSuccess, frameworkldap.OutcomeNotFound, frameworkldap.OutcomeAmbiguous,
		frameworkldap.OutcomeCanceled, frameworkldap.OutcomeTimeout, frameworkldap.OutcomeUnavailable,
		frameworkldap.OutcomeInvalidInput:
		return outcome
	default:
		return frameworkldap.OutcomeUnavailable
	}
}

// Middleware records completed requests using only bounded methods, registered
// route patterns and HTTP status. Install it outside panic recovery and other
// middleware so their final response statuses are observed.
func (registry *Registry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		writer := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)
		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		method := methodLabel(r.Method)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		registry.observe(key{method: method, route: route, status: status}, time.Since(started).Seconds())
	})
}

func (registry *Registry) observe(label key, seconds float64) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	item := registry.data[label]
	item.count++
	item.sum += seconds
	for index, upper := range buckets {
		if seconds <= upper {
			item.buckets[index]++
		}
	}
	registry.data[label] = item
}

// Handler serves Prometheus text exposition. Protect this endpoint separately
// from public application routes; it may reveal route names and traffic volume.
func (registry *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		registry.mu.Lock()
		snapshot := make(map[key]observation, len(registry.data))
		for label, item := range registry.data {
			snapshot[label] = item
		}
		directorySnapshot := make(map[directoryKey]observation, len(registry.directory))
		for label, item := range registry.directory {
			directorySnapshot[label] = item
		}
		postgresSource := registry.postgres
		registry.mu.Unlock()
		var postgresSnapshot *frameworkpg.Stats
		if postgresSource != nil {
			func() {
				defer func() { _ = recover() }()
				stats := postgresSource.Stats()
				postgresSnapshot = &stats
			}()
		}

		labels := make([]key, 0, len(snapshot))
		for label := range snapshot {
			labels = append(labels, label)
		}
		sort.Slice(labels, func(i, j int) bool {
			if labels[i].method != labels[j].method {
				return labels[i].method < labels[j].method
			}
			if labels[i].route != labels[j].route {
				return labels[i].route < labels[j].route
			}
			return labels[i].status < labels[j].status
		})
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintln(w, "# HELP swf_http_requests_total Completed HTTP requests.")
		fmt.Fprintln(w, "# TYPE swf_http_requests_total counter")
		for _, label := range labels {
			fmt.Fprintf(w, "swf_http_requests_total%s %d\n", label.text(), snapshot[label].count)
		}
		fmt.Fprintln(w, "# HELP swf_http_request_duration_seconds HTTP request duration in seconds.")
		fmt.Fprintln(w, "# TYPE swf_http_request_duration_seconds histogram")
		for _, label := range labels {
			item := snapshot[label]
			for index, upper := range buckets {
				fmt.Fprintf(w, "swf_http_request_duration_seconds_bucket%s %d\n", label.textWithBucket(strconv.FormatFloat(upper, 'f', -1, 64)), item.buckets[index])
			}
			fmt.Fprintf(w, "swf_http_request_duration_seconds_bucket%s %d\n", label.textWithBucket("+Inf"), item.count)
			fmt.Fprintf(w, "swf_http_request_duration_seconds_sum%s %s\n", label.text(), strconv.FormatFloat(item.sum, 'f', -1, 64))
			fmt.Fprintf(w, "swf_http_request_duration_seconds_count%s %d\n", label.text(), item.count)
		}

		directoryLabels := make([]directoryKey, 0, len(directorySnapshot))
		for label := range directorySnapshot {
			directoryLabels = append(directoryLabels, label)
		}
		sort.Slice(directoryLabels, func(i, j int) bool {
			if directoryLabels[i].outcome != directoryLabels[j].outcome {
				return directoryLabels[i].outcome < directoryLabels[j].outcome
			}
			return directoryLabels[i].stage < directoryLabels[j].stage
		})
		fmt.Fprintln(w, "# HELP swf_directory_lookups_total Completed directory user lookups.")
		fmt.Fprintln(w, "# TYPE swf_directory_lookups_total counter")
		for _, label := range directoryLabels {
			item := directorySnapshot[label]
			fmt.Fprintf(w, "swf_directory_lookups_total{outcome=%s,stage=%s} %d\n", quote(string(label.outcome)), quote(string(label.stage)), item.count)
		}
		fmt.Fprintln(w, "# HELP swf_directory_lookup_duration_seconds Directory user lookup duration in seconds.")
		fmt.Fprintln(w, "# TYPE swf_directory_lookup_duration_seconds histogram")
		for _, label := range directoryLabels {
			item := directorySnapshot[label]
			labels := fmt.Sprintf("outcome=%s,stage=%s", quote(string(label.outcome)), quote(string(label.stage)))
			for index, upper := range buckets {
				fmt.Fprintf(w, "swf_directory_lookup_duration_seconds_bucket{%s,le=%s} %d\n", labels, quote(strconv.FormatFloat(upper, 'f', -1, 64)), item.buckets[index])
			}
			fmt.Fprintf(w, "swf_directory_lookup_duration_seconds_bucket{%s,le=%s} %d\n", labels, quote("+Inf"), item.count)
			fmt.Fprintf(w, "swf_directory_lookup_duration_seconds_sum{%s} %s\n", labels, strconv.FormatFloat(item.sum, 'f', -1, 64))
			fmt.Fprintf(w, "swf_directory_lookup_duration_seconds_count{%s} %d\n", labels, item.count)
		}
		if postgresSnapshot != nil {
			writePostgresMetrics(w, *postgresSnapshot)
		}
	})
}

func writePostgresMetrics(w http.ResponseWriter, stats frameworkpg.Stats) {
	fmt.Fprintln(w, "# HELP swf_postgres_connections Current PostgreSQL pool connections by bounded state.")
	fmt.Fprintln(w, "# TYPE swf_postgres_connections gauge")
	for _, item := range []struct {
		state string
		value int32
	}{
		{"acquired", stats.AcquiredConnections}, {"constructing", stats.ConstructingConnections},
		{"idle", stats.IdleConnections}, {"max", stats.MaxConnections}, {"total", stats.TotalConnections},
	} {
		fmt.Fprintf(w, "swf_postgres_connections{state=%s} %d\n", quote(item.state), item.value)
	}
	for _, item := range []struct {
		name, help string
		value      int64
	}{
		{"swf_postgres_acquires_total", "Cumulative successful PostgreSQL pool acquires.", stats.AcquireCount},
		{"swf_postgres_acquire_canceled_total", "Cumulative canceled PostgreSQL pool acquires.", stats.CanceledAcquireCount},
		{"swf_postgres_acquire_empty_total", "Cumulative PostgreSQL acquires that waited for a connection.", stats.EmptyAcquireCount},
		{"swf_postgres_connections_created_total", "Cumulative PostgreSQL connections created by the pool.", stats.NewConnectionsCount},
	} {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", item.name, item.help, item.name, item.name, item.value)
	}
	fmt.Fprintln(w, "# HELP swf_postgres_acquire_duration_seconds_total Cumulative time waiting to acquire PostgreSQL connections.")
	fmt.Fprintln(w, "# TYPE swf_postgres_acquire_duration_seconds_total counter")
	fmt.Fprintf(w, "swf_postgres_acquire_duration_seconds_total %s\n", strconv.FormatFloat(stats.AcquireDuration.Seconds(), 'f', -1, 64))
}

func (label key) text() string {
	return fmt.Sprintf("{method=%s,route=%s,status=%q}", quote(label.method), quote(label.route), strconv.Itoa(label.status))
}

func (label key) textWithBucket(bucket string) string {
	base := label.text()
	return strings.TrimSuffix(base, "}") + ",le=" + quote(bucket) + "}"
}

func quote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\""
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *statusWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }
