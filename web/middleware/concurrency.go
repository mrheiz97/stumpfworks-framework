package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/mrheiz97/stumpfworks-framework/web/problem"
)

// LimitConcurrency bounds simultaneous requests. Queue expiry returns a safe
// 503 response instead of allowing unbounded work.
func LimitConcurrency(maximum int, queueTimeout time.Duration) (func(http.Handler) http.Handler, error) {
	if maximum <= 0 {
		return nil, errors.New("maximum concurrency must be positive")
	}
	if queueTimeout < 0 {
		return nil, errors.New("queue timeout must not be negative")
	}
	semaphore := make(chan struct{}, maximum)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if queueTimeout == 0 {
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
					next.ServeHTTP(w, r)
				default:
					unavailable(w)
				}
				return
			}
			timer := time.NewTimer(queueTimeout)
			defer timer.Stop()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
				next.ServeHTTP(w, r)
			case <-timer.C:
				unavailable(w)
			case <-r.Context().Done():
				return
			}
		})
	}, nil
}

func unavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	problem.Write(w, problem.Details{Type: "https://docs.stumpfworks.de/problems/overloaded", Title: "Service temporarily unavailable", Status: http.StatusServiceUnavailable, Code: "service_overloaded"})
}
