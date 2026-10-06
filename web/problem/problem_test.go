package problem

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coreerrors "github.com/mrheiz97/stumpfworks-framework/core/errors"
)

func TestWriteUsesRequestCorrelationID(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "request-1")
	Write(w, Details{Status: http.StatusBadRequest, Code: "validation_failed"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"correlation_id":"request-1"`) {
		t.Fatalf("missing correlation ID: %s", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("content type %q", got)
	}
}

func TestWriteErrorDoesNotExposeCause(t *testing.T) {
	w := httptest.NewRecorder()
	WriteError(w, http.StatusServiceUnavailable, coreerrors.Wrap("database_unavailable", "Service unavailable", errors.New("password=private")))
	if strings.Contains(w.Body.String(), "private") {
		t.Fatalf("internal cause exposed: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "database_unavailable") {
		t.Fatalf("code missing: %s", w.Body.String())
	}
}

func TestWriteRejectsInvalidStatus(t *testing.T) {
	w := httptest.NewRecorder()
	Write(w, Details{Status: 0, Title: "private"})
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private") {
		t.Fatalf("unsafe response: %d %s", w.Code, w.Body.String())
	}
}
