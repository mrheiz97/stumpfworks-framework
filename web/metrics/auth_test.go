package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtectBearer(t *testing.T) {
	const token = "synthetic-metrics-token-32-bytes-minimum"
	protected, err := ProtectBearer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), token)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, authorization string
		want                int
	}{
		{"valid", "Bearer " + token, http.StatusNoContent},
		{"missing", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + token, http.StatusUnauthorized},
		{"wrong token", "Bearer synthetic-metrics-token-32-bytes-wrong!!", http.StatusUnauthorized},
		{"extra whitespace", "Bearer  " + token, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.authorization != "" {
				request.Header.Set("Authorization", tc.authorization)
			}
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("got %d want %d", response.Code, tc.want)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if strings.Contains(response.Body.String(), token) {
				t.Fatal("token exposed in response")
			}
			if tc.want == http.StatusUnauthorized && response.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing challenge")
			}
		})
	}
}

func TestProtectBearerRejectsUnsafeConfiguration(t *testing.T) {
	for _, token := range []string{"", "too-short", strings.Repeat("x", 513), strings.Repeat("x", 31) + " ", strings.Repeat("x", 31) + "\n"} {
		if _, err := ProtectBearer(http.NotFoundHandler(), token); err == nil {
			t.Fatalf("accepted unsafe token length %d", len(token))
		}
	}
	if _, err := ProtectBearer(nil, strings.Repeat("x", 32)); err == nil {
		t.Fatal("nil handler accepted")
	}
}
