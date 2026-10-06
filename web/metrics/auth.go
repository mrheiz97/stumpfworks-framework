package metrics

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

const (
	minBearerTokenBytes = 32
	maxBearerTokenBytes = 512
)

// ProtectBearer wraps a metrics handler with constant-time bearer-token
// verification. Keep the token in protected runtime configuration, never Git.
func ProtectBearer(next http.Handler, token string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("metrics handler is required")
	}
	if !validBearerToken(token) {
		return nil, errors.New("metrics bearer token must be 32..512 visible ASCII bytes without whitespace")
	}
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		actual := sha256.Sum256([]byte(provided))
		if !ok || !validBearerToken(provided) || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}

func validBearerToken(token string) bool {
	if len(token) < minBearerTokenBytes || len(token) > maxBearerTokenBytes {
		return false
	}
	for _, value := range []byte(token) {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}
