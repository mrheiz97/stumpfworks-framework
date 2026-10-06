package validation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	coreerrors "github.com/mrheiz97/stumpfworks-framework/core/errors"
)

type input struct {
	Name string `json:"name"`
}

func decode(t *testing.T, contentType, body string, limit int64) (*input, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	value := new(input)
	err := DecodeJSON(httptest.NewRecorder(), request, value, limit)
	return value, err
}

func code(err error) string {
	if coded, ok := coreerrors.As(err); ok {
		return coded.Code
	}
	return ""
}

func TestDecodeJSON(t *testing.T) {
	value, err := decode(t, "application/json; charset=utf-8", `{"name":"Ada"}`, 1024)
	if err != nil || value.Name != "Ada" {
		t.Fatalf("value=%#v error=%v", value, err)
	}
}

func TestDecodeJSONRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name, contentType, body, want string
		limit                         int64
	}{
		{"content type", "text/plain", `{}`, "unsupported_media_type", 1024},
		{"unknown field", "application/json", `{"other":true}`, "invalid_json", 1024},
		{"two values", "application/json", `{} {}`, "malformed_json", 1024},
		{"too large", "application/json", `{"name":"Ada"}`, "request_too_large", 4},
		{"too large after value", "application/json", `{}          `, "request_too_large", 4},
		{"empty", "application/json", ``, "empty_body", 1024},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decode(t, test.contentType, test.body, test.limit)
			if code(err) != test.want {
				t.Fatalf("code=%q error=%v", code(err), err)
			}
		})
	}
}
