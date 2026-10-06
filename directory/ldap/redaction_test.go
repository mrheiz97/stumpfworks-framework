package ldap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestDirectorySecretsAreOpaque(t *testing.T) {
	const secret = "synthetic-credential-not-real"
	config := testConfig("ldaps://example.test")
	config.BindPassword = secret
	reader, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, &config, reader} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), secret) {
				t.Fatal("directory secret exposed by formatting")
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("directory secret exposed by JSON")
		}
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		logger.Info("synthetic configuration", "directory", value)
		if strings.Contains(output.String(), secret) {
			t.Fatal("directory secret exposed through nested slog value")
		}
	}
	config.URL = "ldaps://user:" + secret + "@example.test"
	encoded, _ := json.Marshal(config)
	if bytes.Contains(encoded, []byte(secret)) {
		t.Fatal("invalid credential-bearing URL exposed before validation")
	}
}
