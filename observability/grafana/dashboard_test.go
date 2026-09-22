package grafana

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDashboardIsValidAndPrivacyBounded(t *testing.T) {
	data, err := os.ReadFile("stumpfworks-overview.json")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard map[string]any
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard["uid"] != "stumpfworks-service-overview" {
		t.Fatal("stable dashboard UID missing")
	}
	text := string(data)
	for _, metric := range []string{"swf_http_requests_total", "swf_http_request_duration_seconds_bucket", "swf_directory_lookups_total", "swf_directory_lookup_duration_seconds_bucket"} {
		if !strings.Contains(text, metric) {
			t.Fatalf("dashboard does not use %s", metric)
		}
	}
	for _, forbidden := range []string{"username", "user_id", "request_id", "client_id", "distinguished_name", "bind_dn"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("dashboard contains forbidden high-cardinality field %q", forbidden)
		}
	}
}
