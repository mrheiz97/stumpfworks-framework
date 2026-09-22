package prometheus

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type ruleFile struct {
	Groups []struct {
		Name  string `json:"name"`
		Rules []struct {
			Alert       string            `json:"alert"`
			Expr        string            `json:"expr"`
			For         string            `json:"for"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"rules"`
	} `json:"groups"`
}

func TestAlertRulesAreBoundedAndActionable(t *testing.T) {
	data, err := os.ReadFile("stumpfworks-alerts.rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var file ruleFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Groups) != 3 {
		t.Fatalf("got %d rule groups", len(file.Groups))
	}
	seen := map[string]bool{}
	for _, group := range file.Groups {
		if group.Name == "" || len(group.Rules) == 0 {
			t.Fatal("empty rule group")
		}
		for _, rule := range group.Rules {
			if rule.Alert == "" || seen[rule.Alert] || rule.Expr == "" || rule.For == "" || rule.Labels["severity"] == "" || rule.Annotations["summary"] == "" || rule.Annotations["description"] == "" {
				t.Fatalf("incomplete or duplicate alert: %+v", rule)
			}
			seen[rule.Alert] = true
			lower := strings.ToLower(rule.Expr + " " + rule.Annotations["description"])
			for _, forbidden := range []string{"username", "user_id", "request_id", "client_id", "bind_dn", "distinguished_name"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("alert %s contains forbidden identity field %q", rule.Alert, forbidden)
				}
			}
		}
	}
	for _, expected := range []string{"StumpfWorksTargetDown", "StumpfWorksHTTP5xxRatioHigh", "StumpfWorksDirectoryUnavailable", "StumpfWorksDirectoryTimeouts", "StumpfWorksDirectoryLatencyHigh", "StumpfWorksPostgresPoolSaturated", "StumpfWorksPostgresAcquireCanceled"} {
		if !seen[expected] {
			t.Fatalf("missing %s", expected)
		}
	}
}
