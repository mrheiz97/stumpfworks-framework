package authz

import (
	"strings"
	"testing"
)

func TestPermissionValidation(t *testing.T) {
	for _, valid := range []string{"access.admin", "access.user.manage", "identity.self-service", "service_2.read-only"} {
		if got, err := Parse(valid); err != nil || string(got) != valid {
			t.Fatalf("valid permission %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", ".access", "access.", "access..admin", "Access.admin", "2access.read", "access/*", "access admin", strings.Repeat("a", MaxKeyBytes+1)} {
		if _, err := Parse(invalid); err == nil {
			t.Fatalf("invalid permission %q accepted", invalid)
		}
	}
}

func TestSetUsesExactExplicitPermissions(t *testing.T) {
	set, err := New("access.admin", "access.user.manage", "access.admin")
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := Parse("access.admin")
	manage, _ := Parse("access.user.manage")
	execute, _ := Parse("access.action.execute")
	if set.Len() != 2 || !set.Has(admin) || !set.HasAll(admin, manage) || !set.HasAny(execute, manage) {
		t.Fatal("exact permission set failed")
	}
	if set.Has(execute) || set.HasAll(admin, execute) {
		t.Fatal("administrator permission implicitly granted physical action")
	}
}

func TestSetRejectsOversizedInputBeforeDeduplication(t *testing.T) {
	values := make([]string, MaxPermission+1)
	for i := range values {
		values[i] = "access.view"
	}
	if _, err := New(values...); err == nil {
		t.Fatal("oversized permission input accepted")
	}
}
