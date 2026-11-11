package policy_test

import (
	"strings"
	"testing"

	"github.com/knight-byte/contraband/internal/policy"
)

func TestCheck(t *testing.T) {
	parsed, err := policy.Parse([]byte(`version: 1
allow:
  - domain: registry.npmjs.org
  - domain: "*.github.com"
    package: esbuild
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		pkg, domain, want string
	}{
		{"", "registry.npmjs.org", policy.Allow},
		{"left-pad", "Registry.NPMjs.org.", policy.Allow},
		{"esbuild", "objects.github.com", policy.Allow},
		{"other", "objects.github.com", policy.Warn},
		{"esbuild", "github.com", policy.Warn},
		{"", "", policy.Warn},
	}
	for _, tc := range tests {
		if got := parsed.Check(tc.pkg, tc.domain); got != tc.want {
			t.Errorf("Check(%q, %q) = %q, want %q", tc.pkg, tc.domain, got, tc.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, content := range []string{
		"version: 2\n",
		"version: 1\nallow:\n  - package: x\n",
		"version: 1\nunknown: true\n",
		"version: 1\nallow:\n  - domain: \"[\"\n",
	} {
		if _, err := policy.Parse([]byte(content)); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", content)
		}
	}
}

func TestAddRuleKeepsComments(t *testing.T) {
	original := []byte("# team policy\nversion: 1\nallow:\n  - domain: registry.npmjs.org # npm\n")
	updated, err := policy.AddRule(original, policy.Rule{Domain: "1.1.1.1", Package: "evil"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.Parse(updated)
	if err != nil {
		t.Fatalf("%v\n%s", err, updated)
	}
	if len(parsed.Allow) != 2 || parsed.Allow[1] != (policy.Rule{Domain: "1.1.1.1", Package: "evil"}) {
		t.Fatalf("rule not appended:\n%s", updated)
	}
	for _, comment := range []string{"# team policy", "# npm"} {
		if !strings.Contains(string(updated), comment) {
			t.Errorf("comment %q lost:\n%s", comment, updated)
		}
	}
	again, err := policy.AddRule(updated, policy.Rule{Domain: "1.1.1.1", Package: "evil"})
	if err != nil || string(again) != string(updated) {
		t.Fatalf("duplicate rule changed the file:\n%s", again)
	}

	fresh, err := policy.AddRule(nil, policy.Rule{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := policy.Parse(fresh); err != nil || len(parsed.Allow) != 1 {
		t.Fatalf("new file: %v\n%s", err, fresh)
	}
}

func TestRemoveRule(t *testing.T) {
	original := []byte("# team policy\nversion: 1\nallow:\n  - domain: registry.npmjs.org\n  - domain: 1.1.1.1\n    package: evil\n")
	updated, removed, err := policy.RemoveRule(original, policy.Rule{Domain: "1.1.1.1", Package: "evil"})
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	parsed, err := policy.Parse(updated)
	if err != nil || len(parsed.Allow) != 1 || parsed.Allow[0].Domain != "registry.npmjs.org" || !strings.Contains(string(updated), "# team policy") {
		t.Fatalf("unexpected result: %v\n%s", err, updated)
	}
	if _, removed, _ := policy.RemoveRule(updated, policy.Rule{Domain: "absent.example"}); removed {
		t.Fatal("reported removing a rule that was not there")
	}
}
