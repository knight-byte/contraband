package policy_test

import (
	"testing"

	"github.com/knight-byte/contraband/internal/policy"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("version: 1\nallow:\n  - domain: registry.npmjs.org\n"))
	f.Fuzz(func(t *testing.T, content []byte) {
		if parsed, err := policy.Parse(content); err == nil {
			parsed.Check("pkg", "example.com")
		}
	})
}
