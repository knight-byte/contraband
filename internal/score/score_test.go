package score_test

import (
	"testing"

	"github.com/knight-byte/contraband/internal/score"
)

func TestIsDownloader(t *testing.T) {
	rules := score.DefaultRules()
	tests := []struct {
		name string
		exe  string
		args []string
		want bool
	}{
		{"curl", "/usr/bin/curl", []string{"curl", "-s", "https://x"}, true},
		{"explicit bash -c", "/bin/bash", []string{"bash", "-c", "id"}, true},
		{"macOS sh re-exec as bash", "/bin/bash", []string{"sh", "-c", "node install.js"}, false},
		{"bash script without -c", "/bin/bash", []string{"bash", "build.sh"}, false},
		{"node", "/usr/local/bin/node", []string{"node", "install.js"}, false},
	}
	for _, tc := range tests {
		if got := rules.IsDownloader(tc.exe, tc.args); got != tc.want {
			t.Errorf("%s: IsDownloader = %v, want %v", tc.name, got, tc.want)
		}
	}
}
