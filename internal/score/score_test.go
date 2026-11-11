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

func TestIsAutoSession(t *testing.T) {
	rules := score.DefaultRules()
	tests := []struct {
		name string
		exe  string
		args []string
		want bool
	}{
		{"npm via env shebang", "/usr/bin/env", []string{"/usr/bin/env", "node", "/opt/homebrew/bin/npm", "install"}, true},
		{"claude versioned binary", "/Users/dev/.local/share/claude/versions/2.1.283", []string{"claude"}, true},
		{"node app", "/usr/local/bin/node", []string{"node", "server.js"}, true},
		{"curl", "/usr/bin/curl", []string{"curl", "https://x"}, false},
		{"argument named npm far down", "/bin/echo", []string{"echo", "a", "b", "npm"}, false},
	}
	for _, tc := range tests {
		if got := rules.IsAutoSession(tc.exe, tc.args); got != tc.want {
			t.Errorf("%s: IsAutoSession = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsCredentialRead(t *testing.T) {
	rules := score.DefaultRules()
	tests := []struct {
		name  string
		names []string
		path  string
		want  bool
	}{
		{"ssh reads its key during git push", []string{"ssh", "ssh"}, "/Users/dev/.ssh/id_ed25519", false},
		{"gh reads its token", []string{"gh"}, "/Users/dev/.config/gh/hosts.yml", false},
		{"git hook cats the ssh key", []string{"cat", "cat"}, "/Users/dev/.ssh/id_ed25519", true},
		{"gh reading aws credentials", []string{"gh"}, "/Users/dev/.aws/credentials", true},
		{"npm reads npmrc as node", []string{"node", "node", "npm"}, "/Users/dev/.npmrc", false},
		{"ordinary file", []string{"cat"}, "/Users/dev/notes.txt", false},
	}
	for _, tc := range tests {
		if got := rules.IsCredentialRead(tc.names, tc.path); got != tc.want {
			t.Errorf("%s: IsCredentialRead = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestProfileFor(t *testing.T) {
	rules := score.DefaultRules()
	rules.Profiles = append([]score.Profile{
		{Name: "payments", Programs: []string{"node"}, Directories: []string{"/work/payments"}, Enforce: score.EnforceStrict},
		{Name: "any-in-sandbox", Directories: []string{"/work/sandbox"}},
	}, rules.Profiles...)
	tests := []struct {
		name string
		exe  string
		args []string
		cwd  string
		want string
	}{
		{"node in payments", "/usr/bin/node", []string{"node", "server.js"}, "/work/payments/api", "payments"},
		{"node elsewhere", "/usr/bin/node", []string{"node", "server.js"}, "/work/other", ""},
		{"directory prefix is not a path prefix", "/usr/bin/node", []string{"node"}, "/work/payments-old", ""},
		{"anything in sandbox", "/usr/bin/python3", []string{"python3"}, "/work/sandbox", "any-in-sandbox"},
		{"claude uses the default agents profile", "/opt/claude/2.1", []string{"claude"}, "/work/other", "ai-agents"},
	}
	for _, tc := range tests {
		got := ""
		if profile := rules.ProfileFor(tc.exe, tc.args, tc.cwd); profile != nil {
			got = profile.Name
		}
		if got != tc.want {
			t.Errorf("%s: profile %q, want %q", tc.name, got, tc.want)
		}
	}
}
