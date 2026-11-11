package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/knight-byte/contraband/internal/correlate"
	"github.com/knight-byte/contraband/internal/daemon"
	"github.com/knight-byte/contraband/internal/score"
)

func TestSupportsUnicode(t *testing.T) {
	tests := []struct {
		allValue, ctype, lang string
		want                  bool
	}{
		{"", "", "en_IN.UTF-8", true},
		{"", "", "C", false},
		{"C", "", "en_US.UTF-8", false},
		{"", "en_US.utf8", "C", true},
		{"", "", "", false},
	}
	for _, tc := range tests {
		t.Setenv("LC_ALL", tc.allValue)
		t.Setenv("LC_CTYPE", tc.ctype)
		t.Setenv("LANG", tc.lang)
		if got := supportsUnicode(); got != tc.want {
			t.Errorf("LC_ALL=%q LC_CTYPE=%q LANG=%q: got %v, want %v", tc.allValue, tc.ctype, tc.lang, got, tc.want)
		}
	}
}

func TestSummaryIsPlainWhenNotATerminal(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LANG", "C")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	path := filepath.Join(t.TempDir(), "out")
	file, err := os.Create(path) //nolint:gosec // path is under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	printSummary(file, "abc", "npm", daemon.EndResponse{Packages: []correlate.PackageSummary{
		{
			Package: "evil", Score: 13, Level: score.Alert,
			Evidence: correlate.Evidence{
				Read:   []string{"/data/.aws/credentials"},
				Ran:    []string{"curl"},
				SentTo: []correlate.Destination{{Host: "1.1.1.1", Note: "raw IP"}},
			},
		},
		{Package: "", Level: score.Log, Evidence: correlate.Evidence{SentTo: []correlate.Destination{{Host: "registry.npmjs.org"}, {Host: "1.1.1.1", Note: "allowed"}}}},
	}})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // path is under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	want := "\ncontraband: 1 package needs review (session abc)\n" +
		"\n  ALERT 13  evil\n" +
		"            read     /data/.aws/credentials\n" +
		"            ran      curl\n" +
		"            sent to  1.1.1.1 (raw IP)\n" +
		"  ok        npm  registry.npmjs.org, 1.1.1.1 (allowed)\n" +
		"\n  inspect:      contraband show abc\n" +
		"  if expected:  contraband allow -package evil 1.1.1.1\n"
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
