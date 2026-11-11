package darwin

import (
	"os"
	"slices"
	"testing"

	"github.com/knight-byte/contraband/internal/event"
)

func TestParseEslogger(t *testing.T) {
	file, err := os.Open("../../../testdata/eslogger.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck // test fixture

	var events []event.Event
	if err := parseEslogger(file, func(evt event.Event) bool { events = append(events, evt); return true }); err != nil {
		t.Fatal(err)
	}
	kinds := make([]event.Kind, 0, len(events))
	for _, evt := range events {
		kinds = append(kinds, evt.Kind)
	}
	if want := []event.Kind{event.Exec, event.Fork, event.Open, event.Exit}; !slices.Equal(kinds, want) {
		t.Fatalf("kinds = %v, want %v (non-dot open and junk dropped)", kinds, want)
	}

	exec := events[0]
	if exec.PID != 17602 || exec.PPID != 1576 || exec.UID != 501 || exec.Exe != "/usr/bin/curl" ||
		exec.Cwd != "/tmp/app/node_modules/evil" || !slices.Equal(exec.Args, []string{"curl", "-s", "http://1.1.1.1/"}) {
		t.Errorf("exec: %+v", exec)
	}
	if fork := events[1]; fork.PID != 17603 || fork.PPID != 1576 {
		t.Errorf("fork: %+v", fork)
	}
	if open := events[2]; open.PID != 17603 || open.Path != "/Users/dev/.aws/credentials" || open.Time.IsZero() {
		t.Errorf("open without time field: %+v", open)
	}
}
