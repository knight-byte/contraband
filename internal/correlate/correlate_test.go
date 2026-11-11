package correlate_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/knight-byte/contraband/internal/correlate"
	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
	"github.com/knight-byte/contraband/internal/sensor/replay"
)

func replayFixture(t *testing.T, path string, baseline map[string]map[string]bool) (*correlate.Session, []event.Flow) {
	t.Helper()
	events := make(chan event.Event, 64)
	if err := (replay.Sensor{Path: path}).Run(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	close(events)

	correlator := correlate.New(score.DefaultRules())
	session := &correlate.Session{ID: "test", RootPID: 1000, UID: 501, Command: "npm install", Baseline: baseline}
	correlator.StartSession(session)
	var flows []event.Flow
	for evt := range events {
		if flow, _ := correlator.Handle(evt); flow != nil {
			flows = append(flows, *flow)
		}
	}
	return correlator.EndSession("test"), flows
}

func TestScoring(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		baseline  map[string]map[string]bool
		pkg       string
		wantLevel score.Level
		wantScore int
	}{
		{name: "benign install", fixture: "../../testdata/benign-npm.jsonl", pkg: "bufferutil", wantLevel: score.Log, wantScore: 0},
		{name: "credential read then raw IP", fixture: "../../testdata/aws-exfil.jsonl", pkg: "foo", wantLevel: score.Alert, wantScore: 13},
		{
			name: "new destination against baseline", fixture: "../../testdata/aws-exfil.jsonl",
			baseline: map[string]map[string]bool{"foo": {"cdn.example.org": true}},
			pkg:      "foo", wantLevel: score.Alert, wantScore: 17,
		},
		{
			name: "package absent from baseline is not new behaviour", fixture: "../../testdata/aws-exfil.jsonl",
			baseline: map[string]map[string]bool{"": {"registry.npmjs.org": true}},
			pkg:      "foo", wantLevel: score.Alert, wantScore: 13,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			session, _ := replayFixture(t, tc.fixture, tc.baseline)
			for _, summary := range session.Summary() {
				if summary.Package != tc.pkg {
					continue
				}
				if summary.Level != tc.wantLevel || summary.Score != tc.wantScore {
					t.Fatalf("got level %s score %d, want %s %d (signals %v)", summary.Level, summary.Score, tc.wantLevel, tc.wantScore, summary.Signals)
				}
				return
			}
			if tc.wantScore != 0 {
				t.Fatalf("package %q missing from summary", tc.pkg)
			}
		})
	}
}

func TestFlowAttribution(t *testing.T) {
	_, flows := replayFixture(t, "../../testdata/benign-npm.jsonl", nil)
	first := flows[0]
	if first.Domain != "registry.npmjs.org" || first.Session != "test" || first.Chain[0] != "/usr/bin/npm" {
		t.Fatalf("unexpected flow %+v", first)
	}
	if flows[1].Package != "bufferutil" {
		t.Fatalf("install script flow not tagged: %+v", flows[1])
	}
}

func TestLateForkStillJoinsSession(t *testing.T) {
	correlator := correlate.New(score.DefaultRules())
	correlator.StartSession(&correlate.Session{ID: "late", RootPID: 1000, UID: 501, Command: "curl"})
	when := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	flow, _ := correlator.Handle(event.Event{
		Time: when, Kind: event.Connect, PID: 2000, PPID: 1000, UID: 501, Exe: "curl",
		Proto: "tcp", Dst: netip.MustParseAddrPort("93.184.215.14:443"),
	})
	if flow == nil || flow.Session != "late" {
		t.Fatalf("connection seen before its fork was not tied to the session: %+v", flow)
	}
	correlator.Handle(event.Event{Time: when, Kind: event.Fork, PID: 2000, PPID: 1000, UID: 501})
	if summary := correlator.EndSession("late").Summary(); len(summary) != 1 || summary[0].SentTo[0].Host != "93.184.215.14" {
		t.Fatalf("summary: %+v", summary)
	}
}

func TestConnectAfterExitStillJoinsSession(t *testing.T) {
	correlator := correlate.New(score.DefaultRules())
	correlator.StartSession(&correlate.Session{ID: "exit", RootPID: 1000, UID: 501, Command: "curl"})
	start := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	dst := netip.MustParseAddrPort("1.1.1.1:80")
	correlator.Handle(event.Event{Time: start, Kind: event.Exec, PID: 2000, PPID: 1000, UID: 501, Exe: "/usr/bin/curl"})
	correlator.Handle(event.Event{Time: start, Kind: event.Exit, PID: 2000})

	late, _ := correlator.Handle(event.Event{Time: start.Add(time.Second), Kind: event.Connect, PID: 2000, Proto: "tcp", Dst: dst})
	if late == nil || late.Session != "exit" {
		t.Fatalf("connection reported after exit lost its session: %+v", late)
	}
	stale, _ := correlator.Handle(event.Event{Time: start.Add(time.Minute), Kind: event.Connect, PID: 2000, Proto: "tcp", Dst: dst})
	if stale.Session != "" {
		t.Fatalf("exited process kept past retention: %+v", stale)
	}
}

func TestApprovedDestinationRaisesNothing(t *testing.T) {
	approved, err := policy.Parse([]byte("version: 1\nallow:\n  - domain: 45.9.148.3\n    package: foo\n"))
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan event.Event, 64)
	if err := (replay.Sensor{Path: "../../testdata/aws-exfil.jsonl"}).Run(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	close(events)
	correlator := correlate.New(score.DefaultRules())
	correlator.StartSession(&correlate.Session{ID: "allow", RootPID: 1000, UID: 501, Command: "npm install", Policy: approved})
	for evt := range events {
		correlator.Handle(evt)
	}
	for _, summary := range correlator.EndSession("allow").Summary() {
		if summary.Package == "foo" && summary.Score != 2 {
			t.Fatalf("approved destination still scored: %+v", summary)
		}
	}
}
