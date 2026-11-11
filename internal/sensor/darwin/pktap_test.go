package darwin

import (
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/knight-byte/contraband/internal/event"
)

func TestParsePktap(t *testing.T) {
	file, err := os.Open("../../../testdata/pktap.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck // test fixture

	var events []event.Event
	if err := parsePktap(file, func(evt event.Event) bool { events = append(events, evt); return true }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3 (inbound SYN dropped): %+v", len(events), events)
	}

	answer := events[0]
	if answer.Kind != event.DNS || answer.Name != "example.com." || answer.PID != 16331 ||
		answer.Addrs[0] != netip.MustParseAddr("2606:4700:9c65:72db:f2fe:fa:ef6b:ff98") || answer.TTL != 26 {
		t.Errorf("dns answer on curl's behalf: %+v", answer)
	}

	syn := events[1]
	if syn.Kind != event.Connect || syn.PID != 1258 || syn.Exe != "Cursor Helper (P" || syn.Proto != "tcp" ||
		syn.Dst != netip.MustParseAddrPort("52.21.130.202:443") {
		t.Errorf("outbound syn: %+v", syn)
	}

	if multi := events[2]; multi.Name != "api2direct.cursor.sh." || len(multi.Addrs) != 3 || multi.PID != 1258 {
		t.Errorf("multi-record answer: %+v", multi)
	}
}

func TestPacketEmittedWithoutNextHeader(t *testing.T) {
	syn := "1794365429.301324 (proc curl:20407, out) IP 192.168.29.55.51035 > 1.1.1.1.80: Flags [S], length 0\n" +
		"\t0x0000:  4500 0028 0000 4000 4006 0000 c0a8 1d37\n" +
		"\t0x0010:  0101 0101 c75b 0050 0000 0000 0000 0000\n" +
		"\t0x0020:  5002 ffff 0000 0000\n"
	reader, writer := io.Pipe()
	got := make(chan event.Event, 1)
	go func() {
		_ = parsePktap(reader, func(evt event.Event) bool { got <- evt; return true })
	}()
	if _, err := writer.Write([]byte(syn)); err != nil {
		t.Fatal(err)
	}
	select {
	case evt := <-got:
		if evt.PID != 20407 || evt.Dst != netip.MustParseAddrPort("1.1.1.1:80") {
			t.Fatalf("unexpected event %+v", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("packet held back until another packet arrives")
	}
	_ = writer.Close()
}
