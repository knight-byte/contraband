//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/knight-byte/contraband/internal/event"
)

// Absolute paths: the daemon runs as root and must not resolve tools via PATH.
const (
	esloggerPath = "/usr/bin/eslogger"
	tcpdumpPath  = "/usr/sbin/tcpdump"

	// pktap delivers packets faster than eslogger delivers the exec that
	// created the process, so network events wait this long to be handled
	// after the process events from the same moment.
	reorderDelay  = 300 * time.Millisecond
	reorderBuffer = 1024
)

var esloggerArgs = []string{"exec", "fork", "exit", "open"}

// pktapFilter keeps DNS answers, outbound TCP SYNs and QUIC Initial packets;
// libpcap cannot index transport headers behind IPv6, hence the ip6[] offsets.
const pktapFilter = "udp src port 53" +
	" or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)" +
	" or (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)" +
	" or (udp dst port 443 and udp[8] & 0xf0 == 0xc0)" +
	" or (ip6 and ip6[6] == 17 and ip6[42:2] == 443 and ip6[48] & 0xf0 == 0xc0)"

var pktapArgs = []string{"--immediate-mode", "-i", "pktap,all", "-k", "NPD", "-n", "-l", "-tt", "-x", "-Q", "inout", pktapFilter}

// Sensor observes processes through eslogger (Endpoint Security) and
// connections through tcpdump on the pktap interface, which tags every packet
// with its owning process. Both ship signed with macOS, so no entitlement is
// needed; the daemon must run as root and the launching terminal needs Full
// Disk Access for eslogger.
type Sensor struct{}

func New(*slog.Logger) (*Sensor, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("macOS sensor: the daemon must run as root")
	}
	for _, tool := range []string{esloggerPath, tcpdumpPath} {
		if _, err := os.Stat(tool); err != nil {
			return nil, fmt.Errorf("macOS sensor: %w", err)
		}
	}
	return &Sensor{}, nil
}

func (sensor *Sensor) Track(uint32) error { return nil }

func (sensor *Sensor) Run(ctx context.Context, events chan<- event.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	emit := func(evt event.Event) bool {
		select {
		case events <- evt:
			return true
		case <-ctx.Done():
			return false
		}
	}
	delayed := make(chan delayedEvent, reorderBuffer)
	emitLater := func(evt event.Event) bool {
		if evt.Kind == event.Connect {
			enrich(&evt)
		}
		select {
		case delayed <- delayedEvent{evt: evt, due: time.Now().Add(reorderDelay)}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go forwardDelayed(ctx, delayed, emit)

	errs := make(chan error, 2)
	go func() {
		errs <- runTool(ctx, esloggerPath, esloggerArgs, func(out io.Reader) error { return parseEslogger(out, emit) })
	}()
	go func() {
		errs <- runTool(ctx, tcpdumpPath, pktapArgs, func(out io.Reader) error { return parsePktap(out, emitLater) })
	}()

	err := <-errs
	cancel()
	return errors.Join(err, <-errs)
}

type delayedEvent struct {
	evt event.Event
	due time.Time
}

func forwardDelayed(ctx context.Context, delayed <-chan delayedEvent, emit func(event.Event) bool) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		var item delayedEvent
		select {
		case <-ctx.Done():
			return
		case item = <-delayed:
		}
		timer.Reset(time.Until(item.due))
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if !emit(item.evt) {
			return
		}
	}
}

// runTool runs one capture tool until it exits or ctx ends. A tool exiting on
// its own is an error: the daemon would otherwise run blind.
func runTool(ctx context.Context, path string, args []string, parse func(io.Reader) error) error {
	toolCtx, stop := context.WithCancel(ctx)
	defer stop()
	cmd := exec.CommandContext(toolCtx, path, args...) //nolint:gosec // fixed tool paths and arguments from this package
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	parseErr := parse(stdout)
	// A parser that stops early leaves the tool blocked on a full pipe.
	stop()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("%s exited: %w: %s", path, errors.Join(parseErr, waitErr), lastLine(stderr.String()))
}

func lastLine(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	return lines[len(lines)-1]
}

// enrich fills owner, parent and full executable path for connections from
// processes that started before the daemon, which eslogger never reported;
// pktap truncates process names to 16 bytes.
func enrich(evt *event.Event) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(evt.PID))
	if err != nil {
		return
	}
	evt.UID = info.Eproc.Ucred.Uid
	evt.PPID = uint32(info.Eproc.Ppid) //nolint:gosec // kernel pids are positive
	if path := executablePath(evt.PID); path != "" {
		evt.Exe = path
	}
}

// executablePath reads kern.procargs2, which starts with a 4-byte argc
// followed by the NUL-terminated executable path.
func executablePath(pid uint32) string {
	raw, err := unix.SysctlRaw("kern.procargs2", int(pid))
	if err != nil || len(raw) <= 4 {
		return ""
	}
	path, _, _ := bytes.Cut(raw[4:], []byte{0})
	return string(path)
}
