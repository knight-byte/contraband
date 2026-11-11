//go:build linux

package linux

//go:generate go tool -modfile=../../../tools/go.mod bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -type event contraband ../../../bpf/contraband.bpf.c -- -I../../../bpf/headers

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/sensor/dnsanswer"
)

const (
	kindExec    = 1
	kindFork    = 2
	kindExit    = 3
	kindOpen    = 4
	kindConnect = 5
	kindDNS     = 6

	familyIPv4 = 2
	protoTCP   = 6

	cgroupRoot        = "/sys/fs/cgroup"
	dropCheckInterval = 10 * time.Second
)

type Sensor struct {
	log     *slog.Logger
	objects contrabandObjects
	links   []link.Link
	mu      sync.Mutex
}

// New loads and attaches the probes. It needs root or CAP_BPF plus
// CAP_PERFMON, and a kernel with BTF (5.8 or later).
func New(logger *slog.Logger) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("linux sensor: %w", err)
	}
	sensor := &Sensor{log: logger}
	if err := loadContrabandObjects(&sensor.objects, nil); err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			logger.Error("kernel verifier rejected the probes", "log", fmt.Sprintf("%+v", verifierErr))
		}
		return nil, fmt.Errorf("linux sensor: %w", err)
	}
	for _, program := range []*ebpf.Program{
		sensor.objects.OnExec, sensor.objects.OnFork, sensor.objects.OnExit, sensor.objects.OnOpen,
		sensor.objects.OnTcpConnect, sensor.objects.OnUdpSendmsg, sensor.objects.OnUdpv6Sendmsg,
	} {
		attached, err := link.AttachTracing(link.TracingOptions{Program: program})
		if err != nil {
			return nil, errors.Join(fmt.Errorf("linux sensor: attach %s: %w", program, err), sensor.close())
		}
		sensor.links = append(sensor.links, attached)
	}
	ingress, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupRoot, Attach: ebpf.AttachCGroupInetIngress, Program: sensor.objects.OnIngress})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("linux sensor: attach dns: %w", err), sensor.close())
	}
	sensor.links = append(sensor.links, ingress)
	return sensor, nil
}

func (sensor *Sensor) Track(pid uint32) error {
	if err := sensor.objects.Tracked.Put(pid, uint8(1)); err != nil {
		return fmt.Errorf("track %d: %w", pid, err)
	}
	return nil
}

func (sensor *Sensor) Run(ctx context.Context, events chan<- event.Event) error {
	defer sensor.close() //nolint:errcheck // probes detach on process exit regardless
	reader, err := ringbuf.NewReader(sensor.objects.Events)
	if err != nil {
		return fmt.Errorf("linux sensor: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()
	go sensor.watchDrops(ctx, events)

	var raw contrabandEvent
	for {
		record, err := reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("linux sensor: %w", err)
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
			sensor.log.Warn("malformed probe event", "err", err)
			continue
		}
		evt, ok := sensor.translate(&raw)
		if !ok {
			continue
		}
		select {
		case events <- evt:
		case <-ctx.Done():
			return nil
		}
	}
}

func (sensor *Sensor) translate(raw *contrabandEvent) (event.Event, bool) {
	evt := event.Event{Time: time.Now(), PID: raw.Pid, PPID: raw.Ppid, UID: raw.Uid}
	data := raw.Data[:min(int(raw.DataLen), len(raw.Data))]
	switch raw.Kind {
	case kindExec:
		evt.Kind = event.Exec
		evt.Exe = string(data)
		enrichFromProc(&evt)
	case kindFork:
		evt.Kind = event.Fork
	case kindExit:
		evt.Kind = event.Exit
	case kindOpen:
		evt.Kind, evt.Path = event.Open, string(data)
	case kindConnect:
		evt.Kind, evt.Proto = event.Connect, "udp"
		if raw.Proto == protoTCP {
			evt.Proto = "tcp"
		}
		evt.Exe = commString(raw.Comm)
		addr := netip.AddrFrom16(raw.Daddr)
		if raw.Family == familyIPv4 {
			addr = netip.AddrFrom4([4]byte(raw.Daddr[:4]))
		}
		evt.Dst = netip.AddrPortFrom(addr.Unmap(), raw.Dport)
	case kindDNS:
		return dnsanswer.Parse(evt.Time, data)
	default:
		return evt, false
	}
	return evt, true
}

// enrichFromProc adds argv and working directory. Processes that exit before
// we look keep only what the probe captured.
func enrichFromProc(evt *event.Event) {
	procDir := "/proc/" + strconv.FormatUint(uint64(evt.PID), 10)
	cmdline, err := os.ReadFile(procDir + "/cmdline") //nolint:gosec // path is built from a numeric pid
	if err == nil && len(cmdline) > 0 {
		evt.Args = strings.Split(strings.TrimSuffix(string(cmdline), "\x00"), "\x00")
	}
	if cwd, err := os.Readlink(procDir + "/cwd"); err == nil {
		evt.Cwd = cwd
	}
	if exe, err := os.Readlink(procDir + "/exe"); err == nil {
		evt.Exe = exe
	}
}

// watchDrops turns ring-buffer overflows into health events, so lost
// visibility is reported rather than silent.
func (sensor *Sensor) watchDrops(ctx context.Context, events chan<- event.Event) {
	ticker := time.NewTicker(dropCheckInterval)
	defer ticker.Stop()
	var reported uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		var perCPU []uint64
		if err := sensor.objects.Drops.Lookup(uint32(0), &perCPU); err != nil {
			sensor.log.Warn("read drop counter", "err", err)
			continue
		}
		var total uint64
		for _, count := range perCPU {
			total += count
		}
		if total == reported {
			continue
		}
		msg := fmt.Sprintf("sensor dropped %d events; some activity was not seen", total-reported)
		reported = total
		select {
		case events <- event.Event{Time: time.Now(), Kind: event.Health, Msg: msg}:
		case <-ctx.Done():
			return
		}
	}
}

func (sensor *Sensor) close() error {
	sensor.mu.Lock()
	defer sensor.mu.Unlock()
	var errs []error
	for _, attached := range sensor.links {
		errs = append(errs, attached.Close())
	}
	sensor.links = nil
	errs = append(errs, sensor.objects.Close())
	return errors.Join(errs...)
}

func commString(comm [16]uint8) string {
	name, _, _ := bytes.Cut(comm[:], []byte{0})
	return string(name)
}
