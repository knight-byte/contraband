package event

import (
	"net/netip"
	"time"
)

type Kind string

const (
	Exec    Kind = "exec"
	Fork    Kind = "fork"
	Exit    Kind = "exit"
	Open    Kind = "open"
	DNS     Kind = "dns"
	Connect Kind = "connect"
	Health  Kind = "health"
)

// Event is the schema every platform sensor emits, so correlation and scoring
// are written once.
type Event struct {
	Time  time.Time      `json:"time"`
	Kind  Kind           `json:"kind"`
	PID   uint32         `json:"pid,omitempty"`
	PPID  uint32         `json:"ppid,omitempty"`
	UID   uint32         `json:"uid,omitempty"`
	Exe   string         `json:"exe,omitempty"`
	Args  []string       `json:"args,omitempty"`
	Cwd   string         `json:"cwd,omitempty"`
	Path  string         `json:"path,omitempty"`
	Name  string         `json:"name,omitempty"`
	Addrs []netip.Addr   `json:"addrs,omitempty"`
	TTL   uint32         `json:"ttl,omitempty"`
	Proto string         `json:"proto,omitempty"`
	Dst   netip.AddrPort `json:"dst,omitzero"`
	SNI   string         `json:"sni,omitempty"`
	Msg   string         `json:"msg,omitempty"`
}

type Flow struct {
	Time    time.Time      `json:"time"`
	Session string         `json:"session,omitempty"`
	Package string         `json:"package,omitempty"`
	PID     uint32         `json:"pid"`
	UID     uint32         `json:"uid"`
	Chain   []string       `json:"chain"`
	Domain  string         `json:"domain,omitempty"`
	Dst     netip.AddrPort `json:"dst"`
	Proto   string         `json:"proto"`
	Verdict string         `json:"verdict,omitempty"`
}

type Alert struct {
	Time    time.Time `json:"time"`
	Session string    `json:"session,omitempty"`
	Package string    `json:"package,omitempty"`
	UID     uint32    `json:"uid,omitempty"`
	Level   string    `json:"level"`
	Score   int       `json:"score"`
	Signals []string  `json:"signals"`
	Msg     string    `json:"msg"`
}
