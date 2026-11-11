package darwin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/knight-byte/contraband/internal/event"
)

type esProcess struct {
	AuditToken struct {
		PID  uint32 `json:"pid"`
		EUID uint32 `json:"euid"`
	} `json:"audit_token"`
	PPID       uint32 `json:"ppid"`
	Executable struct {
		Path string `json:"path"`
	} `json:"executable"`
}

type esFile struct {
	Path string `json:"path"`
}

type esMessage struct {
	Time    time.Time `json:"time"`
	Process esProcess `json:"process"`
	Event   struct {
		Exec *struct {
			Target esProcess `json:"target"`
			Args   []string  `json:"args"`
			Cwd    *esFile   `json:"cwd"`
		} `json:"exec"`
		Fork *struct {
			Child esProcess `json:"child"`
		} `json:"fork"`
		Exit *struct{} `json:"exit"`
		Open *struct {
			File esFile `json:"file"`
		} `json:"open"`
	} `json:"event"`
}

var (
	openKey = []byte(`"open":{`)
	dotPath = []byte(`/.`)
)

// parseEslogger reads eslogger JSON lines. Open events are by far the most
// frequent, and credentials live under dotfiles or dot directories, so opens
// without "/." in the line are dropped before decoding.
func parseEslogger(reader io.Reader, emit func(event.Event) bool) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 256*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.Contains(line, openKey) && !bytes.Contains(line, dotPath) {
			continue
		}
		var msg esMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		evt, ok := msg.toEvent()
		if ok && !emit(evt) {
			return nil
		}
	}
	return scanner.Err()
}

func (msg *esMessage) toEvent() (event.Event, bool) {
	actor := msg.Process
	if msg.Time.IsZero() {
		msg.Time = time.Now()
	}
	evt := event.Event{Time: msg.Time, PID: actor.AuditToken.PID, PPID: actor.PPID, UID: actor.AuditToken.EUID}
	switch {
	case msg.Event.Exec != nil:
		target := msg.Event.Exec.Target
		evt.Kind, evt.Exe, evt.Args = event.Exec, target.Executable.Path, msg.Event.Exec.Args
		evt.UID = target.AuditToken.EUID
		if msg.Event.Exec.Cwd != nil {
			evt.Cwd = msg.Event.Exec.Cwd.Path
		}
	case msg.Event.Fork != nil:
		child := msg.Event.Fork.Child
		evt.Kind, evt.PID, evt.PPID = event.Fork, child.AuditToken.PID, actor.AuditToken.PID
	case msg.Event.Exit != nil:
		evt.Kind = event.Exit
	case msg.Event.Open != nil:
		evt.Kind, evt.Path = event.Open, msg.Event.Open.File.Path
	default:
		return evt, false
	}
	return evt, evt.PID != 0
}
