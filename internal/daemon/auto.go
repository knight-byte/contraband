package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/knight-byte/contraband/internal/correlate"
	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
	"github.com/knight-byte/contraband/internal/store"
)

// startAuto opens a session for a program from the auto_sessions rule that
// ran outside any session. It runs inside Correlator.Handle on the consume
// goroutine, the only goroutine that touches autoSessions.
func (daemon *Daemon) startAuto(ctx context.Context, evt event.Event) *correlate.Session {
	id, err := newID()
	if err != nil {
		daemon.config.Log.Error("automatic session", "err", err)
		return nil
	}
	command := strings.Join(evt.Args, " ")
	if command == "" {
		command = evt.Exe
	}
	approved, _, err := daemon.policies.approved(evt.UID, evt.Cwd)
	if err != nil {
		daemon.config.Log.Warn("automatic session uses an empty policy", "cwd", evt.Cwd, "err", err)
		approved, _ = policy.Parse(nil)
	}
	baseline, err := daemon.baseline(ctx, evt.UID, command, evt.Cwd, id)
	if err != nil {
		daemon.config.Log.Warn("automatic session has no baseline", "err", err)
	}
	if err := daemon.config.Sensor.Track(evt.PID); err != nil {
		daemon.config.Log.Warn("track automatic session", "pid", evt.PID, "err", err)
	}
	enforce := score.Stronger("", daemon.config.Rules.EnforceAuto)
	start := sessionStart{ID: id, UID: evt.UID, RootPID: evt.PID, Command: command, Cwd: evt.Cwd, PolicyHash: approved.Hash, Auto: true, Enforce: enforce}
	if err := daemon.store.Append(ctx, store.KindSessionStart, id, start); err != nil {
		daemon.config.Log.Error("automatic session", "err", err)
		return nil
	}
	daemon.autoSessions[id] = true
	return &correlate.Session{
		ID: id, RootPID: evt.PID, UID: evt.UID, Command: command, Cwd: evt.Cwd,
		Policy: approved, Baseline: baseline, Enforce: enforce, Auto: true,
		Agent: daemon.config.Rules.IsAgent(evt.Exe, evt.Args),
	}
}

func (daemon *Daemon) finishAuto(ctx context.Context, session *correlate.Session) {
	delete(daemon.autoSessions, session.ID)
	response := EndResponse{Packages: session.Summary()}
	if err := daemon.store.Append(ctx, store.KindSessionEnd, session.ID, response); err != nil {
		daemon.config.Log.Error("end automatic session", "err", err)
	}
	for _, pkg := range response.Packages {
		if pkg.Level != score.Log {
			daemon.notify(ctx, session.UID, "Contraband: review "+commandName(session.Command),
				fmt.Sprintf("Session %s flagged. Run: contraband show %s", session.ID, session.ID))
			return
		}
	}
}

// kill stops processes of an enforced session that broke its policy.
func (daemon *Daemon) kill(pids []uint32) {
	for _, pid := range pids {
		if pid <= 1 || int(pid) == os.Getpid() {
			continue
		}
		err := syscall.Kill(int(pid), syscall.SIGKILL)
		if err != nil && !errors.Is(err, syscall.ESRCH) {
			daemon.config.Log.Error("stop process", "pid", pid, "err", err)
		}
	}
}

// notify tells the user about sessions no terminal is watching. It never
// blocks the event pipeline.
func (daemon *Daemon) notify(ctx context.Context, uid uint32, title, message string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := desktopNotify(ctx, uid, title, message); err != nil {
			daemon.config.Log.Debug("desktop notification", "err", err)
		}
	}()
}

func commandName(command string) string {
	first, _, _ := strings.Cut(command, " ")
	if slash := strings.LastIndex(first, "/"); slash >= 0 {
		first = first[slash+1:]
	}
	return first
}
