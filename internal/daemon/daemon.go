package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knight-byte/contraband/internal/correlate"
	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
	"github.com/knight-byte/contraband/internal/store"
)

type Sensor interface {
	Run(ctx context.Context, events chan<- event.Event) error
	// Track asks the sensor to report file events for pid and its descendants.
	Track(pid uint32) error
}

type Config struct {
	Socket string
	DB     string
	Sensor Sensor
	Rules  *score.Rules
	Log    *slog.Logger
}

type openSession struct {
	uid          uint32
	proposalHash string
}

type Daemon struct {
	config     Config
	store      *store.Store
	mu         sync.Mutex
	correlator *correlate.Correlator
	sessions   map[string]openSession
	// autoSessions is touched only by the consume goroutine.
	autoSessions map[string]bool
	policies     policyStore
	approvals    *limiter
	hub          hub
	// Timestamps, in unix nanoseconds, of the newest process and network
	// events handled. Sensors may deliver the two kinds through separate
	// pipelines with different delays.
	latestProcess atomic.Int64
	latestNetwork atomic.Int64
}

const (
	eventBuffer     = 4096
	maxRequestBytes = 1 << 20
	shutdownTimeout = 5 * time.Second
	// Sensors deliver events with some delay; a session waits this long at
	// most for events that happened before it ended.
	drainTimeout  = 2 * time.Second
	drainInterval = 50 * time.Millisecond
)

func Run(ctx context.Context, config Config) error {
	if err := os.MkdirAll(filepath.Dir(config.DB), 0o700); err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	db, err := store.Open(ctx, config.DB)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // nothing left to flush on exit
	if err := db.Verify(ctx); err != nil {
		config.Log.Error("event log failed verification", "err", err)
		if err := db.Append(ctx, store.KindHealth, "", event.Alert{Time: time.Now(), Level: "health", Msg: "event log failed verification: " + err.Error()}); err != nil {
			return err
		}
	}

	daemon := &Daemon{
		config: config, store: db, correlator: correlate.New(config.Rules), sessions: map[string]openSession{}, autoSessions: map[string]bool{},
		policies: policyStore{dir: filepath.Join(filepath.Dir(config.DB), "policies")}, approvals: newLimiter(), hub: newHub(),
	}

	listener, err := listen(ctx, config.Socket)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           daemon.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       withPeer,
		ErrorLog:          slog.NewLogLogger(config.Log.Handler(), slog.LevelWarn),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events := make(chan event.Event, eventBuffer)
	errs := make(chan error, 2)
	go func() {
		if err := config.Sensor.Run(ctx, events); err != nil {
			errs <- err
		}
	}()
	go func() { errs <- server.Serve(listener) }()
	daemon.correlator.OnAutoSession(func(evt event.Event) *correlate.Session { return daemon.startAuto(ctx, evt) })
	go daemon.consume(ctx, events)

	config.Log.Info("daemon started", "socket", config.Socket, "db", config.DB)
	select {
	case <-ctx.Done():
	case err = <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer stop()
	return errors.Join(err, server.Shutdown(shutdownCtx))
}

// listen replaces a stale socket but refuses to remove anything else at that path.
func listen(ctx context.Context, path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("listen: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	// Any local user may connect; every request is authorised by peer credentials.
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // see comment above
		return nil, errors.Join(fmt.Errorf("listen: %w", err), listener.Close())
	}
	return listener, nil
}

func (daemon *Daemon) consume(ctx context.Context, events <-chan event.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-events:
			daemon.config.Log.Debug("sensor event", "event", evt)
			daemon.mu.Lock()
			result := daemon.correlator.Handle(evt)
			daemon.mu.Unlock()
			daemon.kill(result.Kill)
			for _, ended := range result.Ended {
				daemon.finishAuto(ctx, ended)
			}
			flow, alerts := result.Flow, result.Alerts
			if evt.Kind == event.Connect || evt.Kind == event.DNS {
				daemon.latestNetwork.Store(evt.Time.UnixNano())
			} else {
				daemon.latestProcess.Store(evt.Time.UnixNano())
			}
			if flow != nil {
				daemon.record(ctx, store.KindFlow, flow.Session, Message{Flow: flow})
			}
			for index := range alerts {
				kind := store.KindAlert
				if alerts[index].Level == "health" {
					kind = store.KindHealth
				}
				daemon.record(ctx, kind, alerts[index].Session, Message{Alert: &alerts[index]})
				if daemon.autoSessions[alerts[index].Session] && kind == store.KindAlert {
					daemon.notify(ctx, alerts[index].UID, "Contraband: "+strings.ToUpper(alerts[index].Level), alerts[index].Msg)
				}
			}
		}
	}
}

// record writes to the log before anyone is shown the message, so a muted or
// killed client never hides an alert.
func (daemon *Daemon) record(ctx context.Context, kind, session string, msg Message) {
	var body any = msg.Flow
	if msg.Alert != nil {
		body = msg.Alert
	}
	if err := daemon.store.Append(ctx, kind, session, body); err != nil {
		daemon.config.Log.Error("append to event log", "kind", kind, "err", err)
	}
	daemon.hub.publish(msg)
}

type StartRequest struct {
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
	Policy  []byte `json:"policy,omitempty"`
	Enforce string `json:"enforce,omitempty"`
}

type StartResponse struct {
	ID string `json:"id"`
	// PolicyPending is set when the repository's policy file differs from
	// the approved one; only the approved one is enforced.
	PolicyPending bool `json:"policy_pending"`
}

type PolicyResponse struct {
	Approved []byte `json:"approved"`
}

type ApproveRequest struct {
	Cwd      string `json:"cwd"`
	Policy   []byte `json:"policy"`
	Password string `json:"password"`
}

type ShowResponse struct {
	Command  string                     `json:"command"`
	Cwd      string                     `json:"cwd"`
	Started  time.Time                  `json:"started"`
	Flows    []event.Flow               `json:"flows"`
	Packages []correlate.PackageSummary `json:"packages"`
}

type policyApproval struct {
	UID  uint32 `json:"uid"`
	Cwd  string `json:"cwd"`
	Hash string `json:"hash"`
}

type EndRequest struct {
	PolicyHash string `json:"policy_hash"`
	Auto       bool   `json:"auto,omitempty"`
	Enforce    string `json:"enforce,omitempty"`
}

type EndResponse struct {
	Packages      []correlate.PackageSummary `json:"packages"`
	PolicyChanged bool                       `json:"policy_changed"`
}

type DiffResponse struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

type sessionStart struct {
	ID         string `json:"id"`
	UID        uint32 `json:"uid"`
	RootPID    uint32 `json:"root_pid"`
	Command    string `json:"command"`
	Cwd        string `json:"cwd"`
	PolicyHash string `json:"policy_hash"`
	Auto       bool   `json:"auto,omitempty"`
	Enforce    string `json:"enforce,omitempty"`
}

func (daemon *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", daemon.startSession)
	mux.HandleFunc("POST /v1/sessions/{id}/end", daemon.endSession)
	mux.HandleFunc("GET /v1/stream", daemon.stream)
	mux.HandleFunc("GET /v1/diff", daemon.diff)
	mux.HandleFunc("GET /v1/export", daemon.export)
	mux.HandleFunc("GET /v1/sessions/{id}", daemon.show)
	mux.HandleFunc("GET /v1/policy", daemon.approvedPolicy)
	mux.HandleFunc("POST /v1/policy/approve", daemon.approvePolicy)
	return http.MaxBytesHandler(mux, maxRequestBytes)
}

func (daemon *Daemon) startSession(writer http.ResponseWriter, request *http.Request) {
	caller := peerFrom(request.Context())
	var body StartRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		httpError(writer, http.StatusBadRequest, err)
		return
	}
	if _, err := policy.Parse(body.Policy); err != nil {
		httpError(writer, http.StatusBadRequest, err)
		return
	}
	if !score.ValidEnforce(body.Enforce) {
		httpError(writer, http.StatusBadRequest, errors.New("enforce: want risk or strict"))
		return
	}
	approved, approvedContent, err := daemon.policies.approved(caller.UID, body.Cwd)
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	ctx := request.Context()
	id, err := newID()
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	baseline, err := daemon.baseline(ctx, caller.UID, body.Command, body.Cwd, id)
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	if err := daemon.config.Sensor.Track(caller.PID); err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	start := sessionStart{ID: id, UID: caller.UID, RootPID: caller.PID, Command: body.Command, Cwd: body.Cwd, PolicyHash: approved.Hash, Enforce: body.Enforce}
	if err := daemon.store.Append(ctx, store.KindSessionStart, id, start); err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}

	daemon.mu.Lock()
	daemon.sessions[id] = openSession{uid: caller.UID, proposalHash: policy.Hash(body.Policy)}
	daemon.correlator.StartSession(&correlate.Session{
		ID: id, RootPID: caller.PID, UID: caller.UID, Command: body.Command, Cwd: body.Cwd,
		Policy: approved, Baseline: baseline, Enforce: body.Enforce,
		Agent: daemon.config.Rules.IsAgent(commandName(body.Command), nil),
	})
	daemon.mu.Unlock()
	pending := len(body.Policy) > 0 && policy.Hash(body.Policy) != policy.Hash(approvedContent)
	writeJSON(writer, StartResponse{ID: id, PolicyPending: pending})
}

func (daemon *Daemon) endSession(writer http.ResponseWriter, request *http.Request) {
	caller := peerFrom(request.Context())
	id := request.PathValue("id")
	var body EndRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		httpError(writer, http.StatusBadRequest, err)
		return
	}
	daemon.mu.Lock()
	open, found := daemon.sessions[id]
	daemon.mu.Unlock()
	if !found || !caller.canAccess(open.uid) {
		httpError(writer, http.StatusNotFound, errors.New("no such session"))
		return
	}
	daemon.drain(request.Context(), time.Now())

	daemon.mu.Lock()
	if _, stillOpen := daemon.sessions[id]; !stillOpen {
		daemon.mu.Unlock()
		httpError(writer, http.StatusNotFound, errors.New("no such session"))
		return
	}
	delete(daemon.sessions, id)
	session := daemon.correlator.EndSession(id)
	daemon.mu.Unlock()

	ctx := request.Context()
	response := EndResponse{Packages: session.Summary(), PolicyChanged: body.PolicyHash != open.proposalHash}
	if response.PolicyChanged {
		daemon.record(ctx, store.KindHealth, id, Message{Alert: &event.Alert{
			Time: time.Now(), Session: id, UID: session.UID, Level: "health", Msg: policy.FileName + " changed during the session; the session kept its starting policy",
		}})
	}
	if err := daemon.store.Append(ctx, store.KindSessionEnd, id, response); err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	writeJSON(writer, response)
}

// drain waits until both process and network events stamped at or after
// cutoff have been handled, or until drainTimeout, so late sensor events
// still reach a session.
func (daemon *Daemon) drain(ctx context.Context, cutoff time.Time) {
	ctx, cancel := context.WithTimeout(ctx, drainTimeout)
	defer cancel()
	ticker := time.NewTicker(drainInterval)
	defer ticker.Stop()
	for daemon.latestProcess.Load() < cutoff.UnixNano() || daemon.latestNetwork.Load() < cutoff.UnixNano() {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (daemon *Daemon) show(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	id := request.PathValue("id")
	start, err := daemon.ownedSession(ctx, peerFrom(ctx), id)
	if err != nil {
		httpError(writer, http.StatusNotFound, err)
		return
	}
	flows, err := daemon.flows(ctx, id)
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	response := ShowResponse{Command: start.Command, Cwd: start.Cwd, Flows: flows}
	if ends, err := daemon.store.Bodies(ctx, id, store.KindSessionEnd); err == nil && len(ends) > 0 {
		var end EndResponse
		if json.Unmarshal(ends[0], &end) == nil {
			response.Packages = end.Packages
		}
	}
	if len(flows) > 0 {
		response.Started = flows[0].Time
	}
	writeJSON(writer, response)
}

func (daemon *Daemon) approvedPolicy(writer http.ResponseWriter, request *http.Request) {
	caller := peerFrom(request.Context())
	if !caller.ok {
		httpError(writer, http.StatusForbidden, errors.New("unknown caller"))
		return
	}
	_, content, err := daemon.policies.approved(caller.UID, request.URL.Query().Get("cwd"))
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	writeJSON(writer, PolicyResponse{Approved: content})
}

// approvePolicy makes a proposed policy enforceable. Adding any destination
// needs the caller's account password every time, so neither an AI agent nor
// the code being audited can approve its own destinations, even with cached
// sudo rights. Removing destinations only tightens the policy and needs none.
func (daemon *Daemon) approvePolicy(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	caller := peerFrom(ctx)
	if !caller.ok {
		httpError(writer, http.StatusForbidden, errors.New("unknown caller"))
		return
	}
	var body ApproveRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		httpError(writer, http.StatusBadRequest, err)
		return
	}
	if !filepath.IsAbs(body.Cwd) {
		httpError(writer, http.StatusBadRequest, errors.New("cwd must be absolute"))
		return
	}
	parsed, err := policy.Parse(body.Policy)
	if err != nil {
		httpError(writer, http.StatusBadRequest, err)
		return
	}
	current, _, err := daemon.policies.approved(caller.UID, body.Cwd)
	if err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	now := time.Now()
	if added, _ := policy.Diff(current, parsed); len(added) > 0 {
		if !daemon.approvals.allowed(caller.UID, now) {
			httpError(writer, http.StatusTooManyRequests, ErrTooManyTries)
			return
		}
		if err := daemon.verifyAndRecord(ctx, caller.UID, body, now); err != nil {
			httpError(writer, http.StatusForbidden, err)
			return
		}
	}
	if err := daemon.policies.approve(caller.UID, body.Cwd, body.Policy); err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	if err := daemon.store.Append(ctx, store.KindPolicyApproved, "", policyApproval{UID: caller.UID, Cwd: body.Cwd, Hash: parsed.Hash}); err != nil {
		httpError(writer, http.StatusInternalServerError, err)
		return
	}
	writeJSON(writer, PolicyResponse{Approved: body.Policy})
}

func (daemon *Daemon) verifyAndRecord(ctx context.Context, uid uint32, body ApproveRequest, now time.Time) error {
	if err := verifyPassword(ctx, uid, body.Password); err != nil {
		daemon.approvals.fail(uid, now)
		daemon.record(ctx, store.KindHealth, "", Message{Alert: &event.Alert{
			Time: now, UID: uid, Level: "health", Msg: "policy approval refused for " + body.Cwd,
		}})
		return err
	}
	return nil
}

func (daemon *Daemon) stream(writer http.ResponseWriter, request *http.Request) {
	caller := peerFrom(request.Context())
	flusher, ok := writer.(http.Flusher)
	if !ok {
		httpError(writer, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	session := request.URL.Query().Get("session")
	subscription := daemon.hub.subscribe()
	defer daemon.hub.unsubscribe(subscription)

	writer.Header().Set("Content-Type", "application/x-ndjson")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	encoder := json.NewEncoder(writer)
	for {
		select {
		case <-request.Context().Done():
			return
		case msg := <-subscription:
			if !msg.visibleTo(caller, session) {
				continue
			}
			if err := encoder.Encode(msg); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (daemon *Daemon) diff(writer http.ResponseWriter, request *http.Request) {
	caller := peerFrom(request.Context())
	ctx := request.Context()
	query := request.URL.Query()
	before, err := daemon.ownedDestinations(ctx, caller, query.Get("a"))
	if err != nil {
		httpError(writer, http.StatusNotFound, err)
		return
	}
	after, err := daemon.ownedDestinations(ctx, caller, query.Get("b"))
	if err != nil {
		httpError(writer, http.StatusNotFound, err)
		return
	}
	response := DiffResponse{Added: []string{}, Removed: []string{}}
	for key := range after {
		if !before[key] {
			response.Added = append(response.Added, key)
		}
	}
	for key := range before {
		if !after[key] {
			response.Removed = append(response.Removed, key)
		}
	}
	slices.Sort(response.Added)
	slices.Sort(response.Removed)
	writeJSON(writer, response)
}

func (daemon *Daemon) export(writer http.ResponseWriter, request *http.Request) {
	if !peerFrom(request.Context()).isRoot() {
		httpError(writer, http.StatusForbidden, errors.New("export requires root"))
		return
	}
	ctx := request.Context()
	if err := daemon.store.Verify(ctx); err != nil {
		httpError(writer, http.StatusConflict, err)
		return
	}
	writer.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(writer)
	if err := daemon.store.Each(ctx, false, func(record store.Record) error { return encoder.Encode(record) }); err != nil {
		daemon.config.Log.Error("export", "err", err)
	}
}

func (daemon *Daemon) baseline(ctx context.Context, uid uint32, command, cwd, exclude string) (map[string]map[string]bool, error) {
	previous, err := daemon.store.PreviousSession(ctx, uid, command, cwd, exclude)
	if err != nil || previous == "" {
		return nil, err
	}
	flows, err := daemon.flows(ctx, previous)
	if err != nil {
		return nil, err
	}
	baseline := map[string]map[string]bool{}
	for _, flow := range flows {
		if baseline[flow.Package] == nil {
			baseline[flow.Package] = map[string]bool{}
		}
		baseline[flow.Package][destination(flow)] = true
	}
	return baseline, nil
}

func (daemon *Daemon) ownedSession(ctx context.Context, caller peer, session string) (sessionStart, error) {
	starts, err := daemon.store.Bodies(ctx, session, store.KindSessionStart)
	if err != nil {
		return sessionStart{}, err
	}
	var start sessionStart
	if len(starts) == 0 || json.Unmarshal(starts[0], &start) != nil || !caller.canAccess(start.UID) {
		return sessionStart{}, fmt.Errorf("no such session %q", session)
	}
	return start, nil
}

func (daemon *Daemon) ownedDestinations(ctx context.Context, caller peer, session string) (map[string]bool, error) {
	start, err := daemon.ownedSession(ctx, caller, session)
	if err != nil {
		return nil, err
	}
	flows, err := daemon.flows(ctx, session)
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, flow := range flows {
		pkg := flow.Package
		if pkg == "" {
			pkg = start.Command
		}
		keys[pkg+" → "+destination(flow)] = true
	}
	return keys, nil
}

func (daemon *Daemon) flows(ctx context.Context, session string) ([]event.Flow, error) {
	bodies, err := daemon.store.Bodies(ctx, session, store.KindFlow)
	if err != nil {
		return nil, err
	}
	flows := make([]event.Flow, 0, len(bodies))
	for _, body := range bodies {
		var flow event.Flow
		if err := json.Unmarshal(body, &flow); err != nil {
			return nil, fmt.Errorf("decode flow: %w", err)
		}
		flows = append(flows, flow)
	}
	return flows, nil
}

func destination(flow event.Flow) string {
	if flow.Domain != "" {
		return flow.Domain
	}
	return flow.Dst.Addr().String()
}

func newID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func httpError(writer http.ResponseWriter, status int, err error) {
	http.Error(writer, err.Error(), status)
}
