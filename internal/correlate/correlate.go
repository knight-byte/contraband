package correlate

import (
	"cmp"
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
)

const (
	// Apps keep using an address long after its DNS TTL, so names are held
	// at least this long.
	minNameTTL    = 10 * time.Minute
	maxNames      = 50_000
	maxChainDepth = 16
	// Sensors can report a process's last connections after its exit, so
	// exited processes are kept this long.
	exitRetention = 30 * time.Second
	// An automatic session closes this long after its root process exits,
	// once late sensor events have arrived.
	autoEndDelay = 3 * time.Second
)

// Result is everything one event caused.
type Result struct {
	Flow   *event.Flow
	Alerts []event.Alert
	// Kill lists processes to stop because an enforced session broke its policy.
	Kill []uint32
	// Ended lists automatic sessions whose root process has exited.
	Ended []*Session
}

type Session struct {
	ID      string
	RootPID uint32
	UID     uint32
	Command string
	Cwd     string
	Policy  *policy.Policy
	// Baseline maps package to destinations seen in the previous run of the
	// same command. Only packages present in it are compared, so a new
	// dependency or an empty previous run raises nothing.
	Baseline map[string]map[string]bool
	// Enforce is an enforcement mode from the score package: risk stops a
	// process once its session reaches ALERT, strict also stops any process
	// that connects anywhere not approved, not a registry and not local.
	Enforce string
	// Agent marks sessions of AI agents, whose own research traffic is not
	// compared with the previous run.
	Agent bool
	// Auto marks sessions the daemon started itself; they end when their
	// root process exits instead of when a client says so.
	Auto bool

	rootExited time.Time
	cards      map[string]*score.Card
	evidence   map[string]*Evidence
	alerted    map[string]score.Level
}

type Destination struct {
	Host string `json:"host"`
	Note string `json:"note,omitempty"`
}

// Evidence is what a package did, in the order first seen: the facts an
// alert shows instead of rule names.
type Evidence struct {
	Read   []string      `json:"read,omitempty"`
	Ran    []string      `json:"ran,omitempty"`
	SentTo []Destination `json:"sent_to,omitempty"`
}

func (evidence *Evidence) addRead(path string) {
	if !slices.Contains(evidence.Read, path) {
		evidence.Read = append(evidence.Read, path)
	}
}

func (evidence *Evidence) addRan(exe string) {
	if !slices.Contains(evidence.Ran, exe) {
		evidence.Ran = append(evidence.Ran, exe)
	}
}

func (evidence *Evidence) addDestination(host, note string) {
	for index := range evidence.SentTo {
		if evidence.SentTo[index].Host == host {
			return
		}
	}
	evidence.SentTo = append(evidence.SentTo, Destination{Host: host, Note: note})
}

// describe renders the evidence as one line, e.g.
// "read /home/dev/.aws/credentials, ran curl, sent to 1.1.1.1".
func (evidence *Evidence) describe() string {
	var parts []string
	if len(evidence.Read) > 0 {
		parts = append(parts, "read "+listWithMore(evidence.Read))
	}
	if len(evidence.Ran) > 0 {
		parts = append(parts, "ran "+listWithMore(evidence.Ran))
	}
	if len(evidence.SentTo) > 0 {
		hosts := make([]string, 0, len(evidence.SentTo))
		for _, destination := range evidence.SentTo {
			hosts = append(hosts, destination.Host)
		}
		parts = append(parts, "sent to "+listWithMore(hosts))
	}
	return strings.Join(parts, ", ")
}

func listWithMore(items []string) string {
	const shown = 2
	if len(items) <= shown {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s +%d more", strings.Join(items[:shown], ", "), len(items)-shown)
}

type PackageSummary struct {
	Package string      `json:"package"`
	Score   int         `json:"score"`
	Level   score.Level `json:"level"`
	Signals []string    `json:"signals,omitempty"`
	Evidence
}

func (session *Session) Summary() []PackageSummary {
	packages := map[string]bool{}
	for pkg := range session.evidence {
		packages[pkg] = true
	}
	for pkg := range session.cards {
		packages[pkg] = true
	}
	summaries := make([]PackageSummary, 0, len(packages))
	for pkg := range packages {
		summary := PackageSummary{Package: pkg, Level: score.Log}
		if card := session.cards[pkg]; card != nil {
			summary.Score, summary.Level, summary.Signals = card.Score, score.LevelOf(card.Score), card.Signals
		}
		if evidence := session.evidence[pkg]; evidence != nil {
			summary.Evidence = *evidence
		}
		summaries = append(summaries, summary)
	}
	slices.SortFunc(summaries, func(left, right PackageSummary) int {
		return cmp.Or(cmp.Compare(right.Score, left.Score), cmp.Compare(left.Package, right.Package))
	})
	return summaries
}

func (session *Session) evidenceFor(pkg string) *Evidence {
	evidence := session.evidence[pkg]
	if evidence == nil {
		evidence = &Evidence{}
		session.evidence[pkg] = evidence
	}
	return evidence
}

func (session *Session) card(pkg string) *score.Card {
	card := session.cards[pkg]
	if card == nil {
		card = &score.Card{}
		session.cards[pkg] = card
	}
	return card
}

type process struct {
	parentPID uint32
	uid       uint32
	exe       string
	names     []string
	session   *Session
	pkg       string
	exited    time.Time
}

type exitRecord struct {
	pid  uint32
	proc *process
	at   time.Time
}

type resolvedName struct {
	domain  string
	expires time.Time
}

// Correlator is not safe for concurrent use; the daemon feeds it from one goroutine.
type Correlator struct {
	rules     *score.Rules
	autoStart func(event.Event) *Session
	processes map[uint32]*process
	exits     []exitRecord
	names     map[netip.Addr]resolvedName
	sessions  map[string]*Session
}

func New(rules *score.Rules) *Correlator {
	return &Correlator{
		rules:     rules,
		processes: map[uint32]*process{},
		names:     map[netip.Addr]resolvedName{},
		sessions:  map[string]*Session{},
	}
}

// OnAutoSession sets the function that creates a session when a program from
// the auto_sessions rule runs outside any session. It runs inside Handle.
func (correlator *Correlator) OnAutoSession(start func(event.Event) *Session) {
	correlator.autoStart = start
}

func (correlator *Correlator) StartSession(session *Session) {
	session.cards = map[string]*score.Card{}
	session.evidence = map[string]*Evidence{}
	session.alerted = map[string]score.Level{}
	correlator.sessions[session.ID] = session
	root := correlator.processes[session.RootPID]
	if root == nil {
		root = &process{uid: session.UID}
		correlator.processes[session.RootPID] = root
	}
	root.session = session
}

func (correlator *Correlator) EndSession(id string) *Session {
	session := correlator.sessions[id]
	delete(correlator.sessions, id)
	for _, proc := range correlator.processes {
		if proc.session == session {
			proc.session = nil
		}
	}
	return session
}

func (correlator *Correlator) Handle(evt event.Event) Result {
	correlator.forgetExited(evt.Time)
	result := Result{Ended: correlator.endFinishedAuto(evt.Time)}
	switch evt.Kind {
	case event.Fork:
		correlator.fork(evt)
	case event.Exec:
		result.Alerts = correlator.exec(evt)
	case event.Exit:
		if proc := correlator.processes[evt.PID]; proc != nil {
			proc.exited = evt.Time
			correlator.exits = append(correlator.exits, exitRecord{pid: evt.PID, proc: proc, at: evt.Time})
			if proc.session != nil && proc.session.Auto && proc.session.RootPID == evt.PID {
				proc.session.rootExited = evt.Time
			}
		}
	case event.DNS:
		correlator.learnName(evt)
	case event.Open:
		if proc := correlator.processes[evt.PID]; proc != nil && proc.session != nil && correlator.rules.IsCredentialRead(proc.names, evt.Path) {
			proc.session.evidenceFor(proc.pkg).addRead(evt.Path)
		}
	case event.Connect:
		result.Flow, result.Alerts = correlator.connect(evt)
		if result.Flow != nil && result.Flow.Verdict == policy.Blocked {
			result.Kill = correlator.subtree(evt.PID)
		}
	case event.Health:
		result.Alerts = []event.Alert{{Time: evt.Time, Level: "health", Msg: evt.Msg}}
	}
	if result.Kill == nil && correlator.enforcedAlert(evt.PID, result.Alerts) {
		result.Kill = correlator.subtree(evt.PID)
	}
	return result
}

func (correlator *Correlator) enforcedAlert(pid uint32, alerts []event.Alert) bool {
	proc := correlator.processes[pid]
	if proc == nil || proc.session == nil || proc.session.Enforce == "" || proc.session.Enforce == score.EnforceOff {
		return false
	}
	for _, alert := range alerts {
		if alert.Level == string(score.Alert) {
			return true
		}
	}
	return false
}

// subtree returns pid and every live descendant. A client-started session's
// root is the contraband CLI itself and is never included.
func (correlator *Correlator) subtree(pid uint32) []uint32 {
	root := correlator.processes[pid]
	if root == nil || root.session == nil {
		return nil
	}
	var pids []uint32
	for candidate, proc := range correlator.processes {
		if !proc.exited.IsZero() || proc.session != root.session {
			continue
		}
		if candidate == root.session.RootPID && !root.session.Auto {
			continue
		}
		for ancestor, depth := candidate, 0; ancestor != 0 && depth < maxChainDepth; depth++ {
			if ancestor == pid {
				pids = append(pids, candidate)
				break
			}
			next := correlator.processes[ancestor]
			if next == nil {
				break
			}
			ancestor = next.parentPID
		}
	}
	slices.Sort(pids)
	return pids
}

func (correlator *Correlator) endFinishedAuto(now time.Time) []*Session {
	var ended []*Session
	for id, session := range correlator.sessions {
		if session.Auto && !session.rootExited.IsZero() && now.Sub(session.rootExited) >= autoEndDelay {
			ended = append(ended, correlator.EndSession(id))
		}
	}
	return ended
}

// forgetExited drops processes that exited more than exitRetention ago,
// unless the pid has since been reused.
func (correlator *Correlator) forgetExited(now time.Time) {
	expired := 0
	for _, record := range correlator.exits {
		if now.Sub(record.at) < exitRetention {
			break
		}
		if correlator.processes[record.pid] == record.proc {
			delete(correlator.processes, record.pid)
		}
		expired++
	}
	correlator.exits = correlator.exits[expired:]
}

func (correlator *Correlator) fork(evt event.Event) {
	child := correlator.processes[evt.PID]
	if child == nil || !child.exited.IsZero() {
		child = &process{}
		correlator.processes[evt.PID] = child
	}
	child.parentPID, child.uid = evt.PPID, evt.UID
	if parent := correlator.processes[evt.PPID]; parent != nil {
		if child.exe == "" {
			child.exe = parent.exe
		}
		child.session, child.pkg = parent.session, parent.pkg
	}
}

func (correlator *Correlator) exec(evt event.Event) []event.Alert {
	proc := correlator.processes[evt.PID]
	if proc == nil || !proc.exited.IsZero() {
		proc = &process{parentPID: evt.PPID}
		if parent := correlator.processes[evt.PPID]; parent != nil {
			proc.session, proc.pkg = parent.session, parent.pkg
		}
		correlator.processes[evt.PID] = proc
	}
	proc.uid, proc.exe = evt.UID, evt.Exe
	proc.names = score.InvokedNames(evt.Exe, evt.Args)
	if evt.PPID != 0 {
		proc.parentPID = evt.PPID
	}
	if pkg := packageFromPath(evt.Cwd); pkg != "" {
		proc.pkg = pkg
	}
	if correlator.autoStart != nil && correlator.rules.IsAutoSession(evt.Exe, evt.Args) {
		if proc.session == nil {
			if session := correlator.autoStart(evt); session != nil {
				correlator.StartSession(session)
			}
		} else {
			// Wrapping an install in a plain `contraband run` must not switch
			// enforcement off.
			proc.session.Enforce = score.Stronger(proc.session.Enforce, correlator.rules.EnforceAuto)
		}
	}
	if proc.session == nil || proc.pkg == "" || !correlator.rules.IsDownloader(evt.Exe, evt.Args) {
		return nil
	}
	proc.session.evidenceFor(proc.pkg).addRan(path.Base(evt.Exe))
	return correlator.raise(evt.Time, proc.session, proc.pkg, score.SpawnsDownloader)
}

func (correlator *Correlator) learnName(evt event.Event) {
	ttl := max(time.Duration(evt.TTL)*time.Second, minNameTTL)
	if len(correlator.names) > maxNames {
		for addr, name := range correlator.names {
			if evt.Time.After(name.expires) {
				delete(correlator.names, addr)
			}
		}
	}
	domain := strings.TrimSuffix(strings.ToLower(evt.Name), ".")
	for _, addr := range evt.Addrs {
		correlator.names[addr.Unmap()] = resolvedName{domain: domain, expires: evt.Time.Add(ttl)}
	}
}

func (correlator *Correlator) connect(evt event.Event) (*event.Flow, []event.Alert) {
	proc := correlator.processes[evt.PID]
	if proc == nil {
		// Sensors can deliver a connection before the fork that created the
		// process, so membership is inherited through the parent pid.
		proc = &process{parentPID: evt.PPID, uid: evt.UID, exe: evt.Exe}
		if parent := correlator.processes[evt.PPID]; parent != nil {
			proc.session, proc.pkg = parent.session, parent.pkg
		}
		correlator.processes[evt.PID] = proc
	}
	domain := strings.TrimSuffix(strings.ToLower(evt.SNI), ".")
	if name, found := correlator.names[evt.Dst.Addr().Unmap()]; domain == "" && found && !evt.Time.After(name.expires) {
		domain = name.domain
	}
	flow := &event.Flow{
		Time: evt.Time, PID: evt.PID, UID: proc.uid, Chain: correlator.chain(evt.PID),
		Domain: domain, Dst: evt.Dst, Proto: evt.Proto, Package: proc.pkg,
	}
	session := proc.session
	if session == nil {
		return flow, nil
	}
	flow.Session = session.ID
	if isLocal(evt.Dst.Addr()) {
		return flow, nil
	}
	destination := domain
	if destination == "" {
		destination = evt.Dst.Addr().String()
	}
	flow.Verdict = session.Policy.Check(proc.pkg, destination)
	evidence := session.evidenceFor(proc.pkg)
	if flow.Verdict == policy.Allow {
		evidence.addDestination(destination, "allowed")
		return flow, nil
	}
	if correlator.rules.IsRegistry(domain) {
		evidence.addDestination(destination, "")
		return flow, nil
	}
	if session.Enforce == score.EnforceStrict {
		flow.Verdict = policy.Blocked
		evidence.addDestination(destination, "blocked: not approved")
		return flow, []event.Alert{{
			Time: evt.Time, Session: session.ID, UID: session.UID, Package: proc.pkg, Level: string(score.Alert),
			Msg: fmt.Sprintf("stopped %s: it connected to %s, which is not approved", path.Base(proc.exe), destination),
		}}
	}

	var signals []score.Signal
	var notes []string
	if len(evidence.Read) > 0 {
		signals = append(signals, score.SensitiveThenEgress)
	}
	if proc.pkg != "" {
		signals = append(signals, score.NonRegistry)
	}
	switch {
	case domain == "":
		signals = append(signals, score.SuspiciousDest)
		notes = append(notes, "raw IP")
	case correlator.rules.IsSuspicious(domain):
		signals = append(signals, score.SuspiciousDest)
		notes = append(notes, "paste, webhook or tunnel service")
	}
	researching := session.Agent && proc.pkg == ""
	if previous, known := session.Baseline[proc.pkg]; known && !previous[destination] && !researching {
		signals = append(signals, score.NewBehavior)
		notes = append(notes, "new since last run")
	}
	evidence.addDestination(destination, strings.Join(notes, ", "))
	return flow, correlator.raise(evt.Time, session, proc.pkg, signals...)
}

func (correlator *Correlator) raise(when time.Time, session *Session, pkg string, signals ...score.Signal) []event.Alert {
	card := session.card(pkg)
	added := false
	for _, signal := range signals {
		added = card.Add(signal) || added
	}
	level := score.LevelOf(card.Score)
	// One alert per escalation: warn, then alert. Further signals only raise the score.
	if !added || level == score.Log || level == session.alerted[pkg] {
		return nil
	}
	session.alerted[pkg] = level
	return []event.Alert{{
		Time: when, Session: session.ID, UID: session.UID, Package: pkg, Level: string(level), Score: card.Score,
		Signals: slices.Clone(card.Signals),
		Msg:     session.evidenceFor(pkg).describe(),
	}}
}

func (correlator *Correlator) chain(pid uint32) []string {
	var exes []string
	for depth := 0; depth < maxChainDepth && pid != 0; depth++ {
		proc := correlator.processes[pid]
		if proc == nil {
			break
		}
		exes = append(exes, proc.exe)
		pid = proc.parentPID
	}
	return exes
}

func isLocal(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsUnspecified()
}

// packageFromPath maps an install script's working directory to its package:
//
//	/app/node_modules/@scope/name/lib            → @scope/name   (npm)
//	/tmp/pip-install-x8k2/requests_0a1b…/         → requests      (pip)
//	/opt/homebrew/Cellar/wget/1.25.0/             → wget          (Homebrew)
//
// Other layouts fall back to the session command.
func packageFromPath(cwd string) string {
	if index := strings.LastIndex(cwd, "/node_modules/"); index >= 0 {
		parts := strings.SplitN(cwd[index+len("/node_modules/"):], "/", 3)
		if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
			return parts[0] + "/" + parts[1]
		}
		return parts[0]
	}
	if index := strings.Index(cwd, "/pip-install-"); index >= 0 {
		parts := strings.SplitN(cwd[index+1:], "/", 3)
		if len(parts) > 1 {
			// pip names build dirs <name>_<32 hex digits>.
			if cut := strings.LastIndex(parts[1], "_"); cut > 0 && len(parts[1])-cut-1 == 32 {
				return parts[1][:cut]
			}
		}
		return ""
	}
	if index := strings.Index(cwd, "/Cellar/"); index >= 0 {
		name, _, _ := strings.Cut(cwd[index+len("/Cellar/"):], "/")
		return name
	}
	return ""
}
