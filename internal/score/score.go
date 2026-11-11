package score

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"

	"go.yaml.in/yaml/v3"
)

type Level string

const (
	Log   Level = "log"
	Warn  Level = "warn"
	Alert Level = "alert"
)

type Signal struct {
	Name   string
	Weight int
}

// Starting weights; tune against a baseline of popular packages.
var (
	SensitiveThenEgress = Signal{"sensitive file read, then outbound connection", 5}
	NewBehavior         = Signal{"new destination compared with previous run", 4}
	NonRegistry         = Signal{"install script made a non-registry connection", 3}
	SuspiciousDest      = Signal{"raw IP, paste site, webhook or tunnel service", 3}
	SpawnsDownloader    = Signal{"install script spawned curl, wget, bash -c or powershell", 2}
)

func LevelOf(total int) Level {
	switch {
	case total >= 8:
		return Alert
	case total >= 4:
		return Warn
	default:
		return Log
	}
}

// Card accumulates signals for one package in one session; each signal counts once.
type Card struct {
	Score   int
	Signals []string
	seen    map[string]bool
}

// Add returns true when the signal is new for this card.
func (card *Card) Add(signal Signal) bool {
	if card.seen == nil {
		card.seen = map[string]bool{}
	}
	if card.seen[signal.Name] {
		return false
	}
	card.seen[signal.Name] = true
	card.Score += signal.Weight
	card.Signals = append(card.Signals, signal.Name)
	return true
}

//go:embed defaults.yml
var defaultRules []byte

type Rules struct {
	Registries       []string            `yaml:"registries"`
	Suspicious       []string            `yaml:"suspicious_domains"`
	SensitivePaths   []string            `yaml:"sensitive_paths"`
	SensitiveNames   []string            `yaml:"sensitive_names"`
	Downloaders      []string            `yaml:"downloaders"`
	Shells           []string            `yaml:"shells"`
	CredentialOwners map[string][]string `yaml:"credential_owners"`
	AutoSessions     []string            `yaml:"auto_sessions"`
	Agents           []string            `yaml:"agents"`
	EnforceAuto      string              `yaml:"enforce_auto_sessions"`
}

const (
	EnforceOff    = "off"
	EnforceRisk   = "risk"
	EnforceStrict = "strict"
)

// ValidEnforce reports whether mode is an enforcement mode; empty means off.
func ValidEnforce(mode string) bool {
	return mode == "" || mode == EnforceOff || mode == EnforceRisk || mode == EnforceStrict
}

// Stronger returns the stricter of two enforcement modes.
func Stronger(first, second string) string {
	rank := map[string]int{"": 0, EnforceOff: 0, EnforceRisk: 1, EnforceStrict: 2}
	if rank[second] > rank[first] {
		return second
	}
	return first
}

func DefaultRules() *Rules {
	rules, err := parseRules(defaultRules)
	if err != nil {
		panic(fmt.Sprintf("embedded rules: %v", err))
	}
	return rules
}

// LoadRules returns the built-in rules extended by the file at extraPath. A
// missing file means defaults only. The file must be owned by root and not
// writable by anyone else, so a user-level compromise cannot widen the
// allowlists.
func LoadRules(extraPath string) (*Rules, error) {
	rules := DefaultRules()
	if extraPath == "" {
		return rules, nil
	}
	info, err := os.Stat(extraPath)
	if errors.Is(err, fs.ErrNotExist) {
		return rules, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("rules: %s must be owned by root and not group or world writable", extraPath)
	}
	content, err := os.ReadFile(extraPath) //nolint:gosec // path comes from the root daemon's own flags
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	extra, err := parseRules(content)
	if err != nil {
		return nil, fmt.Errorf("rules %s: %w", extraPath, err)
	}
	rules.Registries = append(rules.Registries, extra.Registries...)
	rules.Suspicious = append(rules.Suspicious, extra.Suspicious...)
	rules.SensitivePaths = append(rules.SensitivePaths, extra.SensitivePaths...)
	rules.SensitiveNames = append(rules.SensitiveNames, extra.SensitiveNames...)
	rules.Downloaders = append(rules.Downloaders, extra.Downloaders...)
	rules.Shells = append(rules.Shells, extra.Shells...)
	for tool, paths := range extra.CredentialOwners {
		rules.CredentialOwners[tool] = append(rules.CredentialOwners[tool], paths...)
	}
	rules.AutoSessions = append(rules.AutoSessions, extra.AutoSessions...)
	rules.Agents = append(rules.Agents, extra.Agents...)
	if extra.EnforceAuto != "" {
		rules.EnforceAuto = extra.EnforceAuto
	}
	return rules, nil
}

func parseRules(content []byte) (*Rules, error) {
	rules := &Rules{}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(rules); err != nil {
		return nil, err
	}
	for _, pattern := range rules.SensitiveNames {
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("sensitive_names %q: %w", pattern, err)
		}
	}
	if !ValidEnforce(rules.EnforceAuto) {
		return nil, fmt.Errorf("enforce_auto_sessions %q: want off, risk or strict", rules.EnforceAuto)
	}
	return rules, nil
}

func (rules *Rules) IsRegistry(domain string) bool { return matchDomain(domain, rules.Registries) }

// IsSuspicious treats an empty domain as a raw-IP destination.
func (rules *Rules) IsSuspicious(domain string) bool {
	return domain == "" || matchDomain(domain, rules.Suspicious)
}

func (rules *Rules) IsSensitive(filePath string) bool {
	base := path.Base(filePath)
	for _, pattern := range rules.SensitiveNames {
		if matched, _ := path.Match(pattern, base); matched {
			return true
		}
	}
	for _, fragment := range rules.SensitivePaths {
		if strings.Contains(filePath, fragment) {
			return true
		}
	}
	return false
}

// IsDownloader flags download tools and shells run with -c. A shell is judged
// by the name it was invoked as: macOS /bin/sh re-executes /bin/bash with
// argv[0] "sh", and every npm lifecycle script runs through sh -c.
func (rules *Rules) IsDownloader(exe string, args []string) bool {
	if slices.Contains(rules.Downloaders, path.Base(exe)) {
		return true
	}
	invokedAs := path.Base(exe)
	if len(args) > 0 {
		invokedAs = path.Base(args[0])
	}
	return slices.Contains(rules.Shells, invokedAs) && slices.Contains(args, "-c")
}

// IsCredentialRead reports whether a read of filePath by a process invoked as
// names is a sensitive read: the path is sensitive and the process is not the
// tool that owns that credential.
func (rules *Rules) IsCredentialRead(names []string, filePath string) bool {
	if !rules.IsSensitive(filePath) {
		return false
	}
	for _, name := range names {
		for _, fragment := range rules.CredentialOwners[name] {
			if strings.Contains(filePath, fragment) {
				return false
			}
		}
	}
	return true
}

// InvokedNames returns the names a program can be recognised by: the
// executable and the first three argv entries, since scripts run through an
// interpreter or env (npm is "env node .../npm").
func InvokedNames(exe string, args []string) []string {
	names := []string{path.Base(exe)}
	for index := 0; index < len(args) && index < 3; index++ {
		names = append(names, path.Base(args[index]))
	}
	return names
}

// IsAutoSession reports whether a program should start a session by itself.
func (rules *Rules) IsAutoSession(exe string, args []string) bool {
	return invokedAs(rules.AutoSessions, exe, args)
}

func (rules *Rules) IsAgent(exe string, args []string) bool {
	return invokedAs(rules.Agents, exe, args)
}

func invokedAs(list []string, exe string, args []string) bool {
	for _, name := range InvokedNames(exe, args) {
		if slices.Contains(list, name) {
			return true
		}
	}
	return false
}

// matchDomain matches the domain itself or any subdomain of a listed entry.
func matchDomain(domain string, list []string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, candidate := range list {
		if domain == candidate || strings.HasSuffix(domain, "."+candidate) {
			return true
		}
	}
	return false
}
