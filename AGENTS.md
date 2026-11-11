# AGENTS.md

Rules for any coding agent or contributor working in this repository.

## What this is

Contraband is a local-first egress auditor: it attributes every outbound
connection to a process tree, package and destination, scores supply-chain
behaviour during installs, and keeps a tamper-evident log. Go core, platform
sensors (eBPF on Linux; eslogger + pktap on macOS).

## Layout

```
cmd/contraband/          CLI entry point and subcommand dispatch only
internal/event/          event schema shared by every sensor
internal/sensor/linux/   eBPF loader; generated bpf2go files are committed
internal/sensor/darwin/  eslogger (Endpoint Security) + tcpdump pktap, no entitlement needed
internal/sensor/dnsanswer/ DNS response parsing shared by sensors
internal/sensor/replay/  JSON Lines replay sensor for tests and hosts without a sensor
internal/correlate/      processes, sessions, DNS names → flows and alerts
internal/score/          signal weights and detection rules (defaults.yml is embedded)
internal/policy/         .contraband.yml parsing and checks
internal/store/          append-only, hash-chained SQLite log
internal/daemon/         privileged daemon, unix-socket API, client
bpf/                     BPF C source, minimal CO-RE types, vendored libbpf headers
testdata/                recorded event fixtures
hack/                    VM config and end-to-end script
tools/                   separate module pinning dev tools (go tool -modfile=tools/go.mod)
```

- Everything is under `internal/`. No `pkg/`, `utils`, `common` or `helpers` packages.
- One package, one responsibility. Put code where its data lives.
- Platform code goes in `_linux.go` / `_darwin.go` files, not runtime `GOOS` checks, unless it is a default value.

## Code style

- Names are words. No single-letter identifiers anywhere: receivers, loop
  variables, parameters and closures included (`for index, rule := range rules`,
  `func (store *Store)`). Well-known two-letter names (`db`, `tx`, `ok`, `id`, `mu`) are fine;
  the only single letter allowed is `t *testing.T` in tests. Lint enforces this.
- Comments explain *why*: an invariant, a security reason, a kernel or OS quirk.
  Never restate the code, never narrate changes, never reference tickets,
  ADRs, plans or chat context. No commented-out code.
- No doc comment on an exported identifier whose name already says what it does.
- Errors: wrap with `fmt.Errorf("doing x: %w", err)`; never ignore one silently.
  `_ =` only where failure has no consequence, and `//nolint:errcheck // reason` for deferred closes.
- No panics outside `main` and embedded-asset initialisation.
- `context.Context` is the first parameter of anything that blocks or does I/O.
- Logging: `log/slog` only, structured keys, never log payloads, file contents or secrets.
- No package-level mutable state. Configuration is passed in.
- No interface until there are two implementations; define it where it is consumed.
- Data that changes without code changes (domain lists, paths) lives in data files, not Go literals.

## Dependencies

- Standard library first. A new dependency must be justified in the PR and
  carry an OSI license that permits commercial use (`make licenses` enforces
  the allowlist). Never add a dependency for something a few lines can do.
- Use the latest stable release; Dependabot keeps them current.
- Dev tools are pinned in `tools/go.mod` and run with `go tool -modfile=tools/go.mod <tool>`.
  Never `go install` a tool globally in scripts or CI.

## Security

- The daemon runs as root. Treat every socket request as untrusted: authorise by
  peer credentials, bound request sizes, validate inputs.
- Files the root daemon trusts must be root-owned and not group/world writable.
- Anything that widens what is allowed (policy approval) must need a fresh,
  OS-verified password read from the terminal. Never add a flag, env var or
  API path that skips it: agents and audited code run as the same user.
- Never shell out with user-controlled strings. Never decrypt traffic.
- Fix gosec findings. A suppression needs `//nolint:gosec // reason` explaining why it is safe.
- BPF programs stay minimal: capture and filter in the kernel, parse and decide in user space.
  Fixed map sizes; every drop is counted and reported.

## Tests

- Standard `testing` only, table-driven, fixtures in `testdata/`.
- Every non-trivial branch of detection, policy or log-integrity logic has a test.
- Kernel behaviour is tested end to end with `make test-linux` (Lima VM) and in CI.

## Workflow

- Done means `make check` passes: lint, race tests, govulncheck, osv-scanner,
  gitleaks, license check. Linux-only code is linted with `GOOS=linux`.
- After editing BPF C, run `make generate` and commit the regenerated objects.
- Commits follow Conventional Commits (`feat:`, `fix:`, `chore:` …).
