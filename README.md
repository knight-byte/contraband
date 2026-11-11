# Contraband

Know what your dev tools, package installs and AI agents talk to.

Contraband attributes every outbound connection on your machine to the process
tree, package and domain behind it, scores suspicious install behaviour, and
keeps a tamper-evident log. Nothing leaves the machine and no traffic is decrypted.

## Status

Early development, monitor mode only: nothing is blocked yet.

- **Linux** (kernel 5.8+, BTF): eBPF probes.
- **macOS 13+**: Apple's signed `eslogger` and `tcpdump` (pktap), so no
  entitlement is needed. Run the daemon with `sudo` from a terminal that has
  Full Disk Access.

## Usage

```sh
sudo contraband daemon                 # start the privileged daemon
contraband run -- npm install          # audit one command
contraband watch                       # live view of your connections
contraband show <session>              # what a session did
contraband diff <session-a> <session-b>
sudo contraband export > log.jsonl     # verified, hash-chained event log
```

`contraband run` prints alerts as they happen and a per-package summary:

```
LEVEL  SCORE  PACKAGE    DESTINATIONS
alert  13     foo        45.9.148.3
log    0      (command)  registry.npmjs.org
foo: sensitive file read, then outbound connection; install script made a non-registry connection; ...
```

### Policy

`.contraband.yml` lists the destinations a project is expected to reach:

```yaml
version: 1
allow:
  - domain: registry.npmjs.org
  - domain: "*.github.com"
    package: esbuild
```

The file is only a proposal. The daemon enforces an approved copy kept in its
own root-owned directory, and approving needs your account password every time:

```sh
contraband allow -package esbuild github.com   # edit the file and approve
contraband approve                              # approve manual edits
```

The password is read from the terminal only and checked by the OS, and
failures are rate-limited. An AI agent, a script, or the code being audited
can edit the file but cannot approve it, even with cached `sudo` rights.

When `run` flags a package, it prints the next steps:

```
inspect:      contraband show <session>
if expected:  contraband allow -package evil 1.1.1.1
```

### Detection rules

Registries, suspicious domains and sensitive paths ship in
[`internal/score/defaults.yml`](internal/score/defaults.yml). Extend them with
a root-owned `/etc/contraband/rules.yml` in the same format.

## Development

Requires Go 1.27. Linux sensor work happens in a Lima VM on macOS.

```sh
make check        # lint, tests, govulncheck, osv-scanner, gitleaks, licenses
make generate     # rebuild BPF objects (in the VM)
make test-linux   # load the probes and run the end-to-end test (in the VM)
```

### Trying it on macOS

Give your terminal Full Disk Access (System Settings → Privacy & Security),
reopen it, then:

```sh
make build
sudo ./bin/contraband daemon                     # add -log-level debug to see raw events
./bin/contraband watch                           # in a second terminal
./bin/contraband run -- curl -s https://example.com -o /dev/null
```

Simulate a credential-stealing install script:

```sh
mkdir -p ~/.aws /tmp/app/node_modules/evil && touch ~/.aws/credentials-test
cd /tmp/app && contraband run -- bash -c 'cd node_modules/evil && cat ~/.aws/credentials-test && curl -s -m3 -o /dev/null http://1.1.1.1/'
# alert 13 evil 1.1.1.1
```

See [AGENTS.md](AGENTS.md) for code rules.

## License

Apache-2.0. The BPF program in `bpf/` is dual MIT/GPL-2.0, as the kernel requires.
