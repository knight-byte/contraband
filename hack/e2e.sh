#!/usr/bin/env bash
# Loads the real probes, runs a command under `contraband run` and checks the
# connection is attributed to it by name. Needs root.
set -euo pipefail

workdir=$(mktemp -d)
trap 'kill "${daemon_pid:-}" 2>/dev/null || true; rm -rf "$workdir"' EXIT

CGO_ENABLED=0 go build -trimpath -o "$workdir/contraband" ./cmd/contraband
socket="$workdir/contraband.sock"

"$workdir/contraband" daemon -socket "$socket" -db "$workdir/events.db" -rules "" 2>"$workdir/daemon.log" &
daemon_pid=$!
for _ in $(seq 50); do [ -S "$socket" ] && break; sleep 0.1; done
[ -S "$socket" ] || { cat "$workdir/daemon.log"; exit 1; }

(cd "$workdir" && ./contraband run -socket "$socket" -- curl -sS -o /dev/null https://example.com) 2>"$workdir/run.log"
cat "$workdir/run.log"

grep -q "example.com" "$workdir/run.log" || { echo "FAIL: example.com not attributed"; cat "$workdir/daemon.log"; exit 1; }
"$workdir/contraband" export -socket "$socket" | grep -q '"kind":"flow"' || { echo "FAIL: no flows in export"; exit 1; }
echo PASS
