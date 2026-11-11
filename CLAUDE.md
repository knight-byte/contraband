@AGENTS.md

## Claude Code

- Read the files a change touches before editing; trace callers before changing a shared function.
- Run `make check` (and `make test-linux` for sensor or BPF changes) before saying work is done, and report failures verbatim.
- Do not commit, push or start the VM unless asked.
