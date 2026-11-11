GOTOOL   := go tool -modfile=tools/go.mod
# Host binary of a pinned tool, so GOOS can target the analysis without cross-building the tool.
hosttool = $(shell go tool -modfile=tools/go.mod -n $(1))
VM       := contraband
LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
LDFLAGS  := -s -w

.PHONY: check fmt lint vuln osv secrets licenses test build generate vm test-linux hooks

check: lint test vuln osv secrets licenses

fmt:
	$(GOTOOL) golangci-lint fmt

lint:
	$(GOTOOL) golangci-lint run
	GOOS=linux $(call hosttool,golangci-lint) run

test:
	go test -race ./...

vuln:
	$(GOTOOL) govulncheck ./...
	GOOS=linux $(call hosttool,govulncheck) ./...

osv:
	$(GOTOOL) osv-scanner scan source --recursive .

secrets:
	$(GOTOOL) gitleaks dir --redact --no-banner .

licenses:
	GOOS=linux $(call hosttool,go-licenses) check ./... --allowed_licenses=$(LICENSES)

# Scan pushed commits for secrets before they leave the machine.
hooks:
	git config core.hooksPath .githooks

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/contraband ./cmd/contraband

# BPF objects need clang with the BPF target, so they are built in the VM and committed.
generate: vm
	limactl shell $(VM) -- bash -c 'cd /src && go generate ./internal/sensor/linux/'

vm:
	limactl list --quiet | grep -qx $(VM) || \
		limactl start --name=$(VM) --tty=false --set '.mounts=[{"location":"$(CURDIR)","mountPoint":"/src","writable":true}]' hack/lima.yaml
	limactl list --format '{{.Status}}' $(VM) | grep -qx Running || limactl start $(VM)

test-linux: vm
	limactl shell $(VM) -- bash -c 'cd /src && sudo hack/e2e.sh'
