# AGENTS.md

Guidance for automated coding agents working in this repository.

## Project overview

- Project: `sudosrv` (Go sudo I/O log server)
- Go module: `sudosrv`
- Main entrypoint: `cmd/sudosrv/main.go`
- Core modes:
  - `local`: store sudo I/O logs locally in sudoreplay-compatible layout
  - `relay`: forward logs upstream with local cache/store-and-forward behavior

## Repository map

- `cmd/sudosrv/` - application entrypoint and CLI flag handling
- `internal/config/` - configuration structs, defaults, and YAML loading
- `internal/protocol/` - sudo logsrv protocol processing
- `internal/connection/` - connection/session handling
- `internal/storage/` - local log/session persistence
- `internal/relay/` - relay mode and cache flush behavior
- `internal/server/` - server lifecycle and listeners
- `pkg/sudosrv_proto/` - protobuf schema and generated Go bindings
- `rpm/`, `debian/` - packaging assets

## Build, test, and run

Preferred Make targets:

- `make deps` - tidy Go modules
- `make proto` - regenerate protobuf Go code
- `make build` - generate proto + tidy deps + build `./sudosrv`
- `make test` - run all tests (`go test -timeout 30s -v ./...`)
- `make run CONFIG=path/to/config.yaml` - build and run
- `make rpm` / `make deb` - packaging builds

Direct Go fallback:

- `go test ./...`
- `go build ./cmd/sudosrv`

## Agent rules for common changes

1. Protobuf changes (`pkg/sudosrv_proto/sudo_logsrv.proto`)
   - Regenerate generated code with `make proto`.
   - Include corresponding `sudo_logsrv.pb.go` updates in the same commit.

2. Config/CLI changes
   - Keep defaults and validation consistent across `internal/config/` and `cmd/sudosrv/main.go`.
   - Update README examples when user-facing flags or config semantics change.

3. Runtime behavior changes (relay/storage/protocol/server)
   - Add or update focused tests in the relevant `internal/*/*_test.go` files.
   - Preserve both `local` and `relay` mode behavior unless explicitly changing one mode.

4. Packaging changes (`rpm/`, `debian/`, `Makefile`)
   - Validate the relevant packaging target (`make rpm` or `make deb`) when feasible.

## Code style and safety expectations

- Use standard Go formatting (`gofmt`) for touched Go files.
- Prefer structured logs (`slog`) with stable key names.
- Keep changes scoped to the task; avoid unrelated refactors.
- Do not commit local secrets/certs/keys or generated runtime artifacts.
- Avoid editing generated protobuf output manually; regenerate instead.

## Pre-commit checklist

- Tests for touched areas pass (`make test` or targeted `go test`).
- Build succeeds (`make build` or `go build ./cmd/sudosrv`).
- Documentation is updated if behavior/config/flags changed.
- `git diff` is limited to intentional files.
