# Repository Guidelines

## Project Structure & Modules
- `main.go`: Entry for the proxy (flags: `--config`, `--envfile`, `--debug`, `--trace`).
- `msgtausch-srv/`: Core packages
  - `proxy/`, `resolver/`, `config/`, `stats/`, `dashboard/` (Templ templates in `templates/`).
- `cmd/`: Utilities (`proxy-test`, `throughput-test`, `simulation`).
- `msgtausch-simulation/`: Fuzzy/simulation tests and helpers.
- `docs/`: User docs (see `docs/configuration.md`).
- `examples/`: Example configs and usage.

## Build, Test, and Development
- Go (local):
  - Build: `go build -o msgtausch` (binary: `./msgtausch`).
  - Run: `go run . --config config.json` or `./msgtausch --config config.json`.
  - Test: `go test ./... -race -coverprofile=coverage.out`.
  - Lint: `golangci-lint run` (configured via `.golangci.yml`).
- Docker Buildx Bake (CI-parity):
  - All: `docker buildx bake --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=`
  - Tests only: `docker buildx bake test ...`
  - Build only: `docker buildx bake build ...`
  - Release: `VERSION=vX.Y.Z docker buildx bake release ...`
- Nix (optional):
  - Dev shell: `nix develop` (Go 1.24, Docker, tools).
  - Build: `nix build .#msgtausch`  | Tests: `nix build .#test`.
  - If editing dashboard templates, run: `templ generate` (in Nix this runs automatically).

## Coding Style & Naming
- Go style enforced by `gofmt`/`goimports`; run `golangci-lint run` before pushing.
- Package and file names: lowercase, concise. Tests end with `_test.go`.
- Config keys prefer kebab-case in files (e.g., `listen-address`).

## Testing Guidelines
- Unit/integration: `go test ./...` from repo root. Use `-race` for concurrency.
- Coverage: keep/refresh `coverage.out` via `-coverprofile`.
- Test naming: `TestXxx` in `*_test.go`; integration tests live under `msgtausch-srv/**` and `cmd/**` as applicable.

## Commit & PR Guidelines
- Commits: follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.).
- PRs: include a clear summary, linked issues, and steps to test. Attach screenshots for dashboard/UI changes.
- Required checks: `golangci-lint run` and `go test ./...` must pass. Update `docs/configuration.md` and `config-schema.json` when changing config.
- Security: do not commit private keys or real secrets; prefer `--envfile` and env vars (`MSGTAUSCH_*`).

