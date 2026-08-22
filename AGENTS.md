# Repository Guidelines

## Project Structure & Modules
- `crates/`: Rust workspace split by responsibility.
  - `msgtausch-cli/`: production `msgtausch` binary, startup, listeners, and reload.
  - `msgtausch-config/`: configuration loading and validation.
  - `msgtausch-policy/`: classifiers and remote domain lists.
  - `msgtausch-resolver/`, `msgtausch-routing/`, `msgtausch-interception/`, and `msgtausch-proxy/`: connection setup and HTTP/TLS proxying.
  - `msgtausch-quic/`: QUIC and HTTP/3 transport primitives.
  - `msgtausch-observability/`: Prometheus and OpenTelemetry reporting.
  - `msgtausch-simulation/`: black-box simulation runner and corpus.
- `Cargo.toml`: virtual workspace manifest. The `msgtausch-cli` package owns the production binary.
- `docs/`: User docs (see `docs/configuration.md`).
- `examples/`: Example configs and usage.

## Build, Test, and Development
- Rust (production):
  - Build: `cargo build --release`.
  - Run: `cargo run -- --config examples/config.json`.
  - Test: `cargo test --workspace --all-targets`.
  - Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
  - Format: `cargo fmt --all --check`.
- Docker Buildx Bake (CI-parity):
  - All: `docker buildx bake --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=`
  - Tests only: `docker buildx bake test ...`
  - Build only: `docker buildx bake build ...`
  - Release: `VERSION=vX.Y.Z docker buildx bake release ...`
- Nix (optional):
- Dev shell: `nix develop` (Rust, Docker, and build tools).
  - Build: `nix build .#msgtausch`  | Tests: `nix build .#test`.
  - If editing dashboard templates, run: `templ generate` (in Nix this runs automatically).

## Coding Style & Naming
- Rust style is enforced by `rustfmt` and Clippy with warnings denied.
- Crate and file names: lowercase and concise. Rust tests live beside their modules or in crate integration tests.
- Config keys prefer kebab-case in files (e.g., `listen-address`).

## Testing Guidelines
- Production unit/integration: `cargo test --workspace --all-targets` from the repository root.
- The deterministic simulation corpus lives in `crates/msgtausch-simulation/corpus/`.

## Commit & PR Guidelines
- Commits: follow Conventional Commits (`feat:`, `fix:`, `docs:`, etc.).
- PRs: include a clear summary, linked issues, and steps to test. Attach screenshots for dashboard/UI changes.
- Required checks: Rust format, Clippy, and tests. Update `docs/configuration.md` and `config-schema.json` when changing config.
- Security: do not commit private keys or real secrets; prefer `--envfile` and env vars (`MSGTAUSCH_*`).
