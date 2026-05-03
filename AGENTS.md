# Repository Guidelines

## Project Structure & Module Organization

Rulepath is a Rust workspace. Source code lives under `crates/`, with one crate per responsibility: `rulepath_cli` for the binary, `rulepath_config` for `.rulepath.yml`, `rulepath_ir` for normalized facts, `rulepath_parsers` plus `rulepath_lang_*` for parser-backed facts, `rulepath_frameworks` and `rulepath_orms` for adapters, `rulepath_dataflow` for tracing, and `rulepath_rules` for diagnostics. Fixture applications live in `fixtures/`. Built-in profiles live in `profiles/`. Repository documentation lives in `docs/`, with user-facing summaries in `README.md` and release notes in `CHANGELOG.md`.

## Build, Test, and Development Commands

- `cargo build --locked --workspace`: build every crate with the locked dependency graph.
- `cargo test --locked --workspace`: run unit, integration, fixture, and doc tests.
- `cargo clippy --locked --workspace --all-targets`: run lint checks used by CI.
- `cargo fmt --all -- --check`: verify formatting without changing files.
- `cargo run -p rulepath_cli -- scan fixtures/express_prisma/unsafe`: run the CLI against a representative fixture.

Use `--locked` for verification because dependency versions are pinned in `Cargo.lock`.

## Coding Style & Naming Conventions

Use Rust 2021 and the workspace lint policy in `Cargo.toml`; unsafe code is forbidden. Format with `cargo fmt`. Prefer clear module boundaries matching existing crates instead of adding cross-cutting logic to unrelated layers. Use `snake_case` for functions, modules, and variables; `PascalCase` for types and enum variants. Keep diagnostics, IDs, and fingerprints deterministic by sorting output collections when order can vary.

## Testing Guidelines

Tests use Rust's built-in test framework. Add focused unit tests near the crate that owns the behavior, and add fixture or CLI tests in `crates/rulepath_cli/tests/` for end-to-end scan behavior. Fixture expectations should cover both unsafe and safe examples when changing analysis behavior. Run `cargo test --locked --workspace` before opening a PR.

## Commit & Pull Request Guidelines

Git history uses short imperative commit subjects such as `Implement parser-backed Prisma sinks` or `Normalize config-driven auth evidence`. Keep commits scoped to one issue or behavior. PRs should include a summary, linked issues using `Fixes #N`, documentation changes, and verification commands run. Update `CHANGELOG.md`, `README.md`, or relevant `docs/` pages when behavior, configuration, CLI output, or architecture changes.

## Security & Configuration Tips

Normal scans must remain Rust-native and must not require Python, Node, Docker, network access, or a TypeScript compiler process. Config parsing denies unknown fields; preserve strict validation when adding new settings. Inline suppressions require meaningful reasons by default.
