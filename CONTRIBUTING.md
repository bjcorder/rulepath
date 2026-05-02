# Contributing

Thanks for helping build Rulepath.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

Normal Rulepath scans must remain Rust-native. Do not add a Python, Node, Docker, network, or compiler-process dependency to normal scans.

## Dependency Pinning

Rulepath uses deterministic dependency resolution. See [docs/dependency-pinning.md](docs/dependency-pinning.md).

- Keep `Cargo.lock` committed.
- Use exact `=` requirements for direct Rust dependencies.
- Use `--locked` for build, test, and clippy verification.
- Pin GitHub Actions to full commit SHAs.
- Do not add branch/tag-based Git dependencies.

## Pull Requests

Every PR should describe:

- User-facing behavior changed.
- Tests or fixtures added.
- Config schema changes.
- Output contract changes.
- Whether findings and review hints remain separate.
- Any dependency updates, including `Cargo.lock` checksum changes.

New language, framework, ORM, auth, or rule support should include safe and unsafe fixtures.

## Rule Development

Rules must consume normalized IR and resolved config only. Parser AST inspection belongs in language, framework, ORM, or auth adapters.
