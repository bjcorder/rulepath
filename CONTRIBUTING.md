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

## Pull Requests

Every PR should describe:

- User-facing behavior changed.
- Tests or fixtures added.
- Config schema changes.
- Output contract changes.
- Whether findings and review hints remain separate.

New language, framework, ORM, auth, or rule support should include safe and unsafe fixtures.

## Rule Development

Rules must consume normalized IR and resolved config only. Parser AST inspection belongs in language, framework, ORM, or auth adapters.
