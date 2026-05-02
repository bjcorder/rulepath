# Dependency Pinning

Rulepath is a security-adjacent analyzer, so dependency resolution must be deterministic.

## Policy

- Commit `Cargo.lock` and treat it as security-relevant source.
- Direct Rust dependencies in `Cargo.toml` must use exact version requirements with `=`.
- Registry crate content is pinned by the SHA-256 `checksum` entries in `Cargo.lock`.
- CI must use `cargo ... --locked` for commands that resolve dependencies.
- The Rust toolchain must be pinned in `rust-toolchain.toml` to an exact release, not `stable`.
- GitHub Actions must use full commit SHAs, not tags or branches.
- Git dependencies are discouraged. If one is unavoidable, it must use `rev = "<40-char commit SHA>"`, never a branch or tag.
- Versioned runner labels must be used in CI instead of moving `*-latest` labels.

## Updating Dependencies

Dependency updates must be explicit PRs.

1. Change the direct dependency version in `Cargo.toml` using an exact `=` requirement.
2. Run `cargo update -p <crate> --precise <version>` when updating an existing crate.
3. Run `cargo test --locked --workspace`.
4. Include the `Cargo.lock` checksum changes in the PR.
5. Explain why the update is needed.

For GitHub Actions, resolve the desired tag to a commit SHA and pin the `uses:` entry to that SHA. Keep a comment naming the human-readable tag or branch snapshot for maintainability.

## Verification

Use these commands before merging:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace
cargo build --locked --workspace
```

Any command that would modify `Cargo.lock` during CI should fail.
