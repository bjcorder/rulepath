# Contributing

Thanks for helping build Rulepath.

## Licensing and CLA

Rulepath is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`).

Non-trivial contributions require acceptance of the
[Rulepath Contributor License Agreement](CLA.md) before merge. The CLA keeps
contributors' copyright ownership while granting the project maintainer the
rights needed to distribute, sublicense, relicense, and maintain Rulepath.

When CLA automation is enabled, the required CLA check must pass before a pull
request is merged. Until then, maintainers may record acceptance manually in the
pull request.

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

## Issue Labels

Rulepath uses GitHub Issue labels as the lightweight planning system. Issues remain the source of truth for implementation work; labels make the backlog sortable without requiring a separate project board.

Use these label families consistently:

- `priority:p0` through `priority:p3`: order of attention, with `p0` as critical path work.
- `phase:*`: broad implementation sequence, such as foundation, existing analyzer wedge cleanup, framework/ORM support, product contracts, and adoption/operations.
- `area:*`: ownership or routing dimension, such as parser, framework, ORM, auth, dataflow, rules, CI, docs, Wiki, release, schema, performance, examples, or planning.
- `stack:*`: ecosystem marker for Python or TypeScript work.
- `size:*`: rough implementation size, useful when choosing the next issue.
- `type:tracker`: coordinating issue rather than direct implementation work.

Useful backlog filters:

- Critical path: `is:issue is:open label:priority:p0`
- Foundation work: `is:issue is:open label:phase:1-foundation`
- Parser work: `is:issue is:open label:area:parser`
- Python work: `is:issue is:open label:stack:python`
- Adoption and operations: `is:issue is:open label:phase:5-adoption-ops`

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
