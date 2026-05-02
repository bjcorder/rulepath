# Implementation Notes

Rulepath is Rust-native because static analysis benefits from predictable memory use, parallelism, single-binary distribution, and strong data modeling.

## Runtime Policy

Normal scans should not require:

- Python interpreter.
- Node runtime.
- TypeScript compiler process.
- Docker.
- Network access.

Optional deep-analysis modes may use sidecars later, but those modes must be explicit.

## Deterministic Dependencies

Dependency resolution must be reproducible. Direct Cargo dependencies use exact version requirements, `Cargo.lock` stores registry checksums, CI runs with `--locked`, GitHub Actions are pinned to full commit SHAs, and the Rust toolchain is pinned by `rust-toolchain.toml`.

## Memory Model

Prefer compact IDs internally:

- `FileId`
- `SymbolId`
- `RouteId`
- `SinkId`
- `SourceId`
- `EvidenceId`

Keep spans as file IDs plus byte offsets where practical. Convert to line and column for reports.

## Parallelism

Safe parallel points include file parsing, fact extraction, data-layer extraction, rule evaluation over independent traces, and report formatting. Final output must remain deterministic.

## Error Handling

Fatal errors include config load failures, schema violations, invalid baselines, and output write failures.

Non-fatal diagnostics include parse errors in individual files, unresolved imports, unsupported syntax, and ambiguous resource inference.

Uncertainty should reduce confidence or produce review hints.
