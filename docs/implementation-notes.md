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

## Current Trace Foundation

The current analyzer builds a conservative trace index from parser-backed symbols and calls. Framework and data-layer adapters consume those parsed facts through deterministic registries, then dataflow connects route request sources to operations when parsed calls cross from route handlers into service functions.

Prisma extraction is parser-call backed and recognizes configured client aliases, supported CRUD and bulk methods, nested `where` filters, and `data` mutation payloads while ignoring projection-only `select` and `include` arguments.

SQLAlchemy extraction is parser-call backed for `session.get`, `select`, `update`, `delete`, and `session.execute(...)` wrappers. Object assignment followed by `session.commit()` is modeled as a mutation so request-body field flows are visible to rules.

Auth, authorization, scope, transaction, invariant, and idempotency evidence is normalized in `rulepath_auth`. Evidence classification is driven by resolved config where possible, with route middleware/dependencies and direct helper calls associated back to the nearest route or sink during IR assembly.

The trace remains intentionally narrow and fixture-backed, but it is import- and symbol-aware for simple local and relative imports. Route-to-service tracing respects `analysis.service_layer_tracing` and `analysis.max_call_depth`; unresolved or ambiguous paths should stay out of high-confidence findings rather than inheriting the first available route.
