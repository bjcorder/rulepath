# Architecture

Rulepath is a Rust workspace organized around fact extraction, normalization, tracing, and rule evaluation.

```text
source files
  -> parser adapters
  -> language facts
  -> framework adapter registry
  -> data-layer adapter registry
  -> scan context
  -> auth evidence normalization
  -> service-layer tracing
  -> common IR
  -> invariant rules
  -> reporters
```

Rules consume normalized IR and resolved config only. They must not inspect raw parser ASTs.

## Workspace Crates

- `rulepath_cli`: CLI commands, config loading, scan orchestration, baselines, exit codes.
- `rulepath_config`: strict `.rulepath.yml` models, profile loading, validation, starter config.
- `rulepath_workspace`: repository walking, file indexing, source text loading, span support.
- `rulepath_ir`: language-neutral facts, diagnostics, confidence, severity, fingerprints.
- `rulepath_diagnostics`: human-readable errors and source-oriented diagnostics.
- `rulepath_parsers`: parser traits, raw fact structures, suppression parsing helpers.
- `rulepath_lang_python`: Python syntax extraction.
- `rulepath_lang_typescript`: TypeScript syntax extraction.
- `rulepath_frameworks`: FastAPI, Django, DRF, Express, and Next.js route facts.
- `rulepath_orms`: Django ORM, SQLAlchemy, and Prisma sink facts.
- `rulepath_auth`: auth, authorization, object-scope, and tenant-scope evidence.
- `rulepath_dataflow`: call graph, route-to-service tracing, source propagation.
- `rulepath_rules`: invariant rules and review hints.
- `rulepath_infer`: draft config inference.
- `rulepath_reporters`: text, JSON, and GitHub Actions output.
- `rulepath_sarif`: SARIF output.

## Parser Strategy

TypeScript support uses Oxc as the Rust-native parser foundation. Python support uses tree-sitter with a lightweight lexical pass for comments and suppressions.

Normal scans must stay Rust-native. Optional sidecars may be added later only for explicit deep-analysis modes.

## Pipeline

1. Load and validate config.
2. Merge the configured profile.
3. Build a workspace file index.
4. Parse supported source files into language facts.
5. Run framework adapters over parsed facts.
6. Run data-layer adapters over parsed facts.
7. Build a scan context from workspace, parsed facts, and extracted IR facts.
8. Normalize auth evidence.
9. Trace route-to-sink call paths.
10. Build common IR.
11. Apply suppressions.
12. Evaluate rules.
13. Apply baseline and CI policy.
14. Emit reports.

Framework and data-layer extraction is registered by adapter descriptors, so scan orchestration does not need framework-specific or ORM-specific lexical logic. `rulepath_dataflow` owns the scan context, route-to-operation source propagation, and deterministic IR assembly.
