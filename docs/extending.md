# Extending Rulepath

New support should plug into registries and emit the same common IR. Existing rules should not know which parser, framework, or ORM produced a fact.

## Add A Language

1. Add a stable language ID to config and IR.
2. Choose a Rust-native parser or tree-sitter grammar.
3. Add a `rulepath_lang_*` crate.
4. Emit language facts, not findings.
5. Support Rulepath suppressions.
6. Provide service tracing hooks.
7. Register the adapter.
8. Add safe and unsafe fixtures.

## Add A Framework

Framework adapters discover routes, request-controlled sources, middleware, dependencies, and framework-level auth evidence.

Each adapter should emit route facts with method, path, handler, source span, request sources, route params, middleware, dependencies, and auth evidence.

## Add A Data Layer

Data-layer adapters extract resource operations and query or mutation sinks.

They must identify resource names, operation types, filters, scope fields, mutation fields, transaction evidence, and idempotency evidence where relevant.

## Add A Rule

Rules evaluate IR and resolved config. Each rule needs:

- Stable ID.
- High-confidence gate.
- Explanation text.
- Safe and unsafe fixtures.
- JSON and SARIF output coverage.
