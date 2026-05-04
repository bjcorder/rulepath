# Changelog

All notable changes to Rulepath will be documented here.

## Unreleased

- Bootstrap public repository documentation.
- Add Rust workspace scaffold.
- Add initial CLI, config, IR, reporting, rule, inference, and SARIF foundations.
- Add first-pass route-to-service tracing for Express, FastAPI, and Next.js fixtures.
- Apply suppression policy before reports, baselines, and CI decisions.
- Add parser-backed TypeScript and Python facts for imports, symbols, calls, spans, and suppressions.
- Move Express and FastAPI route extraction into framework adapters with middleware, dependency, handler, and request-source facts.
- Move Prisma and SQLAlchemy sink extraction into data-layer adapters with parser-backed operations, filters, mutation fields, and bulk operation detection.
- Add Django ORM sink extraction for model manager calls, queryset mutations, serializer saves, request-controlled filters, tenant scope filters, and request-body mutation fields.
- Add Next.js App Router and Pages Router API route extraction with dynamic parameter normalization, request body sources, Prisma sink propagation, and Auth.js evidence labels.
- Normalize configured authentication, authorization, scope, transaction, invariant, and idempotency evidence through `rulepath_auth`.
- Replace one-hop service tracing with an import- and symbol-aware call graph that respects `analysis.service_layer_tracing` and `analysis.max_call_depth`.
