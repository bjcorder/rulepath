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
- Add Django and Django REST Framework route extraction for `urls.py` patterns, `APIView`/`ViewSet`/`ModelViewSet` methods, DRF actions, router registrations, request sources, and permission-class evidence.
- Add Next.js App Router and Pages Router API route extraction with dynamic parameter normalization, request body sources, Prisma sink propagation, and Auth.js evidence labels.
- Normalize configured authentication, authorization, scope, transaction, invariant, and idempotency evidence through `rulepath_auth`.
- Replace one-hop service tracing with an import- and symbol-aware call graph that respects `analysis.service_layer_tracing` and `analysis.max_call_depth`.
- Fix ORM source-window slicing so non-ASCII source context cannot panic scans.
- Restrict config-controlled inference output and CI baseline paths to relative paths inside the scan root.
- Restrict suppression parsing to recognized TypeScript/JavaScript and Python comments so string literals cannot suppress findings.
- Include sink identity and primary span location in diagnostic fingerprints; regenerate baselines after upgrading.
- Complete v1 rule and review-hint coverage for `INV001` through `INV008` and `HINT001` through `HINT006`.
- Add GitHub Actions finding annotations and harden text, JSON, SARIF, and CI output contract coverage.
- Stabilize diagnostic fingerprints around semantic route and sink identity, and validate deterministic baseline files.
- Expand the fixture matrix with v1 rule and review-hint coverage plus safe/unsafe structured assertions.
- Improve `.rulepath.inferred.yml` generation using IR facts, deterministic strict-config-compatible YAML, and fixture-backed inference tests.
- Add non-fatal analysis diagnostics for parse errors, unresolved imports, ambiguous resources, and skipped non-UTF8 files.
