# Testing Fixtures

Fixture apps prove that Rulepath works across supported frameworks and data layers.

## Layout

```text
fixtures/
  express_prisma/
    safe/
    unsafe/
  fastapi_sqlalchemy/
    safe/
    unsafe/
  django_drf/
    safe/
    unsafe/
  nextjs_prisma_authjs/
    safe/
    unsafe/
```

Each fixture should be small, readable, and focused on one analysis behavior.

Language adapters also carry parser-level unit coverage for imports, symbols, calls, decorators, and suppressions. Fixture scans should assert the end-to-end path: parser facts, framework route extraction, data-layer operation extraction, trace propagation, and final findings.

## Required Scenarios

Each fixture family should cover:

- Route discovery.
- Request source extraction.
- Authentication evidence.
- Authorization evidence.
- Object-scope evidence.
- Tenant-scope evidence.
- Service-layer tracing.
- ORM sink detection.
- Finding emission.
- Review-hint emission.
- Baseline behavior.
- CI failure behavior.
- Suppression behavior.

## Acceptance Milestones

The first milestone is:

```bash
rulepath scan fixtures/express_prisma/unsafe
```

It should discover an Express route, trace to a Prisma sink, detect request-controlled IDs and body data, and emit `INV001` plus `INV002`.

The second milestone mirrors that behavior for FastAPI and SQLAlchemy.

The Django/DRF fixture pair verifies Django ORM extraction. The unsafe fixture should emit unscoped resource access for a request-controlled object lookup, while the safe fixture should remain clean because tenant filtering or object permission evidence is recognized.
