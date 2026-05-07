# Rulepath

Rulepath is a Rust-native static analysis tool for business logic and security invariant review in internally developed web applications.

It traces from externally reachable routes into service-layer functions and data-layer operations, then checks whether those paths preserve invariants declared in `.rulepath.yml`.

Rulepath is not a generic insecure API scanner. Its first wedge is repeatable review of app-specific invariants:

```text
This route updates an Invoice by ID. Is the lookup scoped to the current tenant?
This handler accepts req.body. Can the client set role, tenant_id, status, or total?
This export endpoint returns bulk data. Does it enforce tenant scope and export permission?
This service changes Client.status. Is there operation-specific authorization?
```

## v1 Scope

Rulepath v1 targets internally developed web applications:

| Area | v1 support |
| --- | --- |
| Implementation language | Rust |
| CLI binary | `rulepath` |
| Source languages analyzed | Python, TypeScript |
| Python frameworks | FastAPI, Django, Django REST Framework |
| TypeScript frameworks | Express, Next.js |
| Data layers | Django ORM, SQLAlchemy, Prisma |
| Policy file | `.rulepath.yml` |
| Inference output | `.rulepath.inferred.yml` |
| Baseline file | `.rulepath.baseline.json` |

Normal scans must not require Python, Node, Docker, network access, or a TypeScript compiler process.

## Analysis Model

Rulepath scans source code through Rust-native parser adapters. TypeScript uses Oxc-backed parsing and Python uses tree-sitter-backed parsing to produce normalized facts for imports, symbols, calls, spans, and suppressions.

Framework adapters convert parsed facts into routes, handlers, middleware/dependencies, and request sources. Data-layer adapters convert parsed calls into operations, filters, mutation fields, bulk flags, and sink spans for Prisma, SQLAlchemy, and Django ORM.

Evidence normalization is config-driven. Authentication guards, authorization helpers, tenant expressions, object-scope checks, transaction markers, invariant helpers, and idempotency helpers are normalized before rule evaluation. Service tracing builds an import- and symbol-aware call graph and respects `analysis.service_layer_tracing` and `analysis.max_call_depth`.

## Build From Source

```bash
cargo build
cargo test
cargo run -p rulepath_cli -- --help
```

The CLI package is named `rulepath_cli`; the binary it produces is named `rulepath`.

## Quickstart

```bash
rulepath init
rulepath config validate
rulepath scan .
rulepath scan . --format json
rulepath scan . --ci
```

`rulepath init` creates a starter `.rulepath.yml`. `rulepath infer .` writes `.rulepath.inferred.yml` as a draft; inferred policy is never silently enforced.

## Core Commands

```bash
rulepath init
rulepath config validate
rulepath infer .
rulepath scan .
rulepath scan . --ci
rulepath scan . --format json
rulepath scan . --format sarif
rulepath baseline create
rulepath explain INV001
```

## Example Config

```yaml
version: 1

profile:
  name: internal_web_app

analysis:
  mode: high_confidence
  service_layer_tracing: true
  max_call_depth: 6
  include_review_hints: true

ci:
  fail: false
  baseline_file: .rulepath.baseline.json

suppressions:
  require_reason: true
  min_reason_length: 20

resources:
  Invoice:
    tenant_fields: [tenant_id, tenantId, client_id, clientId]
    sensitive_fields: [status, amount, total, approved_by, paid_at]
    server_owned_fields: [status, amount, total, approved_by, paid_at]

invariants:
  - id: no_unscoped_invoice_access
    type: scoped_resource_access
    resources: [Invoice]
    operations: [read, update, delete, export]
    required_scope: [tenant]
    severity: high
```

Unknown config keys fail validation. Inline suppressions require a reason by default and are recognized only in language comments, not string literals:

Configured `inference.generated_file` and `ci.baseline_file` values must stay inside the scan root. Use relative paths such as `.rulepath.inferred.yml` or `.rulepath/baseline.json`; absolute paths and `..` segments are rejected.

```ts
// rulepath-disable-next-line INV001 -- enforced by requireSuperAdmin middleware above
const invoice = await prisma.invoice.findUnique({ where: { id } })
```

Suppression policy is enforced during scans. A bare suppression fails fast instead of quietly hiding a finding.

## Output Policy

Rulepath separates high-confidence findings from medium-confidence review hints in every output mode.

```text
Rulepath scan results

Findings: 2
  [HIGH] INV001 Unscoped Invoice access
  [HIGH] INV002 Client-controlled Invoice fields

Review hints: 1
  [MEDIUM] HINT003 Possible workflow state transition
```

CI is advisory by default. `rulepath scan . --ci` exits nonzero only when `.rulepath.yml` sets `ci.fail: true` and an unsuppressed, non-baselined finding matches `ci.fail_on`. Baseline fingerprints include sink identity and primary span location, so regenerate baselines after upgrades that change fingerprint inputs.

Findings are high-confidence invariant violations; review hints are medium-confidence observations for missing configuration or uncertain business semantics. Both classes remain separate in text, JSON, SARIF, and baseline output.

## Documentation

- [Product requirements](docs/product.md)
- [Architecture](docs/architecture.md)
- [Common IR](docs/ir.md)
- [Configuration](docs/configuration.md)
- [Rule catalog](docs/rules.md)
- [CLI and CI contract](docs/cli-ci.md)
- [Extending Rulepath](docs/extending.md)
- [Testing fixtures](docs/testing-fixtures.md)
- [Dependency pinning](docs/dependency-pinning.md)
- [Roadmap](docs/roadmap.md)
- [Implementation notes](docs/implementation-notes.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [SUPPORT.md](SUPPORT.md).

Rulepath is released under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`). Contributions are accepted under the
[Rulepath Contributor License Agreement](CLA.md).
