# Rule Catalog

Rulepath emits high-confidence findings for invariant violations and medium-confidence review hints for observations that need a human decision.

## Findings

| ID | Name |
| --- | --- |
| `INV001` | Unscoped resource access |
| `INV002` | Client-controlled server-owned field |
| `INV003` | Mutation without operation authorization |
| `INV004` | Declared state transition invariant missing |
| `INV005` | Sensitive operation lacks idempotency |
| `INV006` | Bulk update/delete without scope |
| `INV007` | Export/download/report without permission |
| `INV008` | Service-layer sensitive mutation reachable from unprotected route |

## Review Hints

| ID | Name |
| --- | --- |
| `HINT001` | Possible resource not configured |
| `HINT002` | Possible authorization helper not configured |
| `HINT003` | Possible workflow transition |
| `HINT004` | Possible money-like operation |
| `HINT005` | Export-like endpoint |
| `HINT006` | Auth present but scope unclear |

## Rule Requirements

Every finding should include rule ID, title, severity, confidence, resource, operation, route, call path, request-controlled source, sink, missing invariant, observed evidence, expected evidence, suggested fix, and stable fingerprint.

Rules must evaluate IR and config only.
