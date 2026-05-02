# Common Intermediate Representation

The common IR is the contract between analyzers and rules.

It is language-neutral, serializable, stable enough for baselines, and rich enough to explain route-to-sink evidence.

## Core Concepts

- Source files and spans.
- Routes and externally reachable handlers.
- Request-controlled sources.
- Principal facts.
- Evidence facts for authentication, authorization, object scope, tenant scope, idempotency, transactions, and invariants.
- Operation and sink facts.
- Call paths.
- Findings and review hints.

## Stable Fingerprints

Fingerprints should be based on semantic identity:

```text
rule_id
framework
route method/path
resource
operation
sink kind/method
normalized sink expression
normalized file path
```

Line numbers can be included as metadata, but they should not be the primary identity.

## Confidence

IR facts carry confidence where uncertainty matters. Rules should downgrade uncertain paths to review hints instead of emitting speculative findings.
