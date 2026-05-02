# Product Requirements

Rulepath is a deterministic static analyzer for business logic and security invariants in internally developed web applications.

The v1 product should find high-confidence violations of invariants that matter in multi-tenant and workflow-heavy apps:

- Tenant or client scoping for resource access.
- Server-owned fields that must not be controlled by request bodies.
- Operation-specific authorization for sensitive mutations.
- Workflow transition requirements.
- Idempotency for sensitive external operations.
- Export, download, and report permission checks.

## Users

Primary users are developers and security engineers working on internal web applications, client portals, SaaS-style apps, admin panels, workflow tools, billing systems, and reporting dashboards.

Rulepath should fit local development, pre-commit, pull-request CI, and security review workflows.

## Source Of Truth

`.rulepath.yml` is the policy source of truth. It defines frameworks, data layers, analysis settings, CI policy, auth helpers, tenancy fields, resources, sensitive fields, server-owned fields, invariants, and suppression policy.

`.rulepath.inferred.yml` is always a draft. It must never replace or silently extend policy.

## Signal Policy

Rulepath emits two diagnostic classes:

- Findings: high-confidence violations of configured or strongly inferred invariants.
- Review hints: medium-confidence observations that deserve human review.

Findings and review hints must remain separate in text, JSON, SARIF, and CI output.

## Success Criteria

Rulepath v1 is successful when it can scan representative internal apps and detect:

- Unscoped tenant-owned resource access.
- Direct client control over server-owned fields.
- Sensitive mutations without operation authorization.
- Declared state transitions without required evidence.
- Sensitive operations without idempotency evidence.
- Bulk mutations without tenant scope.
- Exports without permission and scope.
- Sensitive service-layer mutations reachable from insufficiently protected routes.
