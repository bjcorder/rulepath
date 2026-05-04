# Configuration

`.rulepath.yml` is the project policy file. The schema is strict: unknown top-level and nested keys fail validation.

## Minimal Config

```yaml
version: 1

profile:
  name: internal_web_app

analysis:
  mode: high_confidence
  service_layer_tracing: true
  max_call_depth: 6
  include_review_hints: true
  include_paths: [app, src]
  exclude_paths: [node_modules, .venv, venv, migrations, tests, dist, build]

ci:
  fail: false
  baseline_file: .rulepath.baseline.json

inference:
  generated_file: .rulepath.inferred.yml
  use_inferred_file_for_scan: false

suppressions:
  require_reason: true
  min_reason_length: 20
```

## Configured File Paths

`inference.generated_file` and `ci.baseline_file` must be relative paths inside the scan root. Absolute paths and paths containing `..` fail with a clear config-key error. Nested paths such as `.rulepath/generated.yml` and `.rulepath/baseline.json` are valid; write commands create parent directories inside the project.

## Resources

Resources define fields that imply tenancy, sensitivity, or server ownership.

```yaml
resources:
  Invoice:
    tenant_fields: [tenant_id, tenantId, client_id, clientId]
    sensitive_fields: [status, amount, total, approved_by, paid_at]
    server_owned_fields: [status, amount, total, approved_by, paid_at]
```

## Suppressions

Supported comments:

```text
rulepath-disable-next-line RULE_ID -- reason
rulepath-disable-line RULE_ID -- reason
rulepath-disable RULE_ID -- reason
rulepath-enable RULE_ID
```

When `suppressions.require_reason` is true, disabling comments must include a reason after `--`.

Suppressed diagnostics are removed before text, JSON, SARIF, baseline, and CI output. Bare or too-short suppression reasons fail the scan when the policy requires reasons.
