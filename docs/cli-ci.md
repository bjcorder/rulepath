# CLI And CI Contract

Rulepath local scans should be fast and explainable. CI is advisory by default and fails only when the project opts in.

## Commands

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

## CI Policy

`rulepath infer .` writes a deterministic `.rulepath.inferred.yml` draft using parsed route, sink, resource, and evidence facts. The draft remains advisory: scans do not consume it unless reviewed content is copied into `.rulepath.yml`.

```yaml
ci:
  fail: true
  fail_on:
    severities: [high, critical]
    confidence: [high]
    include_review_hints: false
    new_findings_only: true
  baseline_file: .rulepath.baseline.json
```

Exit behavior:

- `ci.fail: false`: exit 0 unless there is a fatal error.
- `ci.fail: true`: exit 1 only for matching findings.
- `include_review_hints: false`: review hints do not fail CI.
- `new_findings_only: true`: baseline entries do not fail CI.

`ci.baseline_file` must be a relative path inside the scan root. Absolute paths and paths containing `..` are rejected for both baseline creation and CI reads.

Baseline fingerprints are semantic identifiers, not source-line identifiers. They include the rule, framework, route method and path, resource, operation, sink kind and method, normalized sink shape, and normalized file path when available. Line and column data remain diagnostic metadata only, so whitespace changes and nearby unrelated edits should not invalidate a baseline entry.

Baseline files preserve separate `findings` and `review_hints` entries, are written in deterministic sorted order, and must use the supported baseline schema version. Invalid JSON, unsupported versions, unknown fields, or entries missing `rule_id`, `fingerprint`, or `title` fail the scan with a fatal baseline error.

Suppressions are applied before reporting, baseline creation, and CI failure decisions. When suppression reasons are required, a bare disabling comment is a scan error rather than a hidden finding.

## GitHub Actions Annotations

When `rulepath scan --ci` runs with `GITHUB_ACTIONS=true`, Rulepath emits GitHub Actions `::error` annotations for findings only. Annotations use the finding primary span for file, line, and column, and are written to stderr so JSON and SARIF stdout remain parseable. Review hints are not annotated unless a future policy explicitly opts them in.

## JSON Output

JSON output keeps findings and review hints in separate arrays:

```json
{
  "tool": "rulepath",
  "version": "0.1.0",
  "summary": {
    "findings": 0,
    "review_hints": 0
  },
  "findings": [],
  "review_hints": []
}
```

Findings and review hints include call-path frames when tracing can connect a route to a sink.

## SARIF Output

SARIF output includes stable rule metadata, result locations, `partialFingerprints.rulepathFingerprint`, diagnostic properties, and `codeFlows` when call-path frames are available. Finding results use SARIF `error` level; review hints remain marked as `review_hint` in result properties.
