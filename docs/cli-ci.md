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

Suppressions are applied before reporting, baseline creation, and CI failure decisions. When suppression reasons are required, a bare disabling comment is a scan error rather than a hidden finding.

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
