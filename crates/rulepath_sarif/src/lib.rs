use std::collections::BTreeMap;

use rulepath_ir::{Diagnostic, DiagnosticKind, Severity};
use serde_json::{json, Value};

#[must_use]
pub fn render_sarif(version: &str, diagnostics: &[Diagnostic]) -> Value {
    let results = diagnostics
        .iter()
        .map(diagnostic_to_result)
        .collect::<Vec<_>>();
    let mut rules_by_id = BTreeMap::new();
    for diagnostic in diagnostics {
        rules_by_id.entry(diagnostic.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": diagnostic.rule_id,
                "name": diagnostic.rule_id,
                "shortDescription": {
                    "text": diagnostic.title
                },
                "fullDescription": {
                    "text": diagnostic.missing_invariant.as_deref().unwrap_or(&diagnostic.title)
                },
                "help": {
                    "text": diagnostic.suggested_fix.as_deref().unwrap_or("Review this Rulepath diagnostic.")
                },
                "properties": {
                    "kind": diagnostic_kind(diagnostic.kind),
                    "precision": match diagnostic.kind {
                        DiagnosticKind::Finding => "high",
                        DiagnosticKind::ReviewHint => "medium",
                    }
                }
            })
        });
    }
    let rules = rules_by_id.into_values().collect::<Vec<_>>();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rulepath",
                    "version": version,
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn diagnostic_to_result(diagnostic: &Diagnostic) -> Value {
    let span = diagnostic.primary_span.as_ref();
    json!({
        "ruleId": diagnostic.rule_id,
        "level": sarif_level(diagnostic.severity),
        "message": {
            "text": diagnostic.title
        },
        "locations": span.map(|span| {
            json!([{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": &span.file_id
                    },
                    "region": {
                        "startLine": span.start.line,
                        "startColumn": span.start.column,
                        "endLine": span.end.line,
                        "endColumn": span.end.column
                    }
                }
            }])
        }).unwrap_or_else(|| json!([])),
        "partialFingerprints": {
            "rulepathFingerprint": diagnostic.fingerprint
        },
        "codeFlows": code_flows(diagnostic),
        "properties": {
            "kind": diagnostic_kind(diagnostic.kind),
            "confidence": format!("{:?}", diagnostic.confidence).to_ascii_lowercase(),
            "fingerprint": diagnostic.fingerprint,
            "routeId": diagnostic.route_id,
            "callPathId": diagnostic.call_path_id,
            "sinkId": diagnostic.sink_id,
            "sourceIds": diagnostic.source_ids,
            "missingInvariant": diagnostic.missing_invariant,
            "observedEvidence": diagnostic.observed_evidence,
            "expectedEvidence": diagnostic.expected_evidence,
            "suggestedFix": diagnostic.suggested_fix,
        }
    })
}

fn diagnostic_kind(kind: DiagnosticKind) -> &'static str {
    match kind {
        DiagnosticKind::Finding => "finding",
        DiagnosticKind::ReviewHint => "review_hint",
    }
}

fn code_flows(diagnostic: &Diagnostic) -> Value {
    if diagnostic.call_path.is_empty() {
        return json!([]);
    }

    let locations = diagnostic
        .call_path
        .iter()
        .map(|frame| {
            json!({
                "location": {
                    "message": {
                        "text": &frame.function
                    },
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": &frame.file
                        },
                        "region": {
                            "startLine": frame.line,
                            "startColumn": 1
                        }
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    json!([{
        "threadFlows": [{
            "locations": locations
        }]
    }])
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
