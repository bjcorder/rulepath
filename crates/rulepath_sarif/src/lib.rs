use rulepath_ir::{Diagnostic, DiagnosticKind, Severity};
use serde_json::{json, Value};

#[must_use]
pub fn render_sarif(version: &str, diagnostics: &[Diagnostic]) -> Value {
    let results = diagnostics
        .iter()
        .map(diagnostic_to_result)
        .collect::<Vec<_>>();
    let rules = diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "id": diagnostic.rule_id,
                "name": diagnostic.title,
                "shortDescription": {
                    "text": diagnostic.title
                },
                "properties": {
                    "kind": match diagnostic.kind {
                        DiagnosticKind::Finding => "finding",
                        DiagnosticKind::ReviewHint => "review_hint",
                    }
                }
            })
        })
        .collect::<Vec<_>>();

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
            "kind": match diagnostic.kind {
                DiagnosticKind::Finding => "finding",
                DiagnosticKind::ReviewHint => "review_hint",
            }
        }
    })
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
