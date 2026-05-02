use rulepath_ir::{Confidence, Diagnostic, DiagnosticKind, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub summary: ReportSummary,
    pub findings: Vec<Diagnostic>,
    pub review_hints: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    pub findings: usize,
    pub review_hints: usize,
}

#[must_use]
pub fn build_report(version: &str, diagnostics: Vec<Diagnostic>) -> Report {
    let (findings, review_hints): (Vec<_>, Vec<_>) = diagnostics
        .into_iter()
        .partition(|diagnostic| diagnostic.kind == DiagnosticKind::Finding);
    Report {
        tool: "rulepath".to_owned(),
        version: version.to_owned(),
        summary: ReportSummary {
            findings: findings.len(),
            review_hints: review_hints.len(),
        },
        findings,
        review_hints,
    }
}

pub fn render_json(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}

#[must_use]
pub fn render_text(report: &Report) -> String {
    let mut output = String::new();
    output.push_str("Rulepath scan results\n\n");
    output.push_str(&format!("Findings: {}\n", report.summary.findings));
    for finding in &report.findings {
        output.push_str(&format!(
            "  [{}] {} {}\n",
            severity_label(finding.severity),
            finding.rule_id,
            finding.title
        ));
    }
    output.push_str(&format!(
        "\nReview hints: {}\n",
        report.summary.review_hints
    ));
    for hint in &report.review_hints {
        output.push_str(&format!(
            "  [{}] {} {}\n",
            confidence_label(hint.confidence),
            hint.rule_id,
            hint.title
        ));
    }

    if !report.findings.is_empty() {
        output.push_str("\nDetails\n");
        for finding in &report.findings {
            output.push_str(&render_diagnostic_detail(finding));
        }
    }
    output
}

fn render_diagnostic_detail(diagnostic: &Diagnostic) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "\n{} {:?} confidence\n",
        diagnostic.rule_id, diagnostic.confidence
    ));
    output.push_str(&format!("{}\n", diagnostic.title));
    if let Some(route_id) = &diagnostic.route_id {
        output.push_str(&format!("\nRoute:\n  {route_id}\n"));
    }
    if let Some(call_path_id) = &diagnostic.call_path_id {
        output.push_str(&format!("\nCode path:\n  {call_path_id}\n"));
    }
    if !diagnostic.source_ids.is_empty() {
        output.push_str("\nSource:\n");
        for source in &diagnostic.source_ids {
            output.push_str(&format!("  {source}\n"));
        }
    }
    if let Some(sink_id) = &diagnostic.sink_id {
        output.push_str(&format!("\nSink:\n  {sink_id}\n"));
    }
    if let Some(missing) = &diagnostic.missing_invariant {
        output.push_str(&format!("\nMissing invariant:\n  {missing}\n"));
    }
    if !diagnostic.observed_evidence.is_empty() {
        output.push_str("\nObserved evidence:\n");
        for evidence in &diagnostic.observed_evidence {
            output.push_str(&format!("  {evidence}\n"));
        }
    }
    if !diagnostic.expected_evidence.is_empty() {
        output.push_str("\nExpected evidence:\n");
        for evidence in &diagnostic.expected_evidence {
            output.push_str(&format!("  {evidence}\n"));
        }
    }
    if let Some(fix) = &diagnostic.suggested_fix {
        output.push_str(&format!("\nSuggested fix:\n  {fix}\n"));
    }
    output
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn confidence_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "LOW",
        Confidence::Medium => "MEDIUM",
        Confidence::High => "HIGH",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_report_classes() {
        let report = build_report("0.1.0", Vec::new());
        assert_eq!(report.summary.findings, 0);
        assert_eq!(report.summary.review_hints, 0);
    }
}
