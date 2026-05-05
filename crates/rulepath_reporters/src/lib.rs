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
pub fn render_github_annotations(report: &Report) -> String {
    let mut output = String::new();
    for finding in &report.findings {
        let Some(span) = finding.primary_span.as_ref() else {
            continue;
        };
        let title = format!("{} {}", finding.rule_id, finding.title);
        output.push_str(&format!(
            "::error file={},line={},col={},title={}::{}\n",
            escape_annotation_property(&span.file_id),
            span.start.line,
            span.start.column,
            escape_annotation_property(&title),
            escape_annotation_message(&annotation_message(finding))
        ));
    }
    output
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

fn annotation_message(diagnostic: &Diagnostic) -> String {
    let mut message = diagnostic.title.clone();
    if let Some(route_id) = &diagnostic.route_id {
        message.push_str(&format!(" Route: {route_id}."));
    }
    if let Some(missing) = &diagnostic.missing_invariant {
        message.push_str(&format!(" Missing invariant: {missing}."));
    }
    if let Some(fix) = &diagnostic.suggested_fix {
        message.push_str(&format!(" Suggested fix: {fix}"));
    }
    message
}

fn escape_annotation_property(value: &str) -> String {
    escape_annotation_message(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn escape_annotation_message(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
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
    if !diagnostic.call_path.is_empty() {
        output.push_str("\nCode path:\n");
        for frame in &diagnostic.call_path {
            output.push_str(&format!(
                "  {}:{} {}()\n",
                normalized_path(&frame.file),
                frame.line,
                frame.function
            ));
        }
    } else if let Some(call_path_id) = &diagnostic.call_path_id {
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

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/")
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

    #[test]
    fn github_annotations_include_findings_only() {
        let report = Report {
            tool: "rulepath".to_owned(),
            version: "0.1.0".to_owned(),
            summary: ReportSummary {
                findings: 1,
                review_hints: 1,
            },
            findings: vec![diagnostic(DiagnosticKind::Finding, "INV001")],
            review_hints: vec![diagnostic(DiagnosticKind::ReviewHint, "HINT001")],
        };

        let annotations = render_github_annotations(&report);

        assert!(annotations.contains("::error file=src/invoices.ts,line=10,col=3"));
        assert!(annotations.contains("INV001"));
        assert!(!annotations.contains("HINT001"));
    }

    fn diagnostic(kind: DiagnosticKind, rule_id: &str) -> Diagnostic {
        Diagnostic {
            kind,
            rule_id: rule_id.to_owned(),
            title: "Unscoped Invoice access".to_owned(),
            severity: Severity::High,
            confidence: Confidence::High,
            resource: Some("Invoice".to_owned()),
            operation: None,
            route_id: Some("route:Express:PATCH:/invoices/:id:0".to_owned()),
            call_path_id: None,
            call_path: Vec::new(),
            source_ids: Vec::new(),
            sink_id: Some("sink:1".to_owned()),
            primary_span: Some(rulepath_ir::SourceSpan {
                file_id: "src/invoices.ts".to_owned(),
                start: rulepath_ir::Position::new(10, 3),
                end: rulepath_ir::Position::new(10, 12),
            }),
            missing_invariant: Some("scope required".to_owned()),
            observed_evidence: Vec::new(),
            expected_evidence: Vec::new(),
            suggested_fix: Some("Add tenant scope.".to_owned()),
            fingerprint: "fingerprint".to_owned(),
        }
    }
}
