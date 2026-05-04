use rulepath_config::ResolvedConfig;
use rulepath_ir::{Confidence, EvidenceFact, EvidenceKind, RouteFact, SourceSpan};
use rulepath_parsers::ParsedFile;
use rulepath_workspace::SourceFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClassification {
    Authentication,
    Authorization,
    TenantScope,
    ObjectScope,
    Invariant,
    Transaction,
    Idempotency,
    Unknown,
}

impl From<EvidenceClassification> for Option<EvidenceKind> {
    fn from(value: EvidenceClassification) -> Self {
        match value {
            EvidenceClassification::Authentication => Some(EvidenceKind::Authentication),
            EvidenceClassification::Authorization => Some(EvidenceKind::Authorization),
            EvidenceClassification::TenantScope => Some(EvidenceKind::TenantScope),
            EvidenceClassification::ObjectScope => Some(EvidenceKind::ObjectScope),
            EvidenceClassification::Invariant => Some(EvidenceKind::Invariant),
            EvidenceClassification::Transaction => Some(EvidenceKind::Transaction),
            EvidenceClassification::Idempotency => Some(EvidenceKind::Idempotency),
            EvidenceClassification::Unknown => None,
        }
    }
}

#[must_use]
pub fn classify_helper(helper: &str, config: &ResolvedConfig) -> EvidenceClassification {
    let helper = normalized_helper(helper);
    let lower_helper = helper.to_ascii_lowercase();
    if configured_helpers(
        helper.as_str(),
        &config.raw.auth.authentication_guards.python,
        &config.raw.auth.authentication_guards.typescript,
    ) {
        return EvidenceClassification::Authentication;
    }
    if configured_helpers(
        helper.as_str(),
        &config.raw.auth.authorization_functions.python,
        &config.raw.auth.authorization_functions.typescript,
    ) {
        return EvidenceClassification::Authorization;
    }
    if configured_helpers(
        helper.as_str(),
        &config.raw.tenancy.current_tenant_expressions.python,
        &config.raw.tenancy.current_tenant_expressions.typescript,
    ) {
        return EvidenceClassification::TenantScope;
    }
    if lower_helper.contains("object")
        && (lower_helper.contains("permission") || lower_helper.contains("authorize"))
    {
        return EvidenceClassification::ObjectScope;
    }
    if helper.ends_with("Permission")
        || lower_helper.contains("permission_required")
        || lower_helper.contains("has_perm")
    {
        return EvidenceClassification::Authorization;
    }
    if helper == "commit"
        || helper.ends_with(".commit")
        || lower_helper.contains("transaction")
        || helper == "atomic"
    {
        return EvidenceClassification::Transaction;
    }
    if lower_helper.contains("idempotency") || lower_helper.contains("idempotent") {
        return EvidenceClassification::Idempotency;
    }
    if config.raw.invariants.iter().any(|invariant| {
        invariant
            .requires
            .iter()
            .any(|required| normalized_helper(required) == helper)
    }) {
        return EvidenceClassification::Invariant;
    }
    EvidenceClassification::Unknown
}

#[must_use]
pub fn normalize_file_evidence(
    file: &SourceFile,
    parsed: &ParsedFile,
    config: &ResolvedConfig,
) -> Vec<EvidenceFact> {
    let mut evidence = Vec::new();
    for call in &parsed.calls {
        let helper = normalized_helper(call.callee.as_str());
        if let Some(kind) = Option::<EvidenceKind>::from(classify_helper(helper.as_str(), config)) {
            evidence.push(evidence_fact(
                file,
                &helper,
                kind,
                call.callee.clone(),
                call.span.clone(),
                None,
                None,
                confidence_for(kind, helper.as_str()),
            ));
        }
    }
    for expression in current_tenant_expressions(config) {
        for (line_index, line) in file.text.lines().enumerate() {
            if line.contains(expression.as_str()) {
                evidence.push(evidence_fact(
                    file,
                    expression.as_str(),
                    EvidenceKind::TenantScope,
                    expression.clone(),
                    SourceSpan::single_line(file.relative_path.as_str(), line_index + 1),
                    None,
                    None,
                    Confidence::High,
                ));
            }
        }
    }
    evidence.sort_by(|left, right| {
        left.span
            .start
            .line
            .cmp(&right.span.start.line)
            .then(left.label.cmp(&right.label))
    });
    evidence.dedup_by(|left, right| left.id == right.id);
    evidence
}

#[must_use]
pub fn normalize_route_evidence(
    routes: &[RouteFact],
    config: &ResolvedConfig,
) -> Vec<EvidenceFact> {
    let mut evidence = Vec::new();
    for route in routes {
        for helper in &route.middleware {
            let normalized = normalized_helper(helper);
            if let Some(kind) =
                Option::<EvidenceKind>::from(classify_helper(normalized.as_str(), config))
            {
                evidence.push(evidence_fact(
                    &SourceFile {
                        path: route.span.file_id.clone().into(),
                        relative_path: route.span.file_id.clone(),
                        language: route.language,
                        text: String::new(),
                    },
                    normalized.as_str(),
                    kind,
                    helper.clone(),
                    route.span.clone(),
                    Some(route.id.clone()),
                    None,
                    Confidence::High,
                ));
            }
        }
    }
    evidence
}

fn configured_helpers(helper: &str, python: &[String], typescript: &[String]) -> bool {
    python
        .iter()
        .chain(typescript.iter())
        .any(|candidate| helper_matches(helper, candidate))
}

fn helper_matches(helper: &str, candidate: &str) -> bool {
    let candidate = normalized_helper(candidate);
    helper == candidate
        || helper
            .rsplit('.')
            .next()
            .is_some_and(|last| last == candidate)
}

fn normalized_helper(helper: &str) -> String {
    helper
        .trim()
        .trim_start_matches("Depends(")
        .trim_end_matches(')')
        .split('(')
        .next()
        .unwrap_or(helper)
        .trim()
        .to_owned()
}

fn current_tenant_expressions(config: &ResolvedConfig) -> Vec<String> {
    config
        .raw
        .tenancy
        .current_tenant_expressions
        .python
        .iter()
        .chain(
            config
                .raw
                .tenancy
                .current_tenant_expressions
                .typescript
                .iter(),
        )
        .cloned()
        .collect()
}

fn evidence_fact(
    file: &SourceFile,
    helper: &str,
    kind: EvidenceKind,
    expression: String,
    span: SourceSpan,
    route_id: Option<String>,
    sink_id: Option<String>,
    confidence: Confidence,
) -> EvidenceFact {
    EvidenceFact {
        id: format!(
            "evidence:{}:{}:{}",
            file.relative_path,
            span.start.line,
            label_for(kind, helper)
        ),
        kind,
        label: label_for(kind, helper),
        expression,
        confidence,
        route_id,
        sink_id,
        span,
    }
}

fn label_for(kind: EvidenceKind, helper: &str) -> String {
    format!("{}:{helper}", kind_label(kind))
}

fn kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Authentication => "authentication",
        EvidenceKind::Authorization => "authorization",
        EvidenceKind::ObjectScope => "object_scope",
        EvidenceKind::TenantScope => "tenant_scope",
        EvidenceKind::OwnershipScope => "ownership_scope",
        EvidenceKind::Invariant => "invariant",
        EvidenceKind::Transaction => "transaction",
        EvidenceKind::Idempotency => "idempotency",
        EvidenceKind::Audit => "audit",
    }
}

fn confidence_for(kind: EvidenceKind, helper: &str) -> Confidence {
    match kind {
        EvidenceKind::Transaction | EvidenceKind::Idempotency | EvidenceKind::Invariant => {
            Confidence::Medium
        }
        EvidenceKind::ObjectScope if helper.contains("object") => Confidence::High,
        EvidenceKind::ObjectScope => Confidence::Medium,
        _ => Confidence::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulepath_ir::{Language, Position};
    use rulepath_parsers::CallFact;

    #[test]
    fn classifies_configured_helpers_across_languages() {
        let config = rulepath_config::default_resolved_config();
        assert_eq!(
            classify_helper("requireAuth", &config),
            EvidenceClassification::Authentication
        );
        assert_eq!(
            classify_helper("require_permission", &config),
            EvidenceClassification::Authorization
        );
        assert_eq!(
            classify_helper("req.user.tenantId", &config),
            EvidenceClassification::TenantScope
        );
        assert_eq!(
            classify_helper("InvoicePermission", &config),
            EvidenceClassification::Authorization
        );
        assert_eq!(
            classify_helper("check_object_permissions", &config),
            EvidenceClassification::ObjectScope
        );
    }

    #[test]
    fn normalizes_call_and_tenant_expression_evidence() {
        let config = rulepath_config::default_resolved_config();
        let file = SourceFile {
            path: "src/routes/invoices.ts".into(),
            relative_path: "src/routes/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: "requirePermission(\"invoice:update\")\nconst clientId = req.user.tenantId\n"
                .to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "requirePermission".to_owned(),
                arguments: vec!["\"invoice:update\"".to_owned()],
                span: SourceSpan {
                    file_id: file.relative_path.clone(),
                    start: Position::new(1, 1),
                    end: Position::new(1, 30),
                },
            }],
            suppressions: Vec::new(),
        };

        let evidence = normalize_file_evidence(&file, &parsed, &config);
        assert!(evidence
            .iter()
            .any(|item| item.kind == EvidenceKind::Authorization));
        assert!(evidence
            .iter()
            .any(|item| item.kind == EvidenceKind::TenantScope));
    }
}
