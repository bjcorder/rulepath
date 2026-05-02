use rulepath_config::ResolvedConfig;
use rulepath_ir::{
    fingerprint, Confidence, Diagnostic, DiagnosticKind, EvidenceFact, EvidenceKind, OperationFact,
    OperationType, ProjectIr, Severity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExplanation {
    pub id: &'static str,
    pub title: &'static str,
    pub purpose: &'static str,
    pub safe_patterns: &'static [&'static str],
    pub config_keys: &'static [&'static str],
}

#[must_use]
pub fn evaluate(ir: &ProjectIr, config: &ResolvedConfig) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for operation in &ir.operations {
        let route = ir.route_for_operation(&operation.id);
        let call_path = ir.call_path_for_operation(&operation.id);
        let route_id = route.map(|route| route.id.as_str());
        let evidence = ir.evidence_for_route_or_sink(route_id, &operation.id);

        if should_emit_inv001(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV001",
                format!("Unscoped {} access", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Resource access requires tenant/client/object scope.",
                observed_labels(&evidence),
                vec!["tenant_scope or object_scope".to_owned()],
                "Add tenant/client scope to the query or call a configured object authorization helper.",
            ));
        }

        if should_emit_inv002(operation, config) {
            diagnostics.push(finding(
                "INV002",
                format!("Client-controlled {} fields", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Server-owned or sensitive fields must not be directly controlled by the client.",
                observed_labels(&evidence),
                vec!["allowlisted mutation fields".to_owned()],
                "Allowlist mutable fields and construct the data object server-side.",
            ));
        }

        if should_emit_inv003(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV003",
                format!(
                    "{} mutation without operation authorization",
                    operation.resource
                ),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Sensitive mutations require operation-specific authorization.",
                observed_labels(&evidence),
                vec!["authorization".to_owned()],
                "Add a configured permission or policy helper for this operation.",
            ));
        }

        if should_emit_inv004(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV004",
                format!("{} state transition lacks required evidence", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Configured state transitions require invariant evidence.",
                observed_labels(&evidence),
                vec!["configured transition evidence".to_owned()],
                "Check the prior state and required permission or business condition before updating state.",
            ));
        }

        if should_emit_inv006(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV006",
                format!("Bulk {} mutation without scope", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Bulk update/delete requires tenant/client/object scope.",
                observed_labels(&evidence),
                vec!["tenant_scope or object_scope".to_owned()],
                "Add configured scope fields to the bulk mutation filter.",
            ));
        }

        if should_emit_inv007(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV007",
                format!("{} export without permission or scope", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Export/download/report operations require permission and scope.",
                observed_labels(&evidence),
                vec![
                    "authorization".to_owned(),
                    "tenant_scope or object_scope".to_owned(),
                ],
                "Require export permission and scope the exported resource set.",
            ));
        }

        if should_emit_inv008(
            operation,
            config,
            &evidence,
            call_path.map_or(0, |path| path.frames.len()),
        ) {
            diagnostics.push(finding(
                "INV008",
                format!("Sensitive {} mutation reachable from insufficiently protected route", operation.resource),
                operation,
                route_id,
                call_path.map(|path| path.id.as_str()),
                "Service-layer sensitive mutations require inherited or local auth and scope evidence.",
                observed_labels(&evidence),
                vec!["authorization".to_owned(), "tenant_scope or object_scope".to_owned()],
                "Propagate authorization and scope checks from the route to the service call path.",
            ));
        }

        emit_hints(
            operation,
            config,
            &evidence,
            route_id,
            call_path.map(|path| path.id.as_str()),
            &mut diagnostics,
        );
    }

    diagnostics
}

#[must_use]
pub fn explain(rule_id: &str) -> Option<RuleExplanation> {
    all_explanations()
        .iter()
        .find(|explanation| explanation.id == rule_id)
        .cloned()
}

#[must_use]
pub fn all_explanations() -> &'static [RuleExplanation] {
    &[
        RuleExplanation {
            id: "INV001",
            title: "Unscoped resource access",
            purpose: "Detect request-controlled resource access without configured tenant, ownership, or object-scope evidence.",
            safe_patterns: &["Scope queries by tenant/client/org/owner fields.", "Call a configured object authorization helper."],
            config_keys: &["resources.*.tenant_fields", "tenancy.tenant_fields", "invariants"],
        },
        RuleExplanation {
            id: "INV002",
            title: "Client-controlled server-owned field",
            purpose: "Detect request body data flowing into sensitive or server-owned fields.",
            safe_patterns: &["Allowlist mutable fields.", "Assign server-owned fields from trusted server-side state."],
            config_keys: &["resources.*.server_owned_fields", "resources.*.sensitive_fields"],
        },
        RuleExplanation {
            id: "INV003",
            title: "Mutation without operation authorization",
            purpose: "Detect sensitive state-changing operations without operation-specific authorization.",
            safe_patterns: &["Use configured permission, policy, or can/authorize helpers."],
            config_keys: &["auth.authorization_functions", "resources.*.sensitive_fields"],
        },
        RuleExplanation {
            id: "INV004",
            title: "Declared state transition invariant missing",
            purpose: "Detect configured workflow state transitions that lack required evidence.",
            safe_patterns: &["Check prior state and required transition conditions before mutation."],
            config_keys: &["invariants"],
        },
        RuleExplanation {
            id: "INV005",
            title: "Sensitive operation lacks idempotency",
            purpose: "Detect configured sensitive external operations without idempotency evidence.",
            safe_patterns: &["Require idempotency keys or prior-operation checks."],
            config_keys: &["invariants"],
        },
        RuleExplanation {
            id: "INV006",
            title: "Bulk update/delete without scope",
            purpose: "Detect bulk mutations on tenant-owned resources without configured scope filters.",
            safe_patterns: &["Include tenant/client/org/owner fields in bulk mutation filters."],
            config_keys: &["resources.*.tenant_fields", "tenancy.tenant_fields"],
        },
        RuleExplanation {
            id: "INV007",
            title: "Export/download/report without permission",
            purpose: "Detect export-like operations without permission and tenant/object scope.",
            safe_patterns: &["Require export permission and scope result sets."],
            config_keys: &["invariants", "auth.authorization_functions"],
        },
        RuleExplanation {
            id: "INV008",
            title: "Service-layer sensitive mutation reachable from unprotected route",
            purpose: "Detect route-to-service paths that reach sensitive mutations without auth and scope evidence.",
            safe_patterns: &["Propagate permission and scope checks through service-layer calls."],
            config_keys: &["analysis.service_layer_tracing", "auth", "resources"],
        },
        RuleExplanation {
            id: "HINT001",
            title: "Possible resource not configured",
            purpose: "Identify business-looking resources missing from policy.",
            safe_patterns: &["Add the resource to .rulepath.yml or ignore if not business-sensitive."],
            config_keys: &["resources"],
        },
        RuleExplanation {
            id: "HINT002",
            title: "Possible authorization helper not configured",
            purpose: "Identify helper names that may represent authorization but are not configured.",
            safe_patterns: &["Add custom helpers under auth.authorization_functions."],
            config_keys: &["auth.authorization_functions"],
        },
        RuleExplanation {
            id: "HINT003",
            title: "Possible workflow transition",
            purpose: "Identify status/state changes without configured transition invariants.",
            safe_patterns: &["Add a state_transition invariant when status changes are business-sensitive."],
            config_keys: &["invariants"],
        },
        RuleExplanation {
            id: "HINT004",
            title: "Possible money-like operation",
            purpose: "Identify payment or balance related routes that may need stronger invariants.",
            safe_patterns: &["Configure idempotency and operation authorization invariants."],
            config_keys: &["invariants"],
        },
        RuleExplanation {
            id: "HINT005",
            title: "Export-like endpoint",
            purpose: "Identify export/download/report behavior when resource mapping is unclear.",
            safe_patterns: &["Configure resource mappings and export invariants."],
            config_keys: &["resources", "invariants"],
        },
        RuleExplanation {
            id: "HINT006",
            title: "Auth present but scope unclear",
            purpose: "Identify authenticated routes where object or tenant scope is unclear.",
            safe_patterns: &["Add tenant/object scope evidence to the route-to-sink path."],
            config_keys: &["tenancy", "auth"],
        },
    ]
}

fn should_emit_inv001(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    matches!(
        operation.operation,
        OperationType::Read | OperationType::Update | OperationType::Delete | OperationType::Export
    ) && config.resource(&operation.resource).is_some()
        && has_request_controlled_id(operation)
        && !has_scope(operation, config, evidence)
        && !has_object_or_authorization(evidence)
}

fn should_emit_inv002(operation: &OperationFact, config: &ResolvedConfig) -> bool {
    if !matches!(
        operation.operation,
        OperationType::Create | OperationType::Update | OperationType::BulkUpdate
    ) {
        return false;
    }
    let sensitive_fields = config.sensitive_or_server_owned_fields(&operation.resource);
    if sensitive_fields.is_empty() {
        return false;
    }
    operation.mutation_fields.iter().any(|field| {
        field.source_id.is_some()
            && (field.field == "*"
                || sensitive_fields
                    .iter()
                    .any(|candidate| candidate == &field.field))
    })
}

fn should_emit_inv003(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    is_sensitive_mutation(operation, config) && !has_authorization(evidence)
}

fn should_emit_inv004(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    config.has_state_invariant(&operation.resource)
        && operation.mutation_fields.iter().any(|field| {
            matches!(
                field.field.as_str(),
                "status" | "state" | "stage" | "approval_status"
            )
        })
        && !evidence
            .iter()
            .any(|evidence| evidence.kind == EvidenceKind::Invariant)
}

fn should_emit_inv006(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    matches!(
        operation.operation,
        OperationType::BulkUpdate | OperationType::BulkDelete
    ) && config.resource(&operation.resource).is_some()
        && !has_scope(operation, config, evidence)
}

fn should_emit_inv007(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    matches!(
        operation.operation,
        OperationType::Export | OperationType::Download | OperationType::Report
    ) && config.resource(&operation.resource).is_some()
        && (!has_scope(operation, config, evidence) || !has_authorization(evidence))
}

fn should_emit_inv008(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
    frame_count: usize,
) -> bool {
    frame_count > 1
        && is_sensitive_mutation(operation, config)
        && (!has_scope(operation, config, evidence) || !has_authorization(evidence))
}

fn emit_hints(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
    route_id: Option<&str>,
    call_path_id: Option<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if config.resource(&operation.resource).is_none() && operation.resource != "Unknown" {
        diagnostics.push(hint(
            "HINT001",
            format!("Possible resource not configured: {}", operation.resource),
            operation,
            route_id,
            call_path_id,
            "Add this resource to .rulepath.yml if it is business-sensitive.",
        ));
    }

    if operation.mutation_fields.iter().any(|field| {
        matches!(
            field.field.as_str(),
            "status" | "state" | "stage" | "approval_status"
        )
    }) && !config.has_state_invariant(&operation.resource)
    {
        diagnostics.push(hint(
            "HINT003",
            format!("Possible {} workflow transition", operation.resource),
            operation,
            route_id,
            call_path_id,
            "Consider adding a state_transition invariant.",
        ));
    }

    if matches!(
        operation.operation,
        OperationType::Export | OperationType::Download | OperationType::Report
    ) && operation.resource == "Unknown"
    {
        diagnostics.push(hint(
            "HINT005",
            "Export-like endpoint with unclear resource".to_owned(),
            operation,
            route_id,
            call_path_id,
            "Configure the exported resource and required permission.",
        ));
    }

    if evidence
        .iter()
        .any(|evidence| evidence.kind == EvidenceKind::Authentication)
        && !has_scope(operation, config, evidence)
    {
        diagnostics.push(hint(
            "HINT006",
            format!("Auth present but {} scope is unclear", operation.resource),
            operation,
            route_id,
            call_path_id,
            "Add tenant or object-scope evidence.",
        ));
    }
}

fn finding(
    rule_id: &str,
    title: String,
    operation: &OperationFact,
    route_id: Option<&str>,
    call_path_id: Option<&str>,
    missing_invariant: &str,
    observed_evidence: Vec<String>,
    expected_evidence: Vec<String>,
    suggested_fix: &str,
) -> Diagnostic {
    diagnostic(
        DiagnosticKind::Finding,
        rule_id,
        title,
        Severity::High,
        Confidence::High,
        operation,
        route_id,
        call_path_id,
        Some(missing_invariant.to_owned()),
        observed_evidence,
        expected_evidence,
        Some(suggested_fix.to_owned()),
    )
}

fn hint(
    rule_id: &str,
    title: String,
    operation: &OperationFact,
    route_id: Option<&str>,
    call_path_id: Option<&str>,
    suggested_action: &str,
) -> Diagnostic {
    diagnostic(
        DiagnosticKind::ReviewHint,
        rule_id,
        title,
        Severity::Medium,
        Confidence::Medium,
        operation,
        route_id,
        call_path_id,
        None,
        Vec::new(),
        Vec::new(),
        Some(suggested_action.to_owned()),
    )
}

fn diagnostic(
    kind: DiagnosticKind,
    rule_id: &str,
    title: String,
    severity: Severity,
    confidence: Confidence,
    operation: &OperationFact,
    route_id: Option<&str>,
    call_path_id: Option<&str>,
    missing_invariant: Option<String>,
    observed_evidence: Vec<String>,
    expected_evidence: Vec<String>,
    suggested_fix: Option<String>,
) -> Diagnostic {
    Diagnostic {
        kind,
        rule_id: rule_id.to_owned(),
        title,
        severity,
        confidence,
        resource: Some(operation.resource.clone()),
        operation: Some(operation.operation),
        route_id: route_id.map(ToOwned::to_owned),
        call_path_id: call_path_id.map(ToOwned::to_owned),
        source_ids: operation
            .filters
            .iter()
            .filter_map(|filter| filter.source_id.clone())
            .chain(
                operation
                    .mutation_fields
                    .iter()
                    .filter_map(|field| field.source_id.clone()),
            )
            .collect(),
        sink_id: Some(operation.id.clone()),
        primary_span: Some(operation.span.clone()),
        missing_invariant,
        observed_evidence,
        expected_evidence,
        suggested_fix,
        fingerprint: fingerprint(&[
            rule_id,
            route_id.unwrap_or("no-route"),
            &operation.resource,
            &format!("{:?}", operation.operation),
            &operation.method,
            &operation.span.file_id,
        ]),
    }
}

fn has_request_controlled_id(operation: &OperationFact) -> bool {
    operation
        .filters
        .iter()
        .any(|filter| filter.field.contains("id") && filter.source_id.is_some())
}

fn has_scope(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    let tenant_fields = config.tenant_fields_for(&operation.resource);
    operation
        .filters
        .iter()
        .any(|filter| tenant_fields.iter().any(|field| field == &filter.field))
        || evidence.iter().any(|evidence| {
            matches!(
                evidence.kind,
                EvidenceKind::TenantScope
                    | EvidenceKind::OwnershipScope
                    | EvidenceKind::ObjectScope
            )
        })
}

fn has_authorization(evidence: &[&EvidenceFact]) -> bool {
    evidence
        .iter()
        .any(|evidence| evidence.kind == EvidenceKind::Authorization)
}

fn has_object_or_authorization(evidence: &[&EvidenceFact]) -> bool {
    evidence.iter().any(|evidence| {
        matches!(
            evidence.kind,
            EvidenceKind::Authorization | EvidenceKind::ObjectScope | EvidenceKind::TenantScope
        )
    })
}

fn is_sensitive_mutation(operation: &OperationFact, config: &ResolvedConfig) -> bool {
    matches!(
        operation.operation,
        OperationType::Create
            | OperationType::Update
            | OperationType::Delete
            | OperationType::BulkUpdate
            | OperationType::BulkDelete
            | OperationType::StateTransition
            | OperationType::ExternalSideEffect
    ) && config.resource(&operation.resource).is_some()
}

fn observed_labels(evidence: &[&EvidenceFact]) -> Vec<String> {
    evidence
        .iter()
        .map(|evidence| evidence.label.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explanations_cover_core_rule() {
        let explanation = explain("INV001").expect("INV001 explanation should exist");
        assert_eq!(explanation.title, "Unscoped resource access");
    }
}
