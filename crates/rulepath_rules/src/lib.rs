use rulepath_config::{InvariantConfig, ResolvedConfig};
use rulepath_ir::{
    fingerprint, CallPath, Confidence, Diagnostic, DiagnosticKind, EvidenceFact, EvidenceKind,
    OperationFact, OperationType, ProjectIr, RouteFact, Severity,
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
        let trusted_route_context =
            call_path.is_some_and(|path| path.confidence != Confidence::Low);

        if trusted_route_context && should_emit_inv001(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV001",
                format!("Unscoped {} access", operation.resource),
                operation,
                route,
                call_path,
                "Resource access requires tenant/client/object scope.",
                observed_labels(&evidence),
                vec!["tenant_scope or object_scope".to_owned()],
                "Add tenant/client scope to the query or call a configured object authorization helper.",
            ));
        }

        if trusted_route_context && should_emit_inv002(operation, config) {
            diagnostics.push(finding(
                "INV002",
                format!("Client-controlled {} fields", operation.resource),
                operation,
                route,
                call_path,
                "Server-owned or sensitive fields must not be directly controlled by the client.",
                observed_labels(&evidence),
                vec!["allowlisted mutation fields".to_owned()],
                "Allowlist mutable fields and construct the data object server-side.",
            ));
        }

        if trusted_route_context && should_emit_inv003(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV003",
                format!(
                    "{} mutation without operation authorization",
                    operation.resource
                ),
                operation,
                route,
                call_path,
                "Sensitive mutations require operation-specific authorization.",
                observed_labels(&evidence),
                vec!["authorization".to_owned()],
                "Add a configured permission or policy helper for this operation.",
            ));
        }

        if trusted_route_context && should_emit_inv004(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV004",
                format!("{} state transition lacks required evidence", operation.resource),
                operation,
                route,
                call_path,
                "Configured state transitions require invariant evidence.",
                observed_labels(&evidence),
                vec!["configured transition evidence".to_owned()],
                "Check the prior state and required permission or business condition before updating state.",
            ));
        }

        if trusted_route_context && should_emit_inv005(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV005",
                format!("{} operation lacks idempotency", operation.resource),
                operation,
                route,
                call_path,
                "Configured sensitive operations require idempotency evidence.",
                observed_labels(&evidence),
                vec!["idempotency".to_owned()],
                "Require an idempotency key or call a configured idempotency helper before the operation.",
            ));
        }

        if trusted_route_context && should_emit_inv006(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV006",
                format!("Bulk {} mutation without scope", operation.resource),
                operation,
                route,
                call_path,
                "Bulk update/delete requires tenant/client/object scope.",
                observed_labels(&evidence),
                vec!["tenant_scope or object_scope".to_owned()],
                "Add configured scope fields to the bulk mutation filter.",
            ));
        }

        if trusted_route_context && should_emit_inv007(operation, config, &evidence) {
            diagnostics.push(finding(
                "INV007",
                format!("{} export without permission or scope", operation.resource),
                operation,
                route,
                call_path,
                "Export/download/report operations require permission and scope.",
                observed_labels(&evidence),
                vec![
                    "authorization".to_owned(),
                    "tenant_scope or object_scope".to_owned(),
                ],
                "Require export permission and scope the exported resource set.",
            ));
        }

        if trusted_route_context
            && should_emit_inv008(
                operation,
                config,
                &evidence,
                call_path.map_or(0, |path| path.frames.len()),
            )
        {
            diagnostics.push(finding(
                "INV008",
                format!("Sensitive {} mutation reachable from insufficiently protected route", operation.resource),
                operation,
                route,
                call_path,
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
            route,
            call_path,
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
    (is_sensitive_mutation(operation, config)
        || configured_invariant_applies(config, "operation_authorization", operation))
        && !has_authorization(evidence)
}

fn should_emit_inv004(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    let Some(invariant) = matching_invariant(config, "state_transition", operation) else {
        return false;
    };
    operation.mutation_fields.iter().any(|field| {
        matches!(
            field.field.as_str(),
            "status" | "state" | "stage" | "approval_status"
        )
    }) && !required_evidence_present(invariant, evidence, EvidenceKind::Invariant)
}

fn should_emit_inv005(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    (operation.operation == OperationType::ExternalSideEffect
        || configured_invariant_applies(config, "idempotency", operation)
        || configured_invariant_applies(config, "idempotent_operation", operation)
        || configured_invariant_applies(config, "external_side_effect", operation))
        && !has_idempotency(evidence)
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
        && (!has_inherited_scope(operation, config, evidence) || !has_authorization(evidence))
}

fn emit_hints(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
    route: Option<&RouteFact>,
    call_path: Option<&CallPath>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let route_id = route.map(|route| route.id.as_str());
    if config.resource(&operation.resource).is_none() && operation.resource != "Unknown" {
        diagnostics.push(hint(
            "HINT001",
            format!("Possible resource not configured: {}", operation.resource),
            operation,
            route,
            call_path,
            "Add this resource to .rulepath.yml if it is business-sensitive.",
        ));
    }

    if has_unconfigured_authorization_helper(evidence, config) {
        diagnostics.push(hint(
            "HINT002",
            "Possible authorization helper not configured".to_owned(),
            operation,
            route,
            call_path,
            "Add the helper to auth.authorization_functions if it is required authorization evidence.",
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
            route,
            call_path,
            "Consider adding a state_transition invariant.",
        ));
    }

    if is_money_like_operation(operation, route_id)
        && !configured_invariant_applies(config, "idempotency", operation)
        && !configured_invariant_applies(config, "operation_authorization", operation)
    {
        diagnostics.push(hint(
            "HINT004",
            format!("Possible money-like {} operation", operation.resource),
            operation,
            route,
            call_path,
            "Configure idempotency or operation authorization invariants for money movement.",
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
            route,
            call_path,
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
            route,
            call_path,
            "Add tenant or object-scope evidence.",
        ));
    }
}

fn finding(
    rule_id: &str,
    title: String,
    operation: &OperationFact,
    route: Option<&RouteFact>,
    call_path: Option<&CallPath>,
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
        route,
        call_path,
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
    route: Option<&RouteFact>,
    call_path: Option<&CallPath>,
    suggested_action: &str,
) -> Diagnostic {
    diagnostic(
        DiagnosticKind::ReviewHint,
        rule_id,
        title,
        Severity::Medium,
        Confidence::Medium,
        operation,
        route,
        call_path,
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
    route: Option<&RouteFact>,
    call_path: Option<&CallPath>,
    missing_invariant: Option<String>,
    observed_evidence: Vec<String>,
    expected_evidence: Vec<String>,
    suggested_fix: Option<String>,
) -> Diagnostic {
    let mut source_ids = operation
        .filters
        .iter()
        .filter_map(|filter| filter.source_id.clone())
        .chain(
            operation
                .mutation_fields
                .iter()
                .filter_map(|field| field.source_id.clone()),
        )
        .collect::<Vec<_>>();
    source_ids.sort();
    source_ids.dedup();
    let route_id = route.map(|route| route.id.as_str());

    Diagnostic {
        kind,
        rule_id: rule_id.to_owned(),
        title,
        severity,
        confidence,
        resource: Some(operation.resource.clone()),
        operation: Some(operation.operation),
        route_id: route_id.map(ToOwned::to_owned),
        call_path_id: call_path.map(|path| path.id.clone()),
        call_path: call_path
            .map(|path| path.frames.clone())
            .unwrap_or_default(),
        source_ids,
        sink_id: Some(operation.id.clone()),
        primary_span: Some(operation.span.clone()),
        missing_invariant,
        observed_evidence,
        expected_evidence,
        suggested_fix,
        fingerprint: diagnostic_fingerprint(rule_id, route, operation),
    }
}

fn diagnostic_fingerprint(
    rule_id: &str,
    route: Option<&RouteFact>,
    operation: &OperationFact,
) -> String {
    let framework = route
        .map(|route| format!("{:?}", route.framework))
        .unwrap_or_else(|| "no-framework".to_owned());
    let route_method = route
        .map(|route| route.method.clone())
        .unwrap_or_else(|| "no-route-method".to_owned());
    let route_path = route
        .map(|route| normalize_identity(route.path.as_str()))
        .unwrap_or_else(|| "no-route-path".to_owned());
    let operation_kind = format!("{:?}", operation.operation);
    let sink_kind = format!("{:?}", operation.data_layer);
    let sink_method = normalize_identity(operation.method.as_str());
    let sink_expression = normalized_sink_expression(operation);
    let file_path = normalize_identity(operation.span.file_id.as_str());
    let parts = [
        rule_id.to_owned(),
        framework,
        route_method,
        route_path,
        operation.resource.clone(),
        operation_kind,
        sink_kind,
        sink_method,
        sink_expression,
        file_path,
    ];
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    fingerprint(&refs)
}

fn normalized_sink_expression(operation: &OperationFact) -> String {
    let mut filter_fields = operation
        .filters
        .iter()
        .map(|filter| normalize_identity(filter.field.as_str()))
        .collect::<Vec<_>>();
    filter_fields.sort();
    filter_fields.dedup();
    let mut mutation_fields = operation
        .mutation_fields
        .iter()
        .map(|field| normalize_identity(field.field.as_str()))
        .collect::<Vec<_>>();
    mutation_fields.sort();
    mutation_fields.dedup();
    format!(
        "method={};filters={};mutation_fields={};bulk={}",
        normalize_identity(operation.method.as_str()),
        filter_fields.join(","),
        mutation_fields.join(","),
        operation.bulk
    )
}

fn normalize_identity(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

fn has_inherited_scope(
    operation: &OperationFact,
    config: &ResolvedConfig,
    evidence: &[&EvidenceFact],
) -> bool {
    has_scope(operation, config, evidence)
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
    evidence.iter().any(|evidence| {
        evidence.kind == EvidenceKind::Authorization && evidence.confidence == Confidence::High
    })
}

fn has_idempotency(evidence: &[&EvidenceFact]) -> bool {
    evidence
        .iter()
        .any(|evidence| evidence.kind == EvidenceKind::Idempotency)
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

fn configured_invariant_applies(
    config: &ResolvedConfig,
    invariant_type: &str,
    operation: &OperationFact,
) -> bool {
    matching_invariant(config, invariant_type, operation).is_some()
}

fn matching_invariant<'a>(
    config: &'a ResolvedConfig,
    invariant_type: &str,
    operation: &OperationFact,
) -> Option<&'a InvariantConfig> {
    config
        .raw
        .invariants
        .iter()
        .find(|invariant| invariant_matches(invariant, invariant_type, operation))
}

fn invariant_matches(
    invariant: &InvariantConfig,
    invariant_type: &str,
    operation: &OperationFact,
) -> bool {
    invariant.invariant_type == invariant_type
        && invariant_applies_to_resource(invariant, &operation.resource)
        && invariant_applies_to_operation(invariant, operation.operation)
}

fn invariant_applies_to_resource(invariant: &InvariantConfig, resource: &str) -> bool {
    invariant.resource.as_deref() == Some(resource)
        || invariant.resources.is_empty()
        || invariant.resources.iter().any(|item| item == resource)
}

fn invariant_applies_to_operation(invariant: &InvariantConfig, operation: OperationType) -> bool {
    invariant.operations.is_empty()
        || invariant
            .operations
            .iter()
            .any(|item| item == operation_config_key(operation))
}

fn operation_config_key(operation: OperationType) -> &'static str {
    match operation {
        OperationType::Read => "read",
        OperationType::Create => "create",
        OperationType::Update => "update",
        OperationType::Delete => "delete",
        OperationType::BulkUpdate => "bulk_update",
        OperationType::BulkDelete => "bulk_delete",
        OperationType::Export => "export",
        OperationType::Download => "download",
        OperationType::Report => "report",
        OperationType::StateTransition => "state_transition",
        OperationType::ExternalSideEffect => "external_side_effect",
    }
}

fn required_evidence_present(
    invariant: &InvariantConfig,
    evidence: &[&EvidenceFact],
    default_kind: EvidenceKind,
) -> bool {
    if invariant.requires.is_empty() {
        return evidence
            .iter()
            .any(|evidence| evidence.kind == default_kind);
    }
    invariant
        .requires
        .iter()
        .all(|required| evidence_satisfies_requirement(required, evidence))
}

fn evidence_satisfies_requirement(required: &str, evidence: &[&EvidenceFact]) -> bool {
    let required = required.to_ascii_lowercase();
    match required.as_str() {
        "authorization" | "authz" | "permission" => return has_authorization(evidence),
        "authentication" | "authn" => {
            return evidence
                .iter()
                .any(|evidence| evidence.kind == EvidenceKind::Authentication);
        }
        "idempotency" | "idempotent" => return has_idempotency(evidence),
        "scope" | "tenant_scope" | "object_scope" => {
            return evidence.iter().any(|evidence| {
                matches!(
                    evidence.kind,
                    EvidenceKind::TenantScope
                        | EvidenceKind::OwnershipScope
                        | EvidenceKind::ObjectScope
                )
            });
        }
        _ => {}
    }
    evidence.iter().any(|evidence| {
        normalized_evidence_label(evidence.label.as_str()) == required
            || evidence
                .expression
                .to_ascii_lowercase()
                .contains(required.as_str())
    })
}

fn normalized_evidence_label(label: &str) -> String {
    label
        .rsplit(':')
        .next()
        .unwrap_or(label)
        .trim()
        .to_ascii_lowercase()
}

fn has_unconfigured_authorization_helper(
    evidence: &[&EvidenceFact],
    config: &ResolvedConfig,
) -> bool {
    evidence.iter().any(|evidence| {
        evidence.kind == EvidenceKind::Authorization
            && !configured_authorization_helper(normalized_evidence_label(&evidence.label), config)
    })
}

fn configured_authorization_helper(helper: String, config: &ResolvedConfig) -> bool {
    config
        .raw
        .auth
        .authorization_functions
        .python
        .iter()
        .chain(config.raw.auth.authorization_functions.typescript.iter())
        .any(|candidate| helper_matches_configured_helper(helper.as_str(), candidate))
}

fn helper_matches_configured_helper(helper: &str, candidate: &str) -> bool {
    let candidate = candidate.to_ascii_lowercase();
    helper == candidate
        || helper
            .rsplit('.')
            .next()
            .is_some_and(|last| last == candidate)
}

fn is_money_like_operation(operation: &OperationFact, route_id: Option<&str>) -> bool {
    let resource = operation.resource.to_ascii_lowercase();
    let method = operation.method.to_ascii_lowercase();
    let route_id = route_id.unwrap_or_default().to_ascii_lowercase();
    let fields = operation
        .mutation_fields
        .iter()
        .map(|field| field.field.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let needles = [
        "payment", "charge", "refund", "payout", "invoice", "balance", "amount", "total", "billing",
    ];
    needles.iter().any(|needle| {
        resource.contains(needle)
            || method.contains(needle)
            || route_id.contains(needle)
            || fields.iter().any(|field| field.contains(needle))
    })
}

fn observed_labels(evidence: &[&EvidenceFact]) -> Vec<String> {
    let mut labels = evidence
        .iter()
        .map(|evidence| evidence.label.clone())
        .collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    use rulepath_config::{InvariantConfig, ResourceConfig, RulepathConfig};
    use rulepath_ir::{
        CallFrame, DataLayer, EvidenceFact, FilterFact, Framework, Language, MutationFieldFact,
        Position, RouteFact, SourceSpan,
    };

    #[test]
    fn explanations_cover_core_rule() {
        let explanation = explain("INV001").expect("INV001 explanation should exist");
        assert_eq!(explanation.title, "Unscoped resource access");
    }

    #[test]
    fn explain_covers_every_v1_rule_and_hint() {
        for rule_id in [
            "INV001", "INV002", "INV003", "INV004", "INV005", "INV006", "INV007", "INV008",
            "HINT001", "HINT002", "HINT003", "HINT004", "HINT005", "HINT006",
        ] {
            assert!(explain(rule_id).is_some(), "{rule_id} should explain");
        }
    }

    #[test]
    fn inv001_requires_scope_for_request_controlled_resource_access() {
        let config = config_with_resources(&["Invoice"]);
        let unsafe_ir = ir_with_operation(operation("sink:inv001", 10));
        let safe_ir = ir_with_operation(scoped(operation("sink:inv001", 10)));

        assert_has_rule(&unsafe_ir, &config, "INV001");
        assert_lacks_rule(&safe_ir, &config, "INV001");
    }

    #[test]
    fn inv002_requires_server_owned_fields_to_be_allowlisted() {
        let mut config = config_with_resources(&["Invoice"]);
        config
            .raw
            .resources
            .get_mut("Invoice")
            .expect("resource should exist")
            .server_owned_fields
            .push("status".to_owned());
        let unsafe_ir = ir_with_operation(mutates(operation("sink:inv002", 10), "status", true));
        let safe_ir = ir_with_operation(mutates(operation("sink:inv002", 10), "notes", true));

        assert_has_rule(&unsafe_ir, &config, "INV002");
        assert_lacks_rule(&safe_ir, &config, "INV002");
    }

    #[test]
    fn inv003_requires_authorization_for_sensitive_mutations() {
        let config = config_with_resources(&["Invoice"]);
        let unsafe_ir = ir_with_operation(operation("sink:inv003", 10));
        let safe_ir = ir_with_evidence(
            operation("sink:inv003", 10),
            vec![evidence(
                EvidenceKind::Authorization,
                "authorization:requirePermission",
            )],
        );

        assert_has_rule(&unsafe_ir, &config, "INV003");
        assert_lacks_rule(&safe_ir, &config, "INV003");
    }

    #[test]
    fn inv004_uses_configured_state_transition_requirements() {
        let mut config = config_with_resources(&["Invoice"]);
        config.raw.invariants.push(invariant(
            "invoice_transition",
            "state_transition",
            "Invoice",
            &[OperationType::Update],
            &["checkTransition"],
        ));
        let unsafe_ir = ir_with_operation(mutates(operation("sink:inv004", 10), "status", true));
        let safe_ir = ir_with_evidence(
            mutates(operation("sink:inv004", 10), "status", true),
            vec![evidence(
                EvidenceKind::Invariant,
                "invariant:checkTransition",
            )],
        );

        assert_has_rule(&unsafe_ir, &config, "INV004");
        assert_lacks_rule(&safe_ir, &config, "INV004");
    }

    #[test]
    fn inv005_requires_idempotency_for_configured_sensitive_operations() {
        let mut config = config_with_resources(&["Payment"]);
        config.raw.invariants.push(invariant(
            "payment_idempotency",
            "idempotency",
            "Payment",
            &[OperationType::ExternalSideEffect],
            &[],
        ));
        let unsafe_ir = ir_with_operation(external_operation("sink:inv005", 10));
        let safe_ir = ir_with_evidence(
            external_operation("sink:inv005", 10),
            vec![evidence(
                EvidenceKind::Idempotency,
                "idempotency:requireIdempotency",
            )],
        );

        assert_has_rule(&unsafe_ir, &config, "INV005");
        assert_lacks_rule(&safe_ir, &config, "INV005");
    }

    #[test]
    fn inv006_requires_scope_for_bulk_mutations() {
        let config = config_with_resources(&["Invoice"]);
        let unsafe_ir = ir_with_operation(bulk(operation("sink:inv006", 10)));
        let safe_ir = ir_with_operation(scoped(bulk(operation("sink:inv006", 10))));

        assert_has_rule(&unsafe_ir, &config, "INV006");
        assert_lacks_rule(&safe_ir, &config, "INV006");
    }

    #[test]
    fn inv007_requires_permission_and_scope_for_exports() {
        let config = config_with_resources(&["Invoice"]);
        let unsafe_ir = ir_with_operation(export_operation("sink:inv007", "Invoice", 10));
        let safe_ir = ir_with_evidence(
            scoped(export_operation("sink:inv007", "Invoice", 10)),
            vec![evidence(
                EvidenceKind::Authorization,
                "authorization:requirePermission",
            )],
        );

        assert_has_rule(&unsafe_ir, &config, "INV007");
        assert_lacks_rule(&safe_ir, &config, "INV007");
    }

    #[test]
    fn inv008_requires_inherited_auth_and_scope_for_service_layer_mutations() {
        let config = config_with_resources(&["Invoice"]);
        let unsafe_ir = ir_with_frames(operation("sink:inv008", 10), 2, Vec::new());
        let safe_ir = ir_with_frames(
            operation("sink:inv008", 10),
            2,
            vec![
                evidence(
                    EvidenceKind::Authorization,
                    "authorization:requirePermission",
                ),
                evidence(EvidenceKind::TenantScope, "tenant_scope:req.user.tenantId"),
            ],
        );

        assert_has_rule(&unsafe_ir, &config, "INV008");
        assert_lacks_rule(&safe_ir, &config, "INV008");
    }

    #[test]
    fn emits_all_v1_review_hints() {
        let config = config_with_resources(&["Invoice", "Payment"]);
        let ir = ProjectIr {
            operations: vec![
                operation_with_resource("sink:hint001", "Contract", 10),
                operation("sink:hint002", 20),
                mutates(operation("sink:hint003", 30), "status", true),
                mutates(
                    operation_with_resource("sink:hint004", "Payment", 40),
                    "amount",
                    true,
                ),
                export_operation("sink:hint005", "Unknown", 50),
                operation("sink:hint006", 60),
            ],
            evidence: vec![
                evidence_for_sink(
                    "sink:hint002",
                    EvidenceKind::Authorization,
                    "authorization:InvoicePermission",
                ),
                evidence_for_sink(
                    "sink:hint006",
                    EvidenceKind::Authentication,
                    "authentication:requireAuth",
                ),
            ],
            ..base_ir(Vec::new(), 1, Vec::new())
        };
        let diagnostics = evaluate(&ir, &config);

        for rule_id in [
            "HINT001", "HINT002", "HINT003", "HINT004", "HINT005", "HINT006",
        ] {
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.rule_id == rule_id
                        && diagnostic.kind == DiagnosticKind::ReviewHint),
                "{rule_id} should be emitted as a review hint"
            );
        }
        assert!(diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.rule_id.starts_with("HINT"))
            .all(|diagnostic| diagnostic.kind == DiagnosticKind::ReviewHint
                && diagnostic.confidence == Confidence::Medium));
    }

    #[test]
    fn semantic_fingerprint_ignores_sink_line_number_changes() {
        let config = config_with_invoice_resource();
        let before = first_rule_fingerprint(
            &ir_with_operation(operation(
                "sink:prisma.invoice.update:src/invoices.ts:10",
                10,
            )),
            &config,
            "INV001",
        );
        let after = first_rule_fingerprint(
            &ir_with_operation(operation(
                "sink:prisma.invoice.update:src/invoices.ts:20",
                20,
            )),
            &config,
            "INV001",
        );

        assert_eq!(before, after);
    }

    #[test]
    fn semantic_fingerprint_changes_for_route_resource_operation_or_sink_method() {
        let config = config_with_invoice_resource();
        let base = first_rule_fingerprint(
            &ir_with_operation(operation("sink:base", 10)),
            &config,
            "INV001",
        );

        let mut route_changed = ir_with_operation(operation("sink:base", 10));
        route_changed.routes[0].path = "/clients/:id".to_owned();
        let route_changed = first_rule_fingerprint(&route_changed, &config, "INV001");

        let resource_changed = first_rule_fingerprint(
            &ir_with_operation(operation_with_resource("sink:base", "Client", 10)),
            &config_with_resources(&["Client"]),
            "INV001",
        );

        let operation_changed = first_rule_fingerprint(
            &ir_with_operation(read_operation("sink:base", 10)),
            &config,
            "INV001",
        );

        let mut sink_method_ir = ir_with_operation(operation("sink:base", 10));
        sink_method_ir.operations[0].method = "prisma.invoice.delete".to_owned();
        let sink_method_changed = first_rule_fingerprint(&sink_method_ir, &config, "INV001");

        assert_ne!(base, route_changed);
        assert_ne!(base, resource_changed);
        assert_ne!(base, operation_changed);
        assert_ne!(base, sink_method_changed);
    }

    fn assert_has_rule(ir: &ProjectIr, config: &ResolvedConfig, rule_id: &str) {
        assert!(
            evaluate(ir, config)
                .iter()
                .any(|diagnostic| diagnostic.rule_id == rule_id),
            "{rule_id} should be emitted"
        );
    }

    fn assert_lacks_rule(ir: &ProjectIr, config: &ResolvedConfig, rule_id: &str) {
        assert!(
            evaluate(ir, config)
                .iter()
                .all(|diagnostic| diagnostic.rule_id != rule_id),
            "{rule_id} should not be emitted"
        );
    }

    fn first_rule_fingerprint(ir: &ProjectIr, config: &ResolvedConfig, rule_id: &str) -> String {
        evaluate(ir, config)
            .into_iter()
            .find(|diagnostic| diagnostic.rule_id == rule_id)
            .unwrap_or_else(|| panic!("{rule_id} should be emitted"))
            .fingerprint
    }

    fn config_with_invoice_resource() -> ResolvedConfig {
        config_with_resources(&["Invoice"])
    }

    fn config_with_resources(resources: &[&str]) -> ResolvedConfig {
        let mut raw = RulepathConfig::default();
        raw.auth.authorization_functions.typescript = vec!["requirePermission".to_owned()];
        raw.auth.authorization_functions.python = vec!["require_permission".to_owned()];
        for resource in resources {
            raw.resources.insert(
                (*resource).to_owned(),
                ResourceConfig {
                    tenant_fields: vec!["tenant_id".to_owned()],
                    sensitive_fields: vec!["status".to_owned(), "amount".to_owned()],
                    server_owned_fields: Vec::new(),
                },
            );
        }
        ResolvedConfig::new(raw)
    }

    fn invariant(
        id: &str,
        invariant_type: &str,
        resource: &str,
        operations: &[OperationType],
        requires: &[&str],
    ) -> InvariantConfig {
        InvariantConfig {
            id: id.to_owned(),
            invariant_type: invariant_type.to_owned(),
            resources: vec![resource.to_owned()],
            resource: None,
            operations: operations
                .iter()
                .map(|operation| operation_config_key(*operation).to_owned())
                .collect(),
            fields: Default::default(),
            field: None,
            required_scope: Vec::new(),
            requires: requires.iter().map(|item| (*item).to_owned()).collect(),
            severity: "high".to_owned(),
        }
    }

    fn ir_with_operation(operation: OperationFact) -> ProjectIr {
        ir_with_frames(operation, 1, Vec::new())
    }

    fn ir_with_evidence(operation: OperationFact, evidence: Vec<EvidenceFact>) -> ProjectIr {
        ir_with_frames(operation, 1, evidence)
    }

    fn ir_with_frames(
        operation: OperationFact,
        frame_count: usize,
        evidence: Vec<EvidenceFact>,
    ) -> ProjectIr {
        let call_path = call_path_with_frames(
            format!(
                "callpath:route:express:patch:/invoices/:id:{}",
                operation.id
            )
            .as_str(),
            operation.id.as_str(),
            frame_count,
        );
        base_ir(vec![operation], frame_count, evidence).with_call_paths(vec![call_path])
    }

    trait ProjectIrTestExt {
        fn with_call_paths(self, call_paths: Vec<CallPath>) -> Self;
    }

    impl ProjectIrTestExt for ProjectIr {
        fn with_call_paths(mut self, call_paths: Vec<CallPath>) -> Self {
            self.call_paths = call_paths;
            self
        }
    }

    fn base_ir(
        operations: Vec<OperationFact>,
        _frame_count: usize,
        evidence: Vec<EvidenceFact>,
    ) -> ProjectIr {
        ProjectIr {
            routes: vec![RouteFact {
                id: "route:express:patch:/invoices/:id".to_owned(),
                framework: Framework::Express,
                language: Language::TypeScript,
                method: "PATCH".to_owned(),
                path: "/invoices/:id".to_owned(),
                handler: "updateInvoice".to_owned(),
                span: span(1, 1),
                middleware: Vec::new(),
                sources: vec!["source:route-param".to_owned(), "source:body".to_owned()],
            }],
            operations,
            evidence,
            ..ProjectIr::default()
        }
    }

    fn operation(id: &str, line: usize) -> OperationFact {
        operation_with_resource(id, "Invoice", line)
    }

    fn operation_with_resource(id: &str, resource: &str, line: usize) -> OperationFact {
        OperationFact {
            id: id.to_owned(),
            data_layer: DataLayer::Prisma,
            resource: resource.to_owned(),
            operation: OperationType::Update,
            method: "update".to_owned(),
            filters: vec![FilterFact {
                field: "id".to_owned(),
                value: "invoiceId".to_owned(),
                source_id: Some("source:route-param".to_owned()),
            }],
            mutation_fields: Vec::new(),
            bulk: false,
            span: span(line, 3),
        }
    }

    fn read_operation(id: &str, line: usize) -> OperationFact {
        let mut operation = operation(id, line);
        operation.operation = OperationType::Read;
        operation.method = "findUnique".to_owned();
        operation.mutation_fields.clear();
        operation
    }

    fn external_operation(id: &str, line: usize) -> OperationFact {
        OperationFact {
            id: id.to_owned(),
            data_layer: DataLayer::Unknown,
            resource: "Payment".to_owned(),
            operation: OperationType::ExternalSideEffect,
            method: "payment.charge".to_owned(),
            filters: Vec::new(),
            mutation_fields: Vec::new(),
            bulk: false,
            span: span(line, 3),
        }
    }

    fn export_operation(id: &str, resource: &str, line: usize) -> OperationFact {
        OperationFact {
            id: id.to_owned(),
            data_layer: DataLayer::Unknown,
            resource: resource.to_owned(),
            operation: OperationType::Export,
            method: "response_export".to_owned(),
            filters: Vec::new(),
            mutation_fields: Vec::new(),
            bulk: true,
            span: span(line, 3),
        }
    }

    fn scoped(mut operation: OperationFact) -> OperationFact {
        operation.filters.push(FilterFact {
            field: "tenant_id".to_owned(),
            value: "current tenant".to_owned(),
            source_id: None,
        });
        operation
    }

    fn bulk(mut operation: OperationFact) -> OperationFact {
        operation.operation = OperationType::BulkUpdate;
        operation.bulk = true;
        operation.method = "updateMany".to_owned();
        operation
    }

    fn mutates(
        mut operation: OperationFact,
        field: &str,
        request_controlled: bool,
    ) -> OperationFact {
        operation.mutation_fields.push(MutationFieldFact {
            field: field.to_owned(),
            value: "body".to_owned(),
            source_id: request_controlled.then(|| "source:body".to_owned()),
        });
        operation
    }

    fn evidence(kind: EvidenceKind, label: &str) -> EvidenceFact {
        EvidenceFact {
            id: format!("evidence:{label}"),
            kind,
            label: label.to_owned(),
            expression: normalized_evidence_label(label),
            confidence: Confidence::High,
            route_id: Some("route:express:patch:/invoices/:id".to_owned()),
            sink_id: None,
            span: span(2, 1),
        }
    }

    fn evidence_for_sink(sink_id: &str, kind: EvidenceKind, label: &str) -> EvidenceFact {
        EvidenceFact {
            sink_id: Some(sink_id.to_owned()),
            route_id: None,
            ..evidence(kind, label)
        }
    }

    fn call_path_with_frames(id: &str, sink_id: &str, frame_count: usize) -> CallPath {
        let mut frames = vec![CallFrame {
            function: "inline_handler".to_owned(),
            file: "src/routes/invoices.ts".to_owned(),
            line: 1,
        }];
        if frame_count > 1 {
            frames.push(CallFrame {
                function: "updateInvoice".to_owned(),
                file: "src/services/invoices.ts".to_owned(),
                line: 10,
            });
        }
        CallPath {
            id: id.to_owned(),
            route_id: "route:express:patch:/invoices/:id".to_owned(),
            sink_id: sink_id.to_owned(),
            frames,
            confidence: Confidence::High,
        }
    }

    fn span(line: usize, column: usize) -> SourceSpan {
        SourceSpan {
            file_id: "src/invoices.ts".to_owned(),
            start: Position::new(line, column),
            end: Position::new(line, column + 1),
        }
    }
}
