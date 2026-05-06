use std::collections::{BTreeMap, BTreeSet};

use rulepath_config::ResolvedConfig;
use rulepath_ir::{DataLayer, EvidenceKind, Framework, Language, OperationType, ProjectIr};
use rulepath_workspace::WorkspaceIndex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceResult {
    pub yaml: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InferenceDraft {
    frameworks: BTreeMap<&'static str, BTreeSet<&'static str>>,
    data_layers: BTreeMap<&'static str, BTreeSet<&'static str>>,
    auth: InferredAuth,
    resources: BTreeMap<String, InferredResource>,
    invariants: Vec<InferredInvariant>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InferredAuth {
    authentication_guards: BTreeMap<&'static str, BTreeSet<String>>,
    authorization_functions: BTreeMap<&'static str, BTreeSet<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct InferredResource {
    tenant_fields: BTreeSet<String>,
    sensitive_fields: BTreeSet<String>,
    server_owned_fields: BTreeSet<String>,
    operations: BTreeSet<&'static str>,
    saw_request_body_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InferredInvariant {
    id: String,
    invariant_type: &'static str,
    resources: Vec<String>,
    operations: Vec<&'static str>,
    required_scope: Vec<&'static str>,
    requires: Vec<&'static str>,
    comment: &'static str,
}

#[must_use]
pub fn infer(index: &WorkspaceIndex, config: &ResolvedConfig) -> InferenceResult {
    let ir = rulepath_dataflow::build_project_ir(index, config);
    let draft = infer_from_ir(&ir, config);
    InferenceResult {
        yaml: render_inferred_yaml(&draft),
    }
}

fn infer_from_ir(ir: &ProjectIr, config: &ResolvedConfig) -> InferenceDraft {
    let mut draft = InferenceDraft::default();

    for route in &ir.routes {
        if let Some(name) = framework_name(route.framework) {
            draft
                .frameworks
                .entry(language_key(route.language))
                .or_default()
                .insert(name);
        }
        for source_id in &route.sources {
            if let Some(source) = ir.sources.iter().find(|source| &source.id == source_id) {
                collect_tenant_like_field(&mut draft, source.name.as_str());
            }
        }
    }

    for operation in &ir.operations {
        if let Some(name) = data_layer_name(operation.data_layer) {
            let language = ir.route_for_operation(&operation.id).map_or_else(
                || language_for_file(&operation.span.file_id),
                |route| Some(route.language),
            );
            if let Some(language) = language {
                draft
                    .data_layers
                    .entry(language_key(language))
                    .or_default()
                    .insert(name);
            }
        }
        if operation.resource == "Unknown" {
            continue;
        }
        let resource = draft
            .resources
            .entry(operation.resource.clone())
            .or_default();
        resource
            .operations
            .insert(operation_key(operation.operation));
        for filter in &operation.filters {
            if filter.source_id.is_none() && is_tenant_like_field(filter.field.as_str()) {
                resource.tenant_fields.insert(filter.field.clone());
            }
        }
        for field in &operation.mutation_fields {
            if field.source_id.is_some() {
                resource.saw_request_body_write = true;
                if field.field == "*" {
                    add_common_sensitive_fields(resource);
                } else {
                    resource.sensitive_fields.insert(field.field.clone());
                    resource.server_owned_fields.insert(field.field.clone());
                }
            }
        }
    }

    merge_profile_resource_hints(&mut draft, config);
    infer_auth_helpers(&mut draft, ir);
    draft.invariants = infer_invariants(&draft);
    draft
}

fn collect_tenant_like_field(draft: &mut InferenceDraft, value: &str) {
    if !is_tenant_like_field(value) {
        return;
    }
    for resource in draft.resources.values_mut() {
        resource.tenant_fields.insert(value.to_owned());
    }
}

fn merge_profile_resource_hints(draft: &mut InferenceDraft, config: &ResolvedConfig) {
    for (resource_name, resource) in &mut draft.resources {
        if let Some(configured) = config.resource(resource_name) {
            resource
                .tenant_fields
                .extend(configured.tenant_fields.iter().cloned());
            if resource.saw_request_body_write || !resource.operations.is_empty() {
                resource
                    .sensitive_fields
                    .extend(configured.sensitive_fields.iter().cloned());
                resource
                    .server_owned_fields
                    .extend(configured.server_owned_fields.iter().cloned());
            }
        }
        if resource.tenant_fields.is_empty() {
            resource.tenant_fields.extend(
                ["tenant_id", "tenantId", "client_id", "clientId"]
                    .into_iter()
                    .map(ToOwned::to_owned),
            );
        }
        if resource.sensitive_fields.is_empty() && resource.saw_request_body_write {
            add_common_sensitive_fields(resource);
        }
    }
}

fn infer_auth_helpers(draft: &mut InferenceDraft, ir: &ProjectIr) {
    for evidence in &ir.evidence {
        let Some(language) = language_for_file(&evidence.span.file_id) else {
            continue;
        };
        let helper = helper_from_label(evidence.label.as_str());
        if helper.is_empty() {
            continue;
        }
        match evidence.kind {
            EvidenceKind::Authentication => {
                draft
                    .auth
                    .authentication_guards
                    .entry(language_key(language))
                    .or_default()
                    .insert(helper);
            }
            EvidenceKind::Authorization | EvidenceKind::ObjectScope => {
                draft
                    .auth
                    .authorization_functions
                    .entry(language_key(language))
                    .or_default()
                    .insert(helper);
            }
            _ => {}
        }
    }
}

fn infer_invariants(draft: &InferenceDraft) -> Vec<InferredInvariant> {
    let resources = draft.resources.keys().cloned().collect::<Vec<_>>();
    if resources.is_empty() {
        return Vec::new();
    }
    let mut invariants = vec![
        InferredInvariant {
            id: "inferred_scoped_resource_access".to_owned(),
            invariant_type: "scoped_resource_access",
            resources: resources.clone(),
            operations: vec!["read", "update", "delete", "export", "report"],
            required_scope: vec!["tenant"],
            requires: Vec::new(),
            comment: "High confidence: request-controlled resource access was observed.",
        },
        InferredInvariant {
            id: "inferred_no_client_controlled_server_fields".to_owned(),
            invariant_type: "client_controlled_field",
            resources: resources.clone(),
            operations: vec!["create", "update", "bulk_update"],
            required_scope: Vec::new(),
            requires: Vec::new(),
            comment: "Medium confidence: review field lists before enforcing.",
        },
    ];

    let state_resources = resources_with_field(draft, &["status", "state", "stage"]);
    if !state_resources.is_empty() {
        invariants.push(InferredInvariant {
            id: "inferred_state_transition_review".to_owned(),
            invariant_type: "state_transition",
            resources: state_resources,
            operations: vec!["update", "bulk_update"],
            required_scope: Vec::new(),
            requires: vec!["authorization"],
            comment: "Medium confidence: status-like writes often need workflow checks.",
        });
    }

    let money_resources = draft
        .resources
        .keys()
        .filter(|resource| is_money_like(resource))
        .cloned()
        .collect::<Vec<_>>();
    if !money_resources.is_empty() {
        invariants.push(InferredInvariant {
            id: "inferred_money_operation_idempotency".to_owned(),
            invariant_type: "idempotency",
            resources: money_resources,
            operations: vec!["create", "update", "bulk_update"],
            required_scope: Vec::new(),
            requires: vec!["idempotency"],
            comment: "Medium confidence: money-like resources usually need idempotency.",
        });
    }

    invariants
}

fn render_inferred_yaml(draft: &InferenceDraft) -> String {
    let mut yaml = String::new();
    yaml.push_str(
        "# Draft generated by rulepath infer. Review before copying into .rulepath.yml.\n",
    );
    yaml.push_str(
        "# Confidence comments summarize observed facts; delete comments freely after review.\n",
    );
    yaml.push_str("version: 1\n\n");
    yaml.push_str("profile:\n  name: internal_web_app\n\n");
    yaml.push_str("inference:\n  generated_file: .rulepath.inferred.yml\n  use_inferred_file_for_scan: false\n\n");

    render_language_lists(&mut yaml, "frameworks", &draft.frameworks);
    render_language_lists(&mut yaml, "data_layers", &draft.data_layers);
    render_auth(&mut yaml, &draft.auth);
    render_resources(&mut yaml, &draft.resources);
    render_invariants(&mut yaml, &draft.invariants);
    yaml
}

fn render_language_lists(
    yaml: &mut String,
    section: &str,
    values: &BTreeMap<&'static str, BTreeSet<&'static str>>,
) {
    yaml.push_str(&format!("{section}:\n"));
    for language in ["python", "typescript"] {
        if let Some(items) = values.get(&language) {
            yaml.push_str(&format!("  {language}:\n"));
            for item in items {
                yaml.push_str(&format!("    - {item}\n"));
            }
        } else {
            yaml.push_str(&format!("  {language}: []\n"));
        }
    }
    yaml.push('\n');
}

fn render_auth(yaml: &mut String, auth: &InferredAuth) {
    yaml.push_str("auth:\n");
    yaml.push_str("  authentication_guards:\n");
    render_string_language_lists(yaml, &auth.authentication_guards);
    yaml.push_str("  authorization_functions:\n");
    render_string_language_lists(yaml, &auth.authorization_functions);
    yaml.push('\n');
}

fn render_string_language_lists(
    yaml: &mut String,
    values: &BTreeMap<&'static str, BTreeSet<String>>,
) {
    for language in ["python", "typescript"] {
        if let Some(items) = values.get(&language) {
            yaml.push_str(&format!("    {language}:\n"));
            for item in items {
                yaml.push_str(&format!("      - {item}\n"));
            }
        } else {
            yaml.push_str(&format!("    {language}: []\n"));
        }
    }
}

fn render_resources(yaml: &mut String, resources: &BTreeMap<String, InferredResource>) {
    yaml.push_str("resources:\n");
    for (name, resource) in resources {
        yaml.push_str(&format!("  {name}:\n"));
        yaml.push_str(
            "    # Medium confidence: review tenant and sensitive fields before enforcing.\n",
        );
        yaml.push_str(&format!(
            "    tenant_fields: [{}]\n",
            comma_list(&resource.tenant_fields)
        ));
        yaml.push_str(&format!(
            "    sensitive_fields: [{}]\n",
            comma_list(&resource.sensitive_fields)
        ));
        yaml.push_str(&format!(
            "    server_owned_fields: [{}]\n",
            comma_list(&resource.server_owned_fields)
        ));
    }
    yaml.push('\n');
}

fn render_invariants(yaml: &mut String, invariants: &[InferredInvariant]) {
    yaml.push_str("invariants:\n");
    for invariant in invariants {
        yaml.push_str(&format!("  # {}\n", invariant.comment));
        yaml.push_str(&format!("  - id: {}\n", invariant.id));
        yaml.push_str(&format!("    type: {}\n", invariant.invariant_type));
        yaml.push_str("    resources:\n");
        for resource in &invariant.resources {
            yaml.push_str(&format!("      - {resource}\n"));
        }
        yaml.push_str(&format!(
            "    operations: [{}]\n",
            invariant.operations.join(", ")
        ));
        if !invariant.required_scope.is_empty() {
            yaml.push_str(&format!(
                "    required_scope: [{}]\n",
                invariant.required_scope.join(", ")
            ));
        }
        if !invariant.requires.is_empty() {
            yaml.push_str(&format!(
                "    requires: [{}]\n",
                invariant.requires.join(", ")
            ));
        }
        yaml.push_str("    severity: high\n");
    }
}

fn add_common_sensitive_fields(resource: &mut InferredResource) {
    for field in ["status", "amount", "total", "role"] {
        resource.sensitive_fields.insert(field.to_owned());
        resource.server_owned_fields.insert(field.to_owned());
    }
}

fn resources_with_field(draft: &InferenceDraft, fields: &[&str]) -> Vec<String> {
    draft
        .resources
        .iter()
        .filter(|(_, resource)| {
            resource
                .sensitive_fields
                .iter()
                .any(|field| fields.iter().any(|candidate| field == candidate))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

fn framework_name(framework: Framework) -> Option<&'static str> {
    match framework {
        Framework::FastApi => Some("fastapi"),
        Framework::Django => Some("django"),
        Framework::DjangoRestFramework => Some("django_rest_framework"),
        Framework::Express => Some("express"),
        Framework::NextJs => Some("nextjs"),
        Framework::Unknown => None,
    }
}

fn data_layer_name(data_layer: DataLayer) -> Option<&'static str> {
    match data_layer {
        DataLayer::DjangoOrm => Some("django_orm"),
        DataLayer::SqlAlchemy => Some("sqlalchemy"),
        DataLayer::Prisma => Some("prisma"),
        DataLayer::Unknown => None,
    }
}

fn operation_key(operation: OperationType) -> &'static str {
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

fn language_key(language: Language) -> &'static str {
    match language {
        Language::Python => "python",
        Language::TypeScript => "typescript",
    }
}

fn language_for_file(file_id: &str) -> Option<Language> {
    match file_id.rsplit('.').next() {
        Some("py") => Some(Language::Python),
        Some("ts" | "tsx" | "js" | "jsx") => Some(Language::TypeScript),
        _ => None,
    }
}

fn helper_from_label(label: &str) -> String {
    label.rsplit(':').next().unwrap_or(label).trim().to_owned()
}

fn is_tenant_like_field(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("tenant")
        || value.contains("client")
        || value.contains("org")
        || value.contains("account")
        || value.contains("workspace")
        || value.contains("owner")
}

fn is_money_like(resource: &str) -> bool {
    let resource = resource.to_ascii_lowercase();
    [
        "invoice", "payment", "charge", "refund", "payout", "balance",
    ]
    .iter()
    .any(|needle| resource.contains(needle))
}

fn comma_list(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_index(path: &str) -> (WorkspaceIndex, ResolvedConfig) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path);
        let config = rulepath_config::default_resolved_config();
        let index = rulepath_workspace::scan_workspace(root, &config).expect("fixture should scan");
        (index, config)
    }

    #[test]
    fn express_fixture_inference_uses_ir_facts_and_valid_config_shape() {
        let (index, config) = fixture_index("fixtures/express_prisma/unsafe");
        let inferred = infer(&index, &config).yaml;

        assert!(inferred.contains("typescript:\n    - express"));
        assert!(inferred.contains("typescript:\n    - prisma"));
        assert!(inferred.contains("  Invoice:"));
        assert!(inferred.contains("clientId"));
        assert!(inferred.contains("inferred_scoped_resource_access"));
        assert!(inferred.contains("inferred_no_client_controlled_server_fields"));
        serde_yaml::from_str::<rulepath_config::RulepathConfig>(&inferred)
            .expect("inferred yaml should satisfy strict config shape");
    }

    #[test]
    fn inference_output_is_deterministic() {
        let (index, config) = fixture_index("fixtures/fastapi_sqlalchemy/unsafe");
        let first = infer(&index, &config).yaml;
        let second = infer(&index, &config).yaml;

        assert_eq!(first, second);
        assert!(first.contains("python:\n    - fastapi"));
        assert!(first.contains("python:\n    - sqlalchemy"));
        assert!(first.contains("authentication_guards:\n    python:\n      - get_current_user"));
        assert!(first.contains("  Invoice:"));
    }

    #[test]
    fn operation_key_matches_config_spelling() {
        assert_eq!(operation_key(OperationType::BulkUpdate), "bulk_update");
        assert_eq!(
            operation_key(OperationType::ExternalSideEffect),
            "external_side_effect"
        );
    }
}
