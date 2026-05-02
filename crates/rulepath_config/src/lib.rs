use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const INTERNAL_WEB_APP_PROFILE: &str = include_str!("../../../profiles/internal_web_app.yml");

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config at {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RulepathConfig {
    pub version: u32,
    pub profile: ProfileConfig,
    pub frameworks: LanguageListConfig,
    pub data_layers: LanguageListConfig,
    pub analysis: AnalysisConfig,
    pub ci: CiConfig,
    pub inference: InferenceConfig,
    pub suppressions: SuppressionConfig,
    pub auth: AuthConfig,
    pub tenancy: TenancyConfig,
    pub resources: BTreeMap<String, ResourceConfig>,
    pub invariants: Vec<InvariantConfig>,
}

impl Default for RulepathConfig {
    fn default() -> Self {
        Self {
            version: 1,
            profile: ProfileConfig::default(),
            frameworks: LanguageListConfig::default(),
            data_layers: LanguageListConfig::default(),
            analysis: AnalysisConfig::default(),
            ci: CiConfig::default(),
            inference: InferenceConfig::default(),
            suppressions: SuppressionConfig::default(),
            auth: AuthConfig::default(),
            tenancy: TenancyConfig::default(),
            resources: BTreeMap::new(),
            invariants: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileConfig {
    pub name: String,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            name: "internal_web_app".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LanguageListConfig {
    pub python: Vec<String>,
    pub typescript: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    pub mode: String,
    pub service_layer_tracing: bool,
    pub max_call_depth: usize,
    pub include_review_hints: bool,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            mode: "high_confidence".to_owned(),
            service_layer_tracing: true,
            max_call_depth: 6,
            include_review_hints: true,
            include_paths: vec!["app".to_owned(), "src".to_owned()],
            exclude_paths: vec![
                "node_modules".to_owned(),
                ".venv".to_owned(),
                "venv".to_owned(),
                "migrations".to_owned(),
                "tests".to_owned(),
                "dist".to_owned(),
                "build".to_owned(),
                "target".to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CiConfig {
    pub fail: bool,
    pub fail_on: FailOnConfig,
    pub baseline_file: String,
}

impl Default for CiConfig {
    fn default() -> Self {
        Self {
            fail: false,
            fail_on: FailOnConfig::default(),
            baseline_file: ".rulepath.baseline.json".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct FailOnConfig {
    pub severities: Vec<String>,
    pub confidence: Vec<String>,
    pub include_review_hints: bool,
    pub new_findings_only: bool,
}

impl Default for FailOnConfig {
    fn default() -> Self {
        Self {
            severities: vec!["high".to_owned(), "critical".to_owned()],
            confidence: vec!["high".to_owned()],
            include_review_hints: false,
            new_findings_only: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct InferenceConfig {
    pub generated_file: String,
    pub use_inferred_file_for_scan: bool,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            generated_file: ".rulepath.inferred.yml".to_owned(),
            use_inferred_file_for_scan: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SuppressionConfig {
    pub require_reason: bool,
    pub min_reason_length: usize,
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            require_reason: true,
            min_reason_length: 20,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub principal_expressions: LanguageListConfig,
    pub authentication_guards: LanguageListConfig,
    pub authorization_functions: LanguageListConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TenancyConfig {
    pub tenant_fields: Vec<String>,
    pub current_tenant_expressions: LanguageListConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceConfig {
    pub tenant_fields: Vec<String>,
    pub sensitive_fields: Vec<String>,
    pub server_owned_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct InvariantConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub invariant_type: String,
    pub resources: Vec<String>,
    pub resource: Option<String>,
    pub operations: Vec<String>,
    pub fields: BTreeMap<String, String>,
    pub field: Option<String>,
    pub required_scope: Vec<String>,
    pub requires: Vec<String>,
    pub severity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub raw: RulepathConfig,
}

impl ResolvedConfig {
    #[must_use]
    pub const fn new(raw: RulepathConfig) -> Self {
        Self { raw }
    }

    #[must_use]
    pub fn resource(&self, name: &str) -> Option<&ResourceConfig> {
        self.raw.resources.get(name)
    }

    #[must_use]
    pub fn tenant_fields_for(&self, resource: &str) -> Vec<String> {
        let mut fields = self.raw.tenancy.tenant_fields.clone();
        if let Some(resource_config) = self.resource(resource) {
            for field in &resource_config.tenant_fields {
                if !fields.contains(field) {
                    fields.push(field.clone());
                }
            }
        }
        fields
    }

    #[must_use]
    pub fn sensitive_or_server_owned_fields(&self, resource: &str) -> Vec<String> {
        let mut fields = Vec::new();
        if let Some(resource_config) = self.resource(resource) {
            for field in resource_config
                .sensitive_fields
                .iter()
                .chain(resource_config.server_owned_fields.iter())
            {
                if !fields.contains(field) {
                    fields.push(field.clone());
                }
            }
        }
        fields
    }

    #[must_use]
    pub fn has_state_invariant(&self, resource: &str) -> bool {
        self.raw.invariants.iter().any(|invariant| {
            invariant.invariant_type == "state_transition"
                && (invariant.resource.as_deref() == Some(resource)
                    || invariant.resources.iter().any(|item| item == resource))
        })
    }
}

pub fn load_from_path(path: impl AsRef<Path>) -> Result<ResolvedConfig, ConfigError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let config = parse_config(&text, &path.display().to_string())?;
    Ok(resolve_config(config))
}

pub fn load_project_config(root: impl AsRef<Path>) -> Result<ResolvedConfig, ConfigError> {
    let path = root.as_ref().join(".rulepath.yml");
    if path.exists() {
        load_from_path(path)
    } else {
        Ok(default_resolved_config())
    }
}

pub fn validate_config(path: impl AsRef<Path>) -> Result<(), ConfigError> {
    load_from_path(path).map(|_| ())
}

#[must_use]
pub fn default_resolved_config() -> ResolvedConfig {
    resolve_config(RulepathConfig::default())
}

#[must_use]
pub fn starter_config() -> &'static str {
    r#"version: 1

profile:
  name: internal_web_app

analysis:
  mode: high_confidence
  service_layer_tracing: true
  max_call_depth: 6
  include_review_hints: true
  include_paths:
    - app
    - src
  exclude_paths:
    - node_modules
    - .venv
    - venv
    - migrations
    - tests
    - dist
    - build

ci:
  fail: false
  baseline_file: .rulepath.baseline.json

inference:
  generated_file: .rulepath.inferred.yml
  use_inferred_file_for_scan: false

suppressions:
  require_reason: true
  min_reason_length: 20

# Run `rulepath infer .` to create .rulepath.inferred.yml with draft suggestions.
resources: {}
invariants: []
"#
}

#[must_use]
pub fn schema_json() -> serde_json::Value {
    let schema = schemars::schema_for!(RulepathConfig);
    serde_json::to_value(schema).expect("schema should serialize")
}

fn parse_config(text: &str, path: &str) -> Result<RulepathConfig, ConfigError> {
    serde_yaml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_owned(),
        source,
    })
}

fn resolve_config(project: RulepathConfig) -> ResolvedConfig {
    if project.profile.name == "internal_web_app" {
        let profile = parse_config(INTERNAL_WEB_APP_PROFILE, "profiles/internal_web_app.yml")
            .expect("built-in internal_web_app profile must be valid");
        ResolvedConfig::new(merge_config(profile, project))
    } else {
        ResolvedConfig::new(project)
    }
}

fn merge_config(mut base: RulepathConfig, project: RulepathConfig) -> RulepathConfig {
    base.version = project.version;
    base.profile = project.profile;
    merge_language_lists(&mut base.frameworks, project.frameworks);
    merge_language_lists(&mut base.data_layers, project.data_layers);
    base.analysis = project.analysis;
    base.ci = project.ci;
    base.inference = project.inference;
    base.suppressions = project.suppressions;
    merge_auth(&mut base.auth, project.auth);
    merge_tenancy(&mut base.tenancy, project.tenancy);
    base.resources.extend(project.resources);
    if !project.invariants.is_empty() {
        base.invariants = project.invariants;
    }
    base
}

fn merge_language_lists(base: &mut LanguageListConfig, project: LanguageListConfig) {
    if !project.python.is_empty() {
        base.python = project.python;
    }
    if !project.typescript.is_empty() {
        base.typescript = project.typescript;
    }
}

fn merge_auth(base: &mut AuthConfig, project: AuthConfig) {
    merge_language_lists(
        &mut base.principal_expressions,
        project.principal_expressions,
    );
    merge_language_lists(
        &mut base.authentication_guards,
        project.authentication_guards,
    );
    merge_language_lists(
        &mut base.authorization_functions,
        project.authorization_functions,
    );
}

fn merge_tenancy(base: &mut TenancyConfig, project: TenancyConfig) {
    if !project.tenant_fields.is_empty() {
        base.tenant_fields = project.tenant_fields;
    }
    merge_language_lists(
        &mut base.current_tenant_expressions,
        project.current_tenant_expressions,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_top_level_keys() {
        let err = parse_config("version: 1\nsurprise: true\n", "test.yml").unwrap_err();
        assert!(err.to_string().contains("surprise"));
    }

    #[test]
    fn profile_defaults_are_applied() {
        let resolved = resolve_config(RulepathConfig::default());
        assert!(resolved.raw.resources.contains_key("Invoice"));
        assert!(resolved
            .raw
            .tenancy
            .tenant_fields
            .contains(&"tenant_id".to_owned()));
    }
}
