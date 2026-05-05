use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    TypeScript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    FastApi,
    Django,
    DjangoRestFramework,
    Express,
    NextJs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataLayer {
    DjangoOrm,
    SqlAlchemy,
    Prisma,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Read,
    Create,
    Update,
    Delete,
    BulkUpdate,
    BulkDelete,
    Export,
    Download,
    Report,
    StateTransition,
    ExternalSideEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    RouteParam,
    QueryParam,
    Body,
    Cookie,
    Header,
    Session,
    Form,
    FileUpload,
    UnknownRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Authentication,
    Authorization,
    ObjectScope,
    TenantScope,
    OwnershipScope,
    Invariant,
    Transaction,
    Idempotency,
    Audit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticKind {
    Finding,
    ReviewHint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisDiagnosticSeverity {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisDiagnostic {
    pub code: String,
    pub severity: AnalysisDiagnosticSeverity,
    pub stage: String,
    pub message: String,
    pub file_id: Option<String>,
    pub span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Position {
    #[must_use]
    pub const fn new(line: usize, column: usize) -> Self {
        Self { line, column }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceSpan {
    pub file_id: String,
    pub start: Position,
    pub end: Position,
}

impl SourceSpan {
    #[must_use]
    pub fn single_line(file_id: impl Into<String>, line: usize) -> Self {
        Self {
            file_id: file_id.into(),
            start: Position::new(line, 1),
            end: Position::new(line, 1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RouteFact {
    pub id: String,
    pub framework: Framework,
    pub language: Language,
    pub method: String,
    pub path: String,
    pub handler: String,
    pub span: SourceSpan,
    pub middleware: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceFact {
    pub id: String,
    pub kind: SourceKind,
    pub name: String,
    pub expression: String,
    pub controlled_by_request: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalFact {
    pub id: String,
    pub expression: String,
    pub source: String,
    pub framework: Framework,
    pub confidence: Confidence,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceFact {
    pub id: String,
    pub kind: EvidenceKind,
    pub label: String,
    pub expression: String,
    pub confidence: Confidence,
    pub route_id: Option<String>,
    pub sink_id: Option<String>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FilterFact {
    pub field: String,
    pub value: String,
    pub source_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MutationFieldFact {
    pub field: String,
    pub value: String,
    pub source_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationFact {
    pub id: String,
    pub data_layer: DataLayer,
    pub resource: String,
    pub operation: OperationType,
    pub method: String,
    pub filters: Vec<FilterFact>,
    pub mutation_fields: Vec<MutationFieldFact>,
    pub bulk: bool,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallFrame {
    pub function: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallPath {
    pub id: String,
    pub route_id: String,
    pub sink_id: String,
    pub frames: Vec<CallFrame>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub resource: Option<String>,
    pub operation: Option<OperationType>,
    pub route_id: Option<String>,
    pub call_path_id: Option<String>,
    #[serde(default)]
    pub call_path: Vec<CallFrame>,
    pub source_ids: Vec<String>,
    pub sink_id: Option<String>,
    pub primary_span: Option<SourceSpan>,
    pub missing_invariant: Option<String>,
    pub observed_evidence: Vec<String>,
    pub expected_evidence: Vec<String>,
    pub suggested_fix: Option<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectIr {
    pub routes: Vec<RouteFact>,
    pub sources: Vec<SourceFact>,
    pub principals: Vec<PrincipalFact>,
    pub evidence: Vec<EvidenceFact>,
    pub operations: Vec<OperationFact>,
    pub call_paths: Vec<CallPath>,
    pub analysis_diagnostics: Vec<AnalysisDiagnostic>,
}

impl ProjectIr {
    #[must_use]
    pub fn route_for_operation(&self, operation_id: &str) -> Option<&RouteFact> {
        let call_path = self
            .call_paths
            .iter()
            .find(|path| path.sink_id.as_str() == operation_id)?;
        self.routes
            .iter()
            .find(|route| route.id == call_path.route_id)
    }

    #[must_use]
    pub fn call_path_for_operation(&self, operation_id: &str) -> Option<&CallPath> {
        self.call_paths
            .iter()
            .find(|path| path.sink_id.as_str() == operation_id)
    }

    #[must_use]
    pub fn evidence_for_route_or_sink(
        &self,
        route_id: Option<&str>,
        sink_id: &str,
    ) -> Vec<&EvidenceFact> {
        self.evidence
            .iter()
            .filter(|evidence| {
                evidence.sink_id.as_deref() == Some(sink_id)
                    || route_id.is_some_and(|id| evidence.route_id.as_deref() == Some(id))
            })
            .collect()
    }
}

#[must_use]
pub fn fingerprint(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| part.trim().replace('\\', "/").to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(":")
}
