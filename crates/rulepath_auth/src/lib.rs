use rulepath_config::ResolvedConfig;
use rulepath_ir::EvidenceKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClassification {
    Authentication,
    Authorization,
    TenantScope,
    ObjectScope,
    Unknown,
}

impl From<EvidenceClassification> for Option<EvidenceKind> {
    fn from(value: EvidenceClassification) -> Self {
        match value {
            EvidenceClassification::Authentication => Some(EvidenceKind::Authentication),
            EvidenceClassification::Authorization => Some(EvidenceKind::Authorization),
            EvidenceClassification::TenantScope => Some(EvidenceKind::TenantScope),
            EvidenceClassification::ObjectScope => Some(EvidenceKind::ObjectScope),
            EvidenceClassification::Unknown => None,
        }
    }
}

#[must_use]
pub fn classify_helper(helper: &str, config: &ResolvedConfig) -> EvidenceClassification {
    let helper = helper.trim();
    if config
        .raw
        .auth
        .authentication_guards
        .python
        .iter()
        .chain(config.raw.auth.authentication_guards.typescript.iter())
        .any(|candidate| candidate == helper)
    {
        return EvidenceClassification::Authentication;
    }
    if config
        .raw
        .auth
        .authorization_functions
        .python
        .iter()
        .chain(config.raw.auth.authorization_functions.typescript.iter())
        .any(|candidate| candidate == helper)
    {
        return EvidenceClassification::Authorization;
    }
    EvidenceClassification::Unknown
}
