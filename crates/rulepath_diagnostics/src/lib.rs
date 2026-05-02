use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum RulepathError {
    #[error("configuration error: {0}")]
    #[diagnostic(code(rulepath::config))]
    Config(String),

    #[error("workspace error: {0}")]
    #[diagnostic(code(rulepath::workspace))]
    Workspace(String),

    #[error("scan error: {0}")]
    #[diagnostic(code(rulepath::scan))]
    Scan(String),
}

#[must_use]
pub fn format_source_location(span: &rulepath_ir::SourceSpan) -> String {
    format!("{}:{}:{}", span.file_id, span.start.line, span.start.column)
}
