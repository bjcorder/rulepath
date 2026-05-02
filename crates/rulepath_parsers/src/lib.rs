use rulepath_ir::{Language, SourceSpan};
use rulepath_workspace::SourceFile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportFact {
    pub module: String,
    pub names: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolFact {
    pub name: String,
    pub kind: SymbolKind,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Variable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallFact {
    pub callee: String,
    pub arguments: Vec<String>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionFact {
    pub rule_id: String,
    pub scope: SuppressionScope,
    pub reason: Option<String>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionScope {
    NextLine,
    Line,
    Block,
    Enable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedFile {
    pub language: Language,
    pub file_id: String,
    pub imports: Vec<ImportFact>,
    pub symbols: Vec<SymbolFact>,
    pub calls: Vec<CallFact>,
    pub suppressions: Vec<SuppressionFact>,
}

pub trait LanguageAdapter {
    fn language_id(&self) -> Language;
    fn file_extensions(&self) -> &'static [&'static str];
    fn parse_file(&self, file: &SourceFile) -> ParsedFile;
}

#[must_use]
pub fn extract_suppressions_from_text(file_id: &str, text: &str) -> Vec<SuppressionFact> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| parse_suppression_line(file_id, index + 1, line))
        .collect()
}

fn parse_suppression_line(
    file_id: &str,
    line_number: usize,
    line: &str,
) -> Option<SuppressionFact> {
    let marker_start = line.find("rulepath-")?;
    let after_marker = &line[marker_start..];
    let (scope, rest) = if let Some(rest) = after_marker.strip_prefix("rulepath-disable-next-line")
    {
        (SuppressionScope::NextLine, rest)
    } else if let Some(rest) = after_marker.strip_prefix("rulepath-disable-line") {
        (SuppressionScope::Line, rest)
    } else if let Some(rest) = after_marker.strip_prefix("rulepath-disable") {
        (SuppressionScope::Block, rest)
    } else if let Some(rest) = after_marker.strip_prefix("rulepath-enable") {
        (SuppressionScope::Enable, rest)
    } else {
        return None;
    };

    let mut parts = rest.splitn(2, "--");
    let rule_id = parts.next()?.split_whitespace().next()?.to_owned();
    let reason = parts
        .next()
        .map(str::trim)
        .filter(|reason| !reason.is_empty());
    Some(SuppressionFact {
        rule_id,
        scope,
        reason: reason.map(ToOwned::to_owned),
        span: SourceSpan::single_line(file_id, line_number),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suppression_reason() {
        let text = "// rulepath-disable-next-line INV001 -- tenant scope is enforced above";
        let suppressions = extract_suppressions_from_text("file.ts", text);
        assert_eq!(suppressions[0].rule_id, "INV001");
        assert!(suppressions[0].reason.is_some());
    }
}
