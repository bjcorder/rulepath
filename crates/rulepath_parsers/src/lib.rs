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
pub fn span_for_offsets(file_id: &str, text: &str, start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        file_id: file_id.to_owned(),
        start: position_for_offset(text, start),
        end: position_for_offset(text, end),
    }
}

#[must_use]
pub fn position_for_offset(text: &str, offset: usize) -> rulepath_ir::Position {
    let bounded = offset.min(text.len());
    let mut line = 1;
    let mut column = 1;
    for character in text[..bounded].chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    rulepath_ir::Position::new(line, column)
}

#[must_use]
pub fn extract_suppressions_from_text(
    file_id: &str,
    text: &str,
    language: Language,
) -> Vec<SuppressionFact> {
    comment_lines(text, language)
        .into_iter()
        .filter_map(|(line_number, line)| parse_suppression_line(file_id, line_number, &line))
        .collect()
}

fn comment_lines(text: &str, language: Language) -> Vec<(usize, String)> {
    match language {
        Language::Python => python_comment_lines(text),
        Language::TypeScript => typescript_comment_lines(text),
    }
}

fn python_comment_lines(text: &str) -> Vec<(usize, String)> {
    let mut comments = Vec::new();
    let mut triple_quote: Option<&str> = None;

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let bytes = line.as_bytes();
        let mut cursor = 0;

        while cursor < bytes.len() {
            if let Some(delimiter) = triple_quote {
                if bytes_start_with(bytes, cursor, delimiter.as_bytes()) {
                    triple_quote = None;
                    cursor += delimiter.len();
                } else {
                    cursor += 1;
                }
                continue;
            }

            match bytes[cursor] {
                b'#' => {
                    comments.push((line_number, line[cursor + 1..].to_owned()));
                    break;
                }
                b'\'' | b'"' => {
                    let quote = bytes[cursor];
                    if line[cursor..].starts_with(if quote == b'\'' { "'''" } else { "\"\"\"" }) {
                        triple_quote = Some(if quote == b'\'' { "'''" } else { "\"\"\"" });
                        cursor += 3;
                    } else {
                        cursor += 1;
                        while cursor < bytes.len() {
                            if bytes[cursor] == b'\\' {
                                cursor += 2;
                            } else if bytes[cursor] == quote {
                                cursor += 1;
                                break;
                            } else {
                                cursor += 1;
                            }
                        }
                    }
                }
                _ => cursor += 1,
            }
        }
    }

    comments
}

fn bytes_start_with(bytes: &[u8], cursor: usize, expected: &[u8]) -> bool {
    bytes
        .get(cursor..cursor.saturating_add(expected.len()))
        .is_some_and(|candidate| candidate == expected)
}

fn typescript_comment_lines(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut comments = Vec::new();
    let mut cursor = 0;
    let mut line_number = 1;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\n' => {
                line_number += 1;
                cursor += 1;
            }
            b'\'' | b'"' => {
                cursor = skip_quoted_text(bytes, cursor, bytes[cursor], &mut line_number);
            }
            b'`' => {
                cursor = skip_quoted_text(bytes, cursor, b'`', &mut line_number);
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                let start = cursor + 2;
                let end = text[start..]
                    .find('\n')
                    .map_or(text.len(), |offset| start + offset);
                comments.push((line_number, text[start..end].to_owned()));
                cursor = end;
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                cursor += 2;
                let mut line_start = cursor;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
                        comments.push((line_number, text[line_start..cursor].to_owned()));
                        cursor += 2;
                        break;
                    }
                    if bytes[cursor] == b'\n' {
                        comments.push((line_number, text[line_start..cursor].to_owned()));
                        line_number += 1;
                        cursor += 1;
                        line_start = cursor;
                    } else {
                        cursor += 1;
                    }
                }
            }
            _ => cursor += 1,
        }
    }

    comments
}

fn skip_quoted_text(
    bytes: &[u8],
    mut cursor: usize,
    delimiter: u8,
    line_number: &mut usize,
) -> usize {
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\' {
            if bytes.get(cursor + 1) == Some(&b'\n') {
                *line_number += 1;
            }
            cursor += 2;
        } else if bytes[cursor] == delimiter {
            return cursor + 1;
        } else {
            if bytes[cursor] == b'\n' {
                *line_number += 1;
            }
            cursor += 1;
        }
    }
    cursor
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
        let suppressions = extract_suppressions_from_text("file.ts", text, Language::TypeScript);
        assert_eq!(suppressions[0].rule_id, "INV001");
        assert!(suppressions[0].reason.is_some());
    }

    #[test]
    fn ignores_typescript_string_literals() {
        let text = r#"
const marker = "rulepath-disable-next-line INV001 -- ignored in string";
const other = '// rulepath-disable-line INV002 -- ignored in string';
// rulepath-disable-line INV003 -- parsed from comment
"#;
        let suppressions = extract_suppressions_from_text("file.ts", text, Language::TypeScript);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_id, "INV003");
    }

    #[test]
    fn ignores_python_string_literals() {
        let text = r#"
marker = "rulepath-disable-next-line INV001 -- ignored in string"
other = '# rulepath-disable-line INV002 -- ignored in string'
# rulepath-disable-line INV003 -- parsed from comment
"#;
        let suppressions = extract_suppressions_from_text("file.py", text, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_id, "INV003");
    }

    #[test]
    fn ignores_python_triple_quoted_strings_with_non_ascii_content() {
        let text = r#"
marker = """café rulepath-disable-next-line INV001 -- ignored in string"""
# rulepath-disable-line INV002 -- parsed from comment
"#;
        let suppressions = extract_suppressions_from_text("file.py", text, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_id, "INV002");
    }
}
