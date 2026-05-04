use std::path::Path;

use rulepath_ir::Language;
use rulepath_parsers::{
    extract_suppressions_from_text, span_for_offsets, CallFact, ImportFact, LanguageAdapter,
    ParsedFile, SymbolFact, SymbolKind,
};
use rulepath_workspace::SourceFile;

#[derive(Debug, Default)]
pub struct TypeScriptAdapter;

impl LanguageAdapter for TypeScriptAdapter {
    fn language_id(&self) -> Language {
        Language::TypeScript
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx", "js", "jsx"]
    }

    fn parse_file(&self, file: &SourceFile) -> ParsedFile {
        let mut parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            suppressions: extract_suppressions_from_text(&file.relative_path, &file.text),
        };

        let _parsed_without_panic = parse_with_oxc(file);

        parsed.imports = extract_imports(file);
        parsed.symbols = extract_symbols(file);
        parsed.calls = extract_calls(file);
        parsed
    }
}

#[must_use]
pub fn parser_backend() -> &'static str {
    "oxc"
}

#[cfg(feature = "oxc-backend")]
fn parse_with_oxc(file: &SourceFile) -> bool {
    let allocator = oxc_allocator::Allocator::default();
    let source_type = oxc_span::SourceType::from_path(Path::new(file.relative_path.as_str()))
        .unwrap_or_else(|_| {
            match Path::new(file.relative_path.as_str())
                .extension()
                .and_then(|extension| extension.to_str())
            {
                Some("tsx") => oxc_span::SourceType::tsx(),
                Some("jsx") => oxc_span::SourceType::jsx(),
                Some("js") => oxc_span::SourceType::unambiguous(),
                _ => oxc_span::SourceType::ts(),
            }
        });
    let parsed = oxc_parser::Parser::new(&allocator, &file.text, source_type).parse();
    !parsed.panicked
}

#[cfg(not(feature = "oxc-backend"))]
fn parse_with_oxc(_file: &SourceFile) -> bool {
    true
}

fn extract_imports(file: &SourceFile) -> Vec<ImportFact> {
    let mut imports = Vec::new();
    for (line_start, line) in line_offsets(&file.text) {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let start = line_start + indent;

        if trimmed.starts_with("import ") {
            if let Some((module, names)) = parse_import_statement(trimmed) {
                imports.push(ImportFact {
                    module,
                    names,
                    span: span_for_offsets(
                        &file.relative_path,
                        &file.text,
                        start,
                        start + trimmed.len(),
                    ),
                });
            }
        } else if trimmed.starts_with("export ") && trimmed.contains(" from ") {
            if let Some((module, names)) = parse_export_from_statement(trimmed) {
                imports.push(ImportFact {
                    module,
                    names,
                    span: span_for_offsets(
                        &file.relative_path,
                        &file.text,
                        start,
                        start + trimmed.len(),
                    ),
                });
            }
        }

        for (require_offset, module) in require_calls(trimmed) {
            imports.push(ImportFact {
                module,
                names: Vec::new(),
                span: span_for_offsets(
                    &file.relative_path,
                    &file.text,
                    start + require_offset,
                    start + require_offset + "require".len(),
                ),
            });
        }
    }
    imports.sort_by(|left, right| {
        left.span
            .start
            .line
            .cmp(&right.span.start.line)
            .then(left.module.cmp(&right.module))
    });
    imports
}

fn parse_import_statement(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim_end_matches(';').trim();
    if let Some(rest) = line.strip_prefix("import type ") {
        return parse_import_statement(&format!("import {rest}"));
    }
    let rest = line.strip_prefix("import ")?;
    if let Some(module) = quoted_after(rest, "") {
        return Some((module, Vec::new()));
    }
    let from_index = rest.rfind(" from ")?;
    let bindings = rest[..from_index].trim();
    let module = quoted_after(rest[from_index + " from ".len()..].trim(), "")?;
    Some((module, parse_import_names(bindings)))
}

fn parse_export_from_statement(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim_end_matches(';').trim();
    let from_index = line.rfind(" from ")?;
    let module = quoted_after(line[from_index + " from ".len()..].trim(), "")?;
    let names = if line.contains("* as ") {
        line.split("* as ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .map(|name| vec![name.trim_end_matches(',').to_owned()])
            .unwrap_or_else(|| vec!["*".to_owned()])
    } else if let Some(open) = line.find('{') {
        let close = line[open + 1..].find('}')? + open + 1;
        parse_named_list(&line[open + 1..close])
    } else {
        Vec::new()
    };
    Some((module, names))
}

fn parse_import_names(bindings: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = bindings.trim();
    if rest.starts_with('{') {
        if let Some(close) = rest.find('}') {
            names.extend(parse_named_list(&rest[1..close]));
        }
        return names;
    }
    if let Some(default_name) = rest
        .split(',')
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        if !default_name.starts_with('*') {
            names.push(default_name.to_owned());
        }
    }
    if let Some(namespace_index) = rest.find("* as ") {
        rest = &rest[namespace_index + "* as ".len()..];
        if let Some(name) = rest.split_whitespace().next() {
            names.push(name.trim_end_matches(',').to_owned());
        }
    }
    if let Some(open) = rest.find('{') {
        if let Some(close) = rest[open + 1..].find('}') {
            names.extend(parse_named_list(&rest[open + 1..open + 1 + close]));
        }
    }
    names
}

fn parse_named_list(names: &str) -> Vec<String> {
    names
        .split(',')
        .filter_map(|name| {
            let name = name
                .trim()
                .strip_prefix("type ")
                .unwrap_or(name.trim())
                .trim();
            if name.is_empty() {
                None
            } else {
                Some(
                    name.split(" as ")
                        .last()
                        .unwrap_or(name)
                        .split_whitespace()
                        .next()
                        .unwrap_or(name)
                        .to_owned(),
                )
            }
        })
        .collect()
}

fn require_calls(line: &str) -> Vec<(usize, String)> {
    let mut calls = Vec::new();
    let mut search_start = 0;
    while let Some(relative) = line[search_start..].find("require(") {
        let start = search_start + relative;
        if let Some(module) = quoted_after(&line[start + "require(".len()..], "") {
            calls.push((start, module));
        }
        search_start = start + "require(".len();
    }
    calls
}

fn extract_symbols(file: &SourceFile) -> Vec<SymbolFact> {
    let mut symbols = Vec::new();
    let mut class_depth = 0usize;
    for (line_start, line) in line_offsets(&file.text) {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let start = line_start + indent;
        if let Some(name) = function_name(trimmed) {
            symbols.push(symbol(file, name, SymbolKind::Function, start, trimmed));
        }
        if let Some(name) = class_name(trimmed) {
            symbols.push(symbol(file, name, SymbolKind::Class, start, trimmed));
        }
        if let Some(name) = arrow_function_name(trimmed) {
            symbols.push(symbol(file, name, SymbolKind::Function, start, trimmed));
        }
        if class_depth > 0 {
            if let Some(name) = method_name(trimmed) {
                symbols.push(symbol(file, name, SymbolKind::Method, start, trimmed));
            }
        }
        class_depth = class_depth.saturating_add(trimmed.matches('{').count());
        class_depth = class_depth.saturating_sub(trimmed.matches('}').count());
    }
    symbols
}

fn symbol(
    file: &SourceFile,
    name: String,
    kind: SymbolKind,
    start: usize,
    text: &str,
) -> SymbolFact {
    SymbolFact {
        name,
        kind,
        span: span_for_offsets(&file.relative_path, &file.text, start, start + text.len()),
    }
}

fn function_name(line: &str) -> Option<String> {
    let mut rest = line.strip_prefix("export ").unwrap_or(line);
    rest = rest.strip_prefix("default ").unwrap_or(rest);
    rest = rest.strip_prefix("async ").unwrap_or(rest);
    rest = rest.strip_prefix("function ")?;
    identifier_prefix(rest)
}

fn class_name(line: &str) -> Option<String> {
    let mut rest = line.strip_prefix("export ").unwrap_or(line);
    rest = rest.strip_prefix("default ").unwrap_or(rest);
    rest = rest.strip_prefix("class ")?;
    identifier_prefix(rest)
}

fn arrow_function_name(line: &str) -> Option<String> {
    if !line.contains("=>") {
        return None;
    }
    let rest = line
        .strip_prefix("export ")
        .unwrap_or(line)
        .strip_prefix("const ")
        .or_else(|| line.strip_prefix("let "))
        .or_else(|| line.strip_prefix("var "))?;
    identifier_prefix(rest.split('=').next()?.trim())
}

fn method_name(line: &str) -> Option<String> {
    if line.starts_with("if ")
        || line.starts_with("for ")
        || line.starts_with("while ")
        || line.starts_with("switch ")
        || line.starts_with("catch ")
        || line.starts_with("function ")
        || line.contains("=>")
    {
        return None;
    }
    let open = line.find('(')?;
    let name = line[..open]
        .split_whitespace()
        .last()
        .unwrap_or_default()
        .trim_start_matches("async ");
    (!name.is_empty() && !name.contains('.')).then(|| name.to_owned())
}

fn extract_calls(file: &SourceFile) -> Vec<CallFact> {
    let text = file.text.as_str();
    let bytes = text.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !is_identifier_start(bytes[index] as char) {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < bytes.len() {
            let character = bytes[index] as char;
            if is_identifier_char(character) || character == '.' {
                index += 1;
            } else {
                break;
            }
        }
        let callee = &text[start..index];
        let after_ws = skip_whitespace(text, index);
        if after_ws >= bytes.len()
            || bytes[after_ws] != b'('
            || is_non_call_context(text, start, callee)
        {
            continue;
        }
        let end = find_matching_paren(text, after_ws).unwrap_or(after_ws);
        let arguments = split_arguments(&text[after_ws + 1..end]);
        calls.push(CallFact {
            callee: callee.to_owned(),
            arguments,
            span: span_for_offsets(&file.relative_path, text, start, end + 1),
        });
        index = after_ws + 1;
    }
    calls
}

fn is_non_call_context(text: &str, start: usize, callee: &str) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |index| index + 1);
    let before = text[line_start..start].trim_end();
    matches!(
        callee,
        "if" | "for" | "while" | "switch" | "catch" | "function" | "return"
    ) || before.ends_with("function")
        || before.ends_with("function*")
        || before.ends_with("class")
}

fn split_arguments(arguments: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in arguments.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let value = arguments[start..index].trim();
                if !value.is_empty() {
                    parts.push(value.to_owned());
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let value = arguments[start..].trim();
    if !value.is_empty() {
        parts.push(value.to_owned());
    }
    parts
}

fn quoted_after(text: &str, _prefix: &str) -> Option<String> {
    let text = text.trim_start();
    let quote = text.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &text[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn identifier_prefix(text: &str) -> Option<String> {
    let name = text
        .chars()
        .take_while(|character| is_identifier_char(*character))
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

fn line_offsets(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut offset = 0;
    for raw_line in text.split_inclusive('\n') {
        let line = raw_line.trim_end_matches('\n').trim_end_matches('\r');
        lines.push((offset, line));
        offset += raw_line.len();
    }
    lines
}

fn skip_whitespace(text: &str, mut index: usize) -> usize {
    while index < text.len() && text.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn find_matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, character) in text[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + index);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_identifier_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_' || character == '$'
}

fn is_identifier_char(character: char) -> bool {
    is_identifier_start(character) || character.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ParsedFile {
        TypeScriptAdapter.parse_file(&SourceFile {
            path: "fixture.ts".into(),
            relative_path: "fixture.ts".to_owned(),
            language: Language::TypeScript,
            text: text.to_owned(),
        })
    }

    #[test]
    fn parses_imports_symbols_calls_and_suppressions() {
        let parsed = parse(
            r#"
import express, { Router as ExpressRouter } from "express";
export { helper as routeHelper } from "./helpers";
const prisma = require("@prisma/client");

export async function updateInvoice(id: string) {
  return prisma.invoice.update({ where: { id } });
}

const routeHandler = async (req, res) => updateInvoice(req.params.id);

class InvoiceController {
  async patch(req, res) {
    await updateInvoice(req.params.id);
  }
}

// rulepath-disable-next-line INV001 -- parser test suppression
router.patch("/:id", routeHandler);
"#,
        );

        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "express"));
        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "./helpers"));
        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "@prisma/client"));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "updateInvoice" && symbol.kind == SymbolKind::Function));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "routeHandler" && symbol.kind == SymbolKind::Function));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "patch" && symbol.kind == SymbolKind::Method));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "updateInvoice"));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "prisma.invoice.update"));
        assert_eq!(parsed.suppressions[0].rule_id, "INV001");
        assert!(parsed.calls.iter().all(|call| call.span.start.line > 0));
    }

    #[test]
    fn express_fixture_exposes_route_service_call() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/express_prisma/unsafe/src/routes/invoices.ts");
        let text = std::fs::read_to_string(root).expect("fixture should be readable");
        let parsed = TypeScriptAdapter.parse_file(&SourceFile {
            path: "src/routes/invoices.ts".into(),
            relative_path: "src/routes/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text,
        });

        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "../services/invoices"));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "updateInvoice"));
        assert!(!parsed.calls.is_empty());
    }

    #[test]
    fn crlf_sources_keep_symbol_line_numbers() {
        let parsed = parse("import { prisma } from '@/db'\r\n\r\nexport async function PATCH() {\r\n  await prisma.invoice.update({ where: { id: params.id }, data: body })\r\n}\r\n");

        let patch = parsed
            .symbols
            .iter()
            .find(|symbol| symbol.name == "PATCH")
            .expect("PATCH symbol should be parsed");
        assert_eq!(patch.span.start.line, 3);
        let update = parsed
            .calls
            .iter()
            .find(|call| call.callee == "prisma.invoice.update")
            .expect("Prisma call should be parsed");
        assert_eq!(update.span.start.line, 4);
    }
}
