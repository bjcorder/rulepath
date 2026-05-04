use rulepath_ir::Language;
use rulepath_parsers::{
    extract_suppressions_from_text, span_for_offsets, CallFact, ImportFact, LanguageAdapter,
    ParsedFile, SymbolFact, SymbolKind,
};
use rulepath_workspace::SourceFile;

#[derive(Debug, Default)]
pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn language_id(&self) -> Language {
        Language::Python
    }

    fn file_extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn parse_file(&self, file: &SourceFile) -> ParsedFile {
        let mut parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            suppressions: extract_suppressions_from_text(
                &file.relative_path,
                &file.text,
                file.language,
            ),
        };

        let Some(tree) = parse_tree(file) else {
            return parsed;
        };

        let root = tree.root_node();
        collect_node(file, root, 0, &mut parsed);
        parsed.imports.sort_by(span_order_import);
        parsed.symbols.sort_by(span_order_symbol);
        parsed.calls.sort_by(span_order_call);
        parsed
    }
}

#[must_use]
pub fn parser_backend() -> &'static str {
    "tree-sitter-python"
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_tree(file: &SourceFile) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(&file.text, None)
}

#[cfg(not(feature = "tree-sitter-backend"))]
fn parse_tree(_file: &SourceFile) -> Option<()> {
    None
}

#[cfg(feature = "tree-sitter-backend")]
fn collect_node(
    file: &SourceFile,
    node: tree_sitter::Node<'_>,
    class_depth: usize,
    parsed: &mut ParsedFile,
) {
    match node.kind() {
        "import_statement" => {
            if let Some(import) = parse_import_node(file, node) {
                parsed.imports.push(import);
            }
        }
        "import_from_statement" => {
            if let Some(import) = parse_from_import_node(file, node) {
                parsed.imports.push(import);
            }
        }
        "function_definition" => {
            if let Some(symbol) = parse_function_symbol(file, node, class_depth > 0) {
                parsed.symbols.push(symbol);
            }
        }
        "class_definition" => {
            if let Some(symbol) = parse_class_symbol(file, node) {
                parsed.symbols.push(symbol);
            }
        }
        "call" => {
            if let Some(call) = parse_call_node(file, node) {
                parsed.calls.push(call);
            }
        }
        "decorator" => {
            if let Some(call) = parse_decorator_call(file, node) {
                parsed.calls.push(call);
            }
        }
        _ => {}
    }

    let next_class_depth = if node.kind() == "class_definition" {
        class_depth + 1
    } else {
        class_depth
    };
    for index in 0..node.named_child_count() {
        if let Some(child) = node.named_child(index as u32) {
            collect_node(file, child, next_class_depth, parsed);
        }
    }
}

#[cfg(not(feature = "tree-sitter-backend"))]
fn collect_node(_file: &SourceFile, _node: (), _class_depth: usize, _parsed: &mut ParsedFile) {}

#[cfg(feature = "tree-sitter-backend")]
fn parse_import_node(file: &SourceFile, node: tree_sitter::Node<'_>) -> Option<ImportFact> {
    let text = node_text(file, node)?;
    let rest = text.trim().strip_prefix("import ")?;
    let names = rest
        .split(',')
        .filter_map(|part| {
            let name = part.trim().split(" as ").last()?.trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    let module = rest
        .split(',')
        .next()
        .and_then(|part| part.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    Some(ImportFact {
        module,
        names,
        span: node_span(file, node),
    })
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_from_import_node(file: &SourceFile, node: tree_sitter::Node<'_>) -> Option<ImportFact> {
    let text = node_text(file, node)?;
    let rest = text.trim().strip_prefix("from ")?;
    let (module, names_text) = rest.split_once(" import ")?;
    let names = names_text
        .trim_matches(|character| character == '(' || character == ')')
        .split(',')
        .filter_map(|part| {
            let name = part.trim().split(" as ").last()?.trim();
            (!name.is_empty() && name != "*").then(|| name.to_owned())
        })
        .collect::<Vec<_>>();
    Some(ImportFact {
        module: module.trim().to_owned(),
        names,
        span: node_span(file, node),
    })
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_function_symbol(
    file: &SourceFile,
    node: tree_sitter::Node<'_>,
    is_method: bool,
) -> Option<SymbolFact> {
    let name = node
        .child_by_field_name("name")
        .and_then(|child| node_text(file, child))?
        .to_owned();
    Some(SymbolFact {
        name,
        kind: if is_method {
            SymbolKind::Method
        } else {
            SymbolKind::Function
        },
        span: node_span(file, node),
    })
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_class_symbol(file: &SourceFile, node: tree_sitter::Node<'_>) -> Option<SymbolFact> {
    let name = node
        .child_by_field_name("name")
        .and_then(|child| node_text(file, child))?
        .to_owned();
    Some(SymbolFact {
        name,
        kind: SymbolKind::Class,
        span: node_span(file, node),
    })
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_call_node(file: &SourceFile, node: tree_sitter::Node<'_>) -> Option<CallFact> {
    let function = node.child_by_field_name("function")?;
    let callee = normalize_python_callee(node_text(file, function)?);
    let arguments = node
        .child_by_field_name("arguments")
        .and_then(|arguments| node_text(file, arguments))
        .map(parse_call_arguments)
        .unwrap_or_default();
    Some(CallFact {
        callee,
        arguments,
        span: node_span(file, node),
    })
}

#[cfg(feature = "tree-sitter-backend")]
fn parse_decorator_call(file: &SourceFile, node: tree_sitter::Node<'_>) -> Option<CallFact> {
    let text = node_text(file, node)?.trim().trim_start_matches('@');
    let open = text.find('(')?;
    let callee = text[..open].trim().to_owned();
    let arguments = text
        .rfind(')')
        .map(|close| parse_call_arguments(&text[open..=close]))
        .unwrap_or_default();
    Some(CallFact {
        callee,
        arguments,
        span: node_span(file, node),
    })
}

fn normalize_python_callee(text: &str) -> String {
    text.split_whitespace().collect::<String>()
}

fn parse_call_arguments(text: &str) -> Vec<String> {
    let inner = text.trim().trim_start_matches('(').trim_end_matches(')');
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, character) in inner.char_indices() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let value = inner[start..index].trim();
                if !value.is_empty() {
                    parts.push(value.to_owned());
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    let value = inner[start..].trim();
    if !value.is_empty() {
        parts.push(value.to_owned());
    }
    parts
}

#[cfg(feature = "tree-sitter-backend")]
fn node_text<'a>(file: &'a SourceFile, node: tree_sitter::Node<'_>) -> Option<&'a str> {
    node.utf8_text(file.text.as_bytes()).ok()
}

#[cfg(feature = "tree-sitter-backend")]
fn node_span(file: &SourceFile, node: tree_sitter::Node<'_>) -> rulepath_ir::SourceSpan {
    span_for_offsets(
        &file.relative_path,
        &file.text,
        node.start_byte(),
        node.end_byte(),
    )
}

fn span_order_import(left: &ImportFact, right: &ImportFact) -> std::cmp::Ordering {
    left.span
        .start
        .line
        .cmp(&right.span.start.line)
        .then(left.module.cmp(&right.module))
}

fn span_order_symbol(left: &SymbolFact, right: &SymbolFact) -> std::cmp::Ordering {
    left.span
        .start
        .line
        .cmp(&right.span.start.line)
        .then(left.name.cmp(&right.name))
}

fn span_order_call(left: &CallFact, right: &CallFact) -> std::cmp::Ordering {
    left.span
        .start
        .line
        .cmp(&right.span.start.line)
        .then(left.callee.cmp(&right.callee))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ParsedFile {
        PythonAdapter.parse_file(&SourceFile {
            path: "fixture.py".into(),
            relative_path: "fixture.py".to_owned(),
            language: Language::Python,
            text: text.to_owned(),
        })
    }

    #[test]
    fn parses_imports_decorators_symbols_calls_and_suppressions() {
        let parsed = parse(
            r#"
import os
import app.invoice_service as invoice_service
from fastapi import APIRouter, Depends

router = APIRouter()

class InvoiceService:
    def update_invoice(self, invoice_id, body):
        return session.get(Invoice, invoice_id)

@router.patch("/invoices/{invoice_id}")
async def update_route(invoice_id: str, body: dict, user = Depends(get_current_user)):
    # rulepath-disable-next-line INV001 -- parser test suppression
    return invoice_service.update_invoice(invoice_id, body)
"#,
        );

        assert!(parsed.imports.iter().any(|import| import.module == "os"));
        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "app.invoice_service"));
        assert!(parsed
            .imports
            .iter()
            .any(|import| import.module == "fastapi"));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "InvoiceService" && symbol.kind == SymbolKind::Class));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "update_invoice" && symbol.kind == SymbolKind::Method));
        assert!(parsed
            .symbols
            .iter()
            .any(|symbol| symbol.name == "update_route" && symbol.kind == SymbolKind::Function));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "router.patch"));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "invoice_service.update_invoice"));
        assert!(parsed.calls.iter().any(|call| call.callee == "Depends"));
        assert_eq!(parsed.suppressions[0].rule_id, "INV001");
        assert!(parsed.calls.iter().all(|call| call.span.start.line > 0));
    }

    #[test]
    fn fastapi_fixture_exposes_route_service_call() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/fastapi_sqlalchemy/unsafe/app/routes.py");
        let text = std::fs::read_to_string(root).expect("fixture should be readable");
        let parsed = PythonAdapter.parse_file(&SourceFile {
            path: "app/routes.py".into(),
            relative_path: "app/routes.py".to_owned(),
            language: Language::Python,
            text,
        });

        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "router.patch"));
        assert!(parsed
            .calls
            .iter()
            .any(|call| call.callee == "invoice_service.update_invoice"));
    }
}
