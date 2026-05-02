use rulepath_ir::Language;
use rulepath_parsers::{extract_suppressions_from_text, LanguageAdapter, ParsedFile};
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
        ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            suppressions: extract_suppressions_from_text(&file.relative_path, &file.text),
        }
    }
}

#[must_use]
pub fn parser_backend() -> &'static str {
    "tree-sitter-python"
}
