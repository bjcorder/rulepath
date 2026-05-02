use rulepath_ir::Language;
use rulepath_parsers::{extract_suppressions_from_text, LanguageAdapter, ParsedFile};
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
        ParsedFile {
            language: Language::TypeScript,
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
    "oxc"
}
