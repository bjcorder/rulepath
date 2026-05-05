use std::fs;
use std::path::{Path, PathBuf};

use camino::Utf8PathBuf;
use ignore::WalkBuilder;
use rulepath_config::ResolvedConfig;
use rulepath_ir::{AnalysisDiagnostic, AnalysisDiagnosticSeverity, Language, SourceSpan};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("workspace root is not valid UTF-8: {0}")]
    NonUtf8Root(String),
    #[error("source path is not valid UTF-8: {0}")]
    NonUtf8Path(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: Utf8PathBuf,
    pub relative_path: String,
    pub language: Language,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceIndex {
    pub root: Utf8PathBuf,
    pub files: Vec<SourceFile>,
    pub analysis_diagnostics: Vec<AnalysisDiagnostic>,
}

impl WorkspaceIndex {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

pub fn scan_workspace(
    root: impl AsRef<Path>,
    config: &ResolvedConfig,
) -> Result<WorkspaceIndex, WorkspaceError> {
    let root = root.as_ref();
    let root_utf8 = Utf8PathBuf::from_path_buf(root.to_path_buf())
        .map_err(|path| WorkspaceError::NonUtf8Root(path.display().to_string()))?;
    let enforce_includes = should_enforce_includes(root, &config.raw.analysis.include_paths);
    let mut files = Vec::new();
    let mut analysis_diagnostics = Vec::new();

    for entry in WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .build()
    {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        let path = entry.path();
        let Some(language) = language_for_path(path) else {
            continue;
        };

        let relative_path = relative_path(root, path);
        if is_excluded(&relative_path, &config.raw.analysis.exclude_paths) {
            continue;
        }
        if enforce_includes && !is_included(&relative_path, &config.raw.analysis.include_paths) {
            continue;
        }

        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                analysis_diagnostics.push(AnalysisDiagnostic {
                    code: if error.kind() == std::io::ErrorKind::InvalidData {
                        "skipped_non_utf8_file".to_owned()
                    } else {
                        "skipped_source_file".to_owned()
                    },
                    severity: AnalysisDiagnosticSeverity::Warning,
                    stage: "workspace".to_owned(),
                    message: format!("skipped source file {}: {error}", relative_path),
                    file_id: Some(relative_path.clone()),
                    span: Some(SourceSpan::single_line(relative_path.as_str(), 1)),
                });
                continue;
            }
        };
        let path = Utf8PathBuf::from_path_buf(path.to_path_buf())
            .map_err(|path| WorkspaceError::NonUtf8Path(path.display().to_string()))?;
        files.push(SourceFile {
            path,
            relative_path,
            language,
            text,
        });
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(WorkspaceIndex {
        root: root_utf8,
        files,
        analysis_diagnostics,
    })
}

#[must_use]
pub fn line_number_for_offset(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn language_for_path(path: &Path) -> Option<Language> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => Some(Language::Python),
        Some("ts" | "tsx" | "js" | "jsx") => Some(Language::TypeScript),
        _ => None,
    }
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn should_enforce_includes(root: &Path, include_paths: &[String]) -> bool {
    include_paths
        .iter()
        .map(|include| root.join(PathBuf::from(include)))
        .any(|path| path.exists())
}

fn is_included(relative_path: &str, include_paths: &[String]) -> bool {
    include_paths
        .iter()
        .map(|path| normalize_path(path))
        .any(|include| {
            relative_path == include || relative_path.starts_with(&format!("{include}/"))
        })
}

fn is_excluded(relative_path: &str, exclude_paths: &[String]) -> bool {
    let parts = relative_path.split('/').collect::<Vec<_>>();
    exclude_paths
        .iter()
        .map(|path| normalize_path(path))
        .any(|exclude| {
            relative_path == exclude
                || relative_path.starts_with(&format!("{exclude}/"))
                || parts.iter().any(|part| *part == exclude)
        })
}

fn normalize_path(path: &str) -> String {
    path.trim_matches('/').replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_to_line_is_one_based() {
        assert_eq!(line_number_for_offset("one\ntwo\nthree", 0), 1);
        assert_eq!(line_number_for_offset("one\ntwo\nthree", 4), 2);
    }
}
