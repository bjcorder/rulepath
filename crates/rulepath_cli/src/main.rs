use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rulepath_config::{starter_config, validate_config, ResolvedConfig};
use rulepath_ir::{Confidence, Diagnostic, DiagnosticKind, Severity};
use rulepath_reporters::{build_report, render_json, render_text, Report};
use serde::{Deserialize, Serialize};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "rulepath")]
#[command(version = VERSION)]
#[command(about = "Business logic and invariant analysis for web applications.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a starter .rulepath.yml.
    Init {
        #[arg(long, default_value = "internal_web_app")]
        profile: String,
        #[arg(long)]
        force: bool,
    },
    /// Validate configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Infer a draft .rulepath.inferred.yml.
    Infer {
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Scan a project.
    Scan {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(long)]
        ci: bool,
    },
    /// Manage baselines.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Explain a rule or review hint.
    Explain { rule_id: String },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Validate .rulepath.yml.
    Validate {
        #[arg(default_value = ".rulepath.yml")]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    /// Create .rulepath.baseline.json from the current scan.
    Create {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { profile, force } => init(&profile, force),
        Command::Config { command } => match command {
            ConfigCommand::Validate { path } => {
                validate_config(&path)?;
                println!("Rulepath config is valid: {}", path.display());
                Ok(ExitCode::SUCCESS)
            }
        },
        Command::Infer { path, force } => infer(&path, force),
        Command::Scan { path, format, ci } => scan_command(&path, format, ci),
        Command::Baseline { command } => match command {
            BaselineCommand::Create { path, force } => baseline_create(&path, force),
        },
        Command::Explain { rule_id } => explain(&rule_id),
    }
}

fn init(profile: &str, force: bool) -> Result<ExitCode> {
    if profile != "internal_web_app" {
        bail!("unknown profile: {profile}");
    }
    let path = PathBuf::from(".rulepath.yml");
    if path.exists() && !force {
        bail!(".rulepath.yml already exists; use --force to overwrite");
    }
    fs::write(&path, starter_config()).context("failed to write .rulepath.yml")?;
    println!("Created .rulepath.yml");
    Ok(ExitCode::SUCCESS)
}

fn infer(path: &Path, force: bool) -> Result<ExitCode> {
    let config = rulepath_config::load_project_config(path)?;
    let index = rulepath_workspace::scan_workspace(path, &config)?;
    let inferred = rulepath_infer::infer(&index);
    let output_path = path.join(&config.raw.inference.generated_file);
    if output_path.exists() && !force {
        bail!(
            "{} already exists; use --force to overwrite",
            output_path.display()
        );
    }
    fs::write(&output_path, inferred.yaml).with_context(|| {
        format!(
            "failed to write inferred config to {}",
            output_path.display()
        )
    })?;
    println!("Created {}", output_path.display());
    Ok(ExitCode::SUCCESS)
}

fn scan_command(path: &Path, format: OutputFormat, ci: bool) -> Result<ExitCode> {
    let scan = run_scan(path)?;
    let all_diagnostics = scan
        .report
        .findings
        .iter()
        .chain(scan.report.review_hints.iter())
        .cloned()
        .collect::<Vec<_>>();

    match format {
        OutputFormat::Text => print!("{}", render_text(&scan.report)),
        OutputFormat::Json => println!("{}", render_json(&scan.report)?),
        OutputFormat::Sarif => {
            let sarif = rulepath_sarif::render_sarif(VERSION, &all_diagnostics);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
    }

    if ci && should_fail_ci(path, &scan.config, &scan.report)? {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn baseline_create(path: &Path, force: bool) -> Result<ExitCode> {
    let scan = run_scan(path)?;
    let baseline_path = path.join(&scan.config.raw.ci.baseline_file);
    if baseline_path.exists() && !force {
        bail!(
            "{} already exists; use --force to overwrite",
            baseline_path.display()
        );
    }
    let baseline = BaselineFile::from_report(&scan.report);
    fs::write(&baseline_path, serde_json::to_string_pretty(&baseline)?)
        .with_context(|| format!("failed to write baseline to {}", baseline_path.display()))?;
    println!("Created {}", baseline_path.display());
    Ok(ExitCode::SUCCESS)
}

fn explain(rule_id: &str) -> Result<ExitCode> {
    let Some(explanation) = rulepath_rules::explain(rule_id) else {
        bail!("unknown rule or hint: {rule_id}");
    };
    println!("{} - {}", explanation.id, explanation.title);
    println!();
    println!("{}", explanation.purpose);
    println!();
    println!("Safe patterns:");
    for pattern in explanation.safe_patterns {
        println!("  - {pattern}");
    }
    println!();
    println!("Config keys:");
    for key in explanation.config_keys {
        println!("  - {key}");
    }
    Ok(ExitCode::SUCCESS)
}

struct ScanResult {
    config: ResolvedConfig,
    report: Report,
}

fn run_scan(path: &Path) -> Result<ScanResult> {
    let config = rulepath_config::load_project_config(path)?;
    let index = rulepath_workspace::scan_workspace(path, &config)?;
    let ir = rulepath_dataflow::build_project_ir(&index, &config);
    let diagnostics = rulepath_rules::evaluate(&ir, &config);
    let report = build_report(VERSION, diagnostics);
    Ok(ScanResult { config, report })
}

fn should_fail_ci(path: &Path, config: &ResolvedConfig, report: &Report) -> Result<bool> {
    if !config.raw.ci.fail {
        return Ok(false);
    }
    let baseline = if config.raw.ci.fail_on.new_findings_only {
        load_baseline(path, &config.raw.ci.baseline_file)?
    } else {
        BTreeSet::new()
    };
    Ok(report.findings.iter().any(|finding| {
        matches_ci_policy(finding, config)
            && (!config.raw.ci.fail_on.new_findings_only
                || !baseline.contains(&finding.fingerprint))
    }))
}

fn matches_ci_policy(diagnostic: &Diagnostic, config: &ResolvedConfig) -> bool {
    if diagnostic.kind == DiagnosticKind::ReviewHint && !config.raw.ci.fail_on.include_review_hints
    {
        return false;
    }
    let severity = severity_key(diagnostic.severity);
    let confidence = confidence_key(diagnostic.confidence);
    config
        .raw
        .ci
        .fail_on
        .severities
        .iter()
        .any(|item| item == severity)
        && config
            .raw
            .ci
            .fail_on
            .confidence
            .iter()
            .any(|item| item == confidence)
}

fn load_baseline(path: &Path, file_name: &str) -> Result<BTreeSet<String>> {
    let baseline_path = path.join(file_name);
    if !baseline_path.exists() {
        return Ok(BTreeSet::new());
    }
    let text = fs::read_to_string(&baseline_path)
        .with_context(|| format!("failed to read baseline {}", baseline_path.display()))?;
    let baseline: BaselineFile = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse baseline {}", baseline_path.display()))?;
    Ok(baseline
        .findings
        .into_iter()
        .chain(baseline.review_hints)
        .map(|entry| entry.fingerprint)
        .collect())
}

fn severity_key(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_key(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BaselineFile {
    version: u32,
    findings: Vec<BaselineEntry>,
    review_hints: Vec<BaselineEntry>,
}

impl BaselineFile {
    fn from_report(report: &Report) -> Self {
        Self {
            version: 1,
            findings: report.findings.iter().map(BaselineEntry::from).collect(),
            review_hints: report
                .review_hints
                .iter()
                .map(BaselineEntry::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BaselineEntry {
    rule_id: String,
    fingerprint: String,
    title: String,
}

impl From<&Diagnostic> for BaselineEntry {
    fn from(diagnostic: &Diagnostic) -> Self {
        Self {
            rule_id: diagnostic.rule_id.clone(),
            fingerprint: diagnostic.fingerprint.clone(),
            title: diagnostic.title.clone(),
        }
    }
}
