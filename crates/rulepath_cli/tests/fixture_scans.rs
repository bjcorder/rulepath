use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn run_rulepath(args: &[&str]) -> String {
    let output = command_output(None, args);
    assert!(
        output.status.success(),
        "rulepath exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout should be utf-8")
}

fn run_rulepath_in(cwd: &Path, args: &[&str]) -> Output {
    command_output(Some(cwd), args)
}

fn command_output(cwd: Option<&Path>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rulepath"));
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().expect("rulepath command should run")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("rulepath-{name}-{}-{nonce}", std::process::id()))
}

fn copy_dir_all(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("destination directory should be created");
    for entry in fs::read_dir(from).expect("source directory should be readable") {
        let entry = entry.expect("source directory entry should be readable");
        let destination = to.join(entry.file_name());
        if entry
            .file_type()
            .expect("file type should be readable")
            .is_dir()
        {
            copy_dir_all(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("fixture file should be copied");
        }
    }
}

#[test]
fn express_prisma_unsafe_emits_first_milestone_findings() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("INV001"));
    assert!(stdout.contains("INV002"));
}

#[test]
fn express_prisma_safe_is_clean() {
    let path = fixture_path("fixtures/express_prisma/safe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("Findings: 0"));
}

#[test]
fn fastapi_sqlalchemy_unsafe_emits_python_parity_findings() {
    let path = fixture_path("fixtures/fastapi_sqlalchemy/unsafe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("INV001"));
    assert!(stdout.contains("INV002"));
}

#[test]
fn django_drf_unsafe_emits_unscoped_access_finding() {
    let path = fixture_path("fixtures/django_drf/unsafe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("INV001"));
    assert!(stdout.contains("Unscoped Invoice access"));
}

#[test]
fn django_drf_safe_is_clean() {
    let path = fixture_path("fixtures/django_drf/safe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("Findings: 0"));
}

#[test]
fn traced_service_sink_uses_route_request_sources() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&[
        "scan",
        path.to_str().expect("utf-8 fixture path"),
        "--format",
        "json",
    ]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json output should parse");
    let source_ids = json["findings"][0]["source_ids"]
        .as_array()
        .expect("source_ids should be an array")
        .iter()
        .map(|value| value.as_str().expect("source id should be a string"))
        .collect::<Vec<_>>();
    assert!(source_ids.contains(&"source:src/routes/invoices.ts:route_param"));
    assert!(source_ids.contains(&"source:src/routes/invoices.ts:body"));
    assert!(!source_ids
        .iter()
        .any(|source| source.contains("src/services/invoices.ts")));
}

#[test]
fn fastapi_service_sink_uses_route_request_sources() {
    let path = fixture_path("fixtures/fastapi_sqlalchemy/unsafe");
    let stdout = run_rulepath(&[
        "scan",
        path.to_str().expect("utf-8 fixture path"),
        "--format",
        "json",
    ]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json output should parse");
    let finding = json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .find(|finding| finding["rule_id"] == "INV001")
        .expect("INV001 should be emitted");
    let source_ids = finding["source_ids"]
        .as_array()
        .expect("source_ids should be an array")
        .iter()
        .map(|value| value.as_str().expect("source id should be a string"))
        .collect::<Vec<_>>();
    assert!(source_ids.contains(&"source:app/routes.py:route_param"));
    assert!(source_ids.contains(&"source:app/routes.py:body"));
    assert!(!source_ids
        .iter()
        .any(|source| source.contains("app/invoice_service.py")));
}

#[test]
fn json_output_includes_observed_evidence_labels() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&[
        "scan",
        path.to_str().expect("utf-8 fixture path"),
        "--format",
        "json",
    ]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json output should parse");
    let finding = json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .find(|finding| finding["rule_id"] == "INV001")
        .expect("INV001 should be emitted");
    let observed = finding["observed_evidence"]
        .as_array()
        .expect("observed evidence should be an array")
        .iter()
        .map(|value| value.as_str().expect("evidence label should be a string"))
        .collect::<Vec<_>>();
    assert!(observed.contains(&"authentication:requireAuth"));
}

#[test]
fn text_output_shows_call_path_frames() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    let normalized = stdout.replace('\\', "/");
    assert!(stdout.contains("Code path:"));
    assert!(normalized.contains("src/routes/invoices.ts:10 inline_handler()"));
    assert!(normalized.contains("src/services/invoices.ts:"));
    assert!(normalized.contains("updateInvoice()"));
}

#[test]
fn init_and_config_validate_work_together() {
    let dir = unique_temp_dir("init");
    fs::create_dir_all(&dir).expect("temp dir should be created");
    let init = run_rulepath_in(&dir, &["init"]);
    assert!(
        init.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(dir.join(".rulepath.yml").exists());

    let validate = run_rulepath_in(&dir, &["config", "validate"]);
    assert!(
        validate.status.success(),
        "validate stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
}

#[test]
fn infer_writes_draft_file_without_policy_enforcement() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("infer");
    copy_dir_all(&source, &dir);

    let infer = run_rulepath_in(&dir, &["infer", "."]);
    assert!(
        infer.status.success(),
        "infer stderr: {}",
        String::from_utf8_lossy(&infer.stderr)
    );
    let inferred = fs::read_to_string(dir.join(".rulepath.inferred.yml"))
        .expect("inferred config should be written");
    assert!(inferred.contains("Draft generated by rulepath infer"));
    assert!(inferred.contains("Invoice"));
}

#[test]
fn ci_failure_respects_baseline() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("baseline");
    copy_dir_all(&source, &dir);
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nprofile:\n  name: internal_web_app\nci:\n  fail: true\n",
    )
    .expect("test config should be written");

    let first_ci = run_rulepath_in(&dir, &["scan", ".", "--ci"]);
    assert!(!first_ci.status.success(), "ci should fail before baseline");

    let baseline = run_rulepath_in(&dir, &["baseline", "create", "."]);
    assert!(
        baseline.status.success(),
        "baseline stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    let second_ci = run_rulepath_in(&dir, &["scan", ".", "--ci"]);
    assert!(
        second_ci.status.success(),
        "ci stderr: {}",
        String::from_utf8_lossy(&second_ci.stderr)
    );
}

#[test]
fn suppression_with_reason_removes_matching_finding() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("suppression");
    copy_dir_all(&source, &dir);
    let service_path = dir.join("src/services/invoices.ts");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "return prisma.invoice.update",
            "// rulepath-disable-next-line INV001 -- test fixture documents a legacy global admin path\n  return prisma.invoice.update",
        ),
    )
    .expect("service fixture should be updated");

    let output = run_rulepath_in(&dir, &["scan", "."]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(!stdout.contains("INV001"));
    assert!(stdout.contains("INV002"));
}

#[test]
fn bare_suppression_fails_policy_validation() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("bad-suppression");
    copy_dir_all(&source, &dir);
    let service_path = dir.join("src/services/invoices.ts");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "return prisma.invoice.update",
            "// rulepath-disable-next-line INV001\n  return prisma.invoice.update",
        ),
    )
    .expect("service fixture should be updated");

    let output = run_rulepath_in(&dir, &["scan", "."]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid suppression"));
}
