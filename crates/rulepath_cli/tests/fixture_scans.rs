use std::collections::BTreeSet;
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
    command_output_with_env(cwd, args, &[])
}

fn command_output_with_env(cwd: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rulepath"));
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
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

fn first_finding_fingerprint(json: &serde_json::Value, rule_id: &str) -> String {
    json["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .find(|finding| finding["rule_id"] == rule_id)
        .unwrap_or_else(|| panic!("{rule_id} should be emitted"))
        .get("fingerprint")
        .and_then(serde_json::Value::as_str)
        .expect("fingerprint should be a string")
        .to_owned()
}

fn scan_json(path: &str) -> serde_json::Value {
    let path = fixture_path(path);
    let stdout = run_rulepath(&[
        "scan",
        path.to_str().expect("utf-8 fixture path"),
        "--format",
        "json",
    ]);
    serde_json::from_str(&stdout).expect("json output should parse")
}

fn diagnostic_rule_ids(json: &serde_json::Value, section: &str) -> BTreeSet<String> {
    json[section]
        .as_array()
        .unwrap_or_else(|| panic!("{section} should be an array"))
        .iter()
        .map(|diagnostic| {
            diagnostic["rule_id"]
                .as_str()
                .expect("rule_id should be a string")
                .to_owned()
        })
        .collect()
}

fn assert_contains_all_rules(observed: &BTreeSet<String>, expected: &[&str]) {
    for rule_id in expected {
        assert!(
            observed.contains(*rule_id),
            "{rule_id} should be present in {observed:?}"
        );
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

    assert_eq!(
        finding["route_id"].as_str(),
        Some("route:DjangoRestFramework:GET:/invoices/{pk}:0")
    );
    let source_ids = finding["source_ids"]
        .as_array()
        .expect("source_ids should be an array")
        .iter()
        .map(|value| value.as_str().expect("source id should be a string"))
        .collect::<Vec<_>>();
    assert!(source_ids.contains(&"source:app/views.py:route_param"));
    let observed = finding["observed_evidence"]
        .as_array()
        .expect("observed evidence should be an array")
        .iter()
        .map(|value| value.as_str().expect("evidence label should be a string"))
        .collect::<Vec<_>>();
    assert!(observed.contains(&"authentication:IsAuthenticated"));
    assert_eq!(
        finding["call_path"][0]["function"].as_str(),
        Some("InvoiceViewSet.get_object")
    );
}

#[test]
fn django_drf_safe_is_clean() {
    let path = fixture_path("fixtures/django_drf/safe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("Findings: 0"));
}

#[test]
fn nextjs_prisma_authjs_unsafe_emits_route_sources_and_authjs_evidence() {
    let path = fixture_path("fixtures/nextjs_prisma_authjs/unsafe");
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

    assert_eq!(
        finding["route_id"].as_str(),
        Some("route:NextJs:PATCH:/invoices/:invoiceId:0")
    );
    let source_ids = finding["source_ids"]
        .as_array()
        .expect("source_ids should be an array")
        .iter()
        .map(|value| value.as_str().expect("source id should be a string"))
        .collect::<Vec<_>>();
    assert!(source_ids.contains(&"source:app/api/invoices/[invoiceId]/route.ts:route_param"));
    assert!(source_ids.contains(&"source:app/api/invoices/[invoiceId]/route.ts:body"));
    let observed = finding["observed_evidence"]
        .as_array()
        .expect("observed evidence should be an array")
        .iter()
        .map(|value| value.as_str().expect("evidence label should be a string"))
        .collect::<Vec<_>>();
    assert!(observed.contains(&"authentication:auth"));
    assert_eq!(
        finding["call_path"][0]["file"].as_str(),
        Some("app/api/invoices/[invoiceId]/route.ts")
    );
}

#[test]
fn nextjs_prisma_authjs_safe_is_clean() {
    let path = fixture_path("fixtures/nextjs_prisma_authjs/safe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    assert!(stdout.contains("Findings: 0"));
}

#[test]
fn supported_framework_data_layer_fixtures_have_safe_and_unsafe_coverage() {
    for (family, framework, sink) in [
        ("express_prisma", "Express", "prisma"),
        ("fastapi_sqlalchemy", "FastApi", "sqlalchemy"),
        ("django_drf", "DjangoRestFramework", "django_orm"),
        ("nextjs_prisma_authjs", "NextJs", "prisma"),
    ] {
        let unsafe_json = scan_json(&format!("fixtures/{family}/unsafe"));
        let unsafe_findings = unsafe_json["findings"]
            .as_array()
            .expect("unsafe findings should be an array");
        assert!(
            !unsafe_findings.is_empty(),
            "{family} unsafe fixture should emit findings"
        );
        assert!(
            unsafe_findings.iter().any(|finding| finding["route_id"]
                .as_str()
                .is_some_and(|route_id| route_id.contains(framework))),
            "{family} should exercise {framework} route discovery"
        );
        assert!(
            unsafe_findings.iter().any(|finding| finding["sink_id"]
                .as_str()
                .is_some_and(|sink_id| sink_id.contains(sink))),
            "{family} should exercise {sink} sink extraction"
        );

        let safe_json = scan_json(&format!("fixtures/{family}/safe"));
        assert!(
            safe_json["findings"]
                .as_array()
                .expect("safe findings should be an array")
                .is_empty(),
            "{family} safe fixture should not emit findings"
        );
    }
}

#[test]
fn v1_rule_matrix_covers_every_finding_and_review_hint() {
    let express_json = scan_json("fixtures/express_prisma/unsafe");
    let matrix_json = scan_json("fixtures/v1_rule_matrix/unsafe");
    let mut finding_ids = diagnostic_rule_ids(&express_json, "findings");
    finding_ids.extend(diagnostic_rule_ids(&matrix_json, "findings"));
    assert_contains_all_rules(
        &finding_ids,
        &[
            "INV001", "INV002", "INV003", "INV004", "INV005", "INV006", "INV007", "INV008",
        ],
    );

    let hint_ids = diagnostic_rule_ids(&matrix_json, "review_hints");
    assert_contains_all_rules(
        &hint_ids,
        &[
            "HINT001", "HINT002", "HINT003", "HINT004", "HINT005", "HINT006",
        ],
    );

    for section in ["findings", "review_hints"] {
        for diagnostic in matrix_json[section]
            .as_array()
            .expect("diagnostics should be arrays")
        {
            assert!(diagnostic["fingerprint"].is_string());
            assert!(diagnostic["route_id"].is_string());
            assert!(diagnostic["sink_id"].is_string());
            assert!(diagnostic["primary_span"]["file_id"].is_string());
        }
    }
}

#[test]
fn v1_rule_matrix_safe_fixture_is_clean() {
    let json = scan_json("fixtures/v1_rule_matrix/safe");
    assert!(json["findings"]
        .as_array()
        .expect("findings should be an array")
        .is_empty());
    assert!(json["review_hints"]
        .as_array()
        .expect("review hints should be an array")
        .is_empty());
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
    assert_eq!(finding["severity"].as_str(), Some("high"));
    assert_eq!(finding["confidence"].as_str(), Some("high"));
    assert!(finding["missing_invariant"]
        .as_str()
        .expect("missing invariant should be present")
        .contains("scope"));
    assert!(finding["expected_evidence"]
        .as_array()
        .expect("expected evidence should be an array")
        .iter()
        .any(|value| value == "tenant_scope or object_scope"));
    assert!(finding["suggested_fix"]
        .as_str()
        .expect("suggested fix should be present")
        .contains("scope"));
    assert!(json["review_hints"]
        .as_array()
        .expect("review hints should be an array")
        .iter()
        .all(|hint| hint["confidence"] == "medium"));
    assert!(!finding["call_path"]
        .as_array()
        .expect("call path should be an array")
        .is_empty());
    assert!(json["findings"].is_array());
    assert!(json["review_hints"].is_array());
}

#[test]
fn text_output_shows_call_path_frames() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&["scan", path.to_str().expect("utf-8 fixture path")]);
    let normalized = stdout.replace('\\', "/");
    assert!(stdout.contains("[HIGH] INV001"));
    assert!(stdout.contains("Route:"));
    assert!(stdout.contains("Code path:"));
    assert!(stdout.contains("Source:"));
    assert!(stdout.contains("Sink:"));
    assert!(stdout.contains("Missing invariant:"));
    assert!(stdout.contains("Observed evidence:"));
    assert!(stdout.contains("Expected evidence:"));
    assert!(stdout.contains("Suggested fix:"));
    assert!(normalized.contains("src/routes/invoices.ts:10 inline_handler()"));
    assert!(normalized.contains("src/services/invoices.ts:"));
    assert!(normalized.contains("updateInvoice()"));
}

#[test]
fn sarif_output_includes_rule_metadata_locations_fingerprints_and_codeflows() {
    let path = fixture_path("fixtures/express_prisma/unsafe");
    let stdout = run_rulepath(&[
        "scan",
        path.to_str().expect("utf-8 fixture path"),
        "--format",
        "sarif",
    ]);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("sarif should parse");
    assert_eq!(sarif["version"].as_str(), Some("2.1.0"));
    let run = &sarif["runs"][0];
    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules should be an array");
    assert!(rules
        .iter()
        .any(|rule| rule["id"] == "INV001" && rule["properties"]["kind"] == "finding"));
    let result = run["results"]
        .as_array()
        .expect("results should be an array")
        .iter()
        .find(|result| result["ruleId"] == "INV001")
        .expect("INV001 result should be present");

    assert_eq!(result["level"].as_str(), Some("error"));
    assert!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("location uri should be present")
            .contains("src/services/invoices.ts")
    );
    assert!(result["partialFingerprints"]["rulepathFingerprint"].is_string());
    assert_eq!(result["properties"]["kind"].as_str(), Some("finding"));
    assert!(result["properties"]["sinkId"].is_string());
    assert!(!result["codeFlows"][0]["threadFlows"][0]["locations"]
        .as_array()
        .expect("code flow locations should be an array")
        .is_empty());
}

#[test]
fn github_actions_annotations_emit_findings_only_to_stderr() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("gha-annotations");
    copy_dir_all(&source, &dir);
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nci:\n  fail: false\n",
    )
    .expect("test config should be written");

    let output = command_output_with_env(
        Some(&dir),
        &["scan", ".", "--ci", "--format", "json"],
        &[("GITHUB_ACTIONS", "true")],
    );

    assert!(output.status.success());
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("json stdout should remain parseable");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(stderr.contains("::error file=src/services/invoices.ts,line="));
    assert!(stderr.contains("INV001"));
    assert!(!stderr.contains("HINT"));
}

#[test]
fn explain_covers_v1_rule_and_hint_catalog() {
    for rule_id in [
        "INV001", "INV002", "INV003", "INV004", "INV005", "INV006", "INV007", "INV008", "HINT001",
        "HINT002", "HINT003", "HINT004", "HINT005", "HINT006",
    ] {
        let stdout = run_rulepath(&["explain", rule_id]);
        assert!(stdout.contains(rule_id));
        assert!(stdout.contains("Detect") || stdout.contains("Identify"));
        assert!(stdout.contains("Safe patterns:"));
        assert!(stdout.contains("Config keys:"));
    }
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
    assert!(inferred.contains("use_inferred_file_for_scan: false"));
    assert!(inferred.contains("Invoice"));

    let scan = run_rulepath_in(&dir, &["scan", ".", "--format", "json"]);
    assert!(scan.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("json output should parse");
    assert!(!json["findings"]
        .as_array()
        .expect("findings should be an array")
        .is_empty());
}

#[test]
fn infer_express_fixture_writes_deterministic_fact_based_draft() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("infer-express-quality");
    copy_dir_all(&source, &dir);

    let first = run_rulepath_in(&dir, &["infer", "."]);
    assert!(
        first.status.success(),
        "infer stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_text = fs::read_to_string(dir.join(".rulepath.inferred.yml"))
        .expect("inferred config should be readable");
    let second = run_rulepath_in(&dir, &["infer", ".", "--force"]);
    assert!(
        second.status.success(),
        "infer --force stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_text = fs::read_to_string(dir.join(".rulepath.inferred.yml"))
        .expect("inferred config should be readable");

    assert_eq!(first_text, second_text);
    assert!(first_text.contains("typescript:\n    - express"));
    assert!(first_text.contains("typescript:\n    - prisma"));
    assert!(first_text
        .contains("authentication_guards:\n    python: []\n    typescript:\n      - requireAuth"));
    assert!(first_text.contains("  Invoice:"));
    assert!(first_text.contains("clientId"));
    assert!(first_text.contains("inferred_scoped_resource_access"));
    assert!(first_text.contains("inferred_no_client_controlled_server_fields"));

    let validate = run_rulepath_in(&dir, &["config", "validate", ".rulepath.inferred.yml"]);
    assert!(
        validate.status.success(),
        "inferred draft should be strict-config compatible: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
}

#[test]
fn infer_fastapi_fixture_includes_sqlalchemy_and_helpers() {
    let source = fixture_path("fixtures/fastapi_sqlalchemy/unsafe");
    let dir = unique_temp_dir("infer-fastapi-quality");
    copy_dir_all(&source, &dir);

    let output = run_rulepath_in(&dir, &["infer", "."]);
    assert!(
        output.status.success(),
        "infer stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inferred = fs::read_to_string(dir.join(".rulepath.inferred.yml"))
        .expect("inferred config should be readable");

    assert!(inferred.contains("python:\n    - fastapi"));
    assert!(inferred.contains("python:\n    - sqlalchemy"));
    assert!(inferred.contains("authentication_guards:\n    python:\n      - get_current_user"));
    assert!(inferred.contains("  Invoice:"));
    assert!(inferred.contains("inferred_state_transition_review"));
}

#[test]
fn infer_rejects_generated_file_outside_project() {
    let dir = unique_temp_dir("infer-escape");
    fs::create_dir_all(&dir).expect("temp dir should be created");
    let escaped_name = format!("rulepath-infer-escape-{}.yml", std::process::id());
    fs::write(
        dir.join(".rulepath.yml"),
        format!("version: 1\ninference:\n  generated_file: ../{escaped_name}\n"),
    )
    .expect("test config should be written");

    let output = run_rulepath_in(&dir, &["infer", "."]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inference.generated_file"));
    assert!(!dir
        .parent()
        .expect("temp dir should have a parent")
        .join(escaped_name)
        .exists());
}

#[test]
fn infer_rejects_absolute_generated_file() {
    let dir = unique_temp_dir("infer-absolute");
    fs::create_dir_all(&dir).expect("temp dir should be created");
    let absolute = dir.join("outside.yml");
    let absolute = absolute.to_string_lossy();
    fs::write(
        dir.join(".rulepath.yml"),
        format!("version: 1\ninference:\n  generated_file: '{absolute}'\n"),
    )
    .expect("test config should be written");

    let output = run_rulepath_in(&dir, &["infer", "."]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("inference.generated_file"));
}

#[test]
fn baseline_rejects_file_outside_project() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("baseline-escape");
    copy_dir_all(&source, &dir);
    let escaped_name = format!("rulepath-baseline-escape-{}.json", std::process::id());
    fs::write(
        dir.join(".rulepath.yml"),
        format!("version: 1\nci:\n  baseline_file: ../{escaped_name}\n"),
    )
    .expect("test config should be written");

    let output = run_rulepath_in(&dir, &["baseline", "create", "."]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ci.baseline_file"));
    assert!(!dir
        .parent()
        .expect("temp dir should have a parent")
        .join(escaped_name)
        .exists());
}

#[test]
fn ci_rejects_baseline_file_outside_project() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("ci-baseline-escape");
    copy_dir_all(&source, &dir);
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nci:\n  fail: true\n  baseline_file: ../baseline.json\n",
    )
    .expect("test config should be written");

    let output = run_rulepath_in(&dir, &["scan", ".", "--ci"]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ci.baseline_file"));
}

#[test]
fn nested_config_paths_inside_project_are_allowed() {
    let dir = unique_temp_dir("nested-config-paths");
    fs::create_dir_all(&dir).expect("temp dir should be created");
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\ninference:\n  generated_file: .rulepath/generated.yml\nci:\n  baseline_file: .rulepath/baseline.json\n",
    )
    .expect("test config should be written");

    let infer = run_rulepath_in(&dir, &["infer", "."]);
    assert!(
        infer.status.success(),
        "infer stderr: {}",
        String::from_utf8_lossy(&infer.stderr)
    );
    assert!(dir.join(".rulepath/generated.yml").exists());

    let baseline = run_rulepath_in(&dir, &["baseline", "create", "."]);
    assert!(
        baseline.status.success(),
        "baseline stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    assert!(dir.join(".rulepath/baseline.json").exists());
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
fn baseline_fingerprint_survives_unrelated_sink_line_movement() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("stable-fingerprint-line-move");
    copy_dir_all(&source, &dir);

    let before_stdout = run_rulepath_in(&dir, &["scan", ".", "--format", "json"]);
    assert!(before_stdout.status.success());
    let before_json: serde_json::Value =
        serde_json::from_slice(&before_stdout.stdout).expect("json output should parse");
    let before = first_finding_fingerprint(&before_json, "INV001");

    let service_path = dir.join("src/services/invoices.ts");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "export async function updateInvoice",
            "\n\n\nexport async function updateInvoice",
        ),
    )
    .expect("service fixture should be updated");

    let after_stdout = run_rulepath_in(&dir, &["scan", ".", "--format", "json"]);
    assert!(after_stdout.status.success());
    let after_json: serde_json::Value =
        serde_json::from_slice(&after_stdout.stdout).expect("json output should parse");
    let after = first_finding_fingerprint(&after_json, "INV001");

    assert_eq!(before, after);
}

#[test]
fn ci_new_findings_only_uses_stable_fingerprint_after_line_movement() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("stable-baseline-line-move");
    copy_dir_all(&source, &dir);
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nprofile:\n  name: internal_web_app\nci:\n  fail: true\n",
    )
    .expect("test config should be written");

    let baseline = run_rulepath_in(&dir, &["baseline", "create", "."]);
    assert!(
        baseline.status.success(),
        "baseline stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let service_path = dir.join("src/services/invoices.ts");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "export async function updateInvoice",
            "\n\n\nexport async function updateInvoice",
        ),
    )
    .expect("service fixture should be updated");

    let ci = run_rulepath_in(&dir, &["scan", ".", "--ci"]);

    assert!(
        ci.status.success(),
        "stable fingerprint should keep baseline effective after line movement: {}",
        String::from_utf8_lossy(&ci.stderr)
    );
}

#[test]
fn baseline_create_writes_deterministic_sorted_output() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("deterministic-baseline");
    copy_dir_all(&source, &dir);

    let first = run_rulepath_in(&dir, &["baseline", "create", "."]);
    assert!(first.status.success());
    let first_text = fs::read_to_string(dir.join(".rulepath.baseline.json"))
        .expect("baseline should be readable");
    let second = run_rulepath_in(&dir, &["baseline", "create", ".", "--force"]);
    assert!(second.status.success());
    let second_text = fs::read_to_string(dir.join(".rulepath.baseline.json"))
        .expect("baseline should be readable");
    let baseline: serde_json::Value =
        serde_json::from_str(&first_text).expect("baseline should parse");
    let fingerprints = baseline["findings"]
        .as_array()
        .expect("findings should be an array")
        .iter()
        .map(|entry| {
            (
                entry["rule_id"].as_str().unwrap_or_default().to_owned(),
                entry["fingerprint"].as_str().unwrap_or_default().to_owned(),
                entry["title"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    let mut sorted = fingerprints.clone();
    sorted.sort();

    assert_eq!(first_text, second_text);
    assert_eq!(fingerprints, sorted);
}

#[test]
fn invalid_baseline_json_fails_with_clear_error() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("invalid-baseline-json");
    copy_dir_all(&source, &dir);
    fs::write(dir.join(".rulepath.yml"), "version: 1\nci:\n  fail: true\n")
        .expect("test config should be written");
    fs::write(dir.join(".rulepath.baseline.json"), "{not valid json")
        .expect("invalid baseline should be written");

    let output = run_rulepath_in(&dir, &["scan", ".", "--ci"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to parse baseline"));
    assert!(stderr.contains(".rulepath.baseline.json"));
}

#[test]
fn invalid_baseline_shape_fails_with_clear_error() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("invalid-baseline-shape");
    copy_dir_all(&source, &dir);
    fs::write(dir.join(".rulepath.yml"), "version: 1\nci:\n  fail: true\n")
        .expect("test config should be written");
    fs::write(
        dir.join(".rulepath.baseline.json"),
        r#"{"version":2,"findings":[],"review_hints":[]}"#,
    )
    .expect("invalid baseline should be written");

    let output = run_rulepath_in(&dir, &["scan", ".", "--ci"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid baseline"));
    assert!(stderr.contains("unsupported version 2"));
}

#[test]
fn ci_fail_false_remains_advisory_with_findings() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("ci-advisory");
    copy_dir_all(&source, &dir);
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nci:\n  fail: false\n",
    )
    .expect("test config should be written");

    let output = run_rulepath_in(&dir, &["scan", ".", "--ci"]);

    assert!(
        output.status.success(),
        "ci.fail false should stay advisory"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("INV001"));
}

#[test]
fn ci_review_hints_do_not_fail_when_excluded() {
    let dir = unique_temp_dir("ci-review-hints");
    fs::create_dir_all(dir.join("src")).expect("fixture dirs should be created");
    fs::write(
        dir.join(".rulepath.yml"),
        "version: 1\nci:\n  fail: true\n  fail_on:\n    include_review_hints: false\n",
    )
    .expect("test config should be written");
    fs::write(
        dir.join("src/export.ts"),
        "import express from 'express';\nconst router = express.Router();\nrouter.get('/export', (req, res) => {\n  return res.type('text/csv').send('id,total');\n});\n",
    )
    .expect("test route should be written");

    let output = run_rulepath_in(&dir, &["scan", ".", "--ci", "--format", "json"]);

    assert!(
        output.status.success(),
        "review hints should not fail CI by default"
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("json output should parse");
    assert!(json["findings"]
        .as_array()
        .expect("findings should be an array")
        .is_empty());
    assert!(!json["review_hints"]
        .as_array()
        .expect("review hints should be an array")
        .is_empty());
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
fn typescript_string_literal_suppression_marker_does_not_hide_finding() {
    let source = fixture_path("fixtures/express_prisma/unsafe");
    let dir = unique_temp_dir("ts-string-suppression");
    copy_dir_all(&source, &dir);
    let service_path = dir.join("src/services/invoices.ts");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "return prisma.invoice.update",
            "const marker = \"rulepath-disable-next-line INV001 -- ignored string literal suppression\";\n  return prisma.invoice.update",
        ),
    )
    .expect("service fixture should be updated");

    let output = run_rulepath_in(&dir, &["scan", "."]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("INV001"));
}

#[test]
fn python_string_literal_suppression_marker_does_not_hide_finding() {
    let source = fixture_path("fixtures/fastapi_sqlalchemy/unsafe");
    let dir = unique_temp_dir("py-string-suppression");
    copy_dir_all(&source, &dir);
    let service_path = dir.join("app/invoice_service.py");
    let service = fs::read_to_string(&service_path).expect("service fixture should be readable");
    fs::write(
        &service_path,
        service.replace(
            "invoice = session.get(Invoice, invoice_id)",
            "marker = \"rulepath-disable-next-line INV001 -- ignored string literal suppression\"\n    invoice = session.get(Invoice, invoice_id)",
        ),
    )
    .expect("service fixture should be updated");

    let output = run_rulepath_in(&dir, &["scan", "."]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf-8");
    assert!(stdout.contains("INV001"));
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
