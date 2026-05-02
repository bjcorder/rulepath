use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture_path(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn run_rulepath(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rulepath"))
        .args(args)
        .output()
        .expect("rulepath command should run");
    assert!(
        output.status.success(),
        "rulepath exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout should be utf-8")
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
