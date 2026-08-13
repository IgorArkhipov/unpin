use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as StdCommand,
};

use assert_cmd::Command;
use tempfile::TempDir;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates directory")
        .join("unpin-core")
        .join("tests")
        .join("fixtures")
}

#[test]
fn headless_tui_reports_empty_workflow_projection_without_edit_controls() {
    let temp = TempDir::new().expect("temporary TUI roots");
    let project = temp.path().join("project");
    let state = temp.path().join("state");
    fs::create_dir_all(&project).expect("project root");
    let git = StdCommand::new("git")
        .args(["init", "-q"])
        .current_dir(&project)
        .output()
        .expect("git init");
    assert!(git.status.success(), "git init failed: {:?}", git);

    let output = Command::cargo_bin("unpin")
        .expect("unpin binary")
        .args([
            "tui",
            "--headless",
            "--fixture-root",
            fixtures_root().to_str().expect("fixture path"),
            "--home-root",
            fixtures_root().to_str().expect("fixture path"),
            "--project-root",
            project.to_str().expect("project path"),
            "--app-state-root",
            state.to_str().expect("state path"),
        ])
        .output()
        .expect("headless TUI output");
    assert!(
        output.status.success(),
        "headless TUI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("headless TUI UTF-8");
    assert!(rendered.contains("Workflow session projection:"));
    assert!(rendered.contains("no workflow sessions"));
    assert!(!rendered.contains("workflow editor"));
    assert!(!rendered.contains("live transition"));
}
