use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;

const UNREACHABLE_PROXY: &str = "http://127.0.0.1:1";

fn command_without_network() -> assert_cmd::Command {
    let mut command = cargo_bin_cmd!("crate-dependent-repos");
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(variable, UNREACHABLE_PROXY);
    }
    command.env_remove("NO_PROXY").env_remove("no_proxy");
    command
}

fn assert_output_paths_collide(output: &str, summary: &str) {
    let directory = tempfile::tempdir().unwrap();
    command_without_network()
        .current_dir(directory.path())
        .args([
            "scan",
            "fs2",
            "--version",
            "0.4.3",
            "--output",
            output,
            "--summary-json",
            summary,
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "--output and --summary-json must refer to different files",
        ));

    assert!(!directory.path().join("results.csv").exists());
}

#[test]
fn top_level_help_describes_non_exhaustive_inventory() {
    cargo_bin_cmd!("crate-dependent-repos")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("never represented as exhaustive"))
        .stdout(predicate::str::contains("resolve"))
        .stdout(predicate::str::contains("links"))
        .stdout(predicate::str::contains("scan"));
}

#[test]
fn clap_usage_errors_exit_with_code_two() {
    cargo_bin_cmd!("crate-dependent-repos")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn invalid_semver_is_rejected_before_network_access() {
    cargo_bin_cmd!("crate-dependent-repos")
        .args(["scan", "fs2", "--version", "not-a-version"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value 'not-a-version'"));
}

#[test]
fn bounded_integer_options_reject_zero() {
    cargo_bin_cmd!("crate-dependent-repos")
        .args(["--jobs", "0", "resolve", "fs2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("value must be between 1 and 64"));
}

#[test]
fn links_requires_an_exact_target_version() {
    cargo_bin_cmd!("crate-dependent-repos")
        .args(["links", "fs2"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--version <VERSION>"));
}

#[test]
fn credential_bearing_github_url_is_rejected_without_leaking_the_secret() {
    const SECRET: &str = "codex_fake_secret_53b927ac";
    let query = format!("https://review-user:{SECRET}@github.com/octocat/Hello-World");
    let assertion = command_without_network()
        .args(["resolve", &query])
        .assert()
        .code(1);
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);

    assert!(
        !stdout.contains(SECRET),
        "secret leaked to stdout: {stdout}"
    );
    assert!(
        !stderr.contains(SECRET),
        "secret leaked to stderr: {stderr}"
    );
    assert!(
        stderr
            .to_ascii_lowercase()
            .contains("github repository urls must not contain credentials"),
        "unexpected diagnostic: {stderr}"
    );
}

#[test]
fn identical_output_paths_are_rejected_before_network_access() {
    assert_output_paths_collide("results.csv", "results.csv");
}

#[test]
fn lexically_aliased_output_paths_are_rejected_before_network_access() {
    assert_output_paths_collide("results.csv", "./results.csv");
}
