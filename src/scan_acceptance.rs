use std::{collections::BTreeMap, time::Duration};

use semver::Version;
use serde_json::{Value, json};
use tempfile::tempdir;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

use crate::{
    cli::{ActivityFilter, DependencyKind, Discovery, OptionalFilter, RequirementFilter},
    crates_io::{CratesIoClient, sparse_index_path},
    github::GitHubClient,
    inventory::{ScanOptions, scan},
};

const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[tokio::test]
async fn mocked_scan_preserves_unclassified_presence_without_false_confirmation() {
    let server = MockServer::start().await;
    mount_crates_io(&server).await;

    let manifest = r#"[package]
name = "consumer-app"
version = "2.0.0"
edition = "2024"

[dependencies]
filesystem = { package = "fs2", version = "=0.4.3" }
"#;
    let dependent_lock = format!(
        r#"version = 3

[[package]]
name = "consumer-app"
version = "2.0.0"
dependencies = ["bridge"]

[[package]]
name = "bridge"
version = "1.0.0"
dependencies = ["fs2"]

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO_SOURCE}"
"#
    );
    let root_only_lock = format!(
        r#"version = 3

[[package]]
name = "fs2"
version = "0.4.3"
source = "{CRATES_IO_SOURCE}"
"#
    );
    mount_github(&server, manifest, &dependent_lock, &root_only_lock).await;

    let crates_io = CratesIoClient::with_configuration(
        Url::parse(&format!("{}/api/v1/", server.uri())).unwrap(),
        Url::parse(&format!("{}/index/", server.uri())).unwrap(),
        Duration::ZERO,
        100,
    )
    .unwrap();
    let github =
        GitHubClient::with_api_base(None, Url::parse(&format!("{}/", server.uri())).unwrap())
            .unwrap();
    let output_dir = tempdir().unwrap();
    let csv_path = output_dir.path().join("inventory.csv");
    let summary_path = output_dir.path().join("summary.json");

    let outcome = scan(
        &crates_io,
        &github,
        ScanOptions {
            query: "fs2".to_owned(),
            version: Version::parse("0.4.3").unwrap(),
            explicit_crate: None,
            accept_closest: false,
            requirement_filter: RequirementFilter::Accepts,
            discovery: Discovery::CratesIo,
            dependency_kinds: vec![DependencyKind::Normal],
            optional: OptionalFilter::Include,
            include_forks: false,
            exclude_archived: false,
            stale_after_days: 365,
            activity: ActivityFilter::All,
            committed_since: None,
            committed_before: None,
            max_candidates: None,
            max_repositories: None,
            github_search_limit: 10,
            max_file_bytes: 1024 * 1024,
            output: csv_path.clone(),
            summary_json: Some(summary_path.clone()),
            allow_partial: false,
            require_match: true,
            jobs: 1,
        },
    )
    .await
    .unwrap();

    assert!(!outcome.partial);
    assert!(!outcome.no_match);

    let rows = csv_rows(&csv_path);
    assert_eq!(rows.len(), 2);
    let dependent = row_for_path(&rows, "dependent/Cargo.lock");
    let root_only = row_for_path(&rows, "root-only/Cargo.lock");

    assert_eq!(dependent["lock_status"], "parsed");
    assert_eq!(dependent["exact_resolution_status"], "present");
    assert_eq!(dependent["recorded_relation"], "recorded_transitive");
    assert_eq!(dependent["shortest_dependency_depth"], "2");
    assert_eq!(dependent["exact_crates_io_occurrence_count"], "1");
    assert_eq!(dependent["current_direct_status"], "present");

    assert_eq!(root_only["lock_status"], "parsed");
    assert_eq!(root_only["exact_resolution_status"], "present");
    assert_eq!(
        root_only["recorded_relation"],
        "recorded_present_unclassified"
    );
    assert_eq!(root_only["shortest_dependency_depth"], "0");
    assert_eq!(root_only["exact_crates_io_occurrence_count"], "1");

    for row in &rows {
        assert_eq!(row["github_full_name"], "acme/consumer");
        assert_eq!(row["head_sha"], "head-sha");
        assert_eq!(row["tree_sha"], "tree-sha");
        assert_eq!(row["globally_exhaustive"], "false");
        assert!(row["candidate_scope"].contains("current non-yanked crates.io"));
        assert_eq!(row["any_exact_pin"], "true");
        assert!(row["published_requirements_json"].contains("filesystem"));

        let policy: Value = serde_json::from_str(&row["scan_policy_json"]).unwrap();
        assert_eq!(policy["discovery"], "crates-io");
        assert_eq!(policy["requirement_filter"], "accepts");
    }

    let summary: Value = serde_json::from_slice(&std::fs::read(summary_path).unwrap()).unwrap();
    assert_eq!(summary["globally_exhaustive"], false);
    assert!(summary["candidate_scope"].as_str().is_some());
    assert!(summary["policy"].is_object());
    assert_eq!(summary["candidate_release_records"], 2);
    assert_eq!(summary["candidate_crates"], 2);
    assert_eq!(summary["candidate_repositories"], 2);
    assert_eq!(summary["repositories_scanned"], 1);
    assert_eq!(summary["lockfiles_parsed"], 2);
    assert_eq!(summary["exact_occurrences"], 2);
    assert_eq!(summary["repositories_exact_confirmed"], 1);
    assert_eq!(summary["output_rows"], 2);

    server.verify().await;
}

async fn mount_crates_io(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/api/v1/crates/fs2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "crate": {
                "name": "fs2",
                "max_version": "0.4.3",
                "repository": "https://github.com/danburkert/fs2-rs",
                "homepage": null,
                "description": "mock filesystem extensions",
                "downloads": 10_000
            }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/crates/fs2/reverse_dependencies"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "dependencies": [
                {
                    "id": 7,
                    "version_id": 42,
                    "crate_id": "fs2",
                    "req": "^0.4.3",
                    "kind": "normal",
                    "optional": false,
                    "downloads": 900
                },
                {
                    "id": 8,
                    "version_id": 43,
                    "crate_id": "fs2",
                    "req": "=0.4.3",
                    "kind": "normal",
                    "optional": false,
                    "downloads": 800
                }
            ],
            "versions": [
                {
                    "id": 42,
                    "crate": "consumer",
                    "num": "2.0.0",
                    "yanked": false,
                    "repository": "https://github.com/acme/consumer"
                },
                {
                    "id": 43,
                    "crate": "legacy-consumer",
                    "num": "1.0.0",
                    "yanked": false,
                    "repository": "https://github.com/acme/legacy-consumer"
                }
            ],
            "meta": { "total": 2 }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/index/{}",
            sparse_index_path("consumer").unwrap()
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                json!({
                    "name": "consumer",
                    "vers": "2.0.0",
                    "deps": [{
                        "name": "filesystem",
                        "package": "fs2",
                        "req": "=0.4.3",
                        "kind": "normal",
                        "optional": false,
                        "target": null,
                        "registry": null
                    }]
                })
                .to_string(),
            ),
        )
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/index/{}",
            sparse_index_path("legacy-consumer").unwrap()
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                json!({
                    "name": "legacy-consumer",
                    "vers": "1.0.0",
                    "deps": [{
                        "name": "fs2",
                        "req": "=0.4.3",
                        "kind": "normal",
                        "optional": false,
                        "target": null,
                        "registry": null
                    }]
                })
                .to_string(),
            ),
        )
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_github(
    server: &MockServer,
    manifest: &str,
    dependent_lock: &str,
    root_only_lock: &str,
) {
    for repository_path in ["/repos/acme/consumer", "/repos/acme/legacy-consumer"] {
        Mock::given(method("GET"))
            .and(path(repository_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 99,
                "name": "consumer",
                "full_name": "acme/consumer",
                "html_url": "https://github.com/acme/consumer",
                "owner": {
                    "login": "acme",
                    "id": 11,
                    "html_url": "https://github.com/acme"
                },
                "default_branch": "main",
                "fork": false,
                "archived": false,
                "disabled": false,
                "private": false,
                "pushed_at": "2026-08-01T12:00:00Z"
            })))
            .expect(1)
            .mount(server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/repos/acme/consumer/commits/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sha": "head-sha",
            "html_url": "https://github.com/acme/consumer/commit/head-sha",
            "commit": {
                "author": { "date": "2026-08-01T12:00:00Z" },
                "committer": { "date": "2026-08-01T12:00:00Z" },
                "tree": { "sha": "tree-sha" }
            }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/acme/consumer/git/trees/tree-sha"))
        .and(query_param("recursive", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sha": "tree-sha",
            "truncated": false,
            "tree": [
                tree_entry("Cargo.toml", "manifest-sha", manifest.len()),
                tree_entry("dependent/Cargo.lock", "dependent-lock-sha", dependent_lock.len()),
                tree_entry("root-only/Cargo.lock", "root-only-lock-sha", root_only_lock.len())
            ]
        })))
        .expect(1)
        .mount(server)
        .await;

    for (sha, body) in [
        ("manifest-sha", manifest),
        ("dependent-lock-sha", dependent_lock),
        ("root-only-lock-sha", root_only_lock),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/repos/acme/consumer/git/blobs/{sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
            .expect(1)
            .mount(server)
            .await;
    }
}

fn tree_entry(path: &str, sha: &str, size: usize) -> Value {
    json!({
        "path": path,
        "mode": "100644",
        "type": "blob",
        "sha": sha,
        "size": size
    })
}

fn csv_rows(path: &std::path::Path) -> Vec<BTreeMap<String, String>> {
    let mut reader = csv::Reader::from_path(path).unwrap();
    let headers = reader.headers().unwrap().clone();
    reader
        .records()
        .map(|record| {
            headers
                .iter()
                .zip(record.unwrap().iter())
                .map(|(header, value)| (header.to_owned(), value.to_owned()))
                .collect()
        })
        .collect()
}

fn row_for_path<'a>(
    rows: &'a [BTreeMap<String, String>],
    path: &str,
) -> &'a BTreeMap<String, String> {
    rows.iter()
        .find(|row| row["cargo_lock_path"] == path)
        .unwrap_or_else(|| panic!("missing CSV row for {path}"))
}
