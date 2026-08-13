//! Stable CSV interface shared by inventory producers and offline reports.

use serde::Serialize;

pub const OBSERVED_AT_UTC: &str = "observed_at_utc";
pub const GITHUB_FULL_NAME: &str = "github_full_name";
pub const HEAD_COMMITTED_AT: &str = "head_committed_at";
pub const STALE: &str = "stale";
pub const CURRENT_DIRECT_STATUS: &str = "current_direct_status";
pub const MSRV_EFFECTIVE: &str = "msrv_effective";
pub const MSRV_SOURCE: &str = "msrv_source";
pub const OS_OBSERVED_TARGETS_JSON: &str = "os_observed_targets_json";
pub const OS_HAS_UNCONDITIONAL_DECLARATION: &str = "os_has_unconditional_declaration";
pub const CSV_SCHEMA_VERSION: u32 = 2;

/// One row in the stable inventory CSV interface.
///
/// Field order is part of the format. Additive schema changes belong at the end
/// and must update [`HEADERS`] and its contract tests in the same change.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CsvRow {
    pub observed_at_utc: String,
    pub input_query: String,
    pub target_crate: String,
    pub target_version: String,
    pub target_repository_url: String,
    pub globally_exhaustive: bool,
    pub candidate_scope: String,
    pub repository_scope: String,
    pub scan_policy_json: String,
    pub candidate_sources_json: String,
    pub dependent_crates_json: String,
    pub dependent_versions_json: String,
    pub published_requirements_json: String,
    pub dependency_kinds_json: String,
    pub dependency_targets_json: String,
    pub optional_declarations: String,
    pub published_direct_status: String,
    pub any_requirement_accepts: String,
    pub any_exact_pin: String,
    pub original_repository_urls_json: String,
    pub repository_url: String,
    pub github_repository_id: String,
    pub repository_visibility: String,
    pub github_full_name: String,
    pub default_branch: String,
    pub head_sha: String,
    pub tree_sha: String,
    pub head_committed_at: String,
    pub repo_pushed_at: String,
    pub archived: String,
    pub fork: String,
    pub disabled: String,
    pub stale: String,
    pub inventory_status: String,
    pub tree_truncated: String,
    pub repository_matched_cargo_file_count: usize,
    pub repository_matched_file_limit: usize,
    pub repository_matched_file_bytes_downloaded: u64,
    pub repository_matched_file_byte_budget: u64,
    pub cargo_lock_path: String,
    pub cargo_lock_blob_sha: String,
    pub lock_status: String,
    pub resolved_target_versions_json: String,
    pub resolved_target_sources_json: String,
    pub exact_resolution_status: String,
    pub exact_occurrence_count: usize,
    pub exact_crates_io_occurrence_count: usize,
    pub manifest_paths_json: String,
    pub current_direct_status: String,
    pub current_direct_requirements_json: String,
    pub msrv_effective: String,
    pub msrv_source: String,
    pub msrv_observations_json: String,
    pub os_observed_targets_json: String,
    pub os_has_unconditional_declaration: String,
    pub recorded_relation: String,
    pub shortest_dependency_depth: String,
    pub direct_relation_witness_json: String,
    pub transitive_relation_witness_json: String,
    pub evidence_strength: String,
    pub inclusion_reasons_json: String,
    pub scope_limitations_json: String,
    pub cache_status: String,
    pub reused_from_scan_id: String,
    pub evidence_completeness: String,
    pub error_code: String,
    pub error_message: String,
    pub csv_schema_version: u32,
    pub target_selector_kind: String,
    pub target_version_requirement: String,
    pub target_version_catalog_sha256: String,
    pub tree_inventory_complete: String,
    pub any_requirement_intersects: String,
    pub any_exact_pin_matches_selector: String,
    pub matching_resolution_status: String,
    pub matching_occurrence_count: usize,
    pub matching_crates_io_occurrence_count: usize,
    pub matching_resolved_versions_json: String,
    /// Per-source concrete range evidence. Exact scans use the aggregate
    /// selector-generic columns and leave this range-only cell empty.
    pub range_matching_resolutions_json: String,
    pub matching_recorded_relation: String,
    pub matching_direct_relation_witness_json: String,
    pub matching_transitive_relation_witness_json: String,
}

/// Inventory CSV V2 header order. V2 only appends fields to the V1 contract.
pub const HEADERS: &[&str] = &[
    OBSERVED_AT_UTC,
    "input_query",
    "target_crate",
    "target_version",
    "target_repository_url",
    "globally_exhaustive",
    "candidate_scope",
    "repository_scope",
    "scan_policy_json",
    "candidate_sources_json",
    "dependent_crates_json",
    "dependent_versions_json",
    "published_requirements_json",
    "dependency_kinds_json",
    "dependency_targets_json",
    "optional_declarations",
    "published_direct_status",
    "any_requirement_accepts",
    "any_exact_pin",
    "original_repository_urls_json",
    "repository_url",
    "github_repository_id",
    "repository_visibility",
    GITHUB_FULL_NAME,
    "default_branch",
    "head_sha",
    "tree_sha",
    HEAD_COMMITTED_AT,
    "repo_pushed_at",
    "archived",
    "fork",
    "disabled",
    STALE,
    "inventory_status",
    "tree_truncated",
    "repository_matched_cargo_file_count",
    "repository_matched_file_limit",
    "repository_matched_file_bytes_downloaded",
    "repository_matched_file_byte_budget",
    "cargo_lock_path",
    "cargo_lock_blob_sha",
    "lock_status",
    "resolved_target_versions_json",
    "resolved_target_sources_json",
    "exact_resolution_status",
    "exact_occurrence_count",
    "exact_crates_io_occurrence_count",
    "manifest_paths_json",
    CURRENT_DIRECT_STATUS,
    "current_direct_requirements_json",
    MSRV_EFFECTIVE,
    MSRV_SOURCE,
    "msrv_observations_json",
    OS_OBSERVED_TARGETS_JSON,
    OS_HAS_UNCONDITIONAL_DECLARATION,
    "recorded_relation",
    "shortest_dependency_depth",
    "direct_relation_witness_json",
    "transitive_relation_witness_json",
    "evidence_strength",
    "inclusion_reasons_json",
    "scope_limitations_json",
    "cache_status",
    "reused_from_scan_id",
    "evidence_completeness",
    "error_code",
    "error_message",
    "csv_schema_version",
    "target_selector_kind",
    "target_version_requirement",
    "target_version_catalog_sha256",
    "tree_inventory_complete",
    "any_requirement_intersects",
    "any_exact_pin_matches_selector",
    "matching_resolution_status",
    "matching_occurrence_count",
    "matching_crates_io_occurrence_count",
    "matching_resolved_versions_json",
    "range_matching_resolutions_json",
    "matching_recorded_relation",
    "matching_direct_relation_witness_json",
    "matching_transitive_relation_witness_json",
];

impl CsvRow {
    /// Retained for source compatibility; [`HEADERS`] is the canonical owner.
    pub const HEADERS: &'static [&'static str] = HEADERS;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_headers_match_serde_field_order() {
        let row = CsvRow {
            observed_at_utc: "first-column-sentinel".to_owned(),
            current_direct_status: "middle-column-sentinel".to_owned(),
            matching_transitive_relation_witness_json: "last-column-sentinel".to_owned(),
            ..CsvRow::default()
        };

        let mut writer = csv::Writer::from_writer(Vec::new());
        writer.serialize(&row).unwrap();
        let bytes = writer.into_inner().unwrap();
        let mut reader = csv::Reader::from_reader(bytes.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            HEADERS
        );

        let values = reader.records().next().unwrap().unwrap();
        assert_eq!(values.get(0), Some("first-column-sentinel"));
        assert_eq!(
            values.get(
                HEADERS
                    .iter()
                    .position(|header| *header == CURRENT_DIRECT_STATUS)
                    .unwrap()
            ),
            Some("middle-column-sentinel")
        );
        assert_eq!(values.get(HEADERS.len() - 1), Some("last-column-sentinel"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.csv");
        crate::output::write_csv(&path, HEADERS, &[row]).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn v2_preserves_the_frozen_v1_header_prefix() {
        let v1 = include_str!("../../tests/fixtures/inventory_csv_v1_header.txt")
            .trim()
            .split(',')
            .collect::<Vec<_>>();
        assert_eq!(&HEADERS[..v1.len()], v1);
        assert!(HEADERS.len() > v1.len());
    }
}
