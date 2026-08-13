//! Offline summaries of CSV inventories produced by `scan`.

use std::{cmp::Ordering, collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use csv::{Reader, StringRecord};
use semver::Version;
use serde_json::{Map, Value, json};

use crate::{
    cli::{ReportGroupBy, ReportSort},
    inventory::csv_schema::{
        CURRENT_DIRECT_STATUS, GITHUB_FULL_NAME, HEAD_COMMITTED_AT, MSRV_EFFECTIVE, MSRV_SOURCE,
        OS_HAS_UNCONDITIONAL_DECLARATION, OS_OBSERVED_TARGETS_JSON, STALE,
    },
};

pub fn run_report(
    input: &Path,
    sort: ReportSort,
    group_by: Option<ReportGroupBy>,
    json_output: bool,
) -> Result<()> {
    let ReportInput {
        headers,
        columns,
        rows,
    } = read_report_input(input)?;

    let mut groups = BTreeMap::<String, Vec<StringRecord>>::new();
    for row in rows {
        let key = group_by
            .map(|group| group_value(group, &row, &columns))
            .unwrap_or_default();
        groups.entry(key).or_default().push(row);
    }
    for rows in groups.values_mut() {
        rows.sort_by(|left, right| compare_rows(left, right, &columns, sort));
    }

    if json_output {
        write_json(&headers, &groups, group_by)?;
    } else {
        write_markdown(&groups, &columns, group_by);
    }
    Ok(())
}

struct ReportInput {
    headers: StringRecord,
    columns: Columns,
    rows: Vec<StringRecord>,
}

fn read_report_input(input: &Path) -> Result<ReportInput> {
    let mut reader = Reader::from_path(input)
        .with_context(|| format!("opening report input {}", input.display()))?;
    let headers = reader.headers().context("reading CSV headers")?.clone();
    let columns = columns(&headers)?;
    let rows = reader
        .records()
        .collect::<csv::Result<Vec<_>>>()
        .context("reading report CSV rows")?;
    Ok(ReportInput {
        headers,
        columns,
        rows,
    })
}

#[cfg(test)]
pub(crate) fn validate_report_input(input: &Path) -> Result<()> {
    read_report_input(input).map(drop)
}

#[derive(Clone, Copy, Debug)]
struct Columns {
    repository: usize,
    commit: usize,
    msrv: usize,
    msrv_source: usize,
    os: usize,
    os_unconditional: usize,
    current_direct: usize,
    stale: usize,
}

fn columns(headers: &StringRecord) -> Result<Columns> {
    let index = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .with_context(|| format!("CSV is missing required column `{name}`"))
    };
    Ok(Columns {
        repository: index(GITHUB_FULL_NAME)?,
        commit: index(HEAD_COMMITTED_AT)?,
        msrv: index(MSRV_EFFECTIVE)?,
        msrv_source: index(MSRV_SOURCE)?,
        os: index(OS_OBSERVED_TARGETS_JSON)?,
        os_unconditional: index(OS_HAS_UNCONDITIONAL_DECLARATION)?,
        current_direct: index(CURRENT_DIRECT_STATUS)?,
        stale: index(STALE)?,
    })
}

fn compare_rows(
    left: &StringRecord,
    right: &StringRecord,
    columns: &Columns,
    sort: ReportSort,
) -> Ordering {
    match sort {
        ReportSort::LastCommitDesc => value(right, columns.commit).cmp(value(left, columns.commit)),
        ReportSort::LastCommitAsc => value(left, columns.commit).cmp(value(right, columns.commit)),
        ReportSort::MsrvAsc => semver_cmp(value(left, columns.msrv), value(right, columns.msrv)),
        ReportSort::MsrvDesc => semver_cmp(value(right, columns.msrv), value(left, columns.msrv)),
    }
    .then_with(|| value(left, columns.repository).cmp(value(right, columns.repository)))
    .then_with(|| value(left, columns.commit).cmp(value(right, columns.commit)))
}

fn group_value(group: ReportGroupBy, row: &StringRecord, columns: &Columns) -> String {
    match group {
        ReportGroupBy::Msrv => msrv_display(row, columns),
        ReportGroupBy::Os => dependency_targeting(row, columns),
        ReportGroupBy::Stale => value(row, columns.stale).to_owned(),
    }
}

fn msrv_display(row: &StringRecord, columns: &Columns) -> String {
    let msrv = value(row, columns.msrv);
    if msrv.is_empty() || msrv == "not_declared" {
        return "not declared".to_owned();
    }

    match value(row, columns.msrv_source) {
        "package_field" => format!("{msrv} (package field)"),
        "workspace_inherited" => format!("{msrv} (workspace inherited)"),
        "not_declared" | "" => format!("{msrv} (source unknown)"),
        source => format!("{msrv} ({})", source.replace('_', " ")),
    }
}

fn dependency_targeting(row: &StringRecord, columns: &Columns) -> String {
    match value(row, columns.current_direct) {
        "absent" => return "no direct declaration".to_owned(),
        "present" => {}
        _ => return "unknown".to_owned(),
    }

    let Ok(mut targets) = serde_json::from_str::<Vec<String>>(value(row, columns.os)) else {
        return "unknown (invalid target data)".to_owned();
    };
    targets.sort();
    targets.dedup();
    let targets = targets.join(", ");

    match (value(row, columns.os_unconditional), targets.is_empty()) {
        ("true", true) => "unconditional".to_owned(),
        ("true", false) => format!("unconditional; also target_os: {targets}"),
        ("false", true) => "conditional (no target_os value observed)".to_owned(),
        ("false", false) => format!("target_os: {targets}"),
        (_, true) => "unknown".to_owned(),
        (_, false) => format!("target_os: {targets}; unconditional status unknown"),
    }
}

fn value(row: &StringRecord, column: usize) -> &str {
    row.get(column).unwrap_or("")
}

fn semver_cmp(left: &str, right: &str) -> Ordering {
    match (Version::parse(left), Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

fn write_json(
    headers: &StringRecord,
    groups: &BTreeMap<String, Vec<StringRecord>>,
    group_by: Option<ReportGroupBy>,
) -> Result<()> {
    if group_by.is_none() {
        let rows = groups.values().flatten().map(|row| json_row(headers, row));
        println!(
            "{}",
            serde_json::to_string_pretty(&rows.collect::<Vec<_>>())?
        );
        return Ok(());
    }

    let output = groups
        .iter()
        .map(|(key, rows)| {
            json!({
                "group": key,
                "rows": rows.iter().map(|row| json_row(headers, row)).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn json_row(headers: &StringRecord, row: &StringRecord) -> Value {
    let mut object = Map::new();
    for (header, value) in headers.iter().zip(row.iter()) {
        object.insert(header.to_owned(), Value::String(value.to_owned()));
    }
    Value::Object(object)
}

fn write_markdown(
    groups: &BTreeMap<String, Vec<StringRecord>>,
    columns: &Columns,
    group_by: Option<ReportGroupBy>,
) {
    if group_by.is_some() {
        for (key, rows) in groups {
            println!("### {}\n", markdown_cell(group_label(key)));
            write_markdown_table(rows, columns);
            println!();
        }
    } else {
        write_markdown_table(groups.get("").map(Vec::as_slice).unwrap_or(&[]), columns);
    }
}

fn write_markdown_table(rows: &[StringRecord], columns: &Columns) {
    println!("| Repository | Last Commit | MSRV | Dependency targeting | Stale |");
    println!("|---|---|---|---|---|");
    for row in rows {
        let commit = value(row, columns.commit);
        let commit = if commit.len() > 10 {
            &commit[..10]
        } else {
            commit
        };
        println!(
            "| `{}` | {} | {} | {} | {} |",
            markdown_cell(value(row, columns.repository)),
            markdown_cell(if commit.is_empty() { "-" } else { commit }),
            markdown_cell(&msrv_display(row, columns)),
            markdown_cell(&dependency_targeting(row, columns)),
            markdown_cell(value(row, columns.stale)),
        );
    }
}

fn group_label(key: &str) -> &str {
    if key.is_empty() {
        return "unknown";
    }
    key
}

fn markdown_cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_columns() -> Columns {
        columns(&StringRecord::from(vec![
            GITHUB_FULL_NAME,
            HEAD_COMMITTED_AT,
            MSRV_EFFECTIVE,
            MSRV_SOURCE,
            OS_OBSERVED_TARGETS_JSON,
            OS_HAS_UNCONDITIONAL_DECLARATION,
            CURRENT_DIRECT_STATUS,
            STALE,
        ]))
        .unwrap()
    }

    fn test_row(
        msrv: &str,
        msrv_source: &str,
        targets: &str,
        unconditional: &str,
        current_direct: &str,
    ) -> StringRecord {
        StringRecord::from(vec![
            "acme/widget",
            "2026-08-13T00:00:00Z",
            msrv,
            msrv_source,
            targets,
            unconditional,
            current_direct,
            "false",
        ])
    }

    #[test]
    fn sorts_valid_msrv_before_unknown_values() {
        assert_eq!(semver_cmp("1.70.0", "unknown"), Ordering::Less);
        assert_eq!(semver_cmp("unknown", "not_declared"), Ordering::Greater);
    }

    #[test]
    fn groups_rows_by_selected_column() {
        let columns = test_columns();
        let row = test_row(
            "1.70.0",
            "workspace_inherited",
            "[\"windows\"]",
            "false",
            "present",
        );
        assert_eq!(
            group_value(ReportGroupBy::Msrv, &row, &columns),
            "1.70.0 (workspace inherited)"
        );
        assert_eq!(
            group_value(ReportGroupBy::Os, &row, &columns),
            "target_os: windows"
        );
        assert_eq!(group_value(ReportGroupBy::Stale, &row, &columns), "false");
    }

    #[test]
    fn describes_unconditional_and_targeted_direct_declarations() {
        let columns = test_columns();
        let row = test_row(
            "not_declared",
            "not_declared",
            "[\"windows\",\"linux\",\"linux\"]",
            "true",
            "present",
        );

        assert_eq!(msrv_display(&row, &columns), "not declared");
        assert_eq!(
            dependency_targeting(&row, &columns),
            "unconditional; also target_os: linux, windows"
        );
    }

    #[test]
    fn distinguishes_absent_and_unclassified_targeting() {
        let columns = test_columns();
        let absent = test_row("", "", "[]", "false", "absent");
        let conditional = test_row("", "", "[]", "false", "present");

        assert_eq!(
            dependency_targeting(&absent, &columns),
            "no direct declaration"
        );
        assert_eq!(
            dependency_targeting(&conditional, &columns),
            "conditional (no target_os value observed)"
        );
    }

    #[test]
    fn missing_required_column_is_an_error() {
        let error = columns(&StringRecord::from(vec!["github_full_name"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("head_committed_at"));
    }
}
