//! Offline summaries of CSV inventories produced by `scan`.

use std::{cmp::Ordering, collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use csv::{Reader, StringRecord};
use semver::Version;
use serde_json::{Map, Value, json};

use crate::cli::{ReportGroupBy, ReportSort};

const REQUIRED_COLUMNS: &[&str] = &[
    "github_full_name",
    "head_committed_at",
    "msrv_effective",
    "os_observed_targets_json",
    "stale",
];

pub fn run_report(
    input: &Path,
    sort: ReportSort,
    group_by: Option<ReportGroupBy>,
    json_output: bool,
) -> Result<()> {
    let mut reader = Reader::from_path(input)
        .with_context(|| format!("opening report input {}", input.display()))?;
    let headers = reader.headers().context("reading CSV headers")?.clone();
    let columns = columns(&headers)?;
    let rows = reader
        .records()
        .collect::<csv::Result<Vec<_>>>()
        .context("reading report CSV rows")?;

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
        write_json(&headers, &groups, group_by);
    } else {
        write_markdown(&groups, &columns, group_by);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Columns {
    repository: usize,
    commit: usize,
    msrv: usize,
    os: usize,
    stale: usize,
}

fn columns(headers: &StringRecord) -> Result<Columns> {
    let index = |name: &str| {
        headers
            .iter()
            .position(|header| header == name)
            .with_context(|| format!("CSV is missing required column `{name}`"))
    };
    for name in REQUIRED_COLUMNS {
        index(name)?;
    }
    Ok(Columns {
        repository: index("github_full_name")?,
        commit: index("head_committed_at")?,
        msrv: index("msrv_effective")?,
        os: index("os_observed_targets_json")?,
        stale: index("stale")?,
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
        ReportGroupBy::Msrv => value(row, columns.msrv).to_owned(),
        ReportGroupBy::Os => value(row, columns.os).to_owned(),
        ReportGroupBy::Stale => value(row, columns.stale).to_owned(),
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
) {
    if group_by.is_none() {
        let rows = groups.values().flatten().map(|row| json_row(headers, row));
        println!(
            "{}",
            serde_json::to_string_pretty(&rows.collect::<Vec<_>>())
                .unwrap_or_else(|_| "[]".to_owned())
        );
        return;
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
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "[]".to_owned())
    );
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
    if let Some(group_by) = group_by {
        for (key, rows) in groups {
            println!("### {}\n", markdown_cell(group_label(group_by, key)));
            write_markdown_table(rows, columns);
            println!();
        }
    } else {
        let rows = groups.values().flatten().cloned().collect::<Vec<_>>();
        write_markdown_table(&rows, columns);
    }
}

fn write_markdown_table(rows: &[StringRecord], columns: &Columns) {
    println!("| Repository | Last Commit | MSRV | OS | Stale |");
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
            markdown_cell(value(row, columns.msrv)),
            markdown_cell(value(row, columns.os)),
            markdown_cell(value(row, columns.stale)),
        );
    }
}

fn group_label(group: ReportGroupBy, key: &str) -> &str {
    if key.is_empty() {
        return "unknown";
    }
    match group {
        ReportGroupBy::Msrv | ReportGroupBy::Os | ReportGroupBy::Stale => key,
    }
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
            "github_full_name",
            "head_committed_at",
            "msrv_effective",
            "os_observed_targets_json",
            "stale",
        ]))
        .unwrap()
    }

    #[test]
    fn sorts_valid_msrv_before_unknown_values() {
        assert_eq!(semver_cmp("1.70.0", "unknown"), Ordering::Less);
        assert_eq!(semver_cmp("unknown", "not_declared"), Ordering::Greater);
    }

    #[test]
    fn groups_rows_by_selected_column() {
        let columns = test_columns();
        let row = StringRecord::from(vec![
            "acme/widget",
            "2026-08-13T00:00:00Z",
            "1.70.0",
            "[\"windows\"]",
            "false",
        ]);
        assert_eq!(group_value(ReportGroupBy::Msrv, &row, &columns), "1.70.0");
        assert_eq!(
            group_value(ReportGroupBy::Os, &row, &columns),
            "[\"windows\"]"
        );
        assert_eq!(group_value(ReportGroupBy::Stale, &row, &columns), "false");
    }

    #[test]
    fn missing_required_column_is_an_error() {
        let error = columns(&StringRecord::from(vec!["github_full_name"]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("head_committed_at"));
    }
}
