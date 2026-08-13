use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result};
use serde::Serialize;

pub fn csv_safe(value: impl Into<String>) -> String {
    let value = value.into();
    if value.chars().next().is_some_and(|first| {
        matches!(
            first,
            '=' | '+' | '-' | '@' | '\t' | '\r' | '\n' | '＝' | '＋' | '－' | '＠'
        )
    }) {
        format!("'{value}")
    } else {
        value
    }
}

pub fn write_csv<T: Serialize>(path: &Path, headers: &[&str], rows: &[T]) -> Result<()> {
    write_output(path, |output| {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(output);
        writer.write_record(headers)?;
        for row in rows {
            writer.serialize(row)?;
        }
        writer.flush()?;
        Ok(())
    })
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_output(path, |mut output| {
        serde_json::to_writer_pretty(&mut output, value)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    })
}

fn write_output(path: &Path, write: impl FnOnce(&mut dyn Write) -> Result<()>) -> Result<()> {
    if path == Path::new("-") {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        return write(&mut lock).context("writing output to stdout");
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating output directory {}", parent.display()))?;
    }

    let temp_parent = parent.unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(temp_parent)
        .with_context(|| format!("creating temporary output beside {}", path.display()))?;
    write(temp.as_file_mut())
        .with_context(|| format!("writing temporary output for {}", path.display()))?;
    temp.as_file_mut()
        .sync_all()
        .with_context(|| format!("syncing temporary output for {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestRow<'a> {
        one: &'a str,
        two: &'a str,
    }

    #[test]
    fn protects_spreadsheet_formula_prefixes() {
        assert_eq!(csv_safe("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0");
        assert_eq!(csv_safe("+1"), "'+1");
        assert_eq!(csv_safe("\n=1+1"), "'\n=1+1");
        assert_eq!(csv_safe("＝1+1"), "'＝1+1");
        assert_eq!(csv_safe("＠SUM(A1:A2)"), "'＠SUM(A1:A2)");
        assert_eq!(csv_safe("normal"), "normal");
    }

    #[test]
    fn empty_csv_still_has_a_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.csv");
        let rows: Vec<serde_json::Value> = Vec::new();
        write_csv(&path, &["one", "two"], &rows).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), "one,two\n");
    }

    #[test]
    fn empty_and_nonempty_csv_use_the_same_explicit_header() {
        let dir = tempfile::tempdir().unwrap();
        let empty_path = dir.path().join("empty.csv");
        let populated_path = dir.path().join("populated.csv");
        let empty: Vec<TestRow<'_>> = Vec::new();
        let populated = [TestRow {
            one: "first",
            two: "second",
        }];

        write_csv(&empty_path, &["one", "two"], &empty).unwrap();
        write_csv(&populated_path, &["one", "two"], &populated).unwrap();

        let mut empty_reader = csv::Reader::from_path(empty_path).unwrap();
        let mut populated_reader = csv::Reader::from_path(populated_path).unwrap();
        assert_eq!(
            empty_reader.headers().unwrap(),
            populated_reader.headers().unwrap()
        );
        assert_eq!(
            populated_reader.records().next().unwrap().unwrap(),
            csv::StringRecord::from(vec!["first", "second"])
        );
    }

    #[test]
    fn atomic_output_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("summary.json");
        write_json(&path, &serde_json::json!({"run": 1})).unwrap();
        write_json(&path, &serde_json::json!({"run": 2})).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(value, serde_json::json!({"run": 2}));
    }
}
