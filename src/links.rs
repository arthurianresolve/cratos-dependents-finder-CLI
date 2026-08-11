use std::fmt;

use semver::Version;
use serde::Serialize;
use url::Url;

use crate::github::parse_github_repo;

const CARGO_REQUIREMENTS_DOCS: &str =
    "https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html";
const GITHUB_LIMITS_DOCS: &str = "https://docs.github.com/en/search-github/github-code-search/about-github-code-search#limitations";

#[derive(Clone, Debug, Serialize)]
pub struct DiscoveryLinks {
    pub crate_name: String,
    pub target_version: String,
    pub exact_lockfile_web_search: String,
    pub common_direct_declaration_web_search: String,
    pub exact_pin_declaration_web_search: String,
    pub crates_io_reverse_dependencies_api: String,
    pub github_dependents_page: Option<String>,
    pub cargo_requirement_semantics: String,
    pub github_code_search_limitations: String,
    pub globally_exhaustive: bool,
    pub notes: Vec<String>,
}

impl fmt::Display for DiscoveryLinks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "crate: {}", self.crate_name)?;
        writeln!(f, "target version: {}", self.target_version)?;
        writeln!(
            f,
            "exact Cargo.lock web search: {}",
            self.exact_lockfile_web_search
        )?;
        writeln!(
            f,
            "common direct declaration web search: {}",
            self.common_direct_declaration_web_search
        )?;
        writeln!(
            f,
            "exact-pin declaration web search: {}",
            self.exact_pin_declaration_web_search
        )?;
        writeln!(
            f,
            "crates.io reverse dependencies: {}",
            self.crates_io_reverse_dependencies_api
        )?;
        if let Some(url) = &self.github_dependents_page {
            writeln!(f, "GitHub dependents (all versions, approximate): {url}")?;
        }
        writeln!(
            f,
            "Cargo requirement semantics: {}",
            self.cargo_requirement_semantics
        )?;
        writeln!(
            f,
            "GitHub search limitations: {}",
            self.github_code_search_limitations
        )?;
        writeln!(f, "globally_exhaustive: false")?;
        for note in &self.notes {
            writeln!(f, "note: {note}")?;
        }
        Ok(())
    }
}

pub fn build_links(
    crate_name: &str,
    target_version: &Version,
    repository: Option<&str>,
) -> DiscoveryLinks {
    let escaped_name = regex_escape(crate_name);
    let escaped_version = regex_escape(&target_version.to_string());

    let lock_query = format!(
        r#"path:/(^|\/)Cargo\.lock$/ /name = \"{escaped_name}\"\nversion = \"{escaped_version}\"/ NOT is:fork"#
    );
    let direct_query = format!(
        r#"path:/(^|\/)Cargo\.toml$/ /{escaped_name}\s*=\s*(?:\"{escaped_version}\"|\{{[^\n]*version\s*=\s*\"{escaped_version}\")/ NOT is:fork"#
    );
    let exact_req = regex_escape(&format!("={target_version}"));
    let exact_pin_query = format!(
        r#"path:/(^|\/)Cargo\.toml$/ /{escaped_name}\s*=\s*(?:\"{exact_req}\"|\{{[^\n]*version\s*=\s*\"{exact_req}\")/ NOT is:fork"#
    );

    DiscoveryLinks {
        crate_name: crate_name.to_owned(),
        target_version: target_version.to_string(),
        exact_lockfile_web_search: github_search_url(&lock_query),
        common_direct_declaration_web_search: github_search_url(&direct_query),
        exact_pin_declaration_web_search: github_search_url(&exact_pin_query),
        crates_io_reverse_dependencies_api: format!(
            "https://crates.io/api/v1/crates/{}/reverse_dependencies?page=1&per_page=100",
            encode_path_segment(crate_name)
        ),
        github_dependents_page: repository
            .and_then(parse_github_repo)
            .map(|repo| {
                format!(
                    "https://github.com/{}/network/dependents?dependent_type=REPOSITORY",
                    repo.full_name()
                )
            }),
        cargo_requirement_semantics: CARGO_REQUIREMENTS_DOCS.to_owned(),
        github_code_search_limitations: GITHUB_LIMITS_DOCS.to_owned(),
        globally_exhaustive: false,
        notes: vec![
            "GitHub web code search is login-only, default-branch-only, bounded to 100 results, and not exhaustive.".to_owned(),
            "The GitHub dependents page is public-only, approximate, and has no version filter or supported enumeration API.".to_owned(),
            "The scan command uses crates.io candidates plus immutable GitHub snapshots and parses Cargo files locally.".to_owned(),
        ],
    }
}

fn github_search_url(query: &str) -> String {
    let mut url = Url::parse("https://github.com/search").expect("static GitHub URL is valid");
    url.query_pairs_mut()
        .append_pair("type", "code")
        .append_pair("q", query);
    url.into()
}

fn encode_path_segment(value: &str) -> String {
    let mut url = Url::parse("https://example.invalid/").expect("static URL is valid");
    url.path_segments_mut()
        .expect("base URL supports path segments")
        .push(value);
    url.path().trim_start_matches('/').to_owned()
}

fn regex_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+'
                | '*'
                | '?'
                | '^'
                | '$'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '|'
                | '\\'
                | '/'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_encode_queries_and_repository() {
        let links = build_links(
            "fs2",
            &Version::parse("0.4.3").unwrap(),
            Some("https://github.com/danburkert/fs2-rs.git"),
        );

        assert!(
            links
                .exact_lockfile_web_search
                .contains("github.com/search?")
        );
        assert!(links.exact_lockfile_web_search.contains("Cargo"));
        assert!(links.exact_pin_declaration_web_search.contains("%3D0"));
        assert_eq!(
            links.github_dependents_page.as_deref(),
            Some(
                "https://github.com/danburkert/fs2-rs/network/dependents?dependent_type=REPOSITORY"
            )
        );
        assert!(!links.globally_exhaustive);
    }
}
