//! Canonical exact-version and Cargo-requirement selectors.

use std::fmt;

use semver::{Op, Version, VersionReq};
use serde::{Deserialize, Serialize};

/// The semantics used to select target package versions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionSelectorKind {
    Exact,
    Range,
}

/// A normalized target version selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionSelector {
    Exact(Version),
    Range(VersionReq),
}

impl VersionSelector {
    #[must_use]
    pub fn exact(version: Version) -> Self {
        Self::Exact(version)
    }

    /// Build a range selector, canonicalizing a fully specified `=x.y.z`
    /// requirement to the equivalent exact selector.
    #[must_use]
    pub fn range(requirement: VersionReq) -> Self {
        if let Some(version) = explicit_exact_version(&requirement) {
            Self::Exact(version)
        } else {
            Self::Range(requirement)
        }
    }

    pub fn parse_range(value: &str) -> Result<Self, semver::Error> {
        VersionReq::parse(value).map(Self::range)
    }

    #[must_use]
    pub fn kind(&self) -> VersionSelectorKind {
        match self {
            Self::Exact(_) => VersionSelectorKind::Exact,
            Self::Range(_) => VersionSelectorKind::Range,
        }
    }

    #[must_use]
    pub fn matches(&self, version: &Version) -> bool {
        match self {
            Self::Exact(target) => target == version,
            Self::Range(requirement) => requirement.matches(version),
        }
    }

    #[must_use]
    pub fn as_exact(&self) -> Option<&Version> {
        match self {
            Self::Exact(version) => Some(version),
            Self::Range(_) => None,
        }
    }

    #[must_use]
    pub fn canonical_spec(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for VersionSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(version) => write!(formatter, "={version}"),
            Self::Range(requirement) => requirement.fmt(formatter),
        }
    }
}

/// One release from a complete crates.io sparse-index entry.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PublishedVersionV1 {
    pub version: Version,
    pub yanked: bool,
}

/// Evaluation of a declaration against a selector over published releases.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequirementRangeEvaluation {
    pub requirement: String,
    pub intersects: Option<bool>,
    pub witness: Option<PublishedVersionV1>,
    pub explicit_exact_pin: Option<Version>,
    pub pin_matches_selector: Option<bool>,
    pub error: Option<String>,
}

/// Evaluate set intersection over a complete published-version universe.
///
/// Both yanked and non-yanked releases are valid witnesses because an existing
/// lockfile may continue to resolve a yanked release. Callers must not pass a
/// partial release list and interpret `Some(false)` as proof of disjointness.
#[must_use]
pub fn evaluate_requirement_intersection(
    requirement: &str,
    selector: &VersionSelector,
    published_versions: &[PublishedVersionV1],
) -> RequirementRangeEvaluation {
    match VersionReq::parse(requirement) {
        Ok(declaration) => {
            let explicit_exact_pin = explicit_exact_version(&declaration);
            let pin_matches_selector = explicit_exact_pin
                .as_ref()
                .map(|version| selector.matches(version));
            let witness = published_versions
                .iter()
                .filter(|release| {
                    selector.matches(&release.version) && declaration.matches(&release.version)
                })
                .min()
                .cloned();
            RequirementRangeEvaluation {
                requirement: requirement.to_owned(),
                intersects: Some(witness.is_some()),
                witness,
                explicit_exact_pin,
                pin_matches_selector,
                error: None,
            }
        }
        Err(error) => RequirementRangeEvaluation {
            requirement: requirement.to_owned(),
            intersects: None,
            witness: None,
            explicit_exact_pin: None,
            pin_matches_selector: None,
            error: Some(error.to_string()),
        },
    }
}

fn explicit_exact_version(requirement: &VersionReq) -> Option<Version> {
    let [comparator] = requirement.comparators.as_slice() else {
        return None;
    };
    if comparator.op != Op::Exact {
        return None;
    }
    let mut version = Version::new(comparator.major, comparator.minor?, comparator.patch?);
    version.pre = comparator.pre.clone();
    Some(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, yanked: bool) -> PublishedVersionV1 {
        PublishedVersionV1 {
            version: Version::parse(version).unwrap(),
            yanked,
        }
    }

    #[test]
    fn canonicalizes_only_fully_specified_exact_requirements() {
        let exact = VersionSelector::parse_range("=0.4.3").unwrap();
        assert_eq!(exact.kind(), VersionSelectorKind::Exact);
        assert_eq!(exact.canonical_spec(), "=0.4.3");

        let range = VersionSelector::parse_range("0.4.3").unwrap();
        assert_eq!(range.kind(), VersionSelectorKind::Range);
        assert_eq!(range.canonical_spec(), "^0.4.3");
    }

    #[test]
    fn selector_preserves_cargo_prerelease_matching() {
        let selector = VersionSelector::parse_range(">=1.0.0-alpha.2, <1.0.0").unwrap();
        assert!(selector.matches(&Version::parse("1.0.0-beta.1").unwrap()));
        assert!(!selector.matches(&Version::parse("1.0.0").unwrap()));

        let stable_only = VersionSelector::parse_range(">=1.0.0, <2.0.0").unwrap();
        assert!(!stable_only.matches(&Version::parse("1.1.0-alpha.1").unwrap()));
    }

    #[test]
    fn intersection_uses_the_lowest_published_witness_including_yanked() {
        let selector = VersionSelector::parse_range("^0.4").unwrap();
        let versions = vec![
            release("0.4.3", false),
            release("0.4.1", true),
            release("0.5.0", false),
        ];
        let evaluation = evaluate_requirement_intersection(">=0.4.0", &selector, &versions);

        assert_eq!(evaluation.intersects, Some(true));
        assert_eq!(evaluation.witness, Some(release("0.4.1", true)));
        assert_eq!(evaluation.explicit_exact_pin, None);
    }

    #[test]
    fn intersection_distinguishes_exact_pins_and_parse_failures() {
        let selector = VersionSelector::parse_range("^0.4").unwrap();
        let versions = [release("0.4.3", false)];

        let pin = evaluate_requirement_intersection("=0.4.3", &selector, &versions);
        assert_eq!(pin.explicit_exact_pin, Some(Version::new(0, 4, 3)));
        assert_eq!(pin.pin_matches_selector, Some(true));
        assert_eq!(pin.intersects, Some(true));

        let disjoint = evaluate_requirement_intersection("^0.5", &selector, &versions);
        assert_eq!(disjoint.intersects, Some(false));

        let invalid = evaluate_requirement_intersection("not semver", &selector, &versions);
        assert_eq!(invalid.intersects, None);
        assert!(invalid.error.is_some());
    }
}
