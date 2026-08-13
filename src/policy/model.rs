use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    cargo_evidence::PackageIdentityV1,
    evidence::{EvidenceBundleV1, SeverityV1},
};

fn schema_version() -> u16 {
    PolicyDocumentV1::SCHEMA_VERSION
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownDispositionV1 {
    #[default]
    Indeterminate,
    Fail,
    Warn,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySubjectV1 {
    #[default]
    Target,
    FullGraph,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementModeV1 {
    Any,
    Compatible,
    Exact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationRequirementV1 {
    Direct,
    Transitive,
    DirectAndTransitive,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelectorV1 {
    pub organization: Option<String>,
    pub repository: Option<String>,
}

impl PolicySelectorV1 {
    pub(crate) fn specificity(&self) -> u8 {
        if self.repository.is_some() {
            2
        } else if self.organization.is_some() {
            1
        } else {
            0
        }
    }

    pub(crate) fn matches(&self, repository: &str) -> bool {
        if let Some(selected) = self.repository.as_deref() {
            return selected.eq_ignore_ascii_case(repository);
        }
        self.organization.as_deref().is_none_or(|organization| {
            repository
                .split_once('/')
                .is_some_and(|(owner, _)| owner.eq_ignore_ascii_case(organization))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PolicyCheckV1 {
    Requirement {
        mode: RequirementModeV1,
    },
    ExactResolution,
    Relation {
        required: RelationRequirementV1,
    },
    Staleness {
        max_commit_age_days: u64,
    },
    Msrv {
        #[serde(default)]
        require_declared: bool,
        maximum: Option<Version>,
    },
    License {
        #[serde(default)]
        subject: PolicySubjectV1,
        #[serde(default)]
        allow: BTreeSet<String>,
        #[serde(default)]
        deny: BTreeSet<String>,
    },
    Vulnerability {
        #[serde(default)]
        subject: PolicySubjectV1,
        #[serde(default)]
        deny_advisories: BTreeSet<String>,
        minimum_severity: Option<SeverityV1>,
        #[serde(default)]
        include_withdrawn: bool,
        max_snapshot_age_days: Option<u64>,
        #[serde(default)]
        sources: BTreeSet<String>,
        #[serde(default)]
        unknown_severity: UnknownDispositionV1,
    },
}

impl PolicyCheckV1 {
    pub fn kind(&self) -> PolicyCheckKindV1 {
        match self {
            Self::Requirement { .. } => PolicyCheckKindV1::Requirement,
            Self::ExactResolution => PolicyCheckKindV1::ExactResolution,
            Self::Relation { .. } => PolicyCheckKindV1::Relation,
            Self::Staleness { .. } => PolicyCheckKindV1::Staleness,
            Self::Msrv { .. } => PolicyCheckKindV1::Msrv,
            Self::License { .. } => PolicyCheckKindV1::License,
            Self::Vulnerability { .. } => PolicyCheckKindV1::Vulnerability,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckKindV1 {
    Requirement,
    ExactResolution,
    Relation,
    Staleness,
    Msrv,
    License,
    Vulnerability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyRuleV1 {
    pub id: String,
    #[serde(default)]
    pub selector: PolicySelectorV1,
    #[serde(default)]
    pub unknown: Option<UnknownDispositionV1>,
    #[serde(flatten)]
    pub check: PolicyCheckV1,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PolicyExceptionSubjectV1 {
    pub repository: String,
    pub crate_name: String,
    pub version: Version,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyExceptionV1 {
    pub id: String,
    pub rule_id: String,
    pub subject: PolicyExceptionSubjectV1,
    pub justification: String,
    pub ticket: String,
    pub approver: String,
    pub approved_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocumentV1 {
    #[serde(default = "schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub default_unknown: UnknownDispositionV1,
    #[serde(default)]
    pub rules: Vec<PolicyRuleV1>,
    #[serde(default)]
    pub exceptions: Vec<PolicyExceptionV1>,
}

impl PolicyDocumentV1 {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn from_toml(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }

    /// Validate policy structure without needing repository evidence.
    pub fn validate(&self) -> Vec<PolicyDiagnosticV1> {
        super::evaluate::validate_policy_document(self)
    }
}

#[derive(Clone, Debug)]
pub struct EvaluationContext {
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatusV1 {
    Pass,
    Fail,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionV1 {
    Pass,
    Fail,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyExitStatus {
    Compliant,
    PartialOrIndeterminate,
    Violation,
}

impl PolicyExitStatus {
    pub const fn code(self) -> i32 {
        match self {
            Self::Compliant => 0,
            Self::PartialOrIndeterminate => 4,
            Self::Violation => 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyFindingV1 {
    pub repository: String,
    pub subject: PackageIdentityV1,
    pub rule_id: String,
    pub check: PolicyCheckKindV1,
    pub status: FindingStatusV1,
    /// Warning findings remain visible but do not affect the report decision.
    pub blocking: bool,
    pub code: String,
    pub message: String,
    pub exception_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatusV1 {
    Applied,
    Expired,
    Rejected,
    Unused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExceptionEvaluationV1 {
    pub exception_id: String,
    pub status: ExceptionStatusV1,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PolicyDiagnosticV1 {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyReportV1 {
    pub schema_version: u16,
    pub evidence_schema_version: u16,
    pub evidence_sha256: String,
    pub policy_sha256: String,
    pub evaluated_at: DateTime<Utc>,
    pub target: PackageIdentityV1,
    pub decision: PolicyDecisionV1,
    pub exit_status: PolicyExitStatus,
    pub findings: Vec<PolicyFindingV1>,
    pub exceptions: Vec<ExceptionEvaluationV1>,
    pub diagnostics: Vec<PolicyDiagnosticV1>,
}

impl PolicyReportV1 {
    pub const SCHEMA_VERSION: u16 = 1;

    pub(crate) fn unsupported(
        bundle: &EvidenceBundleV1,
        policy: &PolicyDocumentV1,
        context: &EvaluationContext,
        diagnostics: Vec<PolicyDiagnosticV1>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            evidence_schema_version: bundle.schema_version,
            evidence_sha256: canonical_sha256(bundle),
            policy_sha256: canonical_sha256(policy),
            evaluated_at: context.evaluated_at,
            target: bundle.target.clone(),
            decision: PolicyDecisionV1::Indeterminate,
            exit_status: PolicyExitStatus::PartialOrIndeterminate,
            findings: Vec::new(),
            exceptions: Vec::new(),
            diagnostics,
        }
    }
}

pub(crate) fn canonical_sha256<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => crate::secure_cache::sha256_hex(&bytes),
        Err(_) => String::new(),
    }
}
