use std::collections::{BTreeMap, BTreeSet};

use crate::{
    cargo_evidence::{PackageIdentityV1, RecordedRelation},
    evidence::{
        ADVISORY_SOURCE_OSV, ADVISORY_SOURCE_RUSTSEC, EvidenceBundleV1, EvidenceCompletenessV1,
        PackageEvidenceV1, RepositoryEvidenceV1, RequirementEvidenceSourceV1,
        VulnerabilityEvidenceV1,
    },
};

use super::model::canonical_sha256;
use super::{
    EvaluationContext, ExceptionEvaluationV1, ExceptionStatusV1, FindingStatusV1,
    PolicyCheckKindV1, PolicyCheckV1, PolicyDecisionV1, PolicyDiagnosticV1, PolicyDocumentV1,
    PolicyExceptionV1, PolicyExitStatus, PolicyFindingV1, PolicyReportV1, PolicyRuleV1,
    PolicySubjectV1, RelationRequirementV1, RequirementModeV1, UnknownDispositionV1,
    spdx::expression_accepted,
};

pub fn evaluate(
    bundle: &EvidenceBundleV1,
    policy: &PolicyDocumentV1,
    context: &EvaluationContext,
) -> PolicyReportV1 {
    let diagnostics = validate(bundle, policy);
    if !diagnostics.is_empty() {
        return PolicyReportV1::unsupported(bundle, policy, context, diagnostics);
    }

    let mut repositories = bundle.repositories.iter().collect::<Vec<_>>();
    repositories.sort_by_key(|repository| &repository.repository);
    let mut rules_by_id = BTreeMap::<&str, Vec<&PolicyRuleV1>>::new();
    for rule in &policy.rules {
        rules_by_id.entry(&rule.id).or_default().push(rule);
    }

    let mut findings = Vec::new();
    let mut diagnostics = Vec::new();
    let mut matched_selectors = BTreeSet::new();
    for repository in repositories {
        for (rule_id, rules) in &rules_by_id {
            matched_selectors.extend(
                rules
                    .iter()
                    .copied()
                    .filter(|rule| rule.selector.matches(&repository.repository))
                    .map(rule_selector_key),
            );
            match select_rule(repository, rules) {
                RuleSelection::Selected(rule) => {
                    findings.extend(evaluate_rule(bundle, repository, rule, policy, context))
                }
                RuleSelection::Conflict(check) => {
                    diagnostics.push(diagnostic(
                        "conflicting_rule_selector",
                        format!(
                            "rule `{rule_id}` has conflicting definitions for repository `{}`",
                            repository.repository
                        ),
                    ));
                    findings.push(PolicyFindingV1 {
                        repository: repository.repository.clone(),
                        subject: bundle.target.clone(),
                        rule_id: (*rule_id).to_owned(),
                        check,
                        status: FindingStatusV1::Indeterminate,
                        blocking: true,
                        code: "conflicting_rule_selector".to_owned(),
                        message: "conflicting rule selector".to_owned(),
                        exception_id: None,
                    });
                }
                RuleSelection::NotApplicable => {}
            }
        }
    }
    findings.extend(
        policy
            .rules
            .iter()
            .filter(|rule| !matched_selectors.contains(&rule_selector_key(rule)))
            .map(|rule| unmatched_selector_finding(bundle, rule)),
    );

    sort_findings(&mut findings);
    let mut exceptions = initialize_exceptions(policy, context);
    apply_exceptions(&mut findings, &policy.exceptions, &mut exceptions);
    exceptions.sort_by(|left, right| left.exception_id.cmp(&right.exception_id));
    diagnostics.sort();
    diagnostics.dedup();

    let decision = report_decision(&findings, !diagnostics.is_empty());
    PolicyReportV1 {
        schema_version: PolicyReportV1::SCHEMA_VERSION,
        evidence_schema_version: bundle.schema_version,
        evidence_sha256: canonical_sha256(bundle),
        policy_sha256: canonical_sha256(policy),
        evaluated_at: context.evaluated_at,
        target: bundle.target.clone(),
        decision,
        exit_status: match decision {
            PolicyDecisionV1::Pass => PolicyExitStatus::Compliant,
            PolicyDecisionV1::Fail => PolicyExitStatus::Violation,
            PolicyDecisionV1::Indeterminate => PolicyExitStatus::PartialOrIndeterminate,
        },
        findings,
        exceptions,
        diagnostics,
    }
}

fn rule_selector_key(rule: &PolicyRuleV1) -> (&str, Option<&str>, Option<&str>) {
    (
        &rule.id,
        rule.selector.organization.as_deref(),
        rule.selector.repository.as_deref(),
    )
}

fn unmatched_selector_finding(bundle: &EvidenceBundleV1, rule: &PolicyRuleV1) -> PolicyFindingV1 {
    let repository = rule.selector.repository.clone().unwrap_or_else(|| {
        rule.selector.organization.as_deref().map_or_else(
            || "*".to_owned(),
            |organization| format!("{organization}/*"),
        )
    });
    PolicyFindingV1 {
        repository,
        subject: bundle.target.clone(),
        rule_id: rule.id.clone(),
        check: rule.check.kind(),
        status: FindingStatusV1::Indeterminate,
        blocking: true,
        code: "rule_selector_unmatched".to_owned(),
        message: "policy rule selector matched no repository evidence".to_owned(),
        exception_id: None,
    }
}

fn validate(bundle: &EvidenceBundleV1, policy: &PolicyDocumentV1) -> Vec<PolicyDiagnosticV1> {
    let mut diagnostics = validate_policy_document(policy);
    if !bundle.schema_is_supported() {
        diagnostics.push(diagnostic(
            "unsupported_evidence_schema",
            format!(
                "unsupported evidence schema version {}",
                bundle.schema_version
            ),
        ));
    }
    if bundle.repositories.is_empty() {
        diagnostics.push(diagnostic(
            "no_repository_evidence",
            "evidence bundle contains no repositories",
        ));
    }
    if bundle
        .limitations
        .iter()
        .any(|limitation| limitation.code != "globally_non_exhaustive")
    {
        diagnostics.push(diagnostic(
            "evidence_incomplete",
            "bundle or repository limitations prevent an unconditional policy pass",
        ));
    }

    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

pub(super) fn validate_policy_document(policy: &PolicyDocumentV1) -> Vec<PolicyDiagnosticV1> {
    let mut diagnostics = Vec::new();
    if policy.schema_version != PolicyDocumentV1::SCHEMA_VERSION {
        diagnostics.push(diagnostic(
            "unsupported_policy_schema",
            format!(
                "unsupported policy schema version {}",
                policy.schema_version
            ),
        ));
    }
    if policy.rules.is_empty() {
        diagnostics.push(diagnostic(
            "empty_policy",
            "policy must contain at least one rule",
        ));
    }
    let mut selectors = BTreeSet::new();
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            diagnostics.push(diagnostic(
                "empty_rule_id",
                "policy rule ID must not be empty",
            ));
        }
        if rule.selector.organization.is_some() && rule.selector.repository.is_some() {
            diagnostics.push(diagnostic(
                "ambiguous_rule_selector",
                format!(
                    "rule `{}` cannot select both an organization and a repository",
                    rule.id
                ),
            ));
        }
        let key = (
            rule.id.to_ascii_lowercase(),
            rule.selector
                .organization
                .as_deref()
                .map(str::to_ascii_lowercase),
            rule.selector
                .repository
                .as_deref()
                .map(str::to_ascii_lowercase),
        );
        if !selectors.insert(key) {
            diagnostics.push(diagnostic(
                "duplicate_rule_selector",
                format!("rule `{}` repeats the same selector", rule.id),
            ));
        }
        match &rule.check {
            PolicyCheckV1::License { allow, deny, .. } if allow.is_empty() && deny.is_empty() => {
                diagnostics.push(diagnostic(
                    "empty_license_policy",
                    format!(
                        "license rule `{}` has neither allow nor deny terms",
                        rule.id
                    ),
                ));
            }
            PolicyCheckV1::Vulnerability { sources, .. } => {
                for source in sources {
                    if !is_known_advisory_source(source) {
                        diagnostics.push(diagnostic(
                            "unknown_advisory_source",
                            format!(
                                "vulnerability rule `{}` uses unsupported source `{source}`",
                                rule.id
                            ),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    let rule_ids = policy
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut exception_ids = BTreeSet::new();
    for exception in &policy.exceptions {
        if exception.id.trim().is_empty()
            || exception.rule_id.trim().is_empty()
            || exception.subject.repository.trim().is_empty()
            || exception.subject.crate_name.trim().is_empty()
            || exception.justification.trim().is_empty()
            || exception.ticket.trim().is_empty()
            || exception.approver.trim().is_empty()
        {
            diagnostics.push(diagnostic(
                "incomplete_exception",
                format!("exception `{}` is missing required metadata", exception.id),
            ));
        }
        if !exception_ids.insert(exception.id.to_ascii_lowercase()) {
            diagnostics.push(diagnostic(
                "duplicate_exception_id",
                format!("exception ID `{}` is not unique", exception.id),
            ));
        }
        if !rule_ids.contains(exception.rule_id.as_str()) {
            diagnostics.push(diagnostic(
                "unknown_exception_rule",
                format!(
                    "exception `{}` references unknown rule `{}`",
                    exception.id, exception.rule_id
                ),
            ));
        }
        if exception.expires_at <= exception.approved_at {
            diagnostics.push(diagnostic(
                "invalid_exception_window",
                format!(
                    "exception `{}` must expire after its approval time",
                    exception.id
                ),
            ));
        }
    }
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

enum RuleSelection<'a> {
    Selected(&'a PolicyRuleV1),
    Conflict(PolicyCheckKindV1),
    NotApplicable,
}

fn select_rule<'a>(
    repository: &RepositoryEvidenceV1,
    rules: &'a [&PolicyRuleV1],
) -> RuleSelection<'a> {
    let applicable = rules
        .iter()
        .copied()
        .filter(|rule| rule.selector.matches(&repository.repository))
        .collect::<Vec<_>>();
    let Some(specificity) = applicable
        .iter()
        .map(|rule| rule.selector.specificity())
        .max()
    else {
        return RuleSelection::NotApplicable;
    };
    let selected = applicable
        .into_iter()
        .filter(|rule| rule.selector.specificity() == specificity)
        .collect::<Vec<_>>();
    if selected.len() == 1 {
        RuleSelection::Selected(selected[0])
    } else {
        RuleSelection::Conflict(selected[0].check.kind())
    }
}

fn evaluate_rule(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    policy: &PolicyDocumentV1,
    context: &EvaluationContext,
) -> Vec<PolicyFindingV1> {
    let unknown = rule.unknown.unwrap_or(policy.default_unknown);
    match &rule.check {
        PolicyCheckV1::Requirement { mode } => {
            vec![evaluate_requirement(
                bundle, repository, rule, *mode, unknown,
            )]
        }
        PolicyCheckV1::ExactResolution => {
            vec![evaluate_exact_resolution(bundle, repository, rule, unknown)]
        }
        PolicyCheckV1::Relation { required } => {
            vec![evaluate_relation(
                bundle, repository, rule, *required, unknown,
            )]
        }
        PolicyCheckV1::Staleness {
            max_commit_age_days,
        } => vec![evaluate_staleness(
            bundle,
            repository,
            rule,
            *max_commit_age_days,
            unknown,
            context,
        )],
        PolicyCheckV1::Msrv {
            require_declared,
            maximum,
        } => vec![evaluate_msrv(
            bundle,
            repository,
            rule,
            *require_declared,
            maximum.as_ref(),
            unknown,
        )],
        PolicyCheckV1::License {
            subject,
            allow,
            deny,
        } => evaluate_licenses(bundle, repository, rule, *subject, allow, deny, unknown),
        PolicyCheckV1::Vulnerability {
            subject,
            deny_advisories,
            minimum_severity,
            include_withdrawn,
            max_snapshot_age_days,
            sources,
            unknown_severity,
        } => evaluate_vulnerabilities(
            bundle,
            repository,
            rule,
            VulnerabilityPolicy {
                subject: *subject,
                deny_advisories,
                minimum_severity: *minimum_severity,
                include_withdrawn: *include_withdrawn,
                max_snapshot_age_days: *max_snapshot_age_days,
                sources,
                unknown_severity: *unknown_severity,
                unknown,
            },
            context,
        ),
    }
}

fn evaluate_requirement(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    mode: RequirementModeV1,
    unknown: UnknownDispositionV1,
) -> PolicyFindingV1 {
    let requirements = repository
        .requirements
        .iter()
        .filter(|requirement| requirement.source == RequirementEvidenceSourceV1::CurrentManifest)
        .collect::<Vec<_>>();
    let (matched, observation_unknown) = match mode {
        RequirementModeV1::Any => (!requirements.is_empty(), false),
        RequirementModeV1::Compatible => (
            requirements
                .iter()
                .any(|requirement| requirement.accepts_target == Some(true)),
            requirements
                .iter()
                .any(|requirement| requirement.accepts_target.is_none()),
        ),
        RequirementModeV1::Exact => (
            requirements
                .iter()
                .any(|requirement| requirement.explicit_exact_pin == Some(true)),
            requirements
                .iter()
                .any(|requirement| requirement.explicit_exact_pin.is_none()),
        ),
    };
    if matched {
        pass(bundle, repository, rule, "requirement_satisfied")
    } else if observation_unknown || repository.completeness != EvidenceCompletenessV1::Complete {
        unknown_finding(
            bundle,
            repository,
            rule,
            unknown,
            "requirement_evidence_incomplete",
        )
    } else {
        fail(bundle, repository, rule, "requirement_not_satisfied")
    }
}

fn evaluate_exact_resolution(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    unknown: UnknownDispositionV1,
) -> PolicyFindingV1 {
    if repository.exact_resolution_count > 0 {
        pass(bundle, repository, rule, "exact_resolution_present")
    } else if repository.completeness == EvidenceCompletenessV1::Complete {
        fail(bundle, repository, rule, "exact_resolution_absent")
    } else {
        unknown_finding(
            bundle,
            repository,
            rule,
            unknown,
            "exact_resolution_unknown",
        )
    }
}

fn evaluate_relation(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    required: RelationRequirementV1,
    unknown: UnknownDispositionV1,
) -> PolicyFindingV1 {
    let matched = matches!(
        (required, repository.recorded_relation),
        (
            RelationRequirementV1::Direct,
            RecordedRelation::Direct | RecordedRelation::DirectAndTransitive
        ) | (
            RelationRequirementV1::Transitive,
            RecordedRelation::Transitive | RecordedRelation::DirectAndTransitive
        ) | (
            RelationRequirementV1::DirectAndTransitive,
            RecordedRelation::DirectAndTransitive
        )
    );
    if matched {
        pass(bundle, repository, rule, "relation_satisfied")
    } else if repository.completeness == EvidenceCompletenessV1::Complete
        && repository.recorded_relation != RecordedRelation::PresentUnclassified
    {
        fail(bundle, repository, rule, "relation_not_satisfied")
    } else {
        unknown_finding(bundle, repository, rule, unknown, "relation_unclassified")
    }
}

fn evaluate_staleness(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    max_commit_age_days: u64,
    unknown: UnknownDispositionV1,
    context: &EvaluationContext,
) -> PolicyFindingV1 {
    let Some(committed_at) = repository.head_committed_at else {
        return unknown_finding(bundle, repository, rule, unknown, "commit_time_unknown");
    };
    let age_days = context
        .evaluated_at
        .date_naive()
        .signed_duration_since(committed_at.date_naive())
        .num_days()
        .max(0) as u64;
    if age_days > max_commit_age_days {
        fail(bundle, repository, rule, "repository_stale")
    } else {
        pass(bundle, repository, rule, "repository_active")
    }
}

fn evaluate_msrv(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    require_declared: bool,
    maximum: Option<&semver::Version>,
    unknown: UnknownDispositionV1,
) -> PolicyFindingV1 {
    match repository.msrv.as_ref() {
        Some(msrv) if maximum.is_some_and(|maximum| msrv > maximum) => {
            fail(bundle, repository, rule, "msrv_exceeds_maximum")
        }
        Some(_) => pass(bundle, repository, rule, "msrv_satisfied"),
        None if require_declared && repository.completeness == EvidenceCompletenessV1::Complete => {
            fail(bundle, repository, rule, "msrv_not_declared")
        }
        None if require_declared => unknown_finding(
            bundle,
            repository,
            rule,
            unknown,
            "msrv_declaration_unknown",
        ),
        None => pass(bundle, repository, rule, "msrv_not_required"),
    }
}

fn evaluate_licenses(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    subject: PolicySubjectV1,
    allow: &BTreeSet<String>,
    deny: &BTreeSet<String>,
    unknown: UnknownDispositionV1,
) -> Vec<PolicyFindingV1> {
    let packages = selected_packages(bundle, repository, subject);
    if packages.is_empty() {
        return vec![unknown_finding(
            bundle,
            repository,
            rule,
            unknown,
            "license_evidence_missing",
        )];
    }

    let mut findings = packages
        .into_iter()
        .map(|package| match package.license_expression.as_deref() {
            Some(expression) => match expression_accepted(expression, allow, deny) {
                Ok(true) => package_finding(
                    repository,
                    rule,
                    package.package.clone(),
                    FindingStatusV1::Pass,
                    true,
                    "license_satisfied",
                ),
                Ok(false) => package_finding(
                    repository,
                    rule,
                    package.package.clone(),
                    FindingStatusV1::Fail,
                    true,
                    "license_not_allowed",
                ),
                Err(error) => unknown_package_finding(
                    repository,
                    rule,
                    package.package.clone(),
                    unknown,
                    "license_expression_invalid",
                    error,
                ),
            },
            None => unknown_package_finding(
                repository,
                rule,
                package.package.clone(),
                unknown,
                "license_not_declared",
                "license metadata is missing".to_owned(),
            ),
        })
        .collect::<Vec<_>>();
    if subject == PolicySubjectV1::FullGraph
        && (repository.completeness != EvidenceCompletenessV1::Complete
            || !repository.package_inventory_complete)
    {
        findings.push(unknown_finding(
            bundle,
            repository,
            rule,
            unknown,
            "full_graph_license_evidence_incomplete",
        ));
    }
    findings
}

struct VulnerabilityPolicy<'a> {
    subject: PolicySubjectV1,
    deny_advisories: &'a BTreeSet<String>,
    minimum_severity: Option<crate::evidence::SeverityV1>,
    include_withdrawn: bool,
    max_snapshot_age_days: Option<u64>,
    sources: &'a BTreeSet<String>,
    unknown_severity: UnknownDispositionV1,
    unknown: UnknownDispositionV1,
}

fn evaluate_vulnerabilities(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    policy: VulnerabilityPolicy<'_>,
    context: &EvaluationContext,
) -> Vec<PolicyFindingV1> {
    let sources = advisory_sources(policy.sources);
    let mut findings = snapshot_findings(
        bundle,
        repository,
        rule,
        &sources,
        policy.max_snapshot_age_days,
        policy.unknown,
        context,
    );
    for vulnerability in repository.vulnerabilities.iter().filter(|vulnerability| {
        sources
            .iter()
            .any(|source| source.eq_ignore_ascii_case(&vulnerability.source))
            && package_selected(bundle, &vulnerability.package, policy.subject)
            && (policy.include_withdrawn || !vulnerability.withdrawn)
    }) {
        findings.push(evaluate_vulnerability(
            repository,
            rule,
            vulnerability,
            &policy,
        ));
    }
    if findings.is_empty() {
        findings.push(pass(
            bundle,
            repository,
            rule,
            "no_disallowed_vulnerability_observed",
        ));
    }
    if policy.subject == PolicySubjectV1::FullGraph
        && (repository.completeness != EvidenceCompletenessV1::Complete
            || !repository.package_inventory_complete)
    {
        findings.push(unknown_finding(
            bundle,
            repository,
            rule,
            policy.unknown,
            "full_graph_vulnerability_evidence_incomplete",
        ));
    }
    findings
}

fn snapshot_findings(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    sources: &[String],
    max_age_days: Option<u64>,
    unknown: UnknownDispositionV1,
    context: &EvaluationContext,
) -> Vec<PolicyFindingV1> {
    let mut findings = Vec::new();
    for source in sources {
        let latest = bundle
            .advisory_snapshots
            .iter()
            .filter(|snapshot| snapshot.source.eq_ignore_ascii_case(source))
            .max_by_key(|snapshot| snapshot.collected_at);
        let Some(snapshot) = latest else {
            findings.push(unknown_finding(
                bundle,
                repository,
                rule,
                unknown,
                &format!("{source}_snapshot_missing"),
            ));
            continue;
        };
        if let Some(max_age_days) = max_age_days {
            let age_days = context
                .evaluated_at
                .date_naive()
                .signed_duration_since(snapshot.collected_at.date_naive())
                .num_days()
                .max(0) as u64;
            if age_days > max_age_days {
                findings.push(fail(
                    bundle,
                    repository,
                    rule,
                    &format!("{source}_snapshot_stale"),
                ));
            }
        }
    }
    findings
}

fn evaluate_vulnerability(
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    vulnerability: &VulnerabilityEvidenceV1,
    policy: &VulnerabilityPolicy<'_>,
) -> PolicyFindingV1 {
    if policy
        .deny_advisories
        .iter()
        .any(|id| id.eq_ignore_ascii_case(&vulnerability.advisory_id))
    {
        return package_finding(
            repository,
            rule,
            vulnerability.package.clone(),
            FindingStatusV1::Fail,
            true,
            "advisory_denied",
        );
    }
    let Some(threshold) = policy.minimum_severity else {
        return package_finding(
            repository,
            rule,
            vulnerability.package.clone(),
            FindingStatusV1::Pass,
            true,
            "advisory_below_policy_scope",
        );
    };
    match vulnerability.severity {
        Some(severity) if severity >= threshold => package_finding(
            repository,
            rule,
            vulnerability.package.clone(),
            FindingStatusV1::Fail,
            true,
            "vulnerability_severity_exceeded",
        ),
        Some(_) => package_finding(
            repository,
            rule,
            vulnerability.package.clone(),
            FindingStatusV1::Pass,
            true,
            "vulnerability_below_threshold",
        ),
        None => unknown_package_finding(
            repository,
            rule,
            vulnerability.package.clone(),
            policy.unknown_severity,
            "vulnerability_severity_unknown",
            format!(
                "advisory `{}` has no normalized severity",
                vulnerability.advisory_id
            ),
        ),
    }
}

fn selected_packages<'a>(
    bundle: &EvidenceBundleV1,
    repository: &'a RepositoryEvidenceV1,
    subject: PolicySubjectV1,
) -> Vec<&'a PackageEvidenceV1> {
    repository
        .packages
        .iter()
        .filter(|package| package_selected(bundle, &package.package, subject))
        .collect()
}

fn package_selected(
    bundle: &EvidenceBundleV1,
    package: &PackageIdentityV1,
    subject: PolicySubjectV1,
) -> bool {
    subject == PolicySubjectV1::FullGraph || package_matches_target(package, &bundle.target)
}

fn package_matches_target(package: &PackageIdentityV1, target: &PackageIdentityV1) -> bool {
    package.name == target.name
        && package.version == target.version
        && target
            .source
            .as_ref()
            .is_none_or(|source| package.source.as_ref() == Some(source))
}

fn advisory_sources(configured: &BTreeSet<String>) -> Vec<String> {
    if configured.is_empty() {
        vec![
            ADVISORY_SOURCE_OSV.to_owned(),
            ADVISORY_SOURCE_RUSTSEC.to_owned(),
        ]
    } else {
        configured.iter().cloned().collect()
    }
}

fn is_known_advisory_source(source: &str) -> bool {
    source.eq_ignore_ascii_case(ADVISORY_SOURCE_OSV)
        || source.eq_ignore_ascii_case(ADVISORY_SOURCE_RUSTSEC)
}

fn pass(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    code: &str,
) -> PolicyFindingV1 {
    package_finding(
        repository,
        rule,
        bundle.target.clone(),
        FindingStatusV1::Pass,
        true,
        code,
    )
}

fn fail(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    code: &str,
) -> PolicyFindingV1 {
    package_finding(
        repository,
        rule,
        bundle.target.clone(),
        FindingStatusV1::Fail,
        true,
        code,
    )
}

fn unknown_finding(
    bundle: &EvidenceBundleV1,
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    disposition: UnknownDispositionV1,
    code: &str,
) -> PolicyFindingV1 {
    unknown_package_finding(
        repository,
        rule,
        bundle.target.clone(),
        disposition,
        code,
        code.replace('_', " "),
    )
}

fn package_finding(
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    subject: PackageIdentityV1,
    status: FindingStatusV1,
    blocking: bool,
    code: &str,
) -> PolicyFindingV1 {
    PolicyFindingV1 {
        repository: repository.repository.clone(),
        subject,
        rule_id: rule.id.clone(),
        check: rule.check.kind(),
        status,
        blocking,
        code: code.to_owned(),
        message: code.replace('_', " "),
        exception_id: None,
    }
}

fn unknown_package_finding(
    repository: &RepositoryEvidenceV1,
    rule: &PolicyRuleV1,
    subject: PackageIdentityV1,
    disposition: UnknownDispositionV1,
    code: &str,
    message: String,
) -> PolicyFindingV1 {
    let (status, blocking) = match disposition {
        UnknownDispositionV1::Fail => (FindingStatusV1::Fail, true),
        UnknownDispositionV1::Indeterminate => (FindingStatusV1::Indeterminate, true),
        UnknownDispositionV1::Warn => (FindingStatusV1::Indeterminate, false),
    };
    let mut finding = package_finding(repository, rule, subject, status, blocking, code);
    finding.message = message;
    finding
}

fn initialize_exceptions(
    policy: &PolicyDocumentV1,
    context: &EvaluationContext,
) -> Vec<ExceptionEvaluationV1> {
    policy
        .exceptions
        .iter()
        .map(|exception| {
            let (status, reason) = if exception.approved_at > context.evaluated_at {
                (
                    ExceptionStatusV1::Rejected,
                    "approval time is in the future",
                )
            } else if exception.expires_at <= context.evaluated_at {
                (ExceptionStatusV1::Expired, "exception has expired")
            } else {
                (ExceptionStatusV1::Unused, "no matching violation")
            };
            ExceptionEvaluationV1 {
                exception_id: exception.id.clone(),
                status,
                reason: reason.to_owned(),
            }
        })
        .collect()
}

fn apply_exceptions(
    findings: &mut [PolicyFindingV1],
    exceptions: &[PolicyExceptionV1],
    evaluations: &mut [ExceptionEvaluationV1],
) {
    let mut candidates = exceptions.iter().enumerate().collect::<Vec<_>>();
    candidates.sort_by_key(|(_, exception)| &exception.id);
    for finding in findings
        .iter_mut()
        .filter(|finding| finding.status == FindingStatusV1::Fail && finding.blocking)
    {
        let Some((index, exception)) = candidates.iter().copied().find(|(index, exception)| {
            matches!(
                evaluations[*index].status,
                ExceptionStatusV1::Unused | ExceptionStatusV1::Applied
            ) && exception_matches(exception, finding)
        }) else {
            continue;
        };
        finding.blocking = false;
        finding.exception_id = Some(exception.id.clone());
        evaluations[index].status = ExceptionStatusV1::Applied;
        evaluations[index].reason =
            "matched an exact repository, crate, version, and rule".to_owned();
    }
}

fn exception_matches(exception: &PolicyExceptionV1, finding: &PolicyFindingV1) -> bool {
    exception.rule_id == finding.rule_id
        && exception
            .subject
            .repository
            .eq_ignore_ascii_case(&finding.repository)
        && exception.subject.crate_name == finding.subject.name
        && exception.subject.version == finding.subject.version
}

fn report_decision(findings: &[PolicyFindingV1], has_diagnostics: bool) -> PolicyDecisionV1 {
    if findings
        .iter()
        .any(|finding| finding.blocking && finding.status == FindingStatusV1::Fail)
    {
        PolicyDecisionV1::Fail
    } else if has_diagnostics
        || findings
            .iter()
            .any(|finding| finding.blocking && finding.status == FindingStatusV1::Indeterminate)
    {
        PolicyDecisionV1::Indeterminate
    } else {
        PolicyDecisionV1::Pass
    }
}

fn sort_findings(findings: &mut [PolicyFindingV1]) {
    findings.sort_by(|left, right| {
        (
            &left.repository,
            &left.rule_id,
            left.check,
            &left.subject,
            &left.code,
            &left.message,
        )
            .cmp(&(
                &right.repository,
                &right.rule_id,
                right.check,
                &right.subject,
                &right.code,
                &right.message,
            ))
    });
}

fn diagnostic(code: &str, message: impl Into<String>) -> PolicyDiagnosticV1 {
    PolicyDiagnosticV1 {
        code: code.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone as _, Utc};
    use semver::Version;

    use super::*;
    use crate::{
        evidence::{
            AdvisorySnapshotV1, DirectRequirementEvidenceV1, EvidenceStrengthV1, PackageEvidenceV1,
            RepositoryExplanationV1, RepositoryVisibilityV1, SeverityV1, VulnerabilityEvidenceV1,
        },
        policy::{PolicyExceptionSubjectV1, PolicySelectorV1},
    };

    fn at(day: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, 12, 0, 0).unwrap()
    }

    fn package(name: &str, version: &str) -> PackageIdentityV1 {
        PackageIdentityV1 {
            name: name.to_owned(),
            version: Version::parse(version).unwrap(),
            source: None,
        }
    }

    fn repository() -> RepositoryEvidenceV1 {
        let target = package("fs2", "0.4.3");
        RepositoryEvidenceV1 {
            repository: "acme/app".to_owned(),
            repository_id: Some("1".to_owned()),
            visibility: RepositoryVisibilityV1::Private,
            head_committed_at: Some(at(12)),
            completeness: EvidenceCompletenessV1::Complete,
            requirements: vec![DirectRequirementEvidenceV1 {
                source: RequirementEvidenceSourceV1::CurrentManifest,
                manifest_path: "Cargo.toml".to_owned(),
                package_name: Some("app".to_owned()),
                requirement: Some("=0.4.3".to_owned()),
                accepts_target: Some(true),
                explicit_exact_pin: Some(true),
            }],
            exact_resolution_count: 1,
            recorded_relation: RecordedRelation::Direct,
            direct_witness: None,
            transitive_witness: None,
            msrv: Some(Version::new(1, 70, 0)),
            package_inventory_complete: false,
            packages: vec![PackageEvidenceV1 {
                package: target,
                license_expression: Some("MIT OR Apache-2.0".to_owned()),
            }],
            vulnerabilities: Vec::new(),
            explanation: RepositoryExplanationV1 {
                repository: "acme/app".to_owned(),
                observed_at: at(13),
                strength: EvidenceStrengthV1::VerifiedExactGraph,
                completeness: EvidenceCompletenessV1::Complete,
                steps: Vec::new(),
                limitations: Vec::new(),
                direct_witness: None,
                transitive_witness: None,
            },
        }
    }

    fn bundle(repository: RepositoryEvidenceV1) -> EvidenceBundleV1 {
        EvidenceBundleV1 {
            schema_version: EvidenceBundleV1::SCHEMA_VERSION,
            generated_at: at(13),
            target: package("fs2", "0.4.3"),
            globally_exhaustive: false,
            repositories: vec![repository],
            advisory_snapshots: [ADVISORY_SOURCE_RUSTSEC, ADVISORY_SOURCE_OSV]
                .into_iter()
                .map(|source| AdvisorySnapshotV1 {
                    source: source.to_owned(),
                    revision: "rev".to_owned(),
                    sha256: "hash".to_owned(),
                    collected_at: at(13),
                })
                .collect(),
            limitations: Vec::new(),
        }
    }

    fn rule(id: &str, check: PolicyCheckV1) -> PolicyRuleV1 {
        PolicyRuleV1 {
            id: id.to_owned(),
            selector: PolicySelectorV1::default(),
            unknown: None,
            check,
        }
    }

    fn policy(rules: Vec<PolicyRuleV1>) -> PolicyDocumentV1 {
        PolicyDocumentV1 {
            schema_version: PolicyDocumentV1::SCHEMA_VERSION,
            default_unknown: UnknownDispositionV1::Indeterminate,
            rules,
            exceptions: Vec::new(),
        }
    }

    #[test]
    fn evaluates_all_rule_families_without_io() {
        let allow = ["MIT", "Apache-2.0"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let rules = vec![
            rule(
                "requirement",
                PolicyCheckV1::Requirement {
                    mode: RequirementModeV1::Exact,
                },
            ),
            rule("resolution", PolicyCheckV1::ExactResolution),
            rule(
                "relation",
                PolicyCheckV1::Relation {
                    required: RelationRequirementV1::Direct,
                },
            ),
            rule(
                "stale",
                PolicyCheckV1::Staleness {
                    max_commit_age_days: 30,
                },
            ),
            rule(
                "msrv",
                PolicyCheckV1::Msrv {
                    require_declared: true,
                    maximum: Some(Version::new(1, 75, 0)),
                },
            ),
            rule(
                "license",
                PolicyCheckV1::License {
                    subject: PolicySubjectV1::Target,
                    allow,
                    deny: BTreeSet::new(),
                },
            ),
            rule(
                "vulnerabilities",
                PolicyCheckV1::Vulnerability {
                    subject: PolicySubjectV1::Target,
                    deny_advisories: BTreeSet::new(),
                    minimum_severity: Some(SeverityV1::High),
                    include_withdrawn: false,
                    max_snapshot_age_days: Some(7),
                    sources: BTreeSet::new(),
                    unknown_severity: UnknownDispositionV1::Indeterminate,
                },
            ),
        ];
        let report = evaluate(
            &bundle(repository()),
            &policy(rules),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Pass, "{report:#?}");
        assert_eq!(report.exit_status.code(), 0);
    }

    #[test]
    fn repository_selector_overrides_global_rule() {
        let global = rule(
            "relation",
            PolicyCheckV1::Relation {
                required: RelationRequirementV1::Transitive,
            },
        );
        let mut selected = rule(
            "relation",
            PolicyCheckV1::Relation {
                required: RelationRequirementV1::Direct,
            },
        );
        selected.selector.repository = Some("acme/app".to_owned());
        let report = evaluate(
            &bundle(repository()),
            &policy(vec![global, selected]),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Pass);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn unmatched_repository_selector_is_indeterminate() {
        let mut selected = rule("resolution", PolicyCheckV1::ExactResolution);
        selected.selector.repository = Some("acme/missing".to_owned());

        let report = evaluate(
            &bundle(repository()),
            &policy(vec![selected]),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );

        assert_eq!(report.decision, PolicyDecisionV1::Indeterminate);
        assert_eq!(report.exit_status.code(), 4);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].repository, "acme/missing");
        assert_eq!(report.findings[0].code, "rule_selector_unmatched");
        assert_eq!(report.findings[0].status, FindingStatusV1::Indeterminate);
        assert!(report.findings[0].blocking);
    }

    #[test]
    fn unknown_dispositions_control_the_report_decision() {
        let mut evidence_repository = repository();
        evidence_repository.completeness = EvidenceCompletenessV1::Partial;
        evidence_repository.exact_resolution_count = 0;
        for (disposition, expected, blocking) in [
            (UnknownDispositionV1::Fail, PolicyDecisionV1::Fail, true),
            (
                UnknownDispositionV1::Indeterminate,
                PolicyDecisionV1::Indeterminate,
                true,
            ),
            (UnknownDispositionV1::Warn, PolicyDecisionV1::Pass, false),
        ] {
            let mut selected = rule("resolution", PolicyCheckV1::ExactResolution);
            selected.unknown = Some(disposition);
            let report = evaluate(
                &bundle(evidence_repository.clone()),
                &policy(vec![selected]),
                &EvaluationContext {
                    evaluated_at: at(13),
                },
            );
            assert_eq!(report.decision, expected);
            assert_eq!(report.findings[0].blocking, blocking);
        }
    }

    #[test]
    fn report_order_is_independent_of_repository_and_rule_input_order() {
        let first = repository();
        let mut second = repository();
        second.repository = "acme/another".to_owned();
        second.explanation.repository = second.repository.clone();
        let mut evidence = bundle(first);
        evidence.repositories.push(second);
        let rules = vec![
            rule("z-resolution", PolicyCheckV1::ExactResolution),
            rule(
                "a-requirement",
                PolicyCheckV1::Requirement {
                    mode: RequirementModeV1::Compatible,
                },
            ),
        ];

        let expected = evaluate(
            &evidence,
            &policy(rules.clone()),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        evidence.repositories.reverse();
        let mut reversed_rules = rules;
        reversed_rules.reverse();
        let actual = evaluate(
            &evidence,
            &policy(reversed_rules),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(actual.findings, expected.findings);
    }

    #[test]
    fn exact_unexpired_exception_waives_a_matching_failure() {
        let selected = rule(
            "msrv",
            PolicyCheckV1::Msrv {
                require_declared: true,
                maximum: Some(Version::new(1, 65, 0)),
            },
        );
        let mut document = policy(vec![selected]);
        document.exceptions.push(PolicyExceptionV1 {
            id: "EX-1".to_owned(),
            rule_id: "msrv".to_owned(),
            subject: PolicyExceptionSubjectV1 {
                repository: "acme/app".to_owned(),
                crate_name: "fs2".to_owned(),
                version: Version::new(0, 4, 3),
            },
            justification: "migration scheduled".to_owned(),
            ticket: "ENG-1".to_owned(),
            approver: "reviewer".to_owned(),
            approved_at: at(12),
            expires_at: at(13) + Duration::days(1),
        });
        let report = evaluate(
            &bundle(repository()),
            &document,
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Pass);
        assert_eq!(report.findings[0].status, FindingStatusV1::Fail);
        assert!(!report.findings[0].blocking);
        assert_eq!(report.exceptions[0].status, ExceptionStatusV1::Applied);
    }

    #[test]
    fn expired_exception_is_reported_and_does_not_waive() {
        let selected = rule(
            "msrv",
            PolicyCheckV1::Msrv {
                require_declared: true,
                maximum: Some(Version::new(1, 65, 0)),
            },
        );
        let mut document = policy(vec![selected]);
        document.exceptions.push(PolicyExceptionV1 {
            id: "EX-OLD".to_owned(),
            rule_id: "msrv".to_owned(),
            subject: PolicyExceptionSubjectV1 {
                repository: "acme/app".to_owned(),
                crate_name: "fs2".to_owned(),
                version: Version::new(0, 4, 3),
            },
            justification: "historical migration".to_owned(),
            ticket: "ENG-OLD".to_owned(),
            approver: "reviewer".to_owned(),
            approved_at: at(11),
            expires_at: at(12),
        });
        let report = evaluate(
            &bundle(repository()),
            &document,
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Fail);
        assert_eq!(report.exceptions[0].status, ExceptionStatusV1::Expired);
        assert!(report.findings[0].blocking);
    }

    #[test]
    fn vulnerability_and_snapshot_age_fail_independently() {
        let mut repository = repository();
        repository.vulnerabilities.push(VulnerabilityEvidenceV1 {
            package: package("fs2", "0.4.3"),
            advisory_id: "RUSTSEC-1".to_owned(),
            source: ADVISORY_SOURCE_RUSTSEC.to_owned(),
            severity: Some(SeverityV1::Critical),
            withdrawn: false,
        });
        let mut evidence = bundle(repository);
        evidence.advisory_snapshots[0].collected_at = at(1);
        let selected = rule(
            "vulnerabilities",
            PolicyCheckV1::Vulnerability {
                subject: PolicySubjectV1::Target,
                deny_advisories: BTreeSet::new(),
                minimum_severity: Some(SeverityV1::High),
                include_withdrawn: false,
                max_snapshot_age_days: Some(5),
                sources: BTreeSet::new(),
                unknown_severity: UnknownDispositionV1::Indeterminate,
            },
        );
        let report = evaluate(
            &evidence,
            &policy(vec![selected]),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Fail);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code.ends_with("snapshot_stale"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "vulnerability_severity_exceeded")
        );
    }

    #[test]
    fn full_graph_policy_is_indeterminate_without_complete_package_inventory() {
        let selected = rule(
            "licenses",
            PolicyCheckV1::License {
                subject: PolicySubjectV1::FullGraph,
                allow: ["MIT".to_owned()].into_iter().collect(),
                deny: BTreeSet::new(),
            },
        );
        let report = evaluate(
            &bundle(repository()),
            &policy(vec![selected]),
            &EvaluationContext {
                evaluated_at: at(13),
            },
        );
        assert_eq!(report.decision, PolicyDecisionV1::Indeterminate);
        assert!(report.findings.iter().any(|finding| {
            finding.code == "full_graph_license_evidence_incomplete"
                && finding.status == FindingStatusV1::Indeterminate
        }));
    }

    #[test]
    fn parses_versioned_toml_policy() {
        let parsed = PolicyDocumentV1::from_toml(
            r#"
schema_version = 1
default_unknown = "fail"

[[rules]]
id = "pin"
type = "requirement"
mode = "exact"
"#,
        )
        .unwrap();
        assert_eq!(parsed.rules[0].check.kind(), PolicyCheckKindV1::Requirement);
    }
}
