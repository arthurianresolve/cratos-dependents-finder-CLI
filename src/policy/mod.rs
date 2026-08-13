//! Pure policy-as-code evaluation over versioned evidence bundles.

mod evaluate;
mod model;
mod spdx;

pub use evaluate::evaluate;
pub use model::{
    EvaluationContext, ExceptionEvaluationV1, ExceptionStatusV1, FindingStatusV1,
    PolicyCheckKindV1, PolicyCheckV1, PolicyDecisionV1, PolicyDiagnosticV1, PolicyDocumentV1,
    PolicyExceptionSubjectV1, PolicyExceptionV1, PolicyExitStatus, PolicyFindingV1, PolicyReportV1,
    PolicyRuleV1, PolicySelectorV1, PolicySubjectV1, RelationRequirementV1, RequirementModeV1,
    UnknownDispositionV1,
};
