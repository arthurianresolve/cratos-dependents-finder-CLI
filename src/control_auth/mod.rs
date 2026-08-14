//! Control-plane identity, authentication, authorization, and wire models.
//!
//! Transport adapters authenticate the trusted OIDC proxy or present service
//! tokens. This module turns that transport evidence into validated principals
//! and authorization capabilities. It deliberately has no HTTP-framework or
//! persistence dependency.

mod authorization;
mod model;
mod oidc;
mod rest;
mod service_token;

pub use authorization::{
    AuthorizationDenied, AuthorizedInventoryRequestV1, AuthorizedInventoryScopeV1,
    InventoryScopeRequestV1, authorize_inventory_request, authorize_inventory_scope,
};
pub use model::{
    AuthModelError, ControlPrincipalV1, ControlRoleV1, ControlScopeV1, CredentialProfileAccessV1,
    CredentialProfileIdV1, PrincipalAuthenticationV1, PrincipalGrantV1, PrincipalIdV1,
    RepositoryAccessV1, SCHEMA_VERSION_V1,
};
pub use oidc::{
    AuthenticatedProxyIdentityV1, OidcProxyClaimsV1, OidcTrustError, OidcTrustPolicyV1,
    validate_oidc_proxy_claims,
};
pub use rest::{
    ApiProblemV1, ConcealedNotFoundV1, PageV1, ProblemCodeV1, RequestIdError, RequestIdV1,
    visible_or_not_found,
};
pub use service_token::{
    IssuedServiceTokenV1, ServiceTokenDigestV1, ServiceTokenEntropyError,
    ServiceTokenEntropySourceV1, ServiceTokenIdV1, ServiceTokenIssueError, ServiceTokenRecordV1,
    ServiceTokenSecretV1, ServiceTokenVerificationError, issue_service_token,
    service_token_id_from_presented,
};
