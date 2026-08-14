use std::collections::BTreeSet;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::{
    ControlPrincipalV1, PrincipalAuthenticationV1, PrincipalGrantV1, SCHEMA_VERSION_V1,
    model::principal_id_for_oidc,
};

const MAX_PROXY_ID_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_SUBJECT_BYTES: usize = 512;
const MAX_AUDIENCE_BYTES: usize = 512;
const MAX_CLOCK_SKEW_SECONDS: u32 = 300;

/// Identity established by the control listener's mutually authenticated
/// transport adapter. It is intentionally separate from proxy-supplied claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedProxyIdentityV1 {
    proxy_id: String,
}

impl AuthenticatedProxyIdentityV1 {
    /// Construct only after the transport certificate or equivalent proxy
    /// credential has been authenticated independently of forwarded headers.
    pub(crate) fn from_authenticated_transport(
        proxy_id: impl Into<String>,
    ) -> Result<Self, OidcTrustError> {
        let proxy_id = proxy_id.into();
        if !valid_bounded_value(&proxy_id, MAX_PROXY_ID_BYTES) {
            return Err(OidcTrustError::InvalidPolicy);
        }
        Ok(Self { proxy_id })
    }

    pub fn proxy_id(&self) -> &str {
        &self.proxy_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OidcTrustPolicyV1 {
    pub schema_version: u16,
    pub trusted_proxy_ids: BTreeSet<String>,
    pub issuer: String,
    pub audience: String,
    pub max_clock_skew_seconds: u32,
}

impl OidcTrustPolicyV1 {
    pub fn validate(&self) -> Result<(), OidcTrustError> {
        if self.schema_version != SCHEMA_VERSION_V1
            || self.trusted_proxy_ids.is_empty()
            || self
                .trusted_proxy_ids
                .iter()
                .any(|id| !valid_bounded_value(id, MAX_PROXY_ID_BYTES))
            || !valid_bounded_value(&self.issuer, MAX_ISSUER_BYTES)
            || !valid_bounded_value(&self.audience, MAX_AUDIENCE_BYTES)
            || self.max_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS
        {
            return Err(OidcTrustError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OidcProxyClaimsV1 {
    pub schema_version: u16,
    pub issuer: String,
    pub subject: String,
    pub audiences: BTreeSet<String>,
    pub issued_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub grant: PrincipalGrantV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcTrustError {
    InvalidPolicy,
    UntrustedProxy,
    InvalidClaims,
    ClaimsNotYetValid,
    ClaimsExpired,
}

impl std::fmt::Display for OidcTrustError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("trusted-proxy OIDC claims were not accepted")
    }
}

impl std::error::Error for OidcTrustError {}

pub fn validate_oidc_proxy_claims(
    authenticated_proxy: &AuthenticatedProxyIdentityV1,
    claims: OidcProxyClaimsV1,
    policy: &OidcTrustPolicyV1,
    now: DateTime<Utc>,
) -> Result<ControlPrincipalV1, OidcTrustError> {
    policy.validate()?;
    if !policy
        .trusted_proxy_ids
        .contains(authenticated_proxy.proxy_id())
    {
        return Err(OidcTrustError::UntrustedProxy);
    }
    if claims.schema_version != SCHEMA_VERSION_V1
        || claims.issuer != policy.issuer
        || !claims.audiences.contains(&policy.audience)
        || claims
            .audiences
            .iter()
            .any(|audience| !valid_bounded_value(audience, MAX_AUDIENCE_BYTES))
        || !valid_bounded_value(&claims.subject, MAX_SUBJECT_BYTES)
        || claims.expires_at <= claims.issued_at
        || claims
            .not_before
            .is_some_and(|not_before| not_before >= claims.expires_at)
        || claims.grant.validate().is_err()
    {
        return Err(OidcTrustError::InvalidClaims);
    }

    let clock_skew = TimeDelta::seconds(i64::from(policy.max_clock_skew_seconds));
    let latest_valid_start = now
        .checked_add_signed(clock_skew)
        .ok_or(OidcTrustError::InvalidClaims)?;
    let earliest_valid_expiry = now
        .checked_sub_signed(clock_skew)
        .ok_or(OidcTrustError::InvalidClaims)?;
    if claims.issued_at > latest_valid_start
        || claims
            .not_before
            .is_some_and(|not_before| not_before > latest_valid_start)
    {
        return Err(OidcTrustError::ClaimsNotYetValid);
    }
    if claims.expires_at <= earliest_valid_expiry {
        return Err(OidcTrustError::ClaimsExpired);
    }

    let id = principal_id_for_oidc(&claims.issuer, &claims.subject);
    let principal = ControlPrincipalV1 {
        schema_version: SCHEMA_VERSION_V1,
        id,
        authentication: PrincipalAuthenticationV1::Oidc {
            issuer: claims.issuer,
            subject: claims.subject,
        },
        grant: claims.grant,
    };
    principal
        .validate()
        .map_err(|_| OidcTrustError::InvalidClaims)?;
    Ok(principal)
}

fn valid_bounded_value(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::control_auth::{ControlRoleV1, PrincipalGrantV1, RepositoryAccessV1};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn policy() -> OidcTrustPolicyV1 {
        OidcTrustPolicyV1 {
            schema_version: SCHEMA_VERSION_V1,
            trusted_proxy_ids: BTreeSet::from(["proxy-a".to_owned()]),
            issuer: "https://issuer.example".to_owned(),
            audience: "crate-dependent-repos".to_owned(),
            max_clock_skew_seconds: 30,
        }
    }

    fn claims() -> OidcProxyClaimsV1 {
        OidcProxyClaimsV1 {
            schema_version: SCHEMA_VERSION_V1,
            issuer: "https://issuer.example".to_owned(),
            subject: "user-42".to_owned(),
            audiences: BTreeSet::from(["crate-dependent-repos".to_owned()]),
            issued_at: now() - TimeDelta::minutes(1),
            not_before: None,
            expires_at: now() + TimeDelta::minutes(5),
            grant: PrincipalGrantV1::for_roles(
                BTreeSet::from([ControlRoleV1::InventoryReader]),
                RepositoryAccessV1::public_only(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn transport_identity_is_required_independently_of_claims() {
        let untrusted =
            AuthenticatedProxyIdentityV1::from_authenticated_transport("proxy-b").unwrap();
        assert_eq!(
            validate_oidc_proxy_claims(&untrusted, claims(), &policy(), now()),
            Err(OidcTrustError::UntrustedProxy)
        );
    }

    #[test]
    fn valid_claims_produce_a_stable_non_subject_principal_id() {
        let trusted =
            AuthenticatedProxyIdentityV1::from_authenticated_transport("proxy-a").unwrap();
        let first = validate_oidc_proxy_claims(&trusted, claims(), &policy(), now()).unwrap();
        let second = validate_oidc_proxy_claims(&trusted, claims(), &policy(), now()).unwrap();

        assert_eq!(first.id, second.id);
        assert!(first.id.as_str().starts_with("oidc:"));
        assert!(!first.id.as_str().contains("user-42"));
    }

    #[test]
    fn issuer_audience_and_expiry_are_enforced() {
        let trusted =
            AuthenticatedProxyIdentityV1::from_authenticated_transport("proxy-a").unwrap();
        let mut wrong_audience = claims();
        wrong_audience.audiences.clear();
        assert_eq!(
            validate_oidc_proxy_claims(&trusted, wrong_audience, &policy(), now()),
            Err(OidcTrustError::InvalidClaims)
        );

        let mut expired = claims();
        expired.issued_at = now() - TimeDelta::minutes(2);
        expired.expires_at = now() - TimeDelta::minutes(1);
        assert_eq!(
            validate_oidc_proxy_claims(&trusted, expired, &policy(), now()),
            Err(OidcTrustError::ClaimsExpired)
        );
    }
}
