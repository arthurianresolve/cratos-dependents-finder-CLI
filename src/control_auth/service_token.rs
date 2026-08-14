use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

use super::{
    AuthModelError, ControlPrincipalV1, PrincipalAuthenticationV1, PrincipalGrantV1,
    SCHEMA_VERSION_V1, model::principal_id_for_service_token,
};

const TOKEN_ENTROPY_BYTES: usize = 32;
const TOKEN_PREFIX: &str = "cdr_st_v1_";
const TOKEN_DIGEST_DOMAIN: &[u8] = b"crate-dependent-repos/service-token/digest/v1\0";
const TOKEN_ID_DOMAIN: &[u8] = b"crate-dependent-repos/service-token/id/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceTokenEntropyError;

impl std::fmt::Display for ServiceTokenEntropyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("service-token entropy source failed")
    }
}

impl std::error::Error for ServiceTokenEntropyError {}

/// Entropy adapter supplied by the executable boundary.
///
/// Production implementations must use an operating-system cryptographic RNG.
/// Keeping the source outside this module avoids silently substituting a weak
/// or deterministic generator when no RNG crate is configured.
pub trait ServiceTokenEntropySourceV1 {
    fn fill_token_entropy(
        &mut self,
        output: &mut [u8; TOKEN_ENTROPY_BYTES],
    ) -> Result<(), ServiceTokenEntropyError>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ServiceTokenIdV1(String);

impl ServiceTokenIdV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self, ServiceTokenIssueError> {
        let value = value.into();
        let suffix = value
            .strip_prefix("st_")
            .ok_or(ServiceTokenIssueError::InvalidRecord)?;
        if suffix.len() != 32 || !suffix.bytes().all(is_lower_hex) {
            return Err(ServiceTokenIssueError::InvalidRecord);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ServiceTokenIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ServiceTokenDigestV1([u8; 32]);

impl std::fmt::Debug for ServiceTokenDigestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceTokenDigestV1([REDACTED])")
    }
}

impl Serialize for ServiceTokenDigestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(&self.0))
    }
}

impl<'de> Deserialize<'de> for ServiceTokenDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        decode_hex_32(&String::deserialize(deserializer)?)
            .map(Self)
            .ok_or_else(|| D::Error::custom("invalid service-token SHA-256 digest"))
    }
}

pub struct ServiceTokenSecretV1(String);

impl ServiceTokenSecretV1 {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ServiceTokenSecretV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ServiceTokenSecretV1([REDACTED])")
    }
}

impl Drop for ServiceTokenSecretV1 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceTokenRecordV1 {
    pub schema_version: u16,
    pub id: ServiceTokenIdV1,
    pub principal: ControlPrincipalV1,
    pub digest: ServiceTokenDigestV1,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ServiceTokenRecordV1 {
    pub fn validate(&self) -> Result<(), ServiceTokenIssueError> {
        if self.schema_version != SCHEMA_VERSION_V1 || self.expires_at <= self.issued_at {
            return Err(ServiceTokenIssueError::InvalidRecord);
        }
        self.principal.validate()?;
        match &self.principal.authentication {
            PrincipalAuthenticationV1::ServiceToken { token_id }
                if token_id == self.id.as_str()
                    && self.principal.id.as_str()
                        == principal_id_for_service_token(self.id.as_str())
                            .expect("validated service-token IDs produce valid principal IDs")
                            .as_str() =>
            {
                Ok(())
            }
            PrincipalAuthenticationV1::ServiceToken { .. }
            | PrincipalAuthenticationV1::Oidc { .. } => Err(ServiceTokenIssueError::InvalidRecord),
        }
    }

    pub fn revoke(&mut self, revoked_at: DateTime<Utc>) {
        if self.revoked_at.is_none() {
            self.revoked_at = Some(revoked_at);
        }
    }

    pub fn verify(
        &self,
        presented_token: &str,
        now: DateTime<Utc>,
    ) -> Result<&ControlPrincipalV1, ServiceTokenVerificationError> {
        self.validate()
            .map_err(|_| ServiceTokenVerificationError::Invalid)?;
        let entropy = parse_token(presented_token).ok_or(ServiceTokenVerificationError::Invalid)?;
        let presented_digest = digest(TOKEN_DIGEST_DOMAIN, &entropy);
        if !constant_work_eq_32(&presented_digest, &self.digest.0) {
            return Err(ServiceTokenVerificationError::Invalid);
        }
        if self.revoked_at.is_some() {
            return Err(ServiceTokenVerificationError::Revoked);
        }
        if now < self.issued_at {
            return Err(ServiceTokenVerificationError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(ServiceTokenVerificationError::Expired);
        }
        Ok(&self.principal)
    }
}

#[derive(Debug)]
pub struct IssuedServiceTokenV1 {
    pub secret: ServiceTokenSecretV1,
    pub record: ServiceTokenRecordV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceTokenIssueError {
    EntropyUnavailable,
    InvalidLifetime,
    InvalidRecord,
    InvalidGrant(AuthModelError),
}

impl std::fmt::Display for ServiceTokenIssueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EntropyUnavailable => formatter.write_str("service-token entropy is unavailable"),
            Self::InvalidLifetime => formatter.write_str("service-token lifetime is invalid"),
            Self::InvalidRecord => formatter.write_str("service-token record is invalid"),
            Self::InvalidGrant(error) => {
                write!(formatter, "service-token grant is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for ServiceTokenIssueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidGrant(error) => Some(error),
            Self::EntropyUnavailable | Self::InvalidLifetime | Self::InvalidRecord => None,
        }
    }
}

impl From<AuthModelError> for ServiceTokenIssueError {
    fn from(value: AuthModelError) -> Self {
        Self::InvalidGrant(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceTokenVerificationError {
    Invalid,
    NotYetValid,
    Expired,
    Revoked,
}

impl std::fmt::Display for ServiceTokenVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("service token was not accepted")
    }
}

impl std::error::Error for ServiceTokenVerificationError {}

pub fn issue_service_token(
    entropy_source: &mut impl ServiceTokenEntropySourceV1,
    grant: PrincipalGrantV1,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<IssuedServiceTokenV1, ServiceTokenIssueError> {
    if expires_at <= issued_at {
        return Err(ServiceTokenIssueError::InvalidLifetime);
    }
    grant.validate()?;

    let mut entropy = [0_u8; TOKEN_ENTROPY_BYTES];
    entropy_source
        .fill_token_entropy(&mut entropy)
        .map_err(|_| ServiceTokenIssueError::EntropyUnavailable)?;

    let id_digest = digest(TOKEN_ID_DOMAIN, &entropy);
    let id = ServiceTokenIdV1(format!("st_{}", encode_hex(&id_digest[..16])));
    let principal = ControlPrincipalV1 {
        schema_version: SCHEMA_VERSION_V1,
        id: principal_id_for_service_token(id.as_str())
            .expect("derived service-token IDs produce valid principal IDs"),
        authentication: PrincipalAuthenticationV1::ServiceToken {
            token_id: id.as_str().to_owned(),
        },
        grant,
    };
    let record = ServiceTokenRecordV1 {
        schema_version: SCHEMA_VERSION_V1,
        id,
        principal,
        digest: ServiceTokenDigestV1(digest(TOKEN_DIGEST_DOMAIN, &entropy)),
        issued_at,
        expires_at,
        revoked_at: None,
    };
    let secret = ServiceTokenSecretV1(format!("{TOKEN_PREFIX}{}", encode_hex(&entropy)));
    entropy.zeroize();
    record.validate()?;

    Ok(IssuedServiceTokenV1 { secret, record })
}

/// Derive the digest-only record identifier from a presented service token.
///
/// This lets an authentication adapter perform one indexed record lookup
/// before [`ServiceTokenRecordV1::verify`] performs the secret comparison.
/// Invalid encodings deliberately return the same verification error as an
/// unknown token so callers do not expose token-record existence.
pub fn service_token_id_from_presented(
    presented_token: &str,
) -> Result<ServiceTokenIdV1, ServiceTokenVerificationError> {
    let mut entropy = parse_token(presented_token).ok_or(ServiceTokenVerificationError::Invalid)?;
    let id_digest = digest(TOKEN_ID_DOMAIN, &entropy);
    entropy.zeroize();
    Ok(ServiceTokenIdV1(format!(
        "st_{}",
        encode_hex(&id_digest[..16])
    )))
}

fn parse_token(value: &str) -> Option<[u8; TOKEN_ENTROPY_BYTES]> {
    let encoded = value.strip_prefix(TOKEN_PREFIX)?;
    decode_hex_32(encoded)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Fixed-work comparison for two SHA-256 values.
///
/// This has no data-dependent early exit. An audited constant-time primitive
/// should replace it if one is added as a direct dependency.
fn constant_work_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::TimeDelta;

    use super::*;
    use crate::control_auth::{ControlRoleV1, RepositoryAccessV1};

    struct FixedEntropy([u8; TOKEN_ENTROPY_BYTES]);

    impl ServiceTokenEntropySourceV1 for FixedEntropy {
        fn fill_token_entropy(
            &mut self,
            output: &mut [u8; TOKEN_ENTROPY_BYTES],
        ) -> Result<(), ServiceTokenEntropyError> {
            *output = self.0;
            Ok(())
        }
    }

    fn issue() -> IssuedServiceTokenV1 {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let grant = PrincipalGrantV1::for_roles(
            BTreeSet::from([ControlRoleV1::InventoryReader]),
            RepositoryAccessV1::public_only(),
        )
        .unwrap();
        issue_service_token(
            &mut FixedEntropy([0x5a; TOKEN_ENTROPY_BYTES]),
            grant,
            now,
            now + TimeDelta::hours(1),
        )
        .unwrap()
    }

    #[test]
    fn issued_secret_is_returned_once_but_never_stored() {
        let issued = issue();
        assert_eq!(
            service_token_id_from_presented(issued.secret.expose()).unwrap(),
            issued.record.id
        );
        let stored = serde_json::to_string(&issued.record).unwrap();

        assert!(issued.secret.expose().starts_with(TOKEN_PREFIX));
        assert!(!stored.contains(issued.secret.expose()));
        assert_eq!(
            format!("{:?}", issued.secret),
            "ServiceTokenSecretV1([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", issued.record.digest),
            "ServiceTokenDigestV1([REDACTED])"
        );
    }

    #[test]
    fn verification_checks_digest_lifetime_and_revocation() {
        let mut issued = issue();
        let token = issued.secret.expose().to_owned();
        let now = issued.record.issued_at + TimeDelta::minutes(1);

        assert!(issued.record.verify(&token, now).is_ok());
        assert_eq!(
            issued.record.verify(
                "cdr_st_v1_0000000000000000000000000000000000000000000000000000000000000000",
                now,
            ),
            Err(ServiceTokenVerificationError::Invalid)
        );
        assert_eq!(
            issued.record.verify(&token, issued.record.expires_at),
            Err(ServiceTokenVerificationError::Expired)
        );

        issued.record.revoke(now);
        assert_eq!(
            issued.record.verify(&token, now),
            Err(ServiceTokenVerificationError::Revoked)
        );
    }
}
