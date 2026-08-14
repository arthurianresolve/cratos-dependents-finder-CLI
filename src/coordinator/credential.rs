//! Broker-backed, short-lived credentials for private repository analysis.

use std::{fmt, future::Future, pin::Pin};

use chrono::{DateTime, TimeDelta, Utc};
use futures::StreamExt as _;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

const MINIMUM_TOKEN_LIFETIME_SECONDS: i64 = 30;
const MAXIMUM_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60;
const MAX_BROKER_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialProfileV1 {
    pub schema_version: u16,
    pub id: String,
    pub provider: String,
    pub provider_host: String,
    pub secret_reference: String,
    pub principal_fingerprint: String,
    pub secret_version: String,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CredentialProfileV1 {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), CredentialError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(CredentialError::UnsupportedSchema(self.schema_version));
        }
        for (name, value) in [
            ("profile ID", self.id.as_str()),
            ("provider", self.provider.as_str()),
            ("provider host", self.provider_host.as_str()),
            ("secret reference", self.secret_reference.as_str()),
            ("principal fingerprint", self.principal_fingerprint.as_str()),
            ("secret version", self.secret_version.as_str()),
        ] {
            validate_normalized(name, value)?;
        }
        if self.expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(CredentialError::ProfileExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialRequestV1 {
    pub schema_version: u16,
    pub profile_id: String,
    pub secret_reference: String,
    pub expected_principal_fingerprint: String,
    pub expected_secret_version: String,
    pub agent_id: String,
    /// Upper bound supplied by the task/lease adapter. Brokers must never
    /// return a credential that remains valid beyond this instant.
    pub not_after: DateTime<Utc>,
}

impl CredentialRequestV1 {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn for_profile(
        profile: &CredentialProfileV1,
        agent_id: impl Into<String>,
        not_after: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            profile_id: profile.id.clone(),
            secret_reference: profile.secret_reference.clone(),
            expected_principal_fingerprint: profile.principal_fingerprint.clone(),
            expected_secret_version: profile.secret_version.clone(),
            agent_id: agent_id.into(),
            not_after: profile
                .expires_at
                .map_or(not_after, |profile_expiry| profile_expiry.min(not_after)),
        }
    }

    fn validate(&self) -> Result<(), CredentialError> {
        if self.schema_version != Self::SCHEMA_VERSION {
            return Err(CredentialError::UnsupportedSchema(self.schema_version));
        }
        for (name, value) in [
            ("profile ID", self.profile_id.as_str()),
            ("secret reference", self.secret_reference.as_str()),
            (
                "expected principal fingerprint",
                self.expected_principal_fingerprint.as_str(),
            ),
            (
                "expected secret version",
                self.expected_secret_version.as_str(),
            ),
            ("agent ID", self.agent_id.as_str()),
        ] {
            validate_normalized(name, value)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct BrokerCredential {
    token: Zeroizing<String>,
    pub principal_fingerprint: String,
    pub secret_version: String,
    pub expires_at: DateTime<Utc>,
}

impl BrokerCredential {
    pub fn expose_token(&self) -> &str {
        self.token.as_str()
    }
}

pub type CredentialFuture =
    Pin<Box<dyn Future<Output = Result<BrokerCredential, CredentialError>> + Send + 'static>>;

/// Short-lived credential seam. Implementations may talk to Vault, a cloud
/// secret broker, or a deterministic fake without changing worker logic.
pub trait CredentialBroker: Send + Sync {
    fn issue(&self, request: CredentialRequestV1, now: DateTime<Utc>) -> CredentialFuture;
}

#[derive(Clone)]
pub struct HttpCredentialBroker {
    client: reqwest::Client,
    issue_endpoint: Url,
}

impl HttpCredentialBroker {
    pub fn new(client: reqwest::Client, issue_endpoint: Url) -> Result<Self, CredentialError> {
        if issue_endpoint.scheme() != "https" {
            return Err(CredentialError::InsecureBrokerEndpoint);
        }
        Ok(Self {
            client,
            issue_endpoint,
        })
    }
}

impl CredentialBroker for HttpCredentialBroker {
    fn issue(&self, request: CredentialRequestV1, now: DateTime<Utc>) -> CredentialFuture {
        let client = self.client.clone();
        let endpoint = self.issue_endpoint.clone();
        Box::pin(async move {
            request.validate()?;
            let response = client
                .post(endpoint)
                .json(&request)
                .send()
                .await
                .map_err(CredentialError::Transport)?;
            if response.status() != StatusCode::OK {
                return Err(CredentialError::BrokerRejected(response.status()));
            }
            if response
                .content_length()
                .is_some_and(|length| length > MAX_BROKER_RESPONSE_BYTES)
            {
                return Err(CredentialError::ResponseTooLarge);
            }
            let bytes = read_bounded_response(response).await?;
            let response: BrokerCredentialResponseV1 =
                serde_json::from_slice(&bytes).map_err(CredentialError::InvalidResponse)?;
            validate_response(&request, response, now)
        })
    }
}

async fn read_bounded_response(response: reqwest::Response) -> Result<Vec<u8>, CredentialError> {
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(CredentialError::Transport)?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or(CredentialError::ResponseTooLarge)?;
        if next_length as u64 > MAX_BROKER_RESPONSE_BYTES {
            return Err(CredentialError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Deserialize)]
struct BrokerCredentialResponseV1 {
    schema_version: u16,
    access_token: String,
    principal_fingerprint: String,
    secret_version: String,
    expires_at: DateTime<Utc>,
}

fn validate_response(
    request: &CredentialRequestV1,
    response: BrokerCredentialResponseV1,
    now: DateTime<Utc>,
) -> Result<BrokerCredential, CredentialError> {
    if response.schema_version != CredentialRequestV1::SCHEMA_VERSION {
        return Err(CredentialError::UnsupportedSchema(response.schema_version));
    }
    if response.access_token.trim().is_empty() {
        return Err(CredentialError::EmptyToken);
    }
    if response.principal_fingerprint != request.expected_principal_fingerprint {
        return Err(CredentialError::PrincipalMismatch);
    }
    if response.secret_version != request.expected_secret_version {
        return Err(CredentialError::SecretVersionMismatch);
    }
    if response.expires_at < now + TimeDelta::seconds(MINIMUM_TOKEN_LIFETIME_SECONDS) {
        return Err(CredentialError::TokenExpiresTooSoon);
    }
    let maximum_expiry = request
        .not_after
        .min(now + TimeDelta::seconds(MAXIMUM_TOKEN_LIFETIME_SECONDS));
    if response.expires_at > maximum_expiry {
        return Err(CredentialError::TokenExpiresTooLate);
    }
    Ok(BrokerCredential {
        token: Zeroizing::new(response.access_token),
        principal_fingerprint: response.principal_fingerprint,
        secret_version: response.secret_version,
        expires_at: response.expires_at,
    })
}

fn validate_normalized(name: &'static str, value: &str) -> Result<(), CredentialError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.len() > 512
    {
        return Err(CredentialError::InvalidField(name));
    }
    Ok(())
}

#[derive(Debug)]
pub enum CredentialError {
    UnsupportedSchema(u16),
    InvalidField(&'static str),
    ProfileExpired,
    InsecureBrokerEndpoint,
    Transport(reqwest::Error),
    BrokerRejected(StatusCode),
    ResponseTooLarge,
    InvalidResponse(serde_json::Error),
    EmptyToken,
    PrincipalMismatch,
    SecretVersionMismatch,
    TokenExpiresTooSoon,
    TokenExpiresTooLate,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported credential schema {version}")
            }
            Self::InvalidField(name) => write!(formatter, "invalid {name}"),
            Self::ProfileExpired => formatter.write_str("credential profile is expired"),
            Self::InsecureBrokerEndpoint => {
                formatter.write_str("credential broker endpoint must use HTTPS")
            }
            Self::Transport(_) => formatter.write_str("credential broker transport failed"),
            Self::BrokerRejected(status) => {
                write!(
                    formatter,
                    "credential broker rejected the request with {status}"
                )
            }
            Self::ResponseTooLarge => {
                formatter.write_str("credential broker response is too large")
            }
            Self::InvalidResponse(_) => {
                formatter.write_str("credential broker returned an invalid response")
            }
            Self::EmptyToken => formatter.write_str("credential broker returned an empty token"),
            Self::PrincipalMismatch => {
                formatter.write_str("credential principal does not match the configured profile")
            }
            Self::SecretVersionMismatch => {
                formatter.write_str("credential version does not match the configured profile")
            }
            Self::TokenExpiresTooSoon => {
                formatter.write_str("credential broker token expires too soon")
            }
            Self::TokenExpiresTooLate => {
                formatter.write_str("credential broker token exceeds its allowed lifetime")
            }
        }
    }
}

impl std::error::Error for CredentialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::InvalidResponse(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct StaticCredentialBroker {
    response: std::sync::Arc<StaticCredentialResponse>,
}

#[cfg(test)]
#[derive(Debug)]
struct StaticCredentialResponse {
    token: String,
    principal_fingerprint: String,
    secret_version: String,
    lifetime: TimeDelta,
}

#[cfg(test)]
impl StaticCredentialBroker {
    fn new(
        token: impl Into<String>,
        principal_fingerprint: impl Into<String>,
        secret_version: impl Into<String>,
        lifetime: TimeDelta,
    ) -> Self {
        Self {
            response: std::sync::Arc::new(StaticCredentialResponse {
                token: token.into(),
                principal_fingerprint: principal_fingerprint.into(),
                secret_version: secret_version.into(),
                lifetime,
            }),
        }
    }
}

#[cfg(test)]
impl CredentialBroker for StaticCredentialBroker {
    fn issue(&self, request: CredentialRequestV1, now: DateTime<Utc>) -> CredentialFuture {
        let response = self.response.clone();
        Box::pin(async move {
            request.validate()?;
            validate_response(
                &request,
                BrokerCredentialResponseV1 {
                    schema_version: CredentialRequestV1::SCHEMA_VERSION,
                    access_token: response.token.clone(),
                    principal_fingerprint: response.principal_fingerprint.clone(),
                    secret_version: response.secret_version.clone(),
                    expires_at: now + response.lifetime,
                },
                now,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0).unwrap()
    }

    fn request() -> CredentialRequestV1 {
        CredentialRequestV1 {
            schema_version: 1,
            profile_id: "github-app-production".to_owned(),
            secret_reference: "vault://github/installations/42".to_owned(),
            expected_principal_fingerprint: "installation:42".to_owned(),
            expected_secret_version: "7".to_owned(),
            agent_id: "worker-1".to_owned(),
            not_after: now() + TimeDelta::minutes(15),
        }
    }

    #[tokio::test]
    async fn accepts_only_the_configured_principal_and_version() {
        let broker = StaticCredentialBroker::new(
            "secret-token",
            "installation:42",
            "7",
            TimeDelta::minutes(10),
        );
        let credential = broker.issue(request(), now()).await.unwrap();
        assert_eq!(credential.expose_token(), "secret-token");
        assert_eq!(credential.principal_fingerprint, "installation:42");
        assert_eq!(credential.secret_version, "7");
    }

    #[tokio::test]
    async fn rejects_principal_confusion_and_short_lived_tokens() {
        let wrong = StaticCredentialBroker::new(
            "secret-token",
            "installation:other",
            "7",
            TimeDelta::minutes(10),
        );
        assert!(matches!(
            wrong.issue(request(), now()).await,
            Err(CredentialError::PrincipalMismatch)
        ));

        let expiring = StaticCredentialBroker::new(
            "secret-token",
            "installation:42",
            "7",
            TimeDelta::seconds(10),
        );
        assert!(matches!(
            expiring.issue(request(), now()).await,
            Err(CredentialError::TokenExpiresTooSoon)
        ));

        let overlong = StaticCredentialBroker::new(
            "secret-token",
            "installation:42",
            "7",
            TimeDelta::hours(2),
        );
        assert!(matches!(
            overlong.issue(request(), now()).await,
            Err(CredentialError::TokenExpiresTooLate)
        ));
    }

    #[test]
    fn profile_validation_rejects_expired_or_unnormalized_profiles() {
        let mut profile = CredentialProfileV1 {
            schema_version: 1,
            id: "github-app-production".to_owned(),
            provider: "github".to_owned(),
            provider_host: "api.github.com".to_owned(),
            secret_reference: "vault://github/installations/42".to_owned(),
            principal_fingerprint: "installation:42".to_owned(),
            secret_version: "7".to_owned(),
            enabled: true,
            expires_at: None,
            created_at: now(),
            updated_at: now(),
        };
        profile.validate(now()).unwrap();
        profile.id.push(' ');
        assert!(matches!(
            profile.validate(now()),
            Err(CredentialError::InvalidField("profile ID"))
        ));
    }
}
