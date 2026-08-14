//! Optional admission Interface for individual GitHub HTTP attempts.

use std::fmt;

use chrono::{DateTime, TimeDelta, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProviderV1 {
    GitHub,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRequestResourceV1 {
    Core,
    Search,
}

impl GitHubRequestResourceV1 {
    pub fn provider_resource(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Search => "search",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitHubRequestAttemptV1 {
    pub provider: OutboundProviderV1,
    pub resource: GitHubRequestResourceV1,
    /// One-based attempt number within the client retry loop.
    pub attempt: u8,
    pub max_attempts: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRateResourceV1 {
    Core,
    Search,
    Graphql,
    CodeSearch,
    Other,
}

impl GitHubRateResourceV1 {
    pub(crate) fn from_header(value: &str) -> Self {
        match value {
            "core" => Self::Core,
            "search" => Self::Search,
            "graphql" => Self::Graphql,
            "code_search" => Self::CodeSearch,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitHubRequestRateLimitV1 {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub used: Option<u64>,
    pub reset_epoch: Option<u64>,
    pub resource: Option<GitHubRateResourceV1>,
    pub retry_after_seconds: Option<u64>,
    pub retry_after_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRequestTransportV1 {
    ResponseHeaders,
    ConnectFailure,
    Timeout,
    TransportFailure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GitHubRequestOutcomeV1 {
    pub request: GitHubRequestAttemptV1,
    pub transport: GitHubRequestTransportV1,
    pub status: Option<u16>,
    pub rate_limit: Option<GitHubRequestRateLimitV1>,
}

impl GitHubRequestOutcomeV1 {
    /// Return the earliest useful retry instant carried by a rate-limit
    /// response. This lets a remote gate release the repository task instead
    /// of allowing the GitHub client's retry loop to sleep while it is leased.
    pub fn rate_limit_retry_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let rate = self.rate_limit.as_ref();
        let is_rate_limited = self.status == Some(429)
            || (self.status == Some(403)
                && rate.is_some_and(|rate| {
                    rate.remaining == Some(0)
                        || rate.retry_after_seconds.is_some()
                        || rate.retry_after_at.is_some()
                }));
        if !is_rate_limited {
            return None;
        }

        let retry_at = rate
            .and_then(|rate| rate.retry_after_at)
            .or_else(|| {
                rate.and_then(|rate| rate.retry_after_seconds)
                    .and_then(|seconds| i64::try_from(seconds).ok())
                    .and_then(|seconds| now.checked_add_signed(TimeDelta::seconds(seconds)))
            })
            .or_else(|| {
                rate.and_then(|rate| rate.reset_epoch)
                    .and_then(|epoch| i64::try_from(epoch).ok())
                    .and_then(|epoch| DateTime::<Utc>::from_timestamp(epoch, 0))
            })
            .unwrap_or_else(|| now + TimeDelta::seconds(30));
        Some(retry_at.max(now + TimeDelta::milliseconds(50)))
    }

    /// Retry instant for a distributed worker. Remote workers cooperatively
    /// release their task lease after the first transient transport or server
    /// response; the ungated standalone client retains its local retry loop.
    pub fn cooperative_retry_at(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.rate_limit_retry_at(now).or_else(|| {
            let transient = matches!(
                self.transport,
                GitHubRequestTransportV1::ConnectFailure
                    | GitHubRequestTransportV1::Timeout
                    | GitHubRequestTransportV1::TransportFailure
            ) || self
                .status
                .is_some_and(|status| status == 408 || (500..=599).contains(&status));
            transient.then(|| now + TimeDelta::seconds(1))
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GitHubRequestPermitV1 {
    id: String,
}

impl GitHubRequestPermitV1 {
    pub fn new(id: impl Into<String>) -> Result<Self, GitHubRequestGateError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > 256
            || !id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(GitHubRequestGateError::Protocol);
        }
        Ok(Self { id })
    }

    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for GitHubRequestPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubRequestPermitV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHubRequestGateError {
    Unavailable,
    Rejected,
    /// Admission asked the caller to release any task lease and retry no
    /// earlier than this instant. The gate never sleeps while work is leased.
    DeferredUntil(DateTime<Utc>),
    Protocol,
}

impl fmt::Display for GitHubRequestGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "provider admission is unavailable",
            Self::Rejected => "provider request was not admitted",
            Self::DeferredUntil(_) => "provider request was deferred",
            Self::Protocol => "provider admission protocol failed",
        })
    }
}

impl std::error::Error for GitHubRequestGateError {}

/// Deep asynchronous Interface for provider admission and outcome accounting.
pub trait GitHubRequestGate: Send + Sync {
    fn acquire<'a>(
        &'a self,
        request: GitHubRequestAttemptV1,
    ) -> BoxFuture<'a, Result<GitHubRequestPermitV1, GitHubRequestGateError>>;

    fn finish<'a>(
        &'a self,
        permit: GitHubRequestPermitV1,
        outcome: GitHubRequestOutcomeV1,
    ) -> BoxFuture<'a, Result<(), GitHubRequestGateError>>;
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0).unwrap()
    }

    #[test]
    fn request_resources_have_stable_provider_keys() {
        assert_eq!(GitHubRequestResourceV1::Core.provider_resource(), "core");
        assert_eq!(
            GitHubRequestResourceV1::Search.provider_resource(),
            "search"
        );
    }

    #[test]
    fn rate_limit_retry_prefers_retry_after() {
        let outcome = GitHubRequestOutcomeV1 {
            request: GitHubRequestAttemptV1 {
                provider: OutboundProviderV1::GitHub,
                resource: GitHubRequestResourceV1::Core,
                attempt: 1,
                max_attempts: 3,
            },
            transport: GitHubRequestTransportV1::ResponseHeaders,
            status: Some(429),
            rate_limit: Some(GitHubRequestRateLimitV1 {
                retry_after_seconds: Some(17),
                reset_epoch: Some((now() + TimeDelta::minutes(5)).timestamp() as u64),
                ..GitHubRequestRateLimitV1::default()
            }),
        };
        assert_eq!(
            outcome.rate_limit_retry_at(now()),
            Some(now() + TimeDelta::seconds(17))
        );
    }

    #[test]
    fn ordinary_forbidden_response_does_not_defer() {
        let outcome = GitHubRequestOutcomeV1 {
            request: GitHubRequestAttemptV1 {
                provider: OutboundProviderV1::GitHub,
                resource: GitHubRequestResourceV1::Core,
                attempt: 1,
                max_attempts: 3,
            },
            transport: GitHubRequestTransportV1::ResponseHeaders,
            status: Some(403),
            rate_limit: None,
        };
        assert_eq!(outcome.rate_limit_retry_at(now()), None);
    }

    #[test]
    fn remote_transient_response_releases_the_task_before_local_retry() {
        let outcome = GitHubRequestOutcomeV1 {
            request: GitHubRequestAttemptV1 {
                provider: OutboundProviderV1::GitHub,
                resource: GitHubRequestResourceV1::Core,
                attempt: 1,
                max_attempts: 3,
            },
            transport: GitHubRequestTransportV1::ResponseHeaders,
            status: Some(503),
            rate_limit: None,
        };
        assert_eq!(
            outcome.cooperative_retry_at(now()),
            Some(now() + TimeDelta::seconds(1))
        );
    }
}
