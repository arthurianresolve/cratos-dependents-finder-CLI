use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use super::SCHEMA_VERSION_V1;

const MAX_REQUEST_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RequestIdV1(String);

impl RequestIdV1 {
    pub fn parse(value: impl Into<String>) -> Result<Self, RequestIdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REQUEST_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(RequestIdError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequestIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestIdError;

impl std::fmt::Display for RequestIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request ID is invalid")
    }
}

impl std::error::Error for RequestIdError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemCodeV1 {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    ValidationFailed,
    RateLimited,
    ServiceUnavailable,
    InsufficientStorage,
    InternalError,
}

impl ProblemCodeV1 {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::ValidationFailed => 422,
            Self::RateLimited => 429,
            Self::ServiceUnavailable => 503,
            Self::InsufficientStorage => 507,
            Self::InternalError => 500,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not-found",
            Self::Conflict => "conflict",
            Self::ValidationFailed => "validation-failed",
            Self::RateLimited => "rate-limited",
            Self::ServiceUnavailable => "service-unavailable",
            Self::InsufficientStorage => "insufficient-storage",
            Self::InternalError => "internal-error",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::BadRequest => "Bad request",
            Self::Unauthorized => "Authentication required",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not found",
            Self::Conflict => "Conflict",
            Self::ValidationFailed => "Validation failed",
            Self::RateLimited => "Rate limited",
            Self::ServiceUnavailable => "Service unavailable",
            Self::InsufficientStorage => "Insufficient storage",
            Self::InternalError => "Internal server error",
        }
    }

    fn default_detail(self) -> &'static str {
        match self {
            Self::BadRequest => "the request could not be understood",
            Self::Unauthorized => "valid authentication is required",
            Self::Forbidden => "the requested operation is not permitted",
            Self::NotFound => "the requested resource was not found",
            Self::Conflict => "the request conflicts with current resource state",
            Self::ValidationFailed => "one or more request values are invalid",
            Self::RateLimited => "the request cannot be admitted yet",
            Self::ServiceUnavailable => "a required service is unavailable",
            Self::InsufficientStorage => "the request exceeds available storage capacity",
            Self::InternalError => "the request could not be completed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiProblemV1 {
    pub schema_version: u16,
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub code: ProblemCodeV1,
    pub detail: String,
    pub request_id: RequestIdV1,
}

impl ApiProblemV1 {
    pub fn new(code: ProblemCodeV1, request_id: RequestIdV1) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            type_uri: format!("urn:crate-dependent-repos:problem:{}:v1", code.slug()),
            title: code.title().to_owned(),
            status: code.status(),
            code,
            detail: code.default_detail().to_owned(),
            request_id,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn concealed_not_found(request_id: RequestIdV1) -> Self {
        Self::new(ProblemCodeV1::NotFound, request_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PageV1<Item> {
    pub schema_version: u16,
    pub request_id: RequestIdV1,
    pub items: Vec<Item>,
    pub next_cursor: Option<String>,
}

impl<Item> PageV1<Item> {
    pub fn new(request_id: RequestIdV1, items: Vec<Item>, next_cursor: Option<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1,
            request_id,
            items,
            next_cursor,
        }
    }
}

/// Uniform outward result for both missing and unauthorized resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConcealedNotFoundV1;

impl ConcealedNotFoundV1 {
    pub fn problem(self, request_id: RequestIdV1) -> ApiProblemV1 {
        ApiProblemV1::concealed_not_found(request_id)
    }
}

impl std::fmt::Display for ConcealedNotFoundV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("resource was not found")
    }
}

impl std::error::Error for ConcealedNotFoundV1 {}

/// Return a resource only when it both exists and is visible to the principal.
///
/// The caller must map `ConcealedNotFoundV1` directly to its canonical problem
/// without logging or returning which branch failed.
pub fn visible_or_not_found<Item>(
    item: Option<Item>,
    is_visible: impl FnOnce(&Item) -> bool,
) -> Result<Item, ConcealedNotFoundV1> {
    match item {
        Some(item) if is_visible(&item) => Ok(item),
        Some(_) | None => Err(ConcealedNotFoundV1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id() -> RequestIdV1 {
        RequestIdV1::parse("req-01J8Z9Q2").unwrap()
    }

    #[test]
    fn missing_and_hidden_resources_produce_the_same_problem() {
        let missing = visible_or_not_found::<u8>(None, |_| true)
            .unwrap_err()
            .problem(request_id());
        let hidden = visible_or_not_found(Some(42_u8), |_| false)
            .unwrap_err()
            .problem(request_id());

        assert_eq!(missing, hidden);
        assert_eq!(missing.status, 404);
        assert_eq!(missing.code, ProblemCodeV1::NotFound);
    }

    #[test]
    fn pages_are_keyset_shaped_and_do_not_expose_counts() {
        let page = PageV1::new(request_id(), vec!["repo-a"], Some("opaque".to_owned()));
        let json = serde_json::to_value(page).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["next_cursor"], "opaque");
        assert!(json.get("total").is_none());
        assert!(json.get("count").is_none());
    }

    #[test]
    fn request_ids_are_safe_for_headers_and_logs() {
        assert!(RequestIdV1::parse("request:1234_ab.cd").is_ok());
        assert!(RequestIdV1::parse("request 1234").is_err());
        assert!(RequestIdV1::parse("request\n1234").is_err());
    }
}
