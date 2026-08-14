//! Product control/read REST API, separate from the worker mTLS protocol.

mod coordinator;
mod product;
mod scheduler;

pub use coordinator::CoordinatorControlApiState;
pub use scheduler::{DurableSchedulerRunner, SchedulerRunReportV1};

use std::{io, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context as _, Result};
use axum::{
    Extension, Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, AddExtension, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Layer as _;
use uuid::Uuid;

use crate::{
    catalog::{
        CATALOG_SCHEMA_VERSION_V1, CatalogError, InventoryAccessV1, InventoryNamespaceV1,
        InventoryPageRequestV1, InventoryPageV1, InventoryProjectionStore, InventoryQueryV1,
        SavedInventoryQueryDraftV1, SavedInventoryQueryRevisionV1,
    },
    control_auth::{
        ApiProblemV1, AuthenticatedProxyIdentityV1, AuthorizedInventoryScopeV1, ControlPrincipalV1,
        ControlScopeV1, InventoryScopeRequestV1, OidcProxyClaimsV1, OidcTrustPolicyV1,
        ProblemCodeV1, RequestIdV1, authorize_inventory_request, authorize_inventory_scope,
        validate_oidc_proxy_claims,
    },
    coordinator::{
        ControlCommandV1, ControlOutcomeV1, CredentialProfileV1, JobId,
        OccurrenceMaterializationV1, RepositorySetContentV1, ScanJobV1, ScanScheduleV1, ScanSpecV1,
        ScheduleId, ScheduleRevisionV1, ScheduleStateV1, SchedulerSnapshotV1, SubmitJobV1,
        SubmitOutcome,
    },
    pki,
};

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const OIDC_CLAIMS_HEADER: HeaderName = HeaderName::from_static("x-cdr-oidc-claims");
const MAX_CONTROL_REQUEST_BYTES: usize = 256 * 1024;
const MAX_EXPLICIT_REPOSITORY_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_OIDC_CLAIMS_HEADER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct ControlServerConfig {
    pub listen: SocketAddr,
    pub ca_certificate: PathBuf,
    pub server_certificate: PathBuf,
    pub server_private_key: PathBuf,
    /// Optional, explicitly allowlisted OIDC reverse proxy. The proxy must
    /// authenticate with this exact mTLS leaf certificate before claims are
    /// accepted from the dedicated header.
    pub trusted_oidc_proxy: Option<TrustedOidcProxyConfigV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedOidcProxyConfigV1 {
    pub schema_version: u16,
    pub proxy_id: String,
    pub certificate_sha256: String,
    pub policy: OidcTrustPolicyV1,
}

impl TrustedOidcProxyConfigV1 {
    pub fn validate(&self) -> Result<(), ControlApiStateError> {
        let fingerprint_valid = self.certificate_sha256.len() == 64
            && self
                .certificate_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        if self.schema_version != 1
            || !fingerprint_valid
            || self.policy.validate().is_err()
            || !self.policy.trusted_proxy_ids.contains(&self.proxy_id)
        {
            return Err(ControlApiStateError::ValidationFailed);
        }
        AuthenticatedProxyIdentityV1::from_authenticated_transport(self.proxy_id.clone())
            .map_err(|_| ControlApiStateError::ValidationFailed)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ControlTlsPeerIdentity {
    certificate_sha256: String,
}

#[derive(Clone, Debug)]
struct PeerIdentityAcceptor {
    inner: RustlsAcceptor,
}

impl<I, S> Accept<I, S> for PeerIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, ControlTlsPeerIdentity>;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .ok_or_else(|| io::Error::other("mTLS peer certificate missing"))?;
            let identity = ControlTlsPeerIdentity {
                certificate_sha256: crate::secure_cache::sha256_hex(certificate.as_ref()),
            };
            Ok((stream, Extension(identity).layer(service)))
        })
    }
}

#[derive(Clone, Debug)]
struct TrustedProxyTransportState {
    proxy: Option<TrustedOidcProxyConfigV1>,
}

/// Serve the product control/read API on a listener distinct from the worker
/// protocol. The listener uses the deployment CA for mutual TLS; service-token
/// or trusted-proxy authentication is still required at the HTTP layer.
pub async fn serve<StateT: ControlApiState>(
    config: ControlServerConfig,
    state: StateT,
) -> Result<()> {
    match (&config.trusted_oidc_proxy, state.oidc_policy()) {
        (Some(proxy), Some(policy)) if proxy.policy == *policy => proxy
            .validate()
            .map_err(|_| anyhow::anyhow!("invalid trusted OIDC proxy configuration"))?,
        (None, None) => {}
        _ => anyhow::bail!("OIDC proxy transport and trust policy must be configured together"),
    }
    let tls = pki::server_config(
        &config.ca_certificate,
        &config.server_certificate,
        &config.server_private_key,
    )?;
    let acceptor = PeerIdentityAcceptor {
        inner: RustlsAcceptor::new(RustlsConfig::from_config(Arc::new(tls))),
    };
    tracing::info!(listen = %config.listen, "control API listening with mutual TLS");
    axum_server::bind(config.listen)
        .acceptor(acceptor)
        .serve(router_with_transport(state, config.trusted_oidc_proxy).into_make_service())
        .await
        .context("serving control API")
}

/// State Interface for the product listener. Durable schedule/job methods can
/// be added here without coupling the listener to the worker coordinator API.
pub trait ControlApiState: Clone + Send + Sync + 'static {
    fn inventory(&self) -> &(dyn InventoryProjectionStore + Send + Sync);

    fn readiness(&self) -> BoxFuture<'_, Result<(), ControlApiStateError>>;

    /// Look up the digest-only service-token record and verify the presented
    /// secret, expiry, and revocation before returning its principal.
    fn authenticate_service_token<'a>(
        &'a self,
        presented_token: &'a str,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<ControlPrincipalV1, ControlApiStateError>>;

    fn oidc_policy(&self) -> Option<&OidcTrustPolicyV1>;

    /// Resolve the already-authorized visibility capability into the catalog's
    /// namespace access record. Implementations may enumerate credential
    /// profiles only when `scope.includes_all_credential_profiles()` is true.
    fn inventory_access<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        scope: &'a AuthorizedInventoryScopeV1,
    ) -> BoxFuture<'a, Result<InventoryAccessV1, ControlApiStateError>>;

    fn scheduler_snapshot(
        &self,
    ) -> BoxFuture<'_, Result<SchedulerSnapshotV1, ControlApiStateError>>;

    fn occurrence_materializations(
        &self,
    ) -> BoxFuture<'_, Result<Vec<OccurrenceMaterializationV1>, ControlApiStateError>>;

    fn schedule<'a>(
        &'a self,
        schedule_id: ScheduleId,
    ) -> BoxFuture<'a, Result<Option<ScanScheduleV1>, ControlApiStateError>>;

    fn schedule_revision<'a>(
        &'a self,
        schedule_id: ScheduleId,
        revision: u64,
    ) -> BoxFuture<'a, Result<Option<ScheduleRevisionV1>, ControlApiStateError>>;

    fn apply_control(
        &self,
        command: ControlCommandV1,
    ) -> BoxFuture<'_, Result<ControlOutcomeV1, ControlApiStateError>>;

    fn jobs(&self) -> BoxFuture<'_, Result<Vec<ScanJobV1>, ControlApiStateError>>;

    fn job<'a>(
        &'a self,
        job_id: JobId,
    ) -> BoxFuture<'a, Result<Option<ScanJobV1>, ControlApiStateError>>;

    fn submit_job_with_repositories<'a>(
        &'a self,
        request: SubmitJobV1,
        repositories: Vec<String>,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<SubmitOutcome, ControlApiStateError>>;

    fn cancel_job<'a>(
        &'a self,
        job_id: JobId,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>>;

    fn resume_job<'a>(
        &'a self,
        job_id: JobId,
        now: DateTime<Utc>,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>>;

    fn repository_set<'a>(
        &'a self,
        digest: &'a crate::coordinator::Sha256Digest,
    ) -> BoxFuture<'a, Result<Option<RepositorySetContentV1>, ControlApiStateError>>;

    fn validate_scan_spec_access<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        spec: &'a ScanSpecV1,
    ) -> BoxFuture<'a, Result<(), ControlApiStateError>>;

    /// Resolve the scheduler's internal catalog capability. Private metadata
    /// is returned only when the deployment opt-in and credential profile are
    /// both active.
    fn scheduler_inventory_access<'a>(
        &'a self,
        spec: &'a ScanSpecV1,
    ) -> BoxFuture<'a, Result<InventoryAccessV1, ControlApiStateError>>;

    /// Filter and redact schedule history before it crosses the API boundary.
    fn authorized_schedules<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        schedules: Vec<ScheduleStateV1>,
    ) -> BoxFuture<'a, Result<Vec<ScheduleStateV1>, ControlApiStateError>>;

    /// Remove jobs whose repository credential scope the principal cannot use.
    fn authorized_jobs<'a>(
        &'a self,
        principal: &'a ControlPrincipalV1,
        jobs: Vec<ScanJobV1>,
    ) -> BoxFuture<'a, Result<Vec<ScanJobV1>, ControlApiStateError>>;

    fn credential_profiles(
        &self,
    ) -> BoxFuture<'_, Result<Vec<CredentialProfileV1>, ControlApiStateError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlApiStateError {
    AuthenticationRejected,
    NotFound,
    Conflict,
    ValidationFailed,
    RateLimited,
    Unavailable,
}

impl std::fmt::Display for ControlApiStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("control API state operation failed")
    }
}

impl std::error::Error for ControlApiStateError {}

/// Claims accepted only from middleware that separately authenticated the
/// reverse proxy transport. Ordinary forwarded headers never construct this.
#[derive(Clone, Debug)]
pub struct TrustedProxyAuthenticationV1 {
    authenticated_proxy: AuthenticatedProxyIdentityV1,
    claims: OidcProxyClaimsV1,
}

impl TrustedProxyAuthenticationV1 {
    pub(crate) fn from_authenticated_transport(
        proxy_id: impl Into<String>,
        claims: OidcProxyClaimsV1,
    ) -> Result<Self, ControlApiStateError> {
        let authenticated_proxy =
            AuthenticatedProxyIdentityV1::from_authenticated_transport(proxy_id)
                .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
        Ok(Self {
            authenticated_proxy,
            claims,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventorySearchRequestV1 {
    pub scope: InventoryScopeRequestV1,
    pub query: InventoryQueryV1,
    #[serde(default)]
    pub page: InventoryPageRequestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InventorySearchResponseV1 {
    pub schema_version: u16,
    pub request_id: RequestIdV1,
    pub page: InventoryPageV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SaveInventoryQueryRequestV1 {
    pub query_id: String,
    pub expected_previous_revision: Option<u64>,
    pub name: String,
    pub namespace: InventoryNamespaceV1,
    pub query: InventoryQueryV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SavedInventoryQueryResponseV1 {
    pub schema_version: u16,
    pub request_id: RequestIdV1,
    pub saved_query: SavedInventoryQueryRevisionV1,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SavedQueryReadParameters {
    revision: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct HealthResponseV1 {
    schema_version: u16,
    status: &'static str,
}

pub fn router<StateT: ControlApiState>(state: StateT) -> Router {
    router_with_transport(state, None)
}

fn router_with_transport<StateT: ControlApiState>(
    state: StateT,
    trusted_oidc_proxy: Option<TrustedOidcProxyConfigV1>,
) -> Router {
    let standard = Router::new()
        .route("/livez", get(liveness))
        .route("/readyz", get(readiness::<StateT>))
        .route("/api/v1/inventory/search", post(search_inventory::<StateT>))
        .route(
            "/api/v1/inventory/saved-queries",
            post(save_inventory_query::<StateT>),
        )
        .route(
            "/api/v1/inventory/saved-queries/{query_id}",
            get(read_saved_query::<StateT>),
        )
        .route("/api/v1/openapi.json", get(openapi))
        .merge(product::standard_routes::<StateT>())
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_CONTROL_REQUEST_BYTES));
    let explicit_repository_routes = product::explicit_repository_routes::<StateT>()
        .layer(DefaultBodyLimit::max(MAX_EXPLICIT_REPOSITORY_REQUEST_BYTES));
    standard
        .merge(explicit_repository_routes)
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            TrustedProxyTransportState {
                proxy: trusted_oidc_proxy,
            },
            authenticate_trusted_proxy_transport,
        ))
}

async fn authenticate_trusted_proxy_transport(
    State(transport): State<TrustedProxyTransportState>,
    peer: Option<Extension<ControlTlsPeerIdentity>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut claim_headers = request.headers().get_all(&OIDC_CLAIMS_HEADER).iter();
    let Some(claims_header) = claim_headers.next() else {
        return next.run(request).await;
    };
    let request_id = request_id(request.headers());
    let authenticated = (|| {
        if claim_headers.next().is_some() {
            return Err(ControlApiStateError::AuthenticationRejected);
        }
        let proxy = transport
            .proxy
            .as_ref()
            .ok_or(ControlApiStateError::AuthenticationRejected)?;
        let peer = peer
            .as_ref()
            .ok_or(ControlApiStateError::AuthenticationRejected)?;
        if !proxy
            .certificate_sha256
            .eq_ignore_ascii_case(&peer.0.certificate_sha256)
        {
            return Err(ControlApiStateError::AuthenticationRejected);
        }
        let claims_json = claims_header
            .to_str()
            .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
        if claims_json.len() > MAX_OIDC_CLAIMS_HEADER_BYTES {
            return Err(ControlApiStateError::AuthenticationRejected);
        }
        let claims = serde_json::from_str::<OidcProxyClaimsV1>(claims_json)
            .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
        TrustedProxyAuthenticationV1::from_authenticated_transport(&proxy.proxy_id, claims)
    })();
    match authenticated {
        Ok(authentication) => {
            request.extensions_mut().insert(authentication);
            next.run(request).await
        }
        Err(error) => failure(authentication_problem(error, request_id)),
    }
}

async fn liveness(headers: HeaderMap) -> Response {
    success(
        StatusCode::OK,
        request_id(&headers),
        HealthResponseV1 {
            schema_version: 1,
            status: "live",
        },
    )
}

async fn readiness<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
) -> Response {
    let request_id = request_id(&headers);
    match state.readiness().await {
        Ok(()) => success(
            StatusCode::OK,
            request_id,
            HealthResponseV1 {
                schema_version: 1,
                status: "ready",
            },
        ),
        Err(_) => failure(ApiProblemV1::new(
            ProblemCodeV1::ServiceUnavailable,
            request_id,
        )),
    }
}

async fn search_inventory<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<InventorySearchRequestV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let request = match payload {
        Ok(Json(request)) => request,
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let principal = match authenticate(&state, &headers, proxy, Utc::now()).await {
        Ok(principal) => principal,
        Err(error) => return failure(authentication_problem(error, request_id)),
    };
    let authorized = match authorize_inventory_request(&principal, &request.scope, request.query) {
        Ok(authorized) => authorized,
        Err(_) => return failure(ApiProblemV1::concealed_not_found(request_id)),
    };
    let (mut query, scope) = authorized.into_parts();
    if let Err(problem) = constrain_query_namespace(&request.scope, &scope, &mut query, &request_id)
    {
        return failure(problem);
    }
    let access = match state.inventory_access(&principal, &scope).await {
        Ok(access) if inventory_access_matches(&principal, &scope, &access) => access,
        Ok(_) | Err(ControlApiStateError::Unavailable) => {
            return failure(ApiProblemV1::new(
                ProblemCodeV1::ServiceUnavailable,
                request_id,
            ));
        }
        Err(ControlApiStateError::AuthenticationRejected | ControlApiStateError::NotFound) => {
            return failure(ApiProblemV1::concealed_not_found(request_id));
        }
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match state
        .inventory()
        .search(&access, &query, &request.page)
        .await
    {
        Ok(page) => success(
            StatusCode::OK,
            request_id.clone(),
            InventorySearchResponseV1 {
                schema_version: CATALOG_SCHEMA_VERSION_V1,
                request_id,
                page,
            },
        ),
        Err(error) => failure(catalog_problem(error, request_id)),
    }
}

async fn save_inventory_query<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    payload: Result<Json<SaveInventoryQueryRequestV1>, JsonRejection>,
) -> Response {
    let request_id = request_id(&headers);
    let request = match payload {
        Ok(Json(request)) => request,
        Err(error) => return failure(json_problem(error, request_id)),
    };
    let principal = match authenticate(&state, &headers, proxy, Utc::now()).await {
        Ok(principal) => principal,
        Err(error) => return failure(authentication_problem(error, request_id)),
    };
    if !principal.allows(ControlScopeV1::SchedulesWrite) {
        return failure(ApiProblemV1::concealed_not_found(request_id));
    }
    let requested_scope = match namespace_scope(&request.namespace, &request_id) {
        Ok(scope) => scope,
        Err(problem) => return failure(problem),
    };
    let authorized_scope = match authorize_inventory_scope(&principal, &requested_scope) {
        Ok(scope) => scope,
        Err(_) => return failure(ApiProblemV1::concealed_not_found(request_id)),
    };
    let access = match state.inventory_access(&principal, &authorized_scope).await {
        Ok(access) if inventory_access_matches(&principal, &authorized_scope, &access) => access,
        Ok(_) | Err(ControlApiStateError::Unavailable) => {
            return failure(ApiProblemV1::new(
                ProblemCodeV1::ServiceUnavailable,
                request_id,
            ));
        }
        Err(ControlApiStateError::AuthenticationRejected | ControlApiStateError::NotFound) => {
            return failure(ApiProblemV1::concealed_not_found(request_id));
        }
        Err(error) => return failure(state_problem(error, request_id)),
    };
    let draft = SavedInventoryQueryDraftV1 {
        schema_version: CATALOG_SCHEMA_VERSION_V1,
        query_id: request.query_id,
        expected_previous_revision: request.expected_previous_revision,
        name: request.name,
        namespace: request.namespace,
        query: request.query,
        created_by: principal.id.as_str().to_owned(),
        created_at: Utc::now(),
    };
    match state.inventory().save_query(&access, draft).await {
        Ok(saved_query) => success(
            StatusCode::CREATED,
            request_id.clone(),
            SavedInventoryQueryResponseV1 {
                schema_version: CATALOG_SCHEMA_VERSION_V1,
                request_id,
                saved_query,
            },
        ),
        Err(error) => failure(catalog_problem(error, request_id)),
    }
}

async fn read_saved_query<StateT: ControlApiState>(
    State(state): State<StateT>,
    Path(query_id): Path<String>,
    parameters: Result<Query<SavedQueryReadParameters>, QueryRejection>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    let request_id = request_id(&headers);
    let parameters = match parameters {
        Ok(Query(parameters)) => parameters,
        Err(_) => {
            return failure(ApiProblemV1::new(
                ProblemCodeV1::ValidationFailed,
                request_id,
            ));
        }
    };
    let principal = match authenticate(&state, &headers, proxy, Utc::now()).await {
        Ok(principal) => principal,
        Err(error) => return failure(authentication_problem(error, request_id)),
    };
    let scope = match authorize_inventory_scope(&principal, &InventoryScopeRequestV1::AllAuthorized)
    {
        Ok(scope) => scope,
        Err(_) => return failure(ApiProblemV1::concealed_not_found(request_id)),
    };
    let access = match state.inventory_access(&principal, &scope).await {
        Ok(access) if inventory_access_matches(&principal, &scope, &access) => access,
        Ok(_) | Err(ControlApiStateError::Unavailable) => {
            return failure(ApiProblemV1::new(
                ProblemCodeV1::ServiceUnavailable,
                request_id,
            ));
        }
        Err(ControlApiStateError::AuthenticationRejected | ControlApiStateError::NotFound) => {
            return failure(ApiProblemV1::concealed_not_found(request_id));
        }
        Err(error) => return failure(state_problem(error, request_id)),
    };
    match state
        .inventory()
        .saved_query(&access, &query_id, parameters.revision)
        .await
    {
        Ok(Some(saved_query)) if saved_query_visible(&scope, &saved_query.namespace) => success(
            StatusCode::OK,
            request_id.clone(),
            SavedInventoryQueryResponseV1 {
                schema_version: CATALOG_SCHEMA_VERSION_V1,
                request_id,
                saved_query,
            },
        ),
        Ok(Some(_)) => failure(ApiProblemV1::concealed_not_found(request_id)),
        Ok(None) | Err(CatalogError::Unauthorized) => {
            failure(ApiProblemV1::concealed_not_found(request_id))
        }
        Err(error) => failure(catalog_problem(error, request_id)),
    }
}

async fn openapi(headers: HeaderMap) -> Response {
    success(StatusCode::OK, request_id(&headers), openapi_document())
}

async fn not_found(headers: HeaderMap) -> Response {
    failure(ApiProblemV1::concealed_not_found(request_id(&headers)))
}

async fn authenticate<StateT: ControlApiState>(
    state: &StateT,
    headers: &HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    now: DateTime<Utc>,
) -> Result<ControlPrincipalV1, ControlApiStateError> {
    let bearer = bearer_token(headers)?;
    let principal = match (bearer, proxy) {
        (Some(token), None) => state.authenticate_service_token(token, now).await,
        (None, Some(Extension(proxy))) => {
            let policy = state
                .oidc_policy()
                .ok_or(ControlApiStateError::AuthenticationRejected)?;
            validate_oidc_proxy_claims(&proxy.authenticated_proxy, proxy.claims, policy, now)
                .map_err(|_| ControlApiStateError::AuthenticationRejected)
        }
        (Some(_), Some(_)) | (None, None) => Err(ControlApiStateError::AuthenticationRejected),
    }?;
    principal
        .validate()
        .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
    Ok(principal)
}

fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, ControlApiStateError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ControlApiStateError::AuthenticationRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| ControlApiStateError::AuthenticationRejected)?;
    let (scheme, token) = value
        .split_once(' ')
        .filter(|(scheme, token)| {
            *scheme == "Bearer" && !token.is_empty() && token.trim() == *token
        })
        .ok_or(ControlApiStateError::AuthenticationRejected)?;
    let _ = scheme;
    Ok(Some(token))
}

fn constrain_query_namespace(
    requested: &InventoryScopeRequestV1,
    authorized: &AuthorizedInventoryScopeV1,
    query: &mut InventoryQueryV1,
    request_id: &RequestIdV1,
) -> Result<(), ApiProblemV1> {
    match requested {
        InventoryScopeRequestV1::PublicOnly => {
            query.namespace = Some(InventoryNamespaceV1::Public);
        }
        InventoryScopeRequestV1::CredentialProfile {
            credential_profile_id,
        } => {
            query.namespace = Some(InventoryNamespaceV1::Private {
                credential_profile_id: credential_profile_id.as_str().to_owned(),
            });
        }
        InventoryScopeRequestV1::AllAuthorized => match &query.namespace {
            Some(InventoryNamespaceV1::Public) if !authorized.includes_public() => {
                return Err(ApiProblemV1::concealed_not_found(request_id.clone()));
            }
            Some(InventoryNamespaceV1::Private {
                credential_profile_id,
            }) => {
                let credential_profile_id = crate::control_auth::CredentialProfileIdV1::parse(
                    credential_profile_id.clone(),
                )
                .map_err(|_| {
                    ApiProblemV1::new(ProblemCodeV1::ValidationFailed, request_id.clone())
                })?;
                if !authorized.includes_credential_profile(&credential_profile_id) {
                    return Err(ApiProblemV1::concealed_not_found(request_id.clone()));
                }
            }
            None if !authorized.includes_public() => {
                return Err(ApiProblemV1::new(
                    ProblemCodeV1::ValidationFailed,
                    request_id.clone(),
                ));
            }
            Some(InventoryNamespaceV1::Public) | None => {}
        },
    }
    Ok(())
}

fn inventory_access_matches(
    principal: &ControlPrincipalV1,
    scope: &AuthorizedInventoryScopeV1,
    access: &InventoryAccessV1,
) -> bool {
    access.validate().is_ok()
        && access.principal_id == principal.id.as_str()
        && access.private_credential_profiles.iter().all(|profile| {
            crate::control_auth::CredentialProfileIdV1::parse(profile.clone())
                .is_ok_and(|profile| scope.includes_credential_profile(&profile))
        })
}

fn namespace_scope(
    namespace: &InventoryNamespaceV1,
    request_id: &RequestIdV1,
) -> Result<InventoryScopeRequestV1, ApiProblemV1> {
    match namespace {
        InventoryNamespaceV1::Public => Ok(InventoryScopeRequestV1::PublicOnly),
        InventoryNamespaceV1::Private {
            credential_profile_id,
        } => crate::control_auth::CredentialProfileIdV1::parse(credential_profile_id.clone())
            .map(
                |credential_profile_id| InventoryScopeRequestV1::CredentialProfile {
                    credential_profile_id,
                },
            )
            .map_err(|_| ApiProblemV1::new(ProblemCodeV1::ValidationFailed, request_id.clone())),
    }
}

fn saved_query_visible(
    scope: &AuthorizedInventoryScopeV1,
    namespace: &InventoryNamespaceV1,
) -> bool {
    match namespace {
        InventoryNamespaceV1::Public => scope.includes_public(),
        InventoryNamespaceV1::Private {
            credential_profile_id,
        } => crate::control_auth::CredentialProfileIdV1::parse(credential_profile_id.clone())
            .is_ok_and(|profile| scope.includes_credential_profile(&profile)),
    }
}

fn request_id(headers: &HeaderMap) -> RequestIdV1 {
    headers
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| RequestIdV1::parse(value.to_owned()).ok())
        .unwrap_or_else(|| {
            RequestIdV1::parse(format!("req-{}", Uuid::new_v4().simple()))
                .expect("UUID request IDs are valid")
        })
}

fn success<T: Serialize>(status: StatusCode, request_id: RequestIdV1, body: T) -> Response {
    let mut response = (status, Json(body)).into_response();
    insert_request_id(&mut response, &request_id);
    response
}

fn failure(problem: ApiProblemV1) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let request_id = problem.request_id.clone();
    let mut response = (status, Json(problem)).into_response();
    insert_request_id(&mut response, &request_id);
    response
}

fn insert_request_id(response: &mut Response, request_id: &RequestIdV1) {
    if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
}

fn authentication_problem(error: ControlApiStateError, request_id: RequestIdV1) -> ApiProblemV1 {
    match error {
        ControlApiStateError::AuthenticationRejected => {
            ApiProblemV1::new(ProblemCodeV1::Unauthorized, request_id)
        }
        ControlApiStateError::Unavailable
        | ControlApiStateError::NotFound
        | ControlApiStateError::Conflict
        | ControlApiStateError::ValidationFailed
        | ControlApiStateError::RateLimited => {
            ApiProblemV1::new(ProblemCodeV1::ServiceUnavailable, request_id)
        }
    }
}

fn state_problem(error: ControlApiStateError, request_id: RequestIdV1) -> ApiProblemV1 {
    match error {
        ControlApiStateError::AuthenticationRejected | ControlApiStateError::NotFound => {
            ApiProblemV1::concealed_not_found(request_id)
        }
        ControlApiStateError::Conflict => ApiProblemV1::new(ProblemCodeV1::Conflict, request_id),
        ControlApiStateError::ValidationFailed => {
            ApiProblemV1::new(ProblemCodeV1::ValidationFailed, request_id)
        }
        ControlApiStateError::RateLimited => {
            ApiProblemV1::new(ProblemCodeV1::RateLimited, request_id)
        }
        ControlApiStateError::Unavailable => {
            ApiProblemV1::new(ProblemCodeV1::ServiceUnavailable, request_id)
        }
    }
}

fn json_problem(error: JsonRejection, request_id: RequestIdV1) -> ApiProblemV1 {
    let code = match error {
        JsonRejection::JsonDataError(_) => ProblemCodeV1::ValidationFailed,
        JsonRejection::JsonSyntaxError(_)
        | JsonRejection::MissingJsonContentType(_)
        | JsonRejection::BytesRejection(_) => ProblemCodeV1::BadRequest,
        _ => ProblemCodeV1::BadRequest,
    };
    ApiProblemV1::new(code, request_id)
}

fn catalog_problem(error: CatalogError, request_id: RequestIdV1) -> ApiProblemV1 {
    let code = match error {
        CatalogError::Unauthorized => return ApiProblemV1::concealed_not_found(request_id),
        CatalogError::UnsupportedSchemaVersion(_)
        | CatalogError::InvalidInput(_)
        | CatalogError::InvalidEvidence(_)
        | CatalogError::CursorInvalid => ProblemCodeV1::ValidationFailed,
        CatalogError::CursorStale | CatalogError::RevisionConflict { .. } => {
            ProblemCodeV1::Conflict
        }
        CatalogError::StoreUnavailable => ProblemCodeV1::ServiceUnavailable,
    };
    ApiProblemV1::new(code, request_id)
}

pub fn openapi_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "crate-dependent-repos control API",
            "version": "1.0.0"
        },
        "paths": {
            "/livez": { "get": { "operationId": "liveness", "responses": { "200": { "description": "process is live" } } } },
            "/readyz": { "get": { "operationId": "readiness", "responses": { "200": { "description": "dependencies are ready" }, "503": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/inventory/search": {
                "post": {
                    "operationId": "searchInventory",
                    "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/InventorySearchRequestV1" } } } },
                    "responses": { "200": { "description": "authorized inventory page" }, "401": { "$ref": "#/components/responses/Problem" }, "404": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/inventory/saved-queries": {
                "post": {
                    "operationId": "saveInventoryQuery",
                    "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SaveInventoryQueryRequestV1" } } } },
                    "responses": { "201": { "description": "saved query revision" }, "409": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/inventory/saved-queries/{query_id}": {
                "get": {
                    "operationId": "readSavedInventoryQuery",
                    "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }],
                    "parameters": [
                        { "name": "query_id", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "revision", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1 } }
                    ],
                    "responses": { "200": { "description": "saved query revision" }, "404": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/schedules": {
                "get": {
                    "operationId": "listSchedules",
                    "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }],
                    "responses": { "200": { "description": "authorized schedules" }, "401": { "$ref": "#/components/responses/Problem" }, "503": { "$ref": "#/components/responses/Problem" } }
                },
                "post": {
                    "operationId": "createSchedule",
                    "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }],
                    "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateScheduleRequestV1" } } } },
                    "responses": { "201": { "description": "schedule created" }, "409": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" }, "429": { "$ref": "#/components/responses/Problem" }, "503": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/schedules/{schedule_id}": {
                "get": { "operationId": "readSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "authorized schedule" }, "404": { "$ref": "#/components/responses/Problem" } } },
                "put": { "operationId": "reviseSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "schedule revised" }, "409": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" }, "429": { "$ref": "#/components/responses/Problem" }, "503": { "$ref": "#/components/responses/Problem" } } },
                "delete": { "operationId": "deleteSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }], "responses": { "204": { "description": "schedule deleted" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } }
            },
            "/api/v1/schedules/{schedule_id}/enable": { "post": { "operationId": "enableSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "schedule enabled" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/schedules/{schedule_id}/disable": { "post": { "operationId": "disableSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "schedule disabled" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/schedules/{schedule_id}/trigger": { "post": { "operationId": "triggerSchedule", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "202": { "description": "occurrence planned" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/jobs": {
                "get": { "operationId": "listJobs", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "authorized jobs" }, "503": { "$ref": "#/components/responses/Problem" } } },
                "post": { "operationId": "submitJob", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }], "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubmitJobRequestV1" } } } }, "responses": { "201": { "description": "job created" }, "409": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" }, "429": { "$ref": "#/components/responses/Problem" }, "503": { "$ref": "#/components/responses/Problem" } } }
            },
            "/api/v1/jobs/{job_id}": { "get": { "operationId": "readJob", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "authorized job" }, "404": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/jobs/{job_id}/cancel": { "post": { "operationId": "cancelJob", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "job cancelled" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/jobs/{job_id}/resume": { "post": { "operationId": "resumeJob", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "job resumed" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" }, "429": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/credential-profiles": { "get": { "operationId": "listCredentialProfiles", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "responses": { "200": { "description": "authorized credential profile metadata" }, "404": { "$ref": "#/components/responses/Problem" }, "503": { "$ref": "#/components/responses/Problem" } } } },
            "/api/v1/credential-profiles/{profile_id}": {
                "put": { "operationId": "upsertCredentialProfile", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "credential profile metadata stored" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" }, "422": { "$ref": "#/components/responses/Problem" } } },
                "delete": { "operationId": "revokeCredentialProfile", "security": [{ "serviceToken": [] }, { "trustedProxyOidc": [] }], "parameters": [{ "name": "Idempotency-Key", "in": "header", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "credential profile disabled" }, "404": { "$ref": "#/components/responses/Problem" }, "409": { "$ref": "#/components/responses/Problem" } } }
            },
            "/api/v1/openapi.json": { "get": { "operationId": "openApiDocument", "responses": { "200": { "description": "OpenAPI 3.1 document" } } } }
        },
        "components": {
            "securitySchemes": {
                "serviceToken": { "type": "http", "scheme": "bearer", "bearerFormat": "cdr_st_v1" },
                "trustedProxyOidc": { "type": "mutualTLS", "description": "The listener matches the proxy mTLS leaf SHA-256 before accepting one X-CDR-OIDC-Claims JSON header. The proxy must strip and replace that header; ordinary forwarding headers never establish identity." }
            },
            "schemas": {
                "InventorySearchRequestV1": { "type": "object", "required": ["scope", "query"], "properties": { "scope": { "type": "object" }, "query": { "type": "object" }, "page": { "type": "object" } } },
                "SaveInventoryQueryRequestV1": { "type": "object", "required": ["query_id", "name", "namespace", "query"], "properties": { "query_id": { "type": "string" }, "expected_previous_revision": { "type": ["integer", "null"] }, "name": { "type": "string" }, "namespace": { "type": "object" }, "query": { "type": "object" } } },
                "CreateScheduleRequestV1": { "type": "object", "required": ["schema_version", "schedule_id", "enabled", "definition"] },
                "SubmitJobRequestV1": { "type": "object", "required": ["schema_version", "spec", "repositories"], "properties": { "repositories": { "type": "array", "maxItems": 10000, "items": { "type": "string" } } } },
                "CredentialProfileV1": { "type": "object", "description": "metadata-only external broker profile; no credential material is accepted or returned" },
                "ApiProblemV1": { "type": "object", "required": ["schema_version", "type", "title", "status", "code", "detail", "request_id"] }
            },
            "responses": {
                "Problem": { "description": "stable problem response", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiProblemV1" } } } }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn openapi_covers_every_control_read_route() {
        let document = openapi_document();
        let paths = document["paths"].as_object().unwrap();
        for path in [
            "/livez",
            "/readyz",
            "/api/v1/inventory/search",
            "/api/v1/inventory/saved-queries",
            "/api/v1/inventory/saved-queries/{query_id}",
            "/api/v1/schedules",
            "/api/v1/schedules/{schedule_id}",
            "/api/v1/schedules/{schedule_id}/enable",
            "/api/v1/schedules/{schedule_id}/disable",
            "/api/v1/schedules/{schedule_id}/trigger",
            "/api/v1/jobs",
            "/api/v1/jobs/{job_id}",
            "/api/v1/jobs/{job_id}/cancel",
            "/api/v1/jobs/{job_id}/resume",
            "/api/v1/credential-profiles",
            "/api/v1/credential-profiles/{profile_id}",
            "/api/v1/openapi.json",
        ] {
            assert!(paths.contains_key(path));
        }
        assert_eq!(document["openapi"], "3.1.0");
    }

    #[test]
    fn bearer_parser_rejects_ambiguous_or_noncanonical_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert_eq!(bearer_token(&headers).unwrap(), Some("token"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer token"),
        );
        assert_eq!(
            bearer_token(&headers),
            Err(ControlApiStateError::AuthenticationRejected)
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(
            bearer_token(&headers),
            Err(ControlApiStateError::AuthenticationRejected)
        );
    }

    #[test]
    fn trusted_proxy_configuration_binds_policy_to_certificate_identity() {
        let mut configuration = TrustedOidcProxyConfigV1 {
            schema_version: 1,
            proxy_id: "proxy-a".to_owned(),
            certificate_sha256: "ab".repeat(32),
            policy: OidcTrustPolicyV1 {
                schema_version: 1,
                trusted_proxy_ids: BTreeSet::from(["proxy-a".to_owned()]),
                issuer: "https://issuer.example".to_owned(),
                audience: "crate-dependent-repos".to_owned(),
                max_clock_skew_seconds: 30,
            },
        };
        assert_eq!(configuration.validate(), Ok(()));

        configuration.certificate_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            configuration.validate(),
            Err(ControlApiStateError::ValidationFailed)
        );
    }
}
