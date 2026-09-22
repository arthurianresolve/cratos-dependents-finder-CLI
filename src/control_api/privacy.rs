use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{
    ControlApiState, ControlApiStateError, TrustedProxyAuthenticationV1, authenticate, failure,
    request_id, state_problem, success,
};
use crate::{
    control_auth::{
        ControlPrincipalV1, ControlScopeV1, CredentialProfileAccessV1, CredentialProfileIdV1,
    },
    privacy::{RemovalPlanV1, RemovalScopeV1, SuppressionTargetV1},
};

pub(super) fn routes<S: ControlApiState>() -> Router<S> {
    Router::new()
        .route("/api/v1/privacy/removal-plans", post(plan::<S>))
        .route("/api/v1/privacy/removals", post(remove::<S>))
        .route("/api/v1/privacy/removals/{id}", get(status::<S>))
        .route("/api/v1/privacy/removals/{id}/retry", post(retry::<S>))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalSubmissionV1 {
    pub request_id: String,
    pub plan: RemovalPlanV1,
}

fn allows(principal: &ControlPrincipalV1, scope: &RemovalScopeV1) -> bool {
    if !principal.allows(ControlScopeV1::SystemManage) {
        return false;
    }
    let access = &principal.grant.repository_access;
    match scope {
        RemovalScopeV1::All => {
            access.public && matches!(access.credential_profiles, CredentialProfileAccessV1::All)
        }
        RemovalScopeV1::Public => access.public,
        RemovalScopeV1::CredentialProfile {
            credential_profile_id,
        } => CredentialProfileIdV1::parse(credential_profile_id.clone())
            .is_ok_and(|profile| access.credential_profiles.allows(&profile)),
    }
}

async fn plan<S: ControlApiState>(
    State(state): State<S>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    Json(target): Json<SuppressionTargetV1>,
) -> Response {
    let id = request_id(&headers);
    let Ok(principal) = authenticate(&state, &headers, proxy, Utc::now()).await else {
        return failure(state_problem(
            ControlApiStateError::AuthenticationRejected,
            id,
        ));
    };
    if !allows(&principal, &target.scope) {
        return failure(state_problem(ControlApiStateError::NotFound, id));
    }
    let Some(privacy) = state.privacy() else {
        return failure(state_problem(ControlApiStateError::Unavailable, id));
    };
    match privacy.plan(target).await {
        Ok(plan) => success(StatusCode::OK, id, plan),
        Err(error) => failure(state_problem(removal_error(error), id)),
    }
}

async fn remove<S: ControlApiState>(
    State(state): State<S>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    Json(submission): Json<RemovalSubmissionV1>,
) -> Response {
    let id = request_id(&headers);
    let Ok(principal) = authenticate(&state, &headers, proxy, Utc::now()).await else {
        return failure(state_problem(
            ControlApiStateError::AuthenticationRejected,
            id,
        ));
    };
    if !allows(&principal, &submission.plan.target.scope) {
        return failure(state_problem(ControlApiStateError::NotFound, id));
    }
    let Some(privacy) = state.privacy() else {
        return failure(state_problem(ControlApiStateError::Unavailable, id));
    };
    match privacy.submit(submission.request_id, submission.plan).await {
        Ok(record) => success(StatusCode::ACCEPTED, id, record),
        Err(error) => failure(state_problem(removal_error(error), id)),
    }
}

fn removal_error(error: anyhow::Error) -> ControlApiStateError {
    match error.downcast_ref::<crate::privacy::PrivacyOperationError>() {
        Some(crate::privacy::PrivacyOperationError::Conflict) => ControlApiStateError::Conflict,
        Some(crate::privacy::PrivacyOperationError::InvalidPlan) => {
            ControlApiStateError::ValidationFailed
        }
        None => ControlApiStateError::Unavailable,
    }
}

async fn status<S: ControlApiState>(
    State(state): State<S>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    read_or_retry(state, record_id, headers, proxy, false).await
}

async fn retry<S: ControlApiState>(
    State(state): State<S>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    read_or_retry(state, record_id, headers, proxy, true).await
}

async fn read_or_retry<S: ControlApiState>(
    state: S,
    record_id: String,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    retry: bool,
) -> Response {
    let id = request_id(&headers);
    let Ok(principal) = authenticate(&state, &headers, proxy, Utc::now()).await else {
        return failure(state_problem(
            ControlApiStateError::AuthenticationRejected,
            id,
        ));
    };
    if !principal.allows(ControlScopeV1::SystemManage) {
        return failure(state_problem(ControlApiStateError::NotFound, id));
    }
    let Some(privacy) = state.privacy() else {
        return failure(state_problem(ControlApiStateError::Unavailable, id));
    };
    let Some(record) = privacy
        .status(&record_id)
        .await
        .filter(|record| allows(&principal, &record.target.scope))
    else {
        return failure(state_problem(ControlApiStateError::NotFound, id));
    };
    if !retry {
        return success(StatusCode::OK, id, record);
    }
    match privacy.retry(&record_id).await {
        Ok(record) => success(StatusCode::ACCEPTED, id, record),
        Err(_) => failure(state_problem(ControlApiStateError::Unavailable, id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        catalog::InMemoryInventoryStore,
        control_api::{CoordinatorControlApiState, router},
        control_auth::{
            ControlRoleV1, PrincipalGrantV1, RepositoryAccessV1, ServiceTokenEntropyError,
            ServiceTokenEntropySourceV1, issue_service_token,
        },
        coordinator::{ControlActionV1, ControlCommandV1, TursoCoordinatorStore},
        privacy::PrivacyService,
        secure_cache::EnvelopeKey,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request},
    };
    use chrono::TimeDelta;
    use serde_json::{Value, json};
    use std::{collections::BTreeSet, sync::Arc};
    use tower::ServiceExt as _;

    struct TestEntropy(u8);
    impl ServiceTokenEntropySourceV1 for TestEntropy {
        fn fill_token_entropy(
            &mut self,
            output: &mut [u8; 32],
        ) -> Result<(), ServiceTokenEntropyError> {
            output.fill(self.0);
            Ok(())
        }
    }

    async fn token(
        store: &TursoCoordinatorStore,
        byte: u8,
        role: ControlRoleV1,
        access: RepositoryAccessV1,
    ) -> String {
        let now = Utc::now();
        let issued = issue_service_token(
            &mut TestEntropy(byte),
            PrincipalGrantV1::for_roles(BTreeSet::from([role]), access).unwrap(),
            now - TimeDelta::seconds(1),
            now + TimeDelta::hours(1),
        )
        .unwrap();
        let secret = issued.secret.expose().to_owned();
        store
            .apply_control(ControlCommandV1 {
                schema_version: 1,
                command_id: format!("token-{byte}"),
                expected_generation: None,
                issued_at: now,
                action: ControlActionV1::UpsertServiceToken {
                    record: issued.record,
                },
            })
            .await
            .unwrap();
        secret
    }

    async fn request(
        app: &Router,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn fixture() -> (
        tempfile::TempDir,
        Router,
        Arc<PrivacyService>,
        String,
        String,
        String,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let store = TursoCoordinatorStore::open(
            directory.path().join("coordinator.db"),
            EnvelopeKey::generate("test-key"),
        )
        .await
        .unwrap();
        let inventory = Arc::new(InMemoryInventoryStore::new([55; 32]));
        let privacy = PrivacyService::open(store.clone(), inventory.clone())
            .await
            .unwrap();
        let all_access = RepositoryAccessV1 {
            public: true,
            credential_profiles: CredentialProfileAccessV1::All,
        };
        let admin = token(&store, 1, ControlRoleV1::Admin, all_access.clone()).await;
        let reader = token(&store, 2, ControlRoleV1::InventoryReader, all_access).await;
        let scoped_admin = token(
            &store,
            3,
            ControlRoleV1::Admin,
            RepositoryAccessV1 {
                public: true,
                credential_profiles: CredentialProfileAccessV1::Selected {
                    credential_profile_ids: BTreeSet::from([CredentialProfileIdV1::parse(
                        "allowed",
                    )
                    .unwrap()]),
                },
            },
        )
        .await;
        let state = CoordinatorControlApiState::new(store, inventory, None, true)
            .unwrap()
            .with_privacy(privacy.clone());
        (
            directory,
            router(state),
            privacy,
            admin,
            reader,
            scoped_admin,
        )
    }

    #[tokio::test]
    async fn privacy_routes_authorize_scope_and_enforce_idempotency() {
        let (_directory, app, privacy, admin, reader, scoped_admin) = fixture().await;
        let target = json!({ "repository_id": "42", "scope": { "kind": "public" }, "aliases": [] });
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/api/v1/privacy/removal-plans",
                Some(&reader),
                target.clone()
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert!(
            !request(
                &app,
                Method::POST,
                "/api/v1/privacy/removal-plans",
                None,
                target.clone()
            )
            .await
            .0
            .is_success()
        );
        let mut all = target.clone();
        all["scope"] = json!({ "kind": "all" });
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/api/v1/privacy/removal-plans",
                Some(&scoped_admin),
                all
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let (status, plan) = request(
            &app,
            Method::POST,
            "/api/v1/privacy/removal-plans",
            Some(&admin),
            target.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(privacy.gate.read().await.ledger.records.is_empty());
        let id = uuid::Uuid::new_v4().to_string();
        let submission = json!({ "request_id": id, "plan": plan });
        let first = request(
            &app,
            Method::POST,
            "/api/v1/privacy/removals",
            Some(&admin),
            submission.clone(),
        )
        .await;
        assert_eq!(first.0, StatusCode::ACCEPTED);
        let replay = request(
            &app,
            Method::POST,
            "/api/v1/privacy/removals",
            Some(&admin),
            submission.clone(),
        )
        .await;
        assert_eq!(replay, first);
        let mut conflict = submission;
        conflict["plan"]["target"]["repository_id"] = json!("43");
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/api/v1/privacy/removals",
                Some(&admin),
                conflict
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let status_path = format!("/api/v1/privacy/removals/{id}");
        assert_eq!(
            request(&app, Method::GET, &status_path, Some(&reader), Value::Null)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            request(&app, Method::GET, &status_path, Some(&admin), Value::Null)
                .await
                .0,
            StatusCode::OK
        );
        let denied_target = json!({ "repository_id": "42", "scope": { "kind": "credential_profile", "credential_profile_id": "denied" }, "aliases": [] });
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/api/v1/privacy/removal-plans",
                Some(&scoped_admin),
                denied_target
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let mut invalid = target;
        invalid["repository_id"] = json!("*");
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/api/v1/privacy/removal-plans",
                Some(&admin),
                invalid
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(privacy.gate.read().await.ledger.records.len(), 1);
    }

    #[tokio::test]
    async fn accepted_removal_waits_for_read_side_publication_boundary() {
        let (_directory, app, privacy, admin, _reader, _scoped_admin) = fixture().await;
        let target = json!({ "repository_id": "42", "scope": { "kind": "public" }, "aliases": [] });
        let (_, plan) = request(
            &app,
            Method::POST,
            "/api/v1/privacy/removal-plans",
            Some(&admin),
            target,
        )
        .await;
        let read_side = privacy.gate.read().await;
        let id = uuid::Uuid::new_v4().to_string();
        let submission = json!({ "request_id": id, "plan": plan });
        let call = request(
            &app,
            Method::POST,
            "/api/v1/privacy/removals",
            Some(&admin),
            submission,
        );
        tokio::pin!(call);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut call)
                .await
                .is_err()
        );
        assert!(read_side.ledger.records.is_empty());
        // A read-side response can be serialized before relinquishing this guard.
        let serialized_before_publication =
            serde_json::to_vec(&json!({ "items": ["already-authorized-response"] })).unwrap();
        assert!(!serialized_before_publication.is_empty());
        drop(read_side);
        assert_eq!(call.await.0, StatusCode::ACCEPTED);
        assert_eq!(privacy.gate.read().await.ledger.records.len(), 1);
    }
}
