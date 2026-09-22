use axum::{
    Extension, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use chrono::Utc;

use crate::control_auth::ControlScopeV1;

use super::{
    ControlApiState, ControlApiStateError, TrustedProxyAuthenticationV1, authenticate, failure,
    request_id, state_problem, success,
};

pub(super) fn routes<StateT: ControlApiState>() -> Router<StateT> {
    Router::new()
        .route("/api/v1/providers/github", get(status::<StateT>))
        .route("/api/v1/providers/github/resume", post(resume::<StateT>))
}

async fn status<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    provider_action(state, headers, proxy, false).await
}

async fn resume<StateT: ControlApiState>(
    State(state): State<StateT>,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
) -> Response {
    provider_action(state, headers, proxy, true).await
}

async fn provider_action<StateT: ControlApiState>(
    state: StateT,
    headers: HeaderMap,
    proxy: Option<Extension<TrustedProxyAuthenticationV1>>,
    resume: bool,
) -> Response {
    let request_id = request_id(&headers);
    let now = Utc::now();
    let authorized = authenticate(&state, &headers, proxy, now)
        .await
        .and_then(|principal| {
            if principal.allows(ControlScopeV1::SystemManage) {
                Ok(())
            } else {
                Err(ControlApiStateError::NotFound)
            }
        });
    if let Err(error) = authorized {
        return failure(state_problem(error, request_id));
    }
    let result = if resume {
        state.resume_github_provider(now).await
    } else {
        state.github_provider_status().await
    };
    match result {
        Ok(status) => success(StatusCode::OK, request_id, status),
        Err(error) => failure(state_problem(error, request_id)),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use super::*;
    use crate::{
        catalog::InMemoryInventoryStore,
        control_api::CoordinatorControlApiState,
        control_auth::{
            ControlRoleV1, PrincipalGrantV1, RepositoryAccessV1, ServiceTokenEntropyError,
            ServiceTokenEntropySourceV1, issue_service_token,
        },
        coordinator::{ControlActionV1, ControlCommandV1, TursoCoordinatorStore},
        secure_cache::EnvelopeKey,
    };

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

    #[tokio::test]
    async fn provider_control_requires_admin_not_worker_identity() {
        let directory = tempfile::tempdir().unwrap();
        let store = TursoCoordinatorStore::open(
            directory.path().join("state.db"),
            EnvelopeKey::generate("test-key"),
        )
        .await
        .unwrap();
        let state = CoordinatorControlApiState::new(
            store.clone(),
            Arc::new(InMemoryInventoryStore::new([7; 32])),
            None,
            false,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", "operator".parse().unwrap());
        assert_eq!(
            provider_action(state.clone(), headers, None, true)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        let now = Utc::now();
        for (index, role) in [
            ControlRoleV1::Admin,
            ControlRoleV1::InventoryReader,
            ControlRoleV1::ScanOperator,
            ControlRoleV1::Auditor,
        ]
        .into_iter()
        .enumerate()
        {
            let issued = issue_service_token(
                &mut TestEntropy(index as u8 + 1),
                PrincipalGrantV1::for_roles(
                    BTreeSet::from([role]),
                    RepositoryAccessV1::public_only(),
                )
                .unwrap(),
                now,
                now + chrono::TimeDelta::hours(1),
            )
            .unwrap();
            store
                .apply_control(ControlCommandV1 {
                    schema_version: 1,
                    command_id: format!("token-{index}"),
                    expected_generation: None,
                    issued_at: now,
                    action: ControlActionV1::UpsertServiceToken {
                        record: issued.record,
                    },
                })
                .await
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                format!("Bearer {}", issued.secret.expose())
                    .parse()
                    .unwrap(),
            );
            for resume in [false, true] {
                assert_eq!(
                    provider_action(state.clone(), headers.clone(), None, resume)
                        .await
                        .status(),
                    if role == ControlRoleV1::Admin {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    }
                );
            }
        }
    }
}
