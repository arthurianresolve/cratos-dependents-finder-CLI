use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};

use crate::{
    privacy::{LEDGER_KEY_ID, SuppressionLedgerV1},
    secure_cache::EnvelopeKey,
};

/// Standalone scans have no coordinator credential-profile identity. Apply the
/// union of scopes rather than accidentally ignoring a private suppression.
pub(super) struct StandaloneSuppression {
    path: PathBuf,
    key_path: PathBuf,
    key: EnvelopeKey,
    deployment_id: String,
    revision: u64,
    repositories: BTreeSet<String>,
    aliases: BTreeSet<String>,
}

#[derive(Debug)]
pub struct RepositorySuppressed;

impl fmt::Display for RepositorySuppressed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("repository is excluded by suppression policy")
    }
}

impl std::error::Error for RepositorySuppressed {}

impl StandaloneSuppression {
    pub(super) fn load(path: &Path, key_path: &Path) -> Result<Self> {
        let key = EnvelopeKey::load(key_path, LEDGER_KEY_ID)?;
        let ledger = SuppressionLedgerV1::load(path, &key)?;
        let (repositories, aliases) = Self::indexes(&ledger);
        Ok(Self {
            path: path.to_owned(),
            key_path: key_path.to_owned(),
            key,
            deployment_id: ledger.deployment_id,
            revision: ledger.revision,
            repositories,
            aliases,
        })
    }

    fn indexes(ledger: &SuppressionLedgerV1) -> (BTreeSet<String>, BTreeSet<String>) {
        let repositories = ledger
            .records
            .iter()
            .map(|record| record.target.repository_id.clone())
            .collect();
        let aliases = ledger
            .records
            .iter()
            .flat_map(|record| record.target.aliases.iter().cloned())
            .collect();
        (repositories, aliases)
    }

    pub(super) fn paths(&self) -> [&Path; 2] {
        [&self.path, &self.key_path]
    }

    pub(super) fn suppresses(&self, repository_id: &str, alias: &str) -> bool {
        matches_identity(&self.repositories, &self.aliases, repository_id, alias)
    }

    pub(super) fn validate_results<'a>(
        &self,
        identities: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        let ledger = SuppressionLedgerV1::load(&self.path, &self.key)?;
        ensure!(
            ledger.deployment_id == self.deployment_id && ledger.revision >= self.revision,
            "suppression ledger deployment changed or revision rolled back during scan"
        );
        let (repositories, aliases) = Self::indexes(&ledger);
        ensure!(
            repositories.is_superset(&self.repositories) && aliases.is_superset(&self.aliases),
            "suppression ledger removed existing policy during scan"
        );
        for (repository_id, alias) in identities {
            if matches_identity(&repositories, &aliases, repository_id, alias) {
                return Err(RepositorySuppressed.into());
            }
        }
        Ok(())
    }
}

fn matches_identity(
    repositories: &BTreeSet<String>,
    aliases: &BTreeSet<String>,
    repository_id: &str,
    alias: &str,
) -> bool {
    if !repository_id.is_empty() && repository_id.bytes().all(|byte| byte.is_ascii_digit()) {
        repositories.contains(repository_id)
    } else {
        aliases.contains(&alias.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::{RemovalPhaseV1, RemovalRequestV1, RemovalScopeV1, SuppressionTargetV1};

    fn ledger() -> SuppressionLedgerV1 {
        let deployment_id = uuid::Uuid::new_v4().to_string();
        SuppressionLedgerV1 {
            schema_version: 1,
            deployment_id: deployment_id.clone(),
            revision: 1,
            records: vec![RemovalRequestV1 {
                schema_version: 1,
                request_id: uuid::Uuid::new_v4().to_string(),
                deployment_id,
                revision: 1,
                target: SuppressionTargetV1 {
                    repository_id: "42".to_owned(),
                    scope: RemovalScopeV1::Public,
                    aliases: BTreeSet::from(["acme/old".to_owned()]),
                },
                created_at: chrono::Utc::now(),
                phase: RemovalPhaseV1::Completed,
                attempts_removed: 0,
                artifacts_removed: 0,
                failure_code: None,
                task_cursor: None,
                artifact_cursor: None,
                failed_attempt_cursor: None,
                pending_artifact: None,
            }],
        }
    }

    #[test]
    fn authentication_identity_and_revision_are_enforced_at_publication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate(LEDGER_KEY_ID);
        key.persist_new(&key_path).unwrap();
        let mut ledger = ledger();
        ledger.persist(&path, &key).unwrap();
        let policy = StandaloneSuppression::load(&path, &key_path).unwrap();
        assert!(policy.suppresses("", "ACME/OLD"));
        assert!(policy.suppresses("42", "acme/renamed"));
        assert!(!policy.suppresses("43", "acme/old"));
        assert!(policy.validate_results([("43", "acme/old")]).is_ok());
        assert!(policy.validate_results([("43", "acme/other")]).is_ok());
        assert!(policy.validate_results([("42", "acme/renamed")]).is_err());
        ledger.records.clear();
        ledger.revision = 0;
        ledger.persist(&path, &key).unwrap();
        assert!(policy.validate_results([("43", "acme/other")]).is_err());
        let wrong_key = EnvelopeKey::generate(LEDGER_KEY_ID);
        ledger.persist(&path, &wrong_key).unwrap();
        assert!(policy.validate_results([("43", "acme/other")]).is_err());
        assert!(StandaloneSuppression::load(&directory.path().join("missing"), &key_path).is_err());
    }

    #[test]
    fn newly_suppressed_results_are_rejected_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate(LEDGER_KEY_ID);
        key.persist_new(&key_path).unwrap();
        let mut ledger = ledger();
        ledger.persist(&path, &key).unwrap();
        let policy = StandaloneSuppression::load(&path, &key_path).unwrap();
        let mut record = ledger.records[0].clone();
        record.request_id = uuid::Uuid::new_v4().to_string();
        record.revision = 2;
        record.target.repository_id = "43".to_owned();
        record.target.aliases = BTreeSet::from(["acme/new".to_owned()]);
        ledger.revision = 2;
        ledger.records.push(record);
        ledger.persist(&path, &key).unwrap();
        assert!(policy.validate_results([("43", "acme/new")]).is_err());
    }

    #[tokio::test]
    async fn aliases_block_before_network_and_renames_block_after_metadata() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path as request_path};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ledger");
        let key_path = directory.path().join("key");
        let key = EnvelopeKey::generate(LEDGER_KEY_ID);
        key.persist_new(&key_path).unwrap();
        ledger().persist(&path, &key).unwrap();
        let server = MockServer::start().await;
        Mock::given(request_path("/repos/acme/renamed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42, "name": "renamed", "full_name": "acme/renamed",
                "html_url": "https://github.com/acme/renamed",
                "owner": { "login": "acme", "id": 1, "html_url": "https://github.com/acme" },
                "default_branch": "main", "fork": false, "archived": false,
                "disabled": false, "private": false
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = super::super::GitHubClient::with_api_base(
            None,
            url::Url::parse(&format!("{}/", server.uri())).unwrap(),
        )
        .unwrap()
        .with_suppression_ledger(&path, &key_path)
        .unwrap();
        let old = super::super::GitHubRepo::new("acme", "old").unwrap();
        assert!(
            client
                .repository(&old)
                .await
                .unwrap_err()
                .downcast_ref::<RepositorySuppressed>()
                .is_some()
        );
        assert_eq!(client.usage().requests, 0);
        let renamed = super::super::GitHubRepo::new("acme", "renamed").unwrap();
        assert!(
            client
                .repository(&renamed)
                .await
                .unwrap_err()
                .downcast_ref::<RepositorySuppressed>()
                .is_some()
        );
        assert_eq!(client.usage().requests, 1);
        server.verify().await;
    }
}
