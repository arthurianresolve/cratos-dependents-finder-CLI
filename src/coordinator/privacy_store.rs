//! Small encrypted privacy records, serialized by the coordinator actor.

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    privacy::{RemovalRequestV1, SuppressionLedgerV1},
    secure_cache::EnvelopeKey,
};

#[derive(Deserialize, Serialize)]
struct Directory {
    deployment_id: String,
    revision: u64,
}

fn aad(id: &str) -> Vec<u8> {
    format!("cratos/coordinator-privacy/v1/{id}").into_bytes()
}

pub(super) async fn load(
    connection: &turso::Connection,
    key: &EnvelopeKey,
) -> Result<SuppressionLedgerV1> {
    let directory = directory(connection, key).await?;
    let mut rows = connection.query("SELECT record_id, payload FROM coordinator_privacy WHERE record_id != 'directory' ORDER BY record_id", ()).await?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().await? {
        let id: String = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        let record: RemovalRequestV1 = serde_json::from_slice(&key.open(&aad(&id), &payload)?)?;
        ensure!(record.request_id == id, "privacy record identity mismatch");
        records.push(record);
    }
    let ledger = SuppressionLedgerV1 {
        schema_version: 1,
        deployment_id: directory.deployment_id,
        revision: directory.revision,
        records,
    };
    ledger.validate()?;
    Ok(ledger)
}

async fn directory(connection: &turso::Connection, key: &EnvelopeKey) -> Result<Directory> {
    connection.execute_batch("CREATE TABLE IF NOT EXISTS coordinator_privacy (record_id TEXT PRIMARY KEY, payload BLOB NOT NULL)").await?;
    let mut rows = connection
        .query(
            "SELECT payload FROM coordinator_privacy WHERE record_id = 'directory'",
            (),
        )
        .await?;
    if let Some(row) = rows.next().await? {
        let payload: Vec<u8> = row.get(0)?;
        return Ok(serde_json::from_slice(
            &key.open(&aad("directory"), &payload)?,
        )?);
    }
    drop(rows);
    let directory = Directory {
        deployment_id: uuid::Uuid::new_v4().to_string(),
        revision: 0,
    };
    connection
        .execute(
            "INSERT INTO coordinator_privacy (record_id,payload) VALUES ('directory',?1)",
            turso::params![key.seal(&aad("directory"), &serde_json::to_vec(&directory)?)?],
        )
        .await?;
    Ok(directory)
}

pub(super) async fn put(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    record: &RemovalRequestV1,
) -> Result<()> {
    record.validate()?;
    let mut directory = directory(connection, key).await?;
    ensure!(
        directory.deployment_id == record.deployment_id,
        "privacy deployment mismatch"
    );
    let mut rows = connection
        .query(
            "SELECT payload FROM coordinator_privacy WHERE record_id = ?1",
            turso::params![record.request_id.clone()],
        )
        .await?;
    if let Some(row) = rows.next().await? {
        let payload: Vec<u8> = row.get(0)?;
        let old: RemovalRequestV1 =
            serde_json::from_slice(&key.open(&aad(&record.request_id), &payload)?)?;
        ensure!(
            old.target == record.target
                && old.revision == record.revision
                && old.created_at == record.created_at,
            "privacy request conflicts with earlier request"
        );
    } else {
        ensure!(
            directory.revision.checked_add(1) == Some(record.revision),
            "stale privacy policy revision"
        );
        directory.revision = record.revision;
    }
    drop(rows);
    let payload = key.seal(&aad(&record.request_id), &serde_json::to_vec(record)?)?;
    let metadata = key.seal(&aad("directory"), &serde_json::to_vec(&directory)?)?;
    connection.execute_batch("BEGIN IMMEDIATE").await?;
    let result = async {
        connection.execute("INSERT INTO coordinator_privacy (record_id,payload) VALUES (?1,?2) ON CONFLICT(record_id) DO UPDATE SET payload=excluded.payload",
            turso::params![record.request_id.clone(), payload]).await?;
        connection.execute("UPDATE coordinator_privacy SET payload=?1 WHERE record_id='directory'", turso::params![metadata]).await?;
        // Older executables must not serve a database while ignoring suppression.
        connection.execute("UPDATE coordinator_metadata SET value='2' WHERE key='schema_version'", ()).await?;
        connection.execute_batch("COMMIT").await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK").await;
    }
    result.context("persisting encrypted privacy record")
}

pub(super) async fn adopt_deployment(
    connection: &turso::Connection,
    key: &EnvelopeKey,
    deployment_id: String,
) -> Result<()> {
    uuid::Uuid::parse_str(&deployment_id).context("invalid recovered privacy deployment")?;
    let current = load(connection, key).await?;
    ensure!(
        current.revision == 0 && current.records.is_empty(),
        "cannot replace an established privacy deployment"
    );
    let directory = Directory {
        deployment_id,
        revision: 0,
    };
    connection
        .execute(
            "UPDATE coordinator_privacy SET payload=?1 WHERE record_id='directory'",
            turso::params![key.seal(&aad("directory"), &serde_json::to_vec(&directory)?)?],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::privacy::{RemovalPhaseV1, RemovalScopeV1, SuppressionTargetV1};

    fn record(deployment_id: String) -> RemovalRequestV1 {
        RemovalRequestV1 {
            schema_version: 1,
            request_id: uuid::Uuid::new_v4().to_string(),
            deployment_id,
            revision: 1,
            target: SuppressionTargetV1 {
                repository_id: "123456789".into(),
                scope: RemovalScopeV1::CredentialProfile {
                    credential_profile_id: "private-profile".into(),
                },
                aliases: BTreeSet::from(["private-owner/private-repository".into()]),
            },
            created_at: chrono::Utc::now(),
            phase: RemovalPhaseV1::Pending,
            attempts_removed: 0,
            artifacts_removed: 0,
            failure_code: None,
            task_cursor: None,
            artifact_cursor: None,
            failed_attempt_cursor: None,
            pending_artifact: None,
        }
    }

    async fn initialize(connection: &turso::Connection) {
        connection.execute_batch("CREATE TABLE coordinator_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO coordinator_metadata VALUES ('schema_version','1')").await.unwrap();
    }

    #[tokio::test]
    async fn privacy_records_encrypt_operational_fields_and_preserve_idempotency_on_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("privacy.db");
        let database = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        initialize(&connection).await;
        let key = EnvelopeKey::generate("privacy-test");
        let empty = load(&connection, &key).await.unwrap();
        let mut request = record(empty.deployment_id);
        put(&connection, &key, &request).await.unwrap();
        put(&connection, &key, &request).await.unwrap();
        let mut conflicting = request.clone();
        conflicting.target.repository_id = "999".into();
        assert!(put(&connection, &key, &conflicting).await.is_err());
        assert_eq!(
            load(&connection, &key).await.unwrap().records,
            vec![request.clone()]
        );
        request.phase = RemovalPhaseV1::Catalog;
        request.attempts_removed = 17;
        request.task_cursor = Some("private-task-id".into());
        put(&connection, &key, &request).await.unwrap();
        let mut rows = connection
            .query("SELECT payload FROM coordinator_privacy", ())
            .await
            .unwrap();
        while let Some(row) = rows.next().await.unwrap() {
            let payload: Vec<u8> = row.get(0).unwrap();
            for private in [
                "123456789",
                "private-profile",
                "private-owner",
                "private-task-id",
                "attempts_removed",
            ] {
                assert!(
                    !payload
                        .windows(private.len())
                        .any(|window| window == private.as_bytes())
                );
            }
        }
        drop(rows);
        drop(connection);
        drop(database);
        let database = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            load(&connection, &key).await.unwrap().records,
            vec![request]
        );
        assert!(
            load(&connection, &EnvelopeKey::generate("privacy-test"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn corrupt_privacy_record_fails_closed_and_revision_conflicts_do_not_mutate_policy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("privacy.db");
        let database = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        initialize(&connection).await;
        let key = EnvelopeKey::generate("privacy-test");
        let empty = load(&connection, &key).await.unwrap();
        let request = record(empty.deployment_id);
        put(&connection, &key, &request).await.unwrap();
        let before = load(&connection, &key).await.unwrap();
        let mut stale = request.clone();
        stale.request_id = uuid::Uuid::new_v4().to_string();
        assert!(put(&connection, &key, &stale).await.is_err());
        assert!(
            adopt_deployment(&connection, &key, uuid::Uuid::new_v4().to_string())
                .await
                .is_err()
        );
        assert_eq!(load(&connection, &key).await.unwrap(), before);
        let moved_payload = key
            .seal(
                &aad("another-record"),
                &serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE coordinator_privacy SET payload=?2 WHERE record_id=?1",
                turso::params![request.request_id, moved_payload],
            )
            .await
            .unwrap();
        assert!(load(&connection, &key).await.is_err());
    }

    #[tokio::test]
    async fn missing_privacy_record_cannot_silently_unsuppress_a_repository() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("privacy.db");
        let database = turso::Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        initialize(&connection).await;
        let key = EnvelopeKey::generate("privacy-test");
        let empty = load(&connection, &key).await.unwrap();
        let request = record(empty.deployment_id);
        put(&connection, &key, &request).await.unwrap();
        connection
            .execute(
                "DELETE FROM coordinator_privacy WHERE record_id=?1",
                turso::params![request.request_id],
            )
            .await
            .unwrap();
        assert!(load(&connection, &key).await.is_err());
    }
}
