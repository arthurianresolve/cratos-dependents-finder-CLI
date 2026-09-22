use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    control_api::RemovalSubmissionV1,
    privacy::{RemovalPlanV1, RemovalRequestV1, RemovalScopeV1, SuppressionTargetV1},
};

use super::control::{ControlClient, ControlConnectionArgs};

const MAX_REMOVAL_PLAN_BYTES: u64 = 256 * 1024;

#[derive(Debug, Args)]
pub(super) struct PrivacyArgs {
    #[command(subcommand)]
    command: PrivacyCommand,
}

#[derive(Debug, Subcommand)]
enum PrivacyCommand {
    /// Resolve an exact repository ID and scope into a non-destructive plan.
    Plan(PlanArgs),
    /// Suppress the planned repository immediately and begin online cleanup.
    Remove(RemoveArgs),
    /// Inspect cleanup progress and explicitly retained data categories.
    Status(ReadArgs),
    /// Retry incomplete cleanup without lifting repository suppression.
    Retry(ReadArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Scope {
    Public,
    Profile,
    All,
}

#[derive(Debug, Args)]
struct PlanArgs {
    #[command(flatten)]
    connection: ControlConnectionArgs,
    /// Exact numeric GitHub repository identity; no wildcards.
    #[arg(long)]
    repository_id: String,
    /// Namespace scope; all requires an Admin grant over all namespaces.
    #[arg(long, value_enum)]
    scope: Scope,
    /// Required with --scope profile; rejected with other scopes.
    #[arg(long)]
    credential_profile: Option<String>,
    /// Save the plan to a new file. Protect plans containing private metadata.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RemoveArgs {
    #[command(flatten)]
    connection: ControlConnectionArgs,
    /// Plan JSON returned by `coordinator privacy plan`.
    #[arg(long)]
    plan: PathBuf,
    /// Caller-selected UUID; reuse it with the same plan after a lost response.
    #[arg(long)]
    request_id: Uuid,
}

#[derive(Debug, Args)]
struct ReadArgs {
    #[command(flatten)]
    connection: ControlConnectionArgs,
    /// UUID used when submitting the removal.
    #[arg(long)]
    request_id: Uuid,
}

#[derive(Serialize)]
struct RemovalReceipt<'a> {
    removal: &'a RemovalRequestV1,
    encrypted_operational_history_retained_until_existing_expiry: bool,
    external_exports_and_older_backups_require_separate_handling: bool,
    secure_erasure_claimed: bool,
}

pub(super) async fn run(args: PrivacyArgs) -> Result<()> {
    match args.command {
        PrivacyCommand::Plan(args) => {
            let scope = removal_scope(args.scope, args.credential_profile)?;
            let target = SuppressionTargetV1 {
                repository_id: args.repository_id,
                scope,
                aliases: BTreeSet::new(),
            };
            target.validate()?;
            let client = ControlClient::new(args.connection)?;
            let plan: RemovalPlanV1 = client
                .json(client.post("api/v1/privacy/removal-plans")?.json(&target))
                .await?;
            if let Some(output) = args.output {
                super::write_json_new(&output, &plan)?;
            }
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        PrivacyCommand::Remove(args) => {
            let plan: RemovalPlanV1 = super::read_json_bounded(&args.plan, MAX_REMOVAL_PLAN_BYTES)?;
            ensure!(plan.schema_version == 1, "unsupported removal plan version");
            plan.target.validate()?;
            let client = ControlClient::new(args.connection)?;
            let submission = RemovalSubmissionV1 {
                request_id: args.request_id.to_string(),
                plan,
            };
            eprintln!(
                "Removal request ID: {}. Reuse this ID and plan if the response is lost.",
                submission.request_id
            );
            let record: RemovalRequestV1 = client
                .json(client.post("api/v1/privacy/removals")?.json(&submission))
                .await?;
            print_receipt(&record)
        }
        PrivacyCommand::Status(args) => read_or_retry(args, false).await,
        PrivacyCommand::Retry(args) => read_or_retry(args, true).await,
    }
}

async fn read_or_retry(args: ReadArgs, retry: bool) -> Result<()> {
    let client = ControlClient::new(args.connection)?;
    let path = format!("api/v1/privacy/removals/{}", args.request_id);
    let request = if retry {
        client.post(&format!("{path}/retry"))?
    } else {
        client.get(&path)?
    };
    let record: RemovalRequestV1 = client.json(request).await?;
    print_receipt(&record)
}

fn print_receipt(record: &RemovalRequestV1) -> Result<()> {
    let receipt = RemovalReceipt {
        removal: record,
        encrypted_operational_history_retained_until_existing_expiry: true,
        external_exports_and_older_backups_require_separate_handling: true,
        secure_erasure_claimed: false,
    };
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn removal_scope(scope: Scope, profile: Option<String>) -> Result<RemovalScopeV1> {
    match scope {
        Scope::Profile => {
            let profile = profile
                .ok_or_else(|| anyhow::anyhow!("--scope profile requires --credential-profile"))?;
            crate::control_auth::CredentialProfileIdV1::parse(profile.clone())?;
            Ok(RemovalScopeV1::CredentialProfile {
                credential_profile_id: profile,
            })
        }
        Scope::Public | Scope::All => {
            ensure!(
                profile.is_none(),
                "--credential-profile is only valid with --scope profile"
            );
            Ok(match scope {
                Scope::Public => RemovalScopeV1::Public,
                _ => RemovalScopeV1::All,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_scopes_require_explicit_unambiguous_namespace() {
        assert!(removal_scope(Scope::Profile, None).is_err());
        assert!(removal_scope(Scope::Public, Some("private".into())).is_err());
        assert!(removal_scope(Scope::All, Some("private".into())).is_err());
        assert_eq!(
            removal_scope(Scope::Profile, Some("private".into())).unwrap(),
            RemovalScopeV1::CredentialProfile {
                credential_profile_id: "private".into()
            }
        );
    }
}
