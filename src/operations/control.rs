//! Product control listener client. mTLS alone never grants Admin access.

use std::{fs::File, io::Read as _, path::PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use reqwest::{
    RequestBuilder,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::Zeroizing;

const MAX_SERVICE_TOKEN_BYTES: u64 = 4_096;
const MAX_CONTROL_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Args)]
pub(super) struct ControlConnectionArgs {
    /// HTTPS base URL of the product control listener (normally port 8444).
    #[arg(long)]
    control_url: Url,
    /// Deployment certificate-authority PEM.
    #[arg(long)]
    ca: PathBuf,
    /// Deployment client certificate; a service token is still required.
    #[arg(long)]
    certificate: PathBuf,
    /// Client private-key PEM.
    #[arg(long)]
    private_key: PathBuf,
    /// File containing a control service token, never a worker identifier.
    #[arg(long, conflicts_with = "token_env")]
    token_file: Option<PathBuf>,
    /// Environment variable containing the token (default CRATOS_CONTROL_TOKEN).
    #[arg(long, conflicts_with = "token_file")]
    token_env: Option<String>,
}

#[derive(Debug, Args)]
pub(super) struct GithubArgs {
    #[command(subcommand)]
    command: GithubCommand,
}

#[derive(Debug, Subcommand)]
enum GithubCommand {
    /// Read deployment-wide primary deadlines and secondary-limit suspension.
    Status(ControlConnectionArgs),
    /// Explicitly allow one recovery probe after suspension; deadlines remain.
    Resume(ControlConnectionArgs),
}

pub(super) async fn run_github(args: GithubArgs) -> Result<()> {
    let (connection, resume) = match args.command {
        GithubCommand::Status(connection) => (connection, false),
        GithubCommand::Resume(connection) => (connection, true),
    };
    let client = ControlClient::new(connection)?;
    let request = if resume {
        client.post("api/v1/providers/github/resume")?
    } else {
        client.get("api/v1/providers/github")?
    };
    let status: crate::coordinator::GithubProviderStatusV1 = client.json(request).await?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

pub(super) struct ControlClient {
    base: Url,
    client: reqwest::Client,
    authorization: HeaderValue,
}

impl ControlClient {
    pub(super) fn new(args: ControlConnectionArgs) -> Result<Self> {
        let base = super::validate_coordinator_url(args.control_url)?;
        let token = match args.token_file {
            Some(path) => {
                let mut token = Zeroizing::new(String::new());
                File::open(path)
                    .context("opening service-token file")?
                    .take(MAX_SERVICE_TOKEN_BYTES + 1)
                    .read_to_string(&mut token)
                    .context("reading service-token file")?;
                token
            }
            None => Zeroizing::new(
                std::env::var(args.token_env.as_deref().unwrap_or("CRATOS_CONTROL_TOKEN"))
                    .context("control service-token environment variable is missing or invalid")?,
            ),
        };
        let authorization = service_token_header(&token)?;
        let client = crate::pki::authenticated_client_builder(
            &args.ca,
            &args.certificate,
            &args.private_key,
        )?
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building control API client")?;
        Ok(Self {
            base,
            client,
            authorization,
        })
    }

    pub(super) fn get(&self, path: &str) -> Result<RequestBuilder> {
        Ok(self
            .client
            .get(self.base.join(path)?)
            .header(AUTHORIZATION, self.authorization.clone()))
    }

    pub(super) fn post(&self, path: &str) -> Result<RequestBuilder> {
        Ok(self
            .client
            .post(self.base.join(path)?)
            .header(AUTHORIZATION, self.authorization.clone()))
    }

    pub(super) async fn json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = request.send().await.context("calling control API")?;
        let status = response.status();
        let bytes = super::read_bounded_body(response, MAX_CONTROL_RESPONSE_BYTES).await?;
        // Never echo an untrusted error response: it could reflect credentials.
        ensure!(status.is_success(), "control API returned HTTP {status}");
        serde_json::from_slice(&bytes).context("decoding control API JSON response")
    }
}

fn service_token_header(token: &str) -> Result<HeaderValue> {
    ensure!(
        token.len() <= MAX_SERVICE_TOKEN_BYTES as usize,
        "control service token exceeds size limit"
    );
    let token = token.trim();
    ensure!(
        !token.is_empty() && !token.chars().any(char::is_whitespace),
        "invalid control service-token format"
    );
    let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("invalid control service-token header")?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_header_is_sensitive_and_rejects_invalid_tokens() {
        let header = service_token_header("test-secret\n").unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("test-secret"));
        for token in ["", " \n", "token other", "token\r\nInjected: value"] {
            assert!(service_token_header(token).is_err());
        }
        assert!(service_token_header(&"x".repeat(MAX_SERVICE_TOKEN_BYTES as usize + 1)).is_err());
    }
}
