pub mod advisory;
pub mod cargo_evidence;
pub mod catalog;
pub mod cli;
pub mod control_api;
pub mod control_auth;
pub mod coordinator;
pub mod coordinator_api;
pub mod crates_io;
pub mod distributed;
pub mod evidence;
pub mod explain;
pub mod github;
pub mod inventory;
pub mod links;
pub mod model;
pub mod operations;
pub mod output;
pub mod pki;
pub mod policy;
pub mod report;
pub mod repository_analyzer;
pub mod resolve;
pub mod secure_cache;
pub mod telemetry;
pub mod version_selector;

#[cfg(test)]
mod rollout_gates;
#[cfg(test)]
mod scan_acceptance;

pub use cli::Cli;

pub(crate) fn install_rustls_crypto_provider() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
