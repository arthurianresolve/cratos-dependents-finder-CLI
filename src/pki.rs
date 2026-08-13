//! Local certificate authority and mutual-TLS configuration for LAN agents.

use std::{
    fs::{self, OpenOptions},
    io::{BufReader, Write as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, bail, ensure};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData as _,
};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{output::write_json, secure_cache::sha256_hex};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PkiManifestV1 {
    pub schema_version: u16,
    pub server_name: String,
    pub ca_certificate: String,
    pub server_certificate: String,
    pub server_private_key: String,
    pub operator_certificate: String,
    pub operator_private_key: String,
    pub operator_certificate_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedIdentity {
    pub agent_id: String,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub certificate_sha256: String,
}

pub fn initialize(directory: &Path, server_name: &str) -> Result<PkiManifestV1> {
    ensure_safe_identity(server_name, "server name")?;
    fs::create_dir_all(directory)
        .with_context(|| format!("creating PKI directory {}", directory.display()))?;
    let manifest_path = directory.join("manifest.json");
    if manifest_path.exists() {
        bail!(
            "PKI manifest {} already exists; initialization never overwrites keys",
            manifest_path.display()
        );
    }

    let ca_key = KeyPair::generate().context("generating certificate-authority key")?;
    let issuer = CertifiedIssuer::self_signed(ca_parameters(), ca_key)
        .context("creating certificate authority")?;
    let ca_pem = issuer.pem();
    let ca_key_pem = issuer.key().serialize_pem();
    write_new(&directory.join("ca.pem"), ca_pem.as_bytes(), false)?;
    write_new(&directory.join("ca.key"), ca_key_pem.as_bytes(), true)?;

    let (server_certificate, server_key) =
        issue_leaf(&issuer, server_name, true).context("issuing server certificate")?;
    let server_certificate_path = directory.join("server.pem");
    let server_key_path = directory.join("server.key");
    write_new(
        &server_certificate_path,
        server_certificate.pem().as_bytes(),
        false,
    )?;
    write_new(
        &server_key_path,
        server_key.serialize_pem().as_bytes(),
        true,
    )?;

    let (operator_certificate, operator_key) =
        issue_leaf(&issuer, "operator", false).context("issuing operator certificate")?;
    let operator_certificate_path = directory.join("operator.pem");
    let operator_key_path = directory.join("operator.key");
    write_new(
        &operator_certificate_path,
        operator_certificate.pem().as_bytes(),
        false,
    )?;
    write_new(
        &operator_key_path,
        operator_key.serialize_pem().as_bytes(),
        true,
    )?;

    let manifest = PkiManifestV1 {
        schema_version: 1,
        server_name: server_name.to_owned(),
        ca_certificate: directory.join("ca.pem").display().to_string(),
        server_certificate: server_certificate_path.display().to_string(),
        server_private_key: server_key_path.display().to_string(),
        operator_certificate: operator_certificate_path.display().to_string(),
        operator_private_key: operator_key_path.display().to_string(),
        operator_certificate_sha256: sha256_hex(operator_certificate.der().as_ref()),
    };
    write_json(&manifest_path, &manifest)?;
    Ok(manifest)
}

pub fn issue_agent(
    pki_directory: &Path,
    agent_id: &str,
    output_directory: &Path,
) -> Result<IssuedIdentity> {
    ensure_safe_identity(agent_id, "agent ID")?;
    fs::create_dir_all(output_directory)
        .with_context(|| format!("creating agent directory {}", output_directory.display()))?;
    let ca_pem = fs::read(pki_directory.join("ca.pem")).context("reading certificate authority")?;
    let ca_key_pem = fs::read_to_string(pki_directory.join("ca.key"))
        .context("reading certificate-authority key")?;
    let ca_key = KeyPair::from_pem(&ca_key_pem).context("decoding certificate-authority key")?;
    verify_ca_key_matches_certificate(&ca_pem, &ca_key)?;
    let issuer = Issuer::new(ca_parameters(), ca_key);
    let (certificate, key) = issue_leaf(&issuer, agent_id, false)?;
    let certificate_path = output_directory.join(format!("{agent_id}.pem"));
    let private_key_path = output_directory.join(format!("{agent_id}.key"));
    write_new(&certificate_path, certificate.pem().as_bytes(), false)?;
    write_new(&private_key_path, key.serialize_pem().as_bytes(), true)?;
    Ok(IssuedIdentity {
        agent_id: agent_id.to_owned(),
        certificate_path,
        private_key_path,
        certificate_sha256: sha256_hex(certificate.der().as_ref()),
    })
}

fn ca_parameters() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "crate-dependent-repos local CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(3_650);
    params
}

fn verify_ca_key_matches_certificate(certificate_pem: &[u8], key: &KeyPair) -> Result<()> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem)
        .map_err(|_| anyhow::anyhow!("decoding certificate-authority certificate"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|_| anyhow::anyhow!("parsing certificate-authority certificate"))?;
    ensure!(
        certificate.public_key().raw == key.subject_public_key_info(),
        "certificate-authority key does not match ca.pem"
    );
    Ok(())
}

fn issue_leaf(
    issuer: &Issuer<'_, KeyPair>,
    name: &str,
    server: bool,
) -> Result<(rcgen::Certificate, KeyPair)> {
    let mut params = if server {
        CertificateParams::new(vec![name.to_owned()])?
    } else {
        CertificateParams::default()
    };
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = if server {
        vec![ExtendedKeyUsagePurpose::ServerAuth]
    } else {
        vec![ExtendedKeyUsagePurpose::ClientAuth]
    };
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(365);
    let key = KeyPair::generate()?;
    let certificate = params.signed_by(&key, issuer)?;
    Ok((certificate, key))
}

pub fn server_config(
    ca_certificate: &Path,
    server_certificate: &Path,
    server_private_key: &Path,
) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for certificate in read_certificates(ca_certificate)? {
        roots
            .add(certificate)
            .context("adding coordinator client trust anchor")?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("building mutual-TLS client verifier")?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            read_certificates(server_certificate)?,
            read_private_key(server_private_key)?,
        )
        .context("building coordinator TLS configuration")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

pub fn authenticated_client(
    ca_certificate: &Path,
    client_certificate: &Path,
    client_private_key: &Path,
) -> Result<reqwest::Client> {
    crate::install_rustls_crypto_provider();
    let ca = reqwest::Certificate::from_pem(&fs::read(ca_certificate)?)
        .context("decoding coordinator CA certificate")?;
    let mut identity_pem = fs::read(client_certificate)?;
    identity_pem.extend_from_slice(&fs::read(client_private_key)?);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .context("decoding mutual-TLS client identity")?;
    reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .add_root_certificate(ca)
        .identity(identity)
        .build()
        .context("building mutual-TLS HTTP client")
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        fs::File::open(path).with_context(|| format!("opening certificate {}", path.display()))?,
    );
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("decoding certificate {}", path.display()))?;
    ensure!(
        !certificates.is_empty(),
        "certificate file {} is empty",
        path.display()
    );
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(
        fs::File::open(path).with_context(|| format!("opening private key {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("decoding private key {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("private key file {} is empty", path.display()))
}

fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    if secret {
        restrict_secret_permissions(path)?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn ensure_safe_identity(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("{description} contains unsupported characters");
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting permissions on {}", path.display()))
}

#[cfg(windows)]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
    restrict_windows_secret_permissions(path)
}

#[cfg(not(any(unix, windows)))]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
    bail!(
        "cannot enforce private-key permissions on this platform for {}",
        path.display()
    )
}

#[cfg(windows)]
fn restrict_windows_secret_permissions(path: &Path) -> Result<()> {
    use std::process::Command;

    let identity =
        std::env::var("USERNAME").context("USERNAME is required to restrict key ACLs")?;
    let status = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{identity}:(F)"))
        .args(["/grant:r", "*S-1-5-18:(F)", "/Q"])
        .status()
        .with_context(|| format!("restricting Windows ACL on {}", path.display()))?;
    ensure!(
        status.success(),
        "icacls failed while restricting {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_and_issues_non_overwriting_identities() {
        let directory = tempfile::tempdir().unwrap();
        let pki = directory.path().join("pki");
        initialize(&pki, "localhost").unwrap();
        assert!(initialize(&pki, "localhost").is_err());
        let agent = issue_agent(&pki, "worker-1", &directory.path().join("agent")).unwrap();
        assert_eq!(agent.certificate_sha256.len(), 64);
        assert!(
            server_config(
                &pki.join("ca.pem"),
                &pki.join("server.pem"),
                &pki.join("server.key")
            )
            .is_ok()
        );
    }
}
