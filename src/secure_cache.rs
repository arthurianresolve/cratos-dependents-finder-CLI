//! Application-encrypted, content-addressed storage for collected source blobs.

use std::{
    collections::HashMap,
    fmt, fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock, Weak},
};

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead as _, Generate as _, Payload},
};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"CDRCACHE";
const FORMAT_VERSION: u8 = 1;
const ENVELOPE_MAGIC: &[u8; 7] = b"CDRENV1";
const NONCE_BYTES: usize = 12;
const KEY_BYTES: usize = 32;
const GCM_TAG_BYTES: usize = 16;
const WRAPPED_KEY_BYTES: usize = KEY_BYTES + GCM_TAG_BYTES;

/// A private cache namespace is deliberately tenant-scoped. Its on-disk name is
/// a one-way digest so tenant names do not appear in operational paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecureCacheNamespace<'a> {
    Public,
    Private { tenant_id: &'a str },
}

impl SecureCacheNamespace<'_> {
    fn storage_name(&self) -> String {
        match self {
            Self::Public => "public".to_owned(),
            Self::Private { tenant_id } => format!("private-{}", sha256_hex(tenant_id.as_bytes())),
        }
    }

    fn aad_name(&self) -> String {
        match self {
            Self::Public => "public".to_owned(),
            Self::Private { tenant_id } => format!("private:{tenant_id}"),
        }
    }
}

/// Versioned AES-256-GCM envelope key loaded from a restricted raw key file.
pub struct EnvelopeKey {
    key_id: String,
    material: Zeroizing<[u8; KEY_BYTES]>,
}

impl fmt::Debug for EnvelopeKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeKey")
            .field("key_id", &self.key_id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

impl EnvelopeKey {
    pub fn generate(key_id: impl Into<String>) -> Self {
        let key = Key::<Aes256Gcm>::generate();
        let mut material = [0_u8; KEY_BYTES];
        material.copy_from_slice(key.as_slice());
        Self {
            key_id: key_id.into(),
            material: Zeroizing::new(material),
        }
    }

    pub fn load(path: &Path, key_id: impl Into<String>) -> Result<Self> {
        let bytes = Zeroizing::new(
            fs::read(path).with_context(|| format!("reading envelope key {}", path.display()))?,
        );
        ensure!(
            bytes.len() == KEY_BYTES,
            "envelope key {} must contain exactly {KEY_BYTES} bytes",
            path.display()
        );
        let mut material = [0_u8; KEY_BYTES];
        material.copy_from_slice(bytes.as_slice());
        Ok(Self {
            key_id: key_id.into(),
            material: Zeroizing::new(material),
        })
    }

    /// Persist a newly generated key without replacing an existing key.
    pub fn persist_new(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating key directory {}", parent.display()))?;
        }
        let temp_parent = parent.unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(temp_parent)
            .with_context(|| format!("creating temporary key beside {}", path.display()))?;
        restrict_secret_permissions(temp.path())?;
        temp.write_all(self.material.as_slice())
            .with_context(|| format!("writing temporary envelope key for {}", path.display()))?;
        temp.as_file_mut()
            .sync_all()
            .with_context(|| format!("syncing temporary envelope key for {}", path.display()))?;
        temp.persist_noclobber(path)
            .map_err(|error| error.error)
            .with_context(|| format!("creating envelope key {}", path.display()))?;
        restrict_secret_permissions(path)?;
        Ok(())
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.material.as_slice())
            .expect("AES-256-GCM accepts a 32-byte key")
    }

    pub(crate) fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut generated_key = Key::<Aes256Gcm>::generate();
        let mut data_key_bytes = [0_u8; KEY_BYTES];
        data_key_bytes.copy_from_slice(generated_key.as_slice());
        generated_key.as_mut_slice().fill(0);
        let data_key = Zeroizing::new(data_key_bytes);
        let data_cipher = Aes256Gcm::new_from_slice(data_key.as_slice())
            .map_err(|_| anyhow!("invalid generated application-envelope data key"))?;
        let wrapping_nonce = Nonce::generate();
        let wrapped_key = self
            .cipher()
            .encrypt(
                &wrapping_nonce,
                Payload {
                    msg: data_key.as_slice(),
                    aad,
                },
            )
            .map_err(|_| anyhow!("wrapping application-envelope data key"))?;
        let data_nonce = Nonce::generate();
        let ciphertext = data_cipher
            .encrypt(
                &data_nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("encrypting application envelope"))?;
        let mut encoded = Vec::with_capacity(
            ENVELOPE_MAGIC.len() + NONCE_BYTES + WRAPPED_KEY_BYTES + NONCE_BYTES + ciphertext.len(),
        );
        encoded.extend_from_slice(ENVELOPE_MAGIC);
        encoded.extend_from_slice(wrapping_nonce.as_slice());
        encoded.extend_from_slice(&wrapped_key);
        encoded.extend_from_slice(data_nonce.as_slice());
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    pub(crate) fn open(&self, aad: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
        if !encoded.starts_with(ENVELOPE_MAGIC) {
            return self.open_legacy(aad, encoded);
        }
        let wrapping_nonce_start = ENVELOPE_MAGIC.len();
        let wrapped_key_start = wrapping_nonce_start + NONCE_BYTES;
        let data_nonce_start = wrapped_key_start + WRAPPED_KEY_BYTES;
        let ciphertext_start = data_nonce_start + NONCE_BYTES;
        ensure!(
            encoded.len() >= ciphertext_start + GCM_TAG_BYTES,
            "truncated application envelope"
        );
        let wrapping_nonce = Nonce::try_from(&encoded[wrapping_nonce_start..wrapped_key_start])
            .map_err(|_| anyhow!("invalid application-envelope wrapping nonce"))?;
        let data_key = Zeroizing::new(
            self.cipher()
                .decrypt(
                    &wrapping_nonce,
                    Payload {
                        msg: &encoded[wrapped_key_start..data_nonce_start],
                        aad,
                    },
                )
                .map_err(|_| anyhow!("application-envelope data-key authentication failed"))?,
        );
        ensure!(
            data_key.len() == KEY_BYTES,
            "invalid application-envelope data key"
        );
        let data_cipher = Aes256Gcm::new_from_slice(data_key.as_slice())
            .map_err(|_| anyhow!("invalid application-envelope data key"))?;
        let data_nonce = Nonce::try_from(&encoded[data_nonce_start..ciphertext_start])
            .map_err(|_| anyhow!("invalid application-envelope data nonce"))?;
        data_cipher
            .decrypt(
                &data_nonce,
                Payload {
                    msg: &encoded[ciphertext_start..],
                    aad,
                },
            )
            .map_err(|_| anyhow!("application-envelope authentication failed"))
    }

    fn open_legacy(&self, aad: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            encoded.len() >= NONCE_BYTES + GCM_TAG_BYTES,
            "truncated legacy application envelope"
        );
        let nonce = Nonce::try_from(&encoded[..NONCE_BYTES])
            .map_err(|_| anyhow!("invalid legacy application-envelope nonce"))?;
        self.cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: &encoded[NONCE_BYTES..],
                    aad,
                },
            )
            .map_err(|_| anyhow!("legacy application-envelope authentication failed"))
    }
}

/// Metadata returned for an encrypted content-addressed object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredObject {
    pub sha256: String,
    pub bytes: u64,
    pub path: PathBuf,
    pub key_id: String,
    pub created: bool,
}

#[derive(Clone, Debug)]
pub struct SecureBlobCache {
    root: PathBuf,
    locks: Arc<CacheLockRegistry>,
}

impl SecureBlobCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            locks: Arc::new(CacheLockRegistry::default()),
        }
    }

    /// Serialize a multi-step metadata transaction for one exact cache object.
    /// Different objects remain independent, and ordinary immutable reads do
    /// not acquire this transaction lock.
    pub async fn lock_object(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
    ) -> Result<SecureCacheObjectGuard> {
        ensure_safe_label(content_kind, "content kind")?;
        ensure_sha256(digest)?;
        let path = self.object_path(namespace, content_kind, digest);
        let object_lock = self.locks.transaction_lock(&path).await;
        Ok(SecureCacheObjectGuard {
            _guard: object_lock.lock_owned().await,
        })
    }

    /// Encrypt and atomically store a blob. Existing content with the same
    /// namespace and digest is verified before it is reused.
    pub fn put(
        &self,
        namespace: SecureCacheNamespace<'_>,
        content_kind: &str,
        plaintext: &[u8],
        key: &EnvelopeKey,
    ) -> Result<StoredObject> {
        ensure_safe_label(content_kind, "content kind")?;
        let digest = sha256_hex(plaintext);
        let path = self.object_path(&namespace, content_kind, &digest);
        let object_lock = self.locks.object_lock(&path)?;
        let _guard = object_lock
            .write()
            .map_err(|_| anyhow!("cache object lock poisoned for {}", path.display()))?;
        if path.exists() {
            let existing = self.get_unlocked(&namespace, content_kind, &digest, key, &path)?;
            ensure!(
                existing == plaintext,
                "cache digest collision or corrupt object at {}",
                path.display()
            );
            return Ok(StoredObject {
                sha256: digest,
                bytes: plaintext.len() as u64,
                path,
                key_id: key.key_id().to_owned(),
                created: false,
            });
        }

        let aad = object_aad(&namespace, content_kind, &digest, key.key_id());
        let envelope = key.seal(aad.as_bytes(), plaintext)?;

        let parent = path.parent().expect("cache object path has a parent");
        fs::create_dir_all(parent)
            .with_context(|| format!("creating cache directory {}", parent.display()))?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating temporary cache object for {}", path.display()))?;
        temp.write_all(MAGIC)?;
        temp.write_all(&[FORMAT_VERSION])?;
        temp.write_all(&envelope)?;
        temp.as_file_mut()
            .sync_all()
            .with_context(|| format!("syncing cache object {}", path.display()))?;
        let created = match temp.persist_noclobber(&path) {
            Ok(_) => true,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.get_unlocked(&namespace, content_kind, &digest, key, &path)?;
                ensure!(existing == plaintext, "concurrent cache object differs");
                false
            }
            Err(error) => {
                return Err(error.error)
                    .with_context(|| format!("persisting cache object {}", path.display()));
            }
        };

        Ok(StoredObject {
            sha256: digest,
            bytes: plaintext.len() as u64,
            path,
            key_id: key.key_id().to_owned(),
            created,
        })
    }

    pub fn get(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
        key: &EnvelopeKey,
    ) -> Result<Vec<u8>> {
        ensure_safe_label(content_kind, "content kind")?;
        ensure_sha256(digest)?;
        let path = self.object_path(namespace, content_kind, digest);
        let object_lock = self.locks.object_lock(&path)?;
        let _guard = object_lock
            .read()
            .map_err(|_| anyhow!("cache object lock poisoned for {}", path.display()))?;
        self.get_unlocked(namespace, content_kind, digest, key, &path)
    }

    /// Authenticate one stored object and verify its durable plaintext
    /// metadata without returning the potentially sensitive plaintext to the
    /// caller. The returned path is the canonical content-addressed location
    /// below this cache root.
    pub(crate) fn verify_object(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
        expected_plaintext_bytes: u64,
        key: &EnvelopeKey,
    ) -> Result<PathBuf> {
        let plaintext = Zeroizing::new(self.get(namespace, content_kind, digest, key)?);
        ensure!(
            u64::try_from(plaintext.len()).ok() == Some(expected_plaintext_bytes),
            "cache plaintext length does not match durable metadata"
        );
        Ok(self.object_path(namespace, content_kind, digest))
    }

    fn get_unlocked(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
        key: &EnvelopeKey,
        path: &Path,
    ) -> Result<Vec<u8>> {
        let encoded = fs::read(path)
            .with_context(|| format!("reading encrypted cache object {}", path.display()))?;
        let header_bytes = MAGIC.len() + 1 + NONCE_BYTES;
        ensure!(encoded.len() >= header_bytes, "truncated cache object");
        ensure!(
            &encoded[..MAGIC.len()] == MAGIC,
            "invalid cache object magic"
        );
        ensure!(
            encoded[MAGIC.len()] == FORMAT_VERSION,
            "unsupported cache object format"
        );
        let envelope_start = MAGIC.len() + 1;
        let aad = object_aad(namespace, content_kind, digest, key.key_id());
        let plaintext = key.open(aad.as_bytes(), &encoded[envelope_start..])?;
        ensure!(sha256_hex(&plaintext) == digest, "cache digest mismatch");
        Ok(plaintext)
    }

    /// Remove one exact content-addressed object. Missing objects are treated as
    /// already removed so retention collection can safely resume after a crash.
    pub fn remove(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
    ) -> Result<bool> {
        ensure_safe_label(content_kind, "content kind")?;
        ensure_sha256(digest)?;
        let path = self.object_path(namespace, content_kind, digest);
        let object_lock = self.locks.object_lock(&path)?;
        let _guard = object_lock
            .write()
            .map_err(|_| anyhow!("cache object lock poisoned for {}", path.display()))?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("removing cache object {}", path.display()))
            }
        }
    }

    fn object_path(
        &self,
        namespace: &SecureCacheNamespace<'_>,
        content_kind: &str,
        digest: &str,
    ) -> PathBuf {
        self.root
            .join(namespace.storage_name())
            .join(content_kind)
            .join(&digest[..2])
            .join(format!("{digest}.cdr"))
    }
}

#[derive(Debug, Default)]
struct CacheLockRegistry {
    objects: Mutex<ObjectLocks>,
    transactions: tokio::sync::Mutex<ObjectTransactionLocks>,
}

#[derive(Debug, Default)]
struct ObjectLocks {
    entries: HashMap<PathBuf, Weak<RwLock<()>>>,
    insertions: usize,
}

#[derive(Debug, Default)]
struct ObjectTransactionLocks {
    entries: HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>,
    insertions: usize,
}

/// An exclusive lifecycle guard for a single content-addressed object.
pub struct SecureCacheObjectGuard {
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl CacheLockRegistry {
    fn object_lock(&self, path: &Path) -> Result<Arc<RwLock<()>>> {
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| anyhow!("cache lock registry poisoned"))?;
        if let Some(object_lock) = objects.entries.get(path).and_then(Weak::upgrade) {
            return Ok(object_lock);
        }

        let object_lock = Arc::new(RwLock::new(()));
        objects
            .entries
            .insert(path.to_owned(), Arc::downgrade(&object_lock));
        objects.insertions += 1;
        if objects.insertions.is_multiple_of(1_024) {
            objects.entries.retain(|_, lock| lock.strong_count() > 0);
        }
        Ok(object_lock)
    }

    async fn transaction_lock(&self, path: &Path) -> Arc<tokio::sync::Mutex<()>> {
        let mut transactions = self.transactions.lock().await;
        if let Some(object_lock) = transactions.entries.get(path).and_then(Weak::upgrade) {
            return object_lock;
        }

        let object_lock = Arc::new(tokio::sync::Mutex::new(()));
        transactions
            .entries
            .insert(path.to_owned(), Arc::downgrade(&object_lock));
        transactions.insertions += 1;
        if transactions.insertions.is_multiple_of(1_024) {
            transactions
                .entries
                .retain(|_, lock| lock.strong_count() > 0);
        }
        object_lock
    }
}

fn object_aad(
    namespace: &SecureCacheNamespace<'_>,
    content_kind: &str,
    digest: &str,
    key_id: &str,
) -> String {
    format!(
        "crate-dependent-repos:cache:v1:{}:{content_kind}:{digest}:{key_id}",
        namespace.aad_name()
    )
}

fn ensure_safe_label(value: &str, description: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{description} must contain only ASCII letters, digits, '-' or '_'");
    }
    Ok(())
}

fn ensure_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid SHA-256 digest"
    );
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(unix)]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting permissions on {}", path.display()))
}

#[cfg(windows)]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
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

#[cfg(not(any(unix, windows)))]
fn restrict_secret_permissions(path: &Path) -> Result<()> {
    bail!(
        "cannot enforce envelope-key permissions on this platform for {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_uses_a_fresh_wrapped_data_key_per_record() {
        let key = EnvelopeKey::generate("test-key");
        let first = key.seal(b"context", b"payload").unwrap();
        let second = key.seal(b"context", b"payload").unwrap();

        assert_ne!(first, second);
        assert!(first.starts_with(ENVELOPE_MAGIC));
        assert_eq!(key.open(b"context", &first).unwrap(), b"payload");
        assert_eq!(key.open(b"context", &second).unwrap(), b"payload");
        assert!(key.open(b"different-context", &first).is_err());
    }

    #[test]
    fn legacy_direct_envelopes_remain_readable() {
        let key = EnvelopeKey::generate("test-key");
        let nonce = Nonce::generate();
        let ciphertext = key
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: b"legacy",
                    aad: b"context",
                },
            )
            .unwrap();
        let mut encoded = nonce.to_vec();
        encoded.extend_from_slice(&ciphertext);

        assert_eq!(key.open(b"context", &encoded).unwrap(), b"legacy");
    }

    #[test]
    fn encrypted_cache_round_trip_and_namespace_isolation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let key = EnvelopeKey::generate("key-2026-08");
        let private_a = SecureCacheNamespace::Private { tenant_id: "a" };
        let private_b = SecureCacheNamespace::Private { tenant_id: "b" };

        let stored = cache
            .put(private_a.clone(), "cargo_blob", b"secret", &key)
            .unwrap();
        assert_eq!(
            cache
                .get(&private_a, "cargo_blob", &stored.sha256, &key)
                .unwrap(),
            b"secret"
        );
        assert!(
            !cache
                .object_path(&private_b, "cargo_blob", &stored.sha256)
                .exists()
        );
        assert!(
            !fs::read(stored.path)
                .unwrap()
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
    }

    #[test]
    fn authentication_binds_namespace_and_key_id() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let key = EnvelopeKey::generate("one");
        let namespace = SecureCacheNamespace::Public;
        let stored = cache
            .put(namespace.clone(), "evidence", b"bundle", &key)
            .unwrap();
        let other_key = EnvelopeKey {
            key_id: "two".to_owned(),
            material: Zeroizing::new(*key.material),
        };
        assert!(
            cache
                .get(&namespace, "evidence", &stored.sha256, &other_key)
                .is_err()
        );
    }

    #[test]
    fn persisted_keys_are_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("envelope.key");
        let key = EnvelopeKey::generate("one");
        key.persist_new(&path).unwrap();
        assert!(key.persist_new(&path).is_err());
        assert_eq!(EnvelopeKey::load(&path, "one").unwrap().key_id(), "one");
    }

    #[test]
    fn exact_object_removal_is_idempotent_and_namespace_scoped() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let key = EnvelopeKey::generate("one");
        let public = SecureCacheNamespace::Public;
        let private = SecureCacheNamespace::Private { tenant_id: "a" };
        let public_object = cache
            .put(public.clone(), "evidence", b"same", &key)
            .unwrap();
        cache
            .put(private.clone(), "evidence", b"same", &key)
            .unwrap();

        assert!(
            cache
                .remove(&public, "evidence", &public_object.sha256)
                .unwrap()
        );
        assert!(
            !cache
                .remove(&public, "evidence", &public_object.sha256)
                .unwrap()
        );
        assert_eq!(
            cache
                .get(&private, "evidence", &public_object.sha256, &key)
                .unwrap(),
            b"same"
        );
    }

    #[test]
    fn concurrent_objects_do_not_share_io_locks() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let first = cache
            .locks
            .object_lock(&directory.path().join("first"))
            .unwrap();
        let second = cache
            .locks
            .object_lock(&directory.path().join("second"))
            .unwrap();
        let _first_write = first.write().unwrap();

        assert!(second.try_write().is_ok());
        assert!(first.try_read().is_err());
    }

    #[test]
    fn concurrent_identical_puts_reuse_one_authenticated_object() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let key = Arc::new(EnvelopeKey::generate("one"));
        let threads = (0..8)
            .map(|_| {
                let cache = cache.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    cache
                        .put(SecureCacheNamespace::Public, "evidence", b"shared", &key)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let objects = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(objects.iter().filter(|object| object.created).count(), 1);
        assert_eq!(
            cache
                .get(
                    &SecureCacheNamespace::Public,
                    "evidence",
                    &objects[0].sha256,
                    &key,
                )
                .unwrap(),
            b"shared"
        );
    }

    #[tokio::test]
    async fn lifecycle_transactions_are_scoped_to_one_object() {
        let directory = tempfile::tempdir().unwrap();
        let cache = SecureBlobCache::new(directory.path());
        let first_digest = "a".repeat(64);
        let second_digest = "b".repeat(64);
        let first_guard = cache
            .lock_object(&SecureCacheNamespace::Public, "evidence", &first_digest)
            .await
            .unwrap();
        let first_path =
            cache.object_path(&SecureCacheNamespace::Public, "evidence", &first_digest);
        let first_lock = cache.locks.transaction_lock(&first_path).await;

        assert!(first_lock.try_lock().is_err());
        assert!(
            cache
                .lock_object(&SecureCacheNamespace::Public, "evidence", &second_digest,)
                .await
                .is_ok()
        );
        drop(first_guard);
        assert!(first_lock.try_lock().is_ok());
    }
}
