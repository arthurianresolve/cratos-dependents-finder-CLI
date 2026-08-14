use std::fmt;

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::model::{CatalogError, InventoryAccessV1, InventoryQueryV1, InventorySortV1};

const CURSOR_SCHEMA_VERSION: u16 = 1;
const CURSOR_DOMAIN: &[u8] = b"crate-dependent-repos/inventory-cursor/v1";
const MAX_CURSOR_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct InventorySortKeyV1 {
    pub relevance: u32,
    pub normalized_repository: String,
    pub completed_at: DateTime<Utc>,
    pub msrv: Option<Version>,
    pub attempt_id: String,
}

#[derive(Deserialize, Serialize)]
struct CursorPayloadV1 {
    schema_version: u16,
    principal_fingerprint: String,
    scope_fingerprint: String,
    query_fingerprint: String,
    index_watermark: u64,
    sort: InventorySortV1,
    last: InventorySortKeyV1,
}

#[derive(Debug)]
pub(crate) struct DecodedCursorV1 {
    pub index_watermark: u64,
    pub last: InventorySortKeyV1,
}

pub(crate) struct CursorSigner {
    key: [u8; 32],
}

impl fmt::Debug for CursorSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorSigner")
            .finish_non_exhaustive()
    }
}

impl CursorSigner {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn encode(
        &self,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
        watermark: u64,
        last: InventorySortKeyV1,
    ) -> Result<String, CatalogError> {
        let payload = CursorPayloadV1 {
            schema_version: CURSOR_SCHEMA_VERSION,
            principal_fingerprint: digest_json(&access.principal_id)?,
            scope_fingerprint: digest_json(&access.private_credential_profiles)?,
            query_fingerprint: digest_json(query)?,
            index_watermark: watermark,
            sort: query.sort,
            last,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| CatalogError::CursorInvalid)?;
        let signature = hmac_sha256(&self.key, &bytes);
        Ok(format!("{}.{}", encode_hex(&bytes), encode_hex(&signature)))
    }

    pub fn decode(
        &self,
        encoded: &str,
        access: &InventoryAccessV1,
        query: &InventoryQueryV1,
    ) -> Result<DecodedCursorV1, CatalogError> {
        if encoded.len() > MAX_CURSOR_BYTES {
            return Err(CatalogError::CursorInvalid);
        }
        let (payload_hex, signature_hex) =
            encoded.split_once('.').ok_or(CatalogError::CursorInvalid)?;
        let bytes = decode_hex(payload_hex)?;
        let signature = decode_hex(signature_hex)?;
        let expected_signature = hmac_sha256(&self.key, &bytes);
        if !constant_time_eq(&signature, &expected_signature) {
            return Err(CatalogError::CursorInvalid);
        }
        let payload = serde_json::from_slice::<CursorPayloadV1>(&bytes)
            .map_err(|_| CatalogError::CursorInvalid)?;
        if payload.schema_version != CURSOR_SCHEMA_VERSION
            || payload.principal_fingerprint != digest_json(&access.principal_id)?
            || payload.scope_fingerprint != digest_json(&access.private_credential_profiles)?
            || payload.query_fingerprint != digest_json(query)?
            || payload.sort != query.sort
        {
            return Err(CatalogError::CursorInvalid);
        }
        Ok(DecodedCursorV1 {
            index_watermark: payload.index_watermark,
            last: payload.last,
        })
    }
}

impl Drop for CursorSigner {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, CatalogError> {
    let bytes = serde_json::to_vec(value).map_err(|_| CatalogError::CursorInvalid)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; BLOCK_SIZE];
    let mut outer_pad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(CURSOR_DOMAIN);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, CatalogError> {
    if !value.len().is_multiple_of(2) {
        return Err(CatalogError::CursorInvalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0]).ok_or(CatalogError::CursorInvalid)?;
            let low = decode_nibble(pair[1]).ok_or(CatalogError::CursorInvalid)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::TimeZone as _;

    use super::*;

    fn access(principal_id: &str) -> InventoryAccessV1 {
        InventoryAccessV1 {
            principal_id: principal_id.to_owned(),
            private_credential_profiles: BTreeSet::new(),
        }
    }

    fn key() -> InventorySortKeyV1 {
        InventorySortKeyV1 {
            relevance: 1,
            normalized_repository: "owner/repo".to_owned(),
            completed_at: Utc.with_ymd_and_hms(2026, 8, 14, 0, 0, 0).unwrap(),
            msrv: None,
            attempt_id: "attempt".to_owned(),
        }
    }

    #[test]
    fn cursor_is_bound_to_principal_query_and_signature() {
        let signer = CursorSigner::new([7; 32]);
        let query = InventoryQueryV1::new();
        let encoded = signer
            .encode(&access("reader-a"), &query, 3, key())
            .unwrap();
        assert_eq!(
            signer
                .decode(&encoded, &access("reader-a"), &query)
                .unwrap()
                .index_watermark,
            3
        );
        assert!(matches!(
            signer.decode(&encoded, &access("reader-b"), &query),
            Err(CatalogError::CursorInvalid)
        ));

        let mut tampered = encoded.into_bytes();
        tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(matches!(
            signer.decode(&tampered, &access("reader-a"), &query),
            Err(CatalogError::CursorInvalid)
        ));
    }
}
