//! Actor-local retry policy and bounded serialization for encrypted snapshots.

use std::{
    fmt,
    io::{self, Write},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use serde::Serialize;

const RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub(super) enum AutomaticCompaction {
    #[default]
    Ready,
    RetryAfter(Instant),
    AwaitReduction {
        retry_after: Instant,
        reduction_seen: bool,
    },
}

impl AutomaticCompaction {
    pub(super) fn may_attempt(&self, now: Instant) -> bool {
        match self {
            Self::Ready => true,
            Self::RetryAfter(deadline) => now >= *deadline,
            Self::AwaitReduction {
                retry_after,
                reduction_seen,
            } => *reduction_seen && now >= *retry_after,
        }
    }

    pub(super) fn note_reduction(&mut self) {
        if let Self::AwaitReduction { reduction_seen, .. } = self {
            *reduction_seen = true;
        }
    }

    pub(super) fn succeeded(&mut self) {
        *self = Self::Ready;
    }

    pub(super) fn failed(&mut self, error: &anyhow::Error, now: Instant) -> &'static str {
        let retry_after = now + RETRY_DELAY;
        if error.is::<SnapshotTooLarge>() {
            *self = Self::AwaitReduction {
                retry_after,
                reduction_seen: false,
            };
            "snapshot_size_limit"
        } else {
            *self = Self::RetryAfter(retry_after);
            "storage_or_serialization_failure"
        }
    }
}

#[derive(Debug)]
struct SnapshotTooLarge {
    limit: usize,
}

impl fmt::Display for SnapshotTooLarge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "coordinator snapshot exceeds the {}-byte limit",
            self.limit
        )
    }
}

impl std::error::Error for SnapshotTooLarge {}

struct SnapshotWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for SnapshotWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::other(SnapshotTooLarge { limit: self.limit }));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn snapshot_json(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    let mut writer = SnapshotWriter {
        bytes: Vec::with_capacity(limit.min(64 * 1024)),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(SnapshotTooLarge { limit }.into());
    }
    result.context("serializing coordinator snapshot")?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_failures_wait_without_sleeping() {
        let now = Instant::now();
        let mut policy = AutomaticCompaction::default();
        assert!(policy.may_attempt(now));
        assert_eq!(
            policy.failed(&anyhow::anyhow!("injected failure"), now),
            "storage_or_serialization_failure"
        );
        assert!(!policy.may_attempt(now + RETRY_DELAY - Duration::from_nanos(1)));
        assert!(policy.may_attempt(now + RETRY_DELAY));
        policy.succeeded();
        assert!(policy.may_attempt(now));
    }

    #[test]
    fn oversized_snapshots_need_reduction_and_cooldown() {
        let now = Instant::now();
        let mut policy = AutomaticCompaction::default();
        let error = snapshot_json(&"too large", 2).unwrap_err();
        assert_eq!(policy.failed(&error, now), "snapshot_size_limit");
        assert!(!policy.may_attempt(now + RETRY_DELAY * 100));
        for _ in 0..10 {
            policy.note_reduction();
            assert!(!policy.may_attempt(now + RETRY_DELAY / 2));
        }
        assert!(policy.may_attempt(now + RETRY_DELAY));
        policy.failed(&error, now + RETRY_DELAY);
        assert!(!policy.may_attempt(now + RETRY_DELAY * 2));
        // Successful explicit compaction releases a suspended automatic policy.
        policy.succeeded();
        assert!(policy.may_attempt(now));
    }

    #[test]
    fn capped_serialization_preserves_bytes_and_stops_at_the_limit() {
        let value = serde_json::json!({"records": ["one", "two"], "watermark": 42});
        let expected = serde_json::to_vec(&value).unwrap();
        assert_eq!(snapshot_json(&value, expected.len()).unwrap(), expected);
        let error = snapshot_json(&value, expected.len() - 1).unwrap_err();
        assert!(error.is::<SnapshotTooLarge>());
        assert!(
            snapshot_json(&value, 0)
                .unwrap_err()
                .is::<SnapshotTooLarge>()
        );
        let mut writer = SnapshotWriter {
            bytes: Vec::new(),
            limit: 3,
            exceeded: false,
        };
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"cd").is_err());
        assert_eq!(writer.bytes, b"ab");
    }
}
