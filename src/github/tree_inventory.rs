use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, ensure};
use futures::{StreamExt as _, stream};
use tokio::sync::Semaphore;

use super::{GitHubClient, GitHubRepo, GitHubTree, GitHubTreeEntry};

const DEFAULT_REQUEST_LIMIT: usize = 256;
const DEFAULT_ENTRY_LIMIT: usize = 250_000;
const DEFAULT_DEPTH_LIMIT: usize = 64;
const DEFAULT_CONCURRENCY: usize = 8;
const DEFAULT_JSON_BYTE_LIMIT: u64 = 256 * 1024 * 1024;
const DEFAULT_PATH_BYTE_LIMIT: usize = 16 * 1024;
const DEFAULT_ELAPSED_LIMIT: Duration = Duration::from_secs(120);

/// Safety bounds for adaptive enumeration of an immutable Git tree.
///
/// The first request is always the existing recursive fast path. These limits
/// only become observable when GitHub truncates that response and the client
/// walks exact subtree SHAs to recover the missing paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHubTreeInventoryLimits {
    pub max_requests: usize,
    pub max_entries: usize,
    pub max_depth: usize,
    pub max_in_flight: usize,
    pub max_json_bytes: u64,
    pub max_path_bytes: usize,
    pub max_elapsed: Duration,
}

impl Default for GitHubTreeInventoryLimits {
    fn default() -> Self {
        Self {
            max_requests: DEFAULT_REQUEST_LIMIT,
            max_entries: DEFAULT_ENTRY_LIMIT,
            max_depth: DEFAULT_DEPTH_LIMIT,
            max_in_flight: DEFAULT_CONCURRENCY,
            max_json_bytes: DEFAULT_JSON_BYTE_LIMIT,
            max_path_bytes: DEFAULT_PATH_BYTE_LIMIT,
            max_elapsed: DEFAULT_ELAPSED_LIMIT,
        }
    }
}

impl GitHubTreeInventoryLimits {
    fn validate(self) -> Result<Self> {
        ensure!(
            self.max_requests > 0,
            "Git tree request limit must be positive"
        );
        ensure!(
            self.max_entries > 0,
            "Git tree entry limit must be positive"
        );
        ensure!(self.max_depth > 0, "Git tree depth limit must be positive");
        ensure!(
            self.max_in_flight > 0,
            "Git tree request concurrency must be positive"
        );
        ensure!(
            self.max_json_bytes > 0,
            "Git tree JSON byte limit must be positive"
        );
        ensure!(
            self.max_path_bytes > 0,
            "Git tree path byte limit must be positive"
        );
        ensure!(
            !self.max_elapsed.is_zero(),
            "Git tree elapsed-time limit must be positive"
        );
        Ok(self)
    }
}

/// A bounded, deterministic inventory of one immutable Git tree.
#[derive(Clone, Debug)]
pub struct GitHubTreeInventory {
    pub sha: String,
    pub tree: Vec<GitHubTreeEntry>,
    pub complete: bool,
    pub initial_response_truncated: bool,
    pub requests: usize,
    pub limitations: Vec<GitHubTreeInventoryLimitation>,
}

/// Why an adaptive tree inventory could not prove path absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubTreeInventoryLimitation {
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug)]
struct PendingTree {
    prefix: String,
    sha: String,
    depth: usize,
    recursive: bool,
}

struct FetchedGitTree {
    tree: GitHubTree,
    json_bytes: u64,
}

#[derive(Default)]
struct TreeRecoveryStats {
    failed_subtrees: usize,
    first_failed_subtree: Option<String>,
    first_failure: Option<String>,
    truncated_subtrees: usize,
    request_limit_hit: bool,
    entry_limit_hit: bool,
    depth_limit_hit: bool,
    json_byte_limit_hit: bool,
    path_limit_hit: bool,
    elapsed_limit_hit: bool,
}

impl GitHubClient {
    /// Enumerate an immutable Git tree, recovering a truncated recursive
    /// response through bounded adaptive subtree reads.
    ///
    /// Supplying `request_permits` routes every tree read through the caller's
    /// existing concurrency gate. A non-truncated repository performs exactly
    /// one request and never enters the recovery implementation.
    pub async fn tree_inventory(
        &self,
        repo: &GitHubRepo,
        tree_sha: &str,
        limits: GitHubTreeInventoryLimits,
        request_permits: Option<&Semaphore>,
    ) -> Result<GitHubTreeInventory> {
        let limits = limits.validate()?;
        let started_at = Instant::now();
        let initial = self
            .gated_inventory_tree(repo, tree_sha, true, request_permits)
            .await?;
        if !initial.tree.truncated {
            let inventory_sha = initial.tree.sha;
            return Ok(GitHubTreeInventory {
                sha: inventory_sha,
                tree: initial.tree.tree,
                complete: true,
                initial_response_truncated: false,
                requests: 1,
                limitations: Vec::new(),
            });
        }

        self.recover_tree_inventory(repo, tree_sha, initial, limits, request_permits, started_at)
            .await
    }

    async fn recover_tree_inventory(
        &self,
        repo: &GitHubRepo,
        tree_sha: &str,
        initial: FetchedGitTree,
        limits: GitHubTreeInventoryLimits,
        request_permits: Option<&Semaphore>,
        started_at: Instant,
    ) -> Result<GitHubTreeInventory> {
        let inventory_sha = initial.tree.sha;
        let mut initial_entries = initial.tree.tree;
        initial_entries.sort_by(|left, right| left.path.cmp(&right.path));
        let mut stats = TreeRecoveryStats::default();
        let mut entries = BTreeMap::new();
        for entry in initial_entries {
            if entry.path.len() > limits.max_path_bytes {
                stats.path_limit_hit = true;
                continue;
            }
            if !entries.contains_key(&entry.path) && entries.len() >= limits.max_entries {
                stats.entry_limit_hit = true;
                break;
            }
            entries.insert(entry.path.clone(), entry);
        }
        let mut pending = VecDeque::from([PendingTree {
            prefix: String::new(),
            sha: tree_sha.to_owned(),
            depth: 0,
            recursive: false,
        }]);
        let mut requests = 1usize;
        let mut json_bytes = initial.json_bytes;
        if json_bytes > limits.max_json_bytes {
            stats.json_byte_limit_hit = true;
        }

        while !pending.is_empty() {
            if started_at.elapsed() >= limits.max_elapsed {
                stats.elapsed_limit_hit = true;
                break;
            }
            if stats.entry_limit_hit || stats.json_byte_limit_hit {
                break;
            }
            let available_requests = limits.max_requests.saturating_sub(requests);
            if available_requests == 0 {
                stats.request_limit_hit = true;
                break;
            }
            let batch_len = pending
                .len()
                .min(available_requests)
                .min(limits.max_in_flight);
            let batch = (0..batch_len)
                .map(|position| {
                    let node = pending
                        .pop_front()
                        .expect("batch length never exceeds pending tree count");
                    (position, node)
                })
                .collect::<Vec<_>>();
            requests = requests.saturating_add(batch.len());

            let work = batch.into_iter().map(|(position, node)| async move {
                let result = self
                    .gated_inventory_tree(repo, &node.sha, node.recursive, request_permits)
                    .await;
                (position, node, result)
            });
            let mut responses = stream::iter(work)
                .buffer_unordered(limits.max_in_flight)
                .collect::<Vec<_>>()
                .await;
            responses.sort_by_key(|(position, _, _)| *position);

            for (_, node, response) in responses {
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        stats.failed_subtrees = stats.failed_subtrees.saturating_add(1);
                        stats.first_failed_subtree.get_or_insert(node.prefix);
                        stats
                            .first_failure
                            .get_or_insert_with(|| format!("{error:#}"));
                        continue;
                    }
                };
                json_bytes = json_bytes.saturating_add(response.json_bytes);
                if json_bytes > limits.max_json_bytes {
                    stats.json_byte_limit_hit = true;
                }
                let mut response = response.tree;
                if response.truncated {
                    if node.recursive {
                        pending.push_back(PendingTree {
                            recursive: false,
                            ..node.clone()
                        });
                    } else {
                        stats.truncated_subtrees = stats.truncated_subtrees.saturating_add(1);
                    }
                }
                response
                    .tree
                    .sort_by(|left, right| left.path.cmp(&right.path));

                for mut entry in response.tree {
                    entry.path = prefixed_tree_path(&node.prefix, &entry.path);
                    if entry.path.len() > limits.max_path_bytes {
                        stats.path_limit_hit = true;
                        continue;
                    }
                    if !entries.contains_key(&entry.path) && entries.len() >= limits.max_entries {
                        stats.entry_limit_hit = true;
                        break;
                    }
                    if !node.recursive && entry.is_tree() {
                        let child_depth = node.depth.saturating_add(1);
                        if child_depth > limits.max_depth {
                            stats.depth_limit_hit = true;
                        } else {
                            pending.push_back(PendingTree {
                                prefix: entry.path.clone(),
                                sha: entry.sha.clone(),
                                depth: child_depth,
                                recursive: true,
                            });
                        }
                    }
                    entries.insert(entry.path.clone(), entry);
                }
            }

            if started_at.elapsed() >= limits.max_elapsed {
                stats.elapsed_limit_hit = true;
            }
            if stats.entry_limit_hit || stats.json_byte_limit_hit || stats.elapsed_limit_hit {
                break;
            }
        }

        let limitations = tree_recovery_limitations(&stats, limits);
        Ok(GitHubTreeInventory {
            sha: inventory_sha,
            tree: entries.into_values().collect(),
            complete: limitations.is_empty(),
            initial_response_truncated: true,
            requests,
            limitations,
        })
    }

    async fn gated_inventory_tree(
        &self,
        repo: &GitHubRepo,
        tree_sha: &str,
        recursive: bool,
        request_permits: Option<&Semaphore>,
    ) -> Result<FetchedGitTree> {
        let _permit = match request_permits {
            Some(permits) => Some(
                permits
                    .acquire()
                    .await
                    .context("GitHub request limiter closed unexpectedly")?,
            ),
            None => None,
        };
        self.inventory_tree(repo, tree_sha, recursive).await
    }

    async fn inventory_tree(
        &self,
        repo: &GitHubRepo,
        tree_sha: &str,
        recursive: bool,
    ) -> Result<FetchedGitTree> {
        ensure!(!tree_sha.is_empty(), "GitHub tree SHA cannot be empty");
        let mut url = self.endpoint([
            "repos",
            repo.owner.as_str(),
            repo.name.as_str(),
            "git",
            "trees",
            tree_sha,
        ])?;
        if recursive {
            url.query_pairs_mut().append_pair("recursive", "1");
        }
        let request_kind = if recursive {
            "recursive Git tree"
        } else {
            "Git subtree"
        };
        let (tree, json_bytes) = self
            .get_json_with_size(url)
            .await
            .with_context(|| format!("failed to read {request_kind} {tree_sha} for {repo}"))?;
        Ok(FetchedGitTree { tree, json_bytes })
    }
}

fn prefixed_tree_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.to_owned()
    } else {
        format!("{prefix}/{path}")
    }
}

fn tree_recovery_limitations(
    stats: &TreeRecoveryStats,
    limits: GitHubTreeInventoryLimits,
) -> Vec<GitHubTreeInventoryLimitation> {
    let mut limitations = Vec::new();
    if stats.request_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_request_limit",
            message: format!(
                "Git tree recovery reached its {}-request limit; unvisited subtrees remain unknown",
                limits.max_requests
            ),
        });
    }
    if stats.entry_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_entry_limit",
            message: format!(
                "Git tree recovery reached its {}-entry limit; unvisited paths remain unknown",
                limits.max_entries
            ),
        });
    }
    if stats.depth_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_depth_limit",
            message: format!(
                "Git tree recovery reached its depth limit of {}; deeper paths remain unknown",
                limits.max_depth
            ),
        });
    }
    if stats.json_byte_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_json_byte_limit",
            message: format!(
                "Git tree recovery exceeded its {}-byte JSON budget; unvisited paths remain unknown",
                limits.max_json_bytes
            ),
        });
    }
    if stats.path_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_path_limit",
            message: format!(
                "one or more Git paths exceeded the {}-byte path limit and were not retained",
                limits.max_path_bytes
            ),
        });
    }
    if stats.elapsed_limit_hit {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_tree_recovery_elapsed_limit",
            message: format!(
                "Git tree recovery reached its {:?} elapsed-time limit; unvisited paths remain unknown",
                limits.max_elapsed
            ),
        });
    }
    if stats.failed_subtrees > 0 {
        let first = stats
            .first_failed_subtree
            .as_deref()
            .filter(|path| !path.is_empty())
            .unwrap_or("<root>");
        let cause = stats.first_failure.as_deref().unwrap_or("unknown error");
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_subtree_fetch_failed",
            message: format!(
                "{} Git subtree request(s) failed; the first unavailable subtree was {first}: {cause}",
                stats.failed_subtrees
            ),
        });
    }
    if stats.truncated_subtrees > 0 {
        limitations.push(GitHubTreeInventoryLimitation {
            code: "github_subtree_truncated",
            message: format!(
                "GitHub truncated {} direct subtree response(s); missing paths remain unknown",
                stats.truncated_subtrees
            ),
        });
    }
    limitations
}
