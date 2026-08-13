# crate-dependent-repos

`crate-dependent-repos` builds an evidence-oriented inventory of public Rust
repositories that declare a crate or record an exact crate version in a
default-branch `Cargo.lock`.

It deliberately keeps these observations separate:

- a current published crate version directly declares the target, according to
  crates.io and its sparse index;
- a current default-branch `Cargo.toml` directly declares the target;
- a current default-branch `Cargo.lock` records the exact target version;
- the lockfile graph records that version as direct, transitive, both, or merely
  present but unclassifiable from the available roots.

None of those observations proves that a dependency is enabled for a particular
feature set, target, deployed binary, or runtime path.

## Toolchain

The project uses Rust **1.97.1** and Rust edition **2024**. The exact toolchain is
pinned in `rust-toolchain.toml`.

```powershell
cargo build --locked --release
```

The resulting executable is
`target\release\crate-dependent-repos.exe` on Windows.

## Commands

### Resolve a name

```powershell
cargo run --locked -- resolve fs2
cargo run --locked -- resolve fs2-rs
cargo run --locked -- resolve https://github.com/danburkert/fs2-rs
cargo run --locked -- resolve fs2 --json
```

Exact crates.io names are selected automatically. Fuzzy names are ranked but
are not silently scanned. Bare repository names use a bounded public GitHub
name search; use `owner/repo` when that search is ambiguous. Repository URLs
are resolved through canonical GitHub metadata and a bounded inspection of
default-branch package manifests. A repository that maps to several crates
requires an explicit `--crate-name` on `links` or `scan`.

### Generate bounded discovery links

```powershell
cargo run --locked -- links fs2 --version 0.4.3
```

This prints:

- an exact multiline `Cargo.lock` query for GitHub's new web code search;
- common direct-declaration and explicit `=0.4.3` queries for `Cargo.toml`;
- the crates.io reverse-dependency API URL;
- the repository's GitHub Dependents page when a GitHub URL is known;
- the Cargo requirement and GitHub search-limit documentation.

The links are supplemental. The CLI does not scrape GitHub's Dependents page,
and it does not send new-web regex syntax to the materially different REST code
search endpoint.

### Scan candidates and write CSV

```powershell
$env:GITHUB_TOKEN = gh auth token

cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --requirement-filter accepts `
  --output fs2-0.4.3.csv `
  --summary-json fs2-0.4.3.summary.json
```

Exact pins only:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --requirement-filter exact `
  --output fs2-exact-pins.csv
```

Stale repositories whose default-branch HEAD commit is at least two years old:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --stale-after-days 730 `
  --activity stale `
  --output fs2-stale.csv
```

Explicit date bounds are also available:

```powershell
cargo run --locked -- scan fs2 `
  --version 0.4.3 `
  --committed-before 2024-01-01 `
  --output fs2-before-2024.csv
```

The default discovery source is `crates-io`. `--discovery github-code` or
`--discovery both` adds a bounded legacy GitHub REST code-search seed. Those
rows remain labeled as bounded and are verified from the repository's current
default-branch snapshot.

Run `cargo run --locked -- scan --help` for kind, optional-dependency,
fork/archive, candidate cap, file-size, activity, partial-result, and
require-match controls.

### Report an existing CSV

`report` performs offline sorting/grouping, so it does not contact crates.io or
GitHub:

```powershell
cargo run --locked -- report fs2-0.4.3.csv `
  --sort msrv-asc `
  --group-by stale

cargo run --locked -- report fs2-0.4.3.csv --json
```

The report command expects the current scan CSV schema and fails with a clear
column error when given an unrelated CSV.

## What `scan` does

For a crates.io-seeded run, the CLI:

1. resolves the requested crate without silently accepting an ambiguous fuzzy
   match;
2. pages through crates.io's reverse-dependency endpoint at no more than one
   API request per second;
3. joins dependency records to dependent versions by `version_id`;
4. reads the corresponding sparse-index entry to recover every matching
   declaration, including renamed and duplicated dependencies;
5. evaluates requirements with Cargo-compatible SemVer rules;
6. groups candidate crates by canonical GitHub repository;
7. resolves each repository and freezes its default branch to an immutable
   commit and tree SHA;
8. enumerates files whose final component is exactly `Cargo.lock` or
   `Cargo.toml`, subject to recorded per-repository safety bounds;
9. parses those blobs structurally and emits one CSV row per repository and
   lockfile, including negative and partial states;
10. classifies staleness from the frozen default-branch HEAD commit time while
    also reporting GitHub's repository-wide `pushed_at` value.

If GitHub reports a recursive tree as truncated, the result is marked partial;
absence is never claimed from an incomplete tree.

Repository inspection is public-only. Private search results or repositories
visible to the supplied token are discarded. Per-file, per-repository matched
file-count, cumulative download, request-time, and JSON-response bounds prevent
a pathological repository from consuming unbounded resources; reaching one of
those bounds is recorded as partial evidence. Cargo manifest blobs are fetched
concurrently while one shared `--jobs` limit bounds GitHub request pressure
across all repository inspections.

## Requirement filters

`--requirement-filter` has three modes:

- `accepts` (default): retain a published declaration when at least one matching
  requirement accepts the requested version;
- `exact`: retain it only when at least one declaration is an explicit, single
  exact comparator such as `=0.4.3`;
- `any`: retain declarations without filtering on the requested version.

If sparse-index enrichment fails for an individual candidate, semantic filters
retain it with `unknown`/partial evidence instead of turning missing declaration
data into a false negative.

Cargo's bare `0.4.3` syntax is a caret-compatible range, not a pin. It accepts
compatible `0.4.x` releases at or above `0.4.3`; it is not treated as exact.

## CSV evidence

The CSV is designed for audit and follow-up rather than a single optimistic
boolean. It includes:

- input, canonical crate, target version, collection time, discovery source,
  `globally_exhaustive: false`, candidate scope, and the applied scan policy;
- dependent crate/version, every published matching requirement, kind, target,
  optional status, acceptance, and exact-pin status;
- original and canonical repository URLs, GitHub repository ID, branch, immutable
  commit/tree identities, commit time, `pushed_at`, fork/archive state, and stale
  classification;
- inventory completeness, tree truncation, blob/path identities, parse status,
  every resolved target version/source, exact occurrence counts, and exact
  crates.io-registry occurrence counts;
- current manifest declarations and requirements;
- declared MSRV observations and effective MSRV source, plus OS names inferred
  from `cfg(target_os = "...")` dependency selectors;
- recorded direct/transitive relation and shortest lockfile-graph depth when it
  can be established;
- row-level error codes and messages.

`not_found`, `absent`, `unknown`, `truncated`, and `failed` remain distinct.
Untrusted text is protected from spreadsheet formula execution in CSV cells.
An exact package entry is confirmed as a dependent only when the lock graph
supports a direct or transitive path from a recorded root; root-only or
unreachable presence remains visible but does not satisfy `--require-match`.

## Authentication and rate limits

Set `GITHUB_TOKEN` (preferred) or `GH_TOKEN`. Public repository APIs can be used
without authentication, but GitHub's unauthenticated primary limit is too small
for useful inventories, and REST code search requires authentication. A token is
never written to output or error details. Credential-bearing GitHub URLs, URL
queries, and fragments are rejected before any network request or output.

The client uses the current versioned GitHub REST API, pins repository content to
an immutable commit, and treats search caps, `incomplete_results`, rate limits,
tree truncation, oversized blobs, parse failures, and missing repositories as
explicit evidence states.

CSV and summary paths must be different after lexical path normalization.
Explicit file outputs are written through a temporary file and atomically
replace an existing target only after serialization succeeds.

crates.io asks API clients to remain at or below one request per second and to
send an identifying user agent. Broad historical or ecosystem-wide analysis is
better served by the daily crates.io database dump; this CLI's default workflow
uses the current reverse-dependency API plus the sparse index.

## Known completeness limits

The run summary always records `globally_exhaustive: false` because:

- GitHub code search covers indexed default branches only, omits documented
  content classes, does not support exhaustive search, and shows at most 100
  results in the new web UI;
- REST code search is a distinct, legacy, authenticated and rate-limited seed,
  capped at 1,000 results per query;
- GitHub Dependents is public-only, approximate, unversioned, and has no supported
  enumeration API;
- crates.io's reverse endpoint currently represents current non-yanked default
  dependent versions, not every historical release;
- repository URLs are publisher metadata and may be missing, stale, non-GitHub,
  or shared by multiple crates;
- a library repository may intentionally omit `Cargo.lock`;
- a lockfile entry can be optional, target-specific, unused by the build of
  interest, or impossible to classify when its graph roots are ambiguous.

Primary references:

- [Cargo dependency requirements](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [Cargo registry index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)
- [crates.io data-access policy](https://crates.io/data-access)
- [GitHub code-search limitations](https://docs.github.com/en/search-github/github-code-search/about-github-code-search#limitations)
- [GitHub REST code search](https://docs.github.com/en/rest/search/search#search-code)
- [GitHub Git Trees API](https://docs.github.com/en/rest/git/trees#get-a-tree)

## Exit codes

- `0`: output was produced under the requested completeness policy;
- `1`: a fatal failure occurred before useful output;
- `2`: command-line usage or argument validation failed (Clap's conventional
  usage-error code);
- `3`: `--require-match` was set and no direct or transitive exact lockfile
  resolution was confirmed;
- `4`: usable output exists but the run is partial (unless `--allow-partial`).

When a run is both partial and has no confirmed match, partial-result code `4`
takes precedence unless `--allow-partial` is set.

## Development checks

```powershell
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

Live network smoke tests should never assert a fixed public result count: crates,
repository heads, indexes, and search totals change over time.
