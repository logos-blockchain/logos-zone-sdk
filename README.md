# Logos Zone SDK

Zone SDK and SQL libraries for Logos Blockchain.

This workspace contains:

- `zone-sdk`: `logos-blockchain-zone-sdk`, for zone sequencers and readers.
- `logos_sql`: `logos-sql`, SQLite replication built on the SDK.
- `tests/zone-sdk` and `tests/logos-sql`: their Cucumber suites.

## Development

Use the Rust toolchain in `rust-toolchain.toml`. The shared node, protocol,
HTTP and test-support crates are Git dependencies pinned to one node commit in
`Cargo.toml`. The node's native circuit/prover build prerequisites still
apply; see the node repository's build instructions for platform setup.

Lints, formatting, TOML style, the workspace dependency policy and the
cargo-deny rules are the node repository's. The same checks run in CI
(`.github/workflows/code-check.yml`) and as pre-commit hooks
(`.pre-commit-config.yaml`):

```sh
cargo +nightly-2026-08-15 fmt --all -- --check
taplo lint && taplo fmt --check
scripts/check-workspace-dependency-policies.sh
cargo machete --with-metadata
cargo-deny --locked --config .cargo-deny.toml check
CARGO_BUILD_WARNINGS=deny cargo clippy --locked --workspace --all-targets --all-features
cargo test --locked --workspace --lib
```

See [integration test instructions](tests/README.md) for the Cucumber suites,
which run against node processes.

## Consumption and releases

External consumers pin a release tag or commit of this repository. Use the
toolchain in `rust-toolchain.toml` in the consuming project too; Cargo does not
select a dependency repository's toolchain for its consumers. Package names
stay `logos-blockchain-zone-sdk` and `logos-sql`. Both inherit the workspace
version as they did in the node repository and are not published to crates.io;
independent versioning is a release-process decision still to be taken. SQL
uses the SDK from the same workspace snapshot, so a SQL tag selects the
matching SDK source. Record the compatible node revision with each release.
Maintenance branches can carry fixes for older supported node versions.

## Updating the node revision

Every `lb-*` and `logos-blockchain-tests` entry in `[workspace.dependencies]`
pins the same node revision, and the Cucumber lane builds the node binary from
it. Bump them together, refresh `Cargo.lock`, then run the unit tests and both
Cucumber suites before marking the new revision compatible.

## History

The baseline was extracted from the node repository using `git-filter-repo`.
Authors and dates are preserved. The filtered commit hashes differ.

Historical snapshots retain their original manifests and may require the
original node workspace to build. Standalone build configuration is introduced
by the migration changes on top of that history.

The shared historical Cucumber world is retained only while it contained SDK
and SQL state, up to the earlier test-suite extraction boundary.
