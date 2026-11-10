# SDK and SQL integration tests

The client suites reuse `logos-blockchain-tests` and `blockchain-test-logos`
from the pinned node revision. Node deployment, funding, shared steps and
diagnostics remain owned by the node repository.

## Node binary

The suites start real node processes. The node harness is a Git dependency
here, so without a supplied binary it would build the node inside Cargo's
checkout of the node repository, or fail in CI. Always provide a binary built
from the pinned node revision with the `testing` feature:

```sh
rev="$(sed -nE 's/^lb-core += \{.*rev = "([0-9a-f]{40})".*$/\1/p' Cargo.toml)"
cargo install --locked --git https://github.com/logos-blockchain/logos-blockchain.git --rev "$rev" --features testing --root target/node logos-blockchain-node
export LOGOS_BLOCKCHAIN_NODE_BIN="$PWD/target/node/bin/logos-blockchain-node"
```

`LOGOS_BLOCKCHAIN_NODE_DOWNLOAD_URL` with `LOGOS_BLOCKCHAIN_NODE_DOWNLOAD_SHA256`
selects a node release tarball instead, once the pinned revision is a release.

## Running the suites

```sh
cargo test --locked -p logos-blockchain-zone-tests --features cucumber --test cucumber -- --tags '@zone_ci and not (@broken or @undefined_behaviour)'
cargo test --locked -p logos-blockchain-sql-tests --features cucumber --test cucumber -- --tags '@logos_sql_ci and not (@broken or @undefined_behaviour)'
```

Set `CUCUMBER_RETRIES=0` locally so retries do not mask flaky scenarios, and
`MAX_CUCUMBER_CONCURRENT_SCENARIOS=1` as CI does. Scenario artifacts live under
each suite's `cucumber_tests/temp` directory.

The password-manager scenario drives the actual example executable:

```sh
cargo build --locked -p logos-sql --example password_manager
export PASSWORD_MANAGER_BIN="$PWD/target/debug/examples/password_manager"
cargo test --locked -p logos-blockchain-sql-tests --features cucumber --test cucumber -- --tags '@password_manager'
```

`PASSWORD_MANAGER_BIN` defaults to that debug path; set it for other build
directories or profiles. The settlement benchmark belongs to
`logos-blockchain-sql-tests`; run it with `--release` and
`--tags '@logos_sql_benchmark'`.

Compose and Kubernetes deployment modes need the node repository's images,
cfgsync and deployment setup. These suites default to local process deployment.

## CI

`.github/workflows/cucumber-integration-tests.yml` builds the pinned node
binary and runs both suites and the password-manager scenario on the
self-hosted runners, in the merge queue and on demand, as the node repository's
lane did before the move.

After updating the node revision, run both suites before marking the new
revision compatible. Compilation and unit tests alone do not establish node
interoperability.
