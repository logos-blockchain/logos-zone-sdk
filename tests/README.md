# SDK and SQL integration tests

On this release branch the suites are the node's own zone and Logos SQL
Cucumber suites at the pinned node release: steps and features come from
`logos-blockchain-tests`. The `[patch]` section of the workspace manifest
builds that harness against the `ZoneSDK` and Logos SQL of this repository
instead of the node's own copies (Logos SQL here is the node's at that release), and the two packages here only hold the
runner.

## Node binary

The suites start real node processes. The node harness is a Git dependency
here, so without a supplied binary it would build the node inside Cargo's
checkout of the node repository, or fail in CI. Always provide a binary built
from the pinned node release with the `testing` feature:

```sh
tag="$(sed -nE 's/^lb-core += \{.*tag = "([^"]+)".*$/\1/p' Cargo.toml)"
cargo install --locked --git https://github.com/logos-blockchain/logos-blockchain.git --tag "$tag" --features testing --root target/node logos-blockchain-node
export LOGOS_BLOCKCHAIN_NODE_BIN="$PWD/target/node/bin/logos-blockchain-node"
```

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

Set `PASSWORD_MANAGER_BIN` explicitly: the default points into the node checkout.

The runner only supports local process deployment.

## CI

`.github/workflows/cucumber-integration-tests.yml` builds the pinned node
binary and runs both suites and the password-manager scenario on the
self-hosted runners, in the merge queue and on demand, as the node repository's
lane did before the move.

After updating the node release, run both suites before marking the new
release compatible. Compilation and unit tests alone do not establish node
interoperability.
