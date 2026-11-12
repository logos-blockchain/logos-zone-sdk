# logos-blockchain-zone-sdk-module-backend

Zone SDK `adapter::Node` backend that reads Bedrock through `blockchain_module` via
[`logos-blockchain-client`](https://github.com/logos-blockchain/logos-blockchain-module/tree/master/rust-client), a drop-in for `adapter::NodeHttpClient`:

```rust
let node = NodeModuleClient::new();   // "blockchain_module"
let mut sequencer = ZoneSequencer::init(channel_id, signing_key, node, funding, None);
```
Runs inside a Logos module loaded next to `blockchain_module`.

`logos-blockchain-client` must pin the same node revision as this workspace, or the
node types on both sides of the backend are different types and it will not compile.
Bump the client pin in the root `Cargo.toml` together with the node revision.

`limits()` returns an error: `blockchain_module` has no call for the node's limits
yet, so `ZoneSequencer::max_inscription_size` fails on this backend.
