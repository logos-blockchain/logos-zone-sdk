use std::sync::Arc;

use async_trait::async_trait;
use futures::stream;
use lb_zone_sdk::{
    adapter::{BoxStream, Node},
    node_types::{
        ApiBlock, BlockInfo, ChainServiceInfo, ChannelId, ChannelState, Error, Events, HeaderId,
        LimitsResponseBody, ProcessedBlockEvent, SignedOps, Slot, StandardMode, TimeInfo,
        Unverified, WalletFundRequestBody, WalletFundResponseBody,
    },
};
use logos_blockchain_client::{
    BlockchainModuleClient, EventData, EventSubscription, LogosError, ModuleError, StreamItem,
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

const TARGET: &str = "zone_sdk::module_backend";
const STREAM_CAPACITY: usize = 64;

type Callback<T> = Box<dyn FnOnce(Result<T, ModuleError>) + Send + 'static>;

/// Holds only the module's name: binding a client is cheap, the Logos SDK
/// shares one connection per module name, so each call binds its own.
#[derive(Clone)]
pub struct NodeModuleClient {
    module: Arc<str>,
}

impl Default for NodeModuleClient {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeModuleClient {
    #[must_use]
    pub fn new() -> Self {
        Self::bind("blockchain_module")
    }

    #[must_use]
    pub fn bind(module_name: &str) -> Self {
        Self {
            module: Arc::from(module_name),
        }
    }

    async fn call<T, S>(&self, start: S) -> Result<T, Error>
    where
        T: Send + 'static,
        S: FnOnce(&BlockchainModuleClient, Callback<T>),
    {
        let (tx, rx) = oneshot::channel::<Result<T, ModuleError>>();
        start(
            &BlockchainModuleClient::bind(&self.module),
            Box::new(move |result| {
                drop(tx.send(result));
            }),
        );
        rx.await
            .map_err(|_| Error::Client("module reply channel closed".to_owned()))?
            .map_err(to_sdk_error)
    }

    fn event_stream<T, Sub, Dec>(
        &self,
        event: &'static str,
        subscribe: Sub,
        decode_item: Dec,
    ) -> Result<BoxStream<T>, Error>
    where
        T: Send + 'static,
        Sub: FnOnce(&mut BlockchainModuleClient) -> Result<EventSubscription, LogosError>,
        Dec: Fn(&EventData) -> Result<StreamItem<T>, ModuleError> + Send + 'static,
    {
        let mut client = BlockchainModuleClient::bind(&self.module);
        let subscription = subscribe(&mut client)
            .map_err(|e| Error::Client(format!("{event}: subscribe: {e}")))?;

        let (tx, rx) = mpsc::channel::<T>(STREAM_CAPACITY);
        std::thread::Builder::new()
            .name(format!("zone-sdk-{event}"))
            .spawn(move || {
                // Ends, and unsubscribes, on the first event after the stream is
                // dropped.
                for ev in subscription {
                    match decode_item(&ev) {
                        Ok(StreamItem::Item(item)) => {
                            if tx.blocking_send(item).is_err() {
                                break;
                            }
                        }
                        Ok(StreamItem::End) => {
                            debug!(target: TARGET, event, "module ended the stream");
                            break;
                        }
                        Err(e) => {
                            warn!(target: TARGET, event, error = %e, "undecodable event, skipping");
                        }
                    }
                }
            })
            .map_err(|e| Error::Client(format!("{event}: spawn listener thread: {e}")))?;

        Ok(Box::pin(stream::unfold(rx, async |mut rx| {
            rx.recv().await.map(|item| (item, rx))
        })))
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Used as a `map_err` function, which hands over the error by value."
)]
fn to_sdk_error(e: ModuleError) -> Error {
    match e {
        ModuleError::Transport { .. } => Error::Client(e.to_string()),
        ModuleError::NodeNotRunning { .. }
        | ModuleError::NotFound { .. }
        | ModuleError::Module { .. }
        | ModuleError::Decode { .. } => Error::Server(e.to_string()),
    }
}

#[async_trait]
impl Node for NodeModuleClient {
    async fn consensus_info(&self) -> Result<ChainServiceInfo, Error> {
        self.call(BlockchainModuleClient::cryptarchia_info_async)
            .await
            .map(|info| info.to_chain_service_info())
    }

    async fn time_info(&self) -> Result<TimeInfo, Error> {
        self.call(BlockchainModuleClient::time_info_async).await
    }

    /// `blockchain_module` has no call for the node's limits yet: the node's C
    /// bindings do not expose them. Everything else in the SDK works without
    /// this; only `ZoneSequencer::max_inscription_size` reports the error.
    async fn limits(&self) -> Result<LimitsResponseBody, Error> {
        Err(Error::Server(format!(
            "{}: limits are not exposed by the module",
            self.module
        )))
    }

    async fn channel_state(&self, channel_id: ChannelId) -> Result<Option<ChannelState>, Error> {
        self.call(|c, cb| c.channel_state_async(channel_id, cb))
            .await
    }

    async fn block_stream(&self) -> Result<BoxStream<ProcessedBlockEvent>, Error> {
        self.event_stream(
            "processedBlock",
            BlockchainModuleClient::on_processed_block,
            BlockchainModuleClient::processed_block_item,
        )
    }

    async fn lib_stream(&self) -> Result<BoxStream<BlockInfo>, Error> {
        self.event_stream(
            "libBlock",
            BlockchainModuleClient::on_lib_block,
            BlockchainModuleClient::lib_block_item,
        )
    }

    async fn block(&self, id: HeaderId) -> Result<Option<ApiBlock>, Error> {
        self.call(|c, cb| c.block_async(id, cb)).await
    }

    async fn block_events(&self, id: HeaderId) -> Result<Option<Events>, Error> {
        self.call(|c, cb| c.block_events_async(id, cb)).await
    }

    async fn immutable_blocks(
        &self,
        slot_from: Slot,
        slot_to: Slot,
    ) -> Result<Vec<ApiBlock>, Error> {
        self.call(|c, cb| c.blocks_async(slot_from, slot_to, cb))
            .await
    }

    async fn post_transaction(&self, tx: SignedOps<Unverified, StandardMode>) -> Result<(), Error> {
        self.call(|c, cb| c.submit_transaction_async(&tx, cb))
            .await
            .map(|_hash| ())
    }

    async fn fund_tx(
        &self,
        request: WalletFundRequestBody,
    ) -> Result<WalletFundResponseBody, Error> {
        self.call(|c, cb| c.fund_tx_async(&request, cb)).await
    }
}
