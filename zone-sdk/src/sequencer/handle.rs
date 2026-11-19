use lb_core::{
    mantle::{
        SignedOps,
        channel::{SlotTimeframe, SlotTimeout},
        ledger::verification_mode::StandardMode,
        ops::{
            StepProof,
            channel::{
                MsgId, VerifiedChannelKeys,
                inscribe::{Inscription, InscriptionOp, MiniBlocks},
            },
        },
        programs::ProgramVerificationKey,
        transactions::{Ops, states::Unverified},
    },
    proofs::channel_multi_sig_proof::IndexedSignatures,
};
use lb_key_management_system_service::keys::Ed25519Signature;

use super::{
    program_steps::{MiniBlockSpec, ProgramInscription},
    types::{
        Error, PreparedChannelConfig, ProgramNotesView, ProgramRegisterInfo, SequencerCheckpoint,
    },
    zone_sequencer::ZoneSequencer,
};
use crate::{adapter, sequencer::zone_sequencer::PublishReceipt};

/// Drive-loop handle for issuing commands to the sequencer.
///
/// Obtained via [`ZoneSequencer::handle`]. Because the handle holds a `&mut`
/// borrow of the sequencer, only the drive task can hold one — the borrow
/// checker enforces "drive-loop only," which removes any actor-vs-caller
/// deadlock window and lets every state-mutating method return the resulting
/// [`PublishReceipt`] inline so the caller can persist outbox + checkpoint
/// atomically.
///
/// Pattern:
/// ```ignore
/// loop {
///     tokio::select! {
///         Some(msg) = ui_rx.recv() => {
///             let publish_receipt = sequencer.handle().publish(msg)?;
///             db.tx(|t| {
///                 t.outbox(publish_receipt);
///                 t.save_checkpoint(publish_receipt.checkpoint());
///             });
///         }
///         ev = sequencer.next_event() => {
///             handle_event(ev, &mut sequencer, &mut db).await;
///         }
///     }
/// }
/// ```
pub struct SequencerHandle<'a, Node> {
    sequencer: &'a mut ZoneSequencer<Node>,
}

impl<'a, Node> SequencerHandle<'a, Node> {
    pub(super) const fn new(sequencer: &'a mut ZoneSequencer<Node>) -> Self {
        Self { sequencer }
    }
}

impl<Node> SequencerHandle<'_, Node>
where
    Node: adapter::Node + Clone + Send + Sync + 'static,
{
    /// Enqueue an inscription onto the zone's channel.
    ///
    /// First funds the transaction from the node's wallet
    /// ([`SequencerConfig::funding`](super::SequencerConfig::funding), one
    /// HTTP round-trip) and signs the funded hash; a funding failure returns
    /// an error without mutating state. Then records the inscription as
    /// pending and queues a `post_transaction` future onto the drive loop's
    /// in-flight pool — the post itself happens asynchronously the next time
    /// the drive loop polls `next_event`. The returned
    /// [`PublishResult`](super::PublishResult) reflects this queued state, not
    /// a network acknowledgement; the tx may not have reached the node yet.
    /// The accompanying [`SequencerCheckpoint`](super::SequencerCheckpoint)
    /// captures the new pending state so the caller can persist outbox +
    /// checkpoint atomically.
    ///
    /// Returns [`Error::Unavailable`] if cold-start backfill is still in
    /// progress (the sequencer hasn't emitted [`super::Event::Ready`] yet),
    /// or while the node is disconnected: funding needs the node, and a fresh
    /// `Ready` event is emitted when the reconnect completes, signalling it is
    /// safe to retry. To wait for readiness asynchronously, subscribe via
    /// [`ZoneSequencer::subscribe_ready`].
    pub async fn publish(&mut self, data: Inscription) -> Result<PublishReceipt, Error> {
        self.sequencer.do_publish(data).await
    }

    /// Build the inscription of `data` applying `mini_blocks` on the current
    /// publish tip, without publishing it.
    ///
    /// The returned op fixes the `op_id` the program step proofs bind. A
    /// user step or program deposit binds its own id, not the `op_id`.
    pub fn prepare_inscription(
        &mut self,
        data: Inscription,
        mini_blocks: MiniBlocks,
    ) -> Result<InscriptionOp, Error> {
        self.sequencer.do_prepare_inscription(data, mini_blocks)
    }

    /// Build the inscription of `data` with `mini_blocks` on the current
    /// publish tip, its program steps spending the channel's program notes
    /// and carrying the witness of their spend, without publishing it. The
    /// spends are proven with [`super::prove_program_step`], off the drive
    /// loop, and the inscription is published with
    /// [`Self::submit_prepared_inscription`] and
    /// [`ProgramInscription::step_proofs`]. Async counterpart:
    /// [`super::SequencerClient::prepare_program_inscription`].
    pub fn prepare_program_inscription(
        &mut self,
        data: Inscription,
        mini_blocks: Vec<MiniBlockSpec>,
    ) -> Result<ProgramInscription, Error> {
        self.sequencer
            .do_prepare_program_inscription(data, mini_blocks)
    }

    /// Enqueue a prepared inscription with one proof per step.
    ///
    /// The op is published as prepared: a stale re-fund replaces only the
    /// fee inputs, so the `op_id` and every proof stay valid. The op is never
    /// rebuilt silently. A publish tip that moved since
    /// [`Self::prepare_inscription`] fails with [`Error::ChannelStateChanged`],
    /// and an inscription that lands then drops off the canonical branch
    /// comes back orphaned in a [`super::ChannelUpdate`] with its steps. Both
    /// mean: prepare again, re-prove the program steps against the new
    /// `op_id`, keep the holders' proofs, submit again.
    pub async fn submit_prepared_inscription(
        &mut self,
        op: InscriptionOp,
        step_proofs: Vec<StepProof>,
    ) -> Result<PublishReceipt, Error> {
        self.sequencer
            .do_submit_prepared_inscription(op, step_proofs)
            .await
    }

    /// Build an [`Ops`] for the given ops and an inscription message,
    /// without submitting it.
    ///
    /// The returned [`Ops`] should be signed by all parties and
    /// submitted via [`Self::submit_signed_tx`]. Does not mutate sequencer
    /// state.
    pub fn prepare_tx(
        &mut self,
        ops: Ops,
        data: Inscription,
    ) -> Result<(Ops, MsgId, Ed25519Signature), Error> {
        self.sequencer.do_prepare_tx(ops, data)
    }

    /// Sign an [`Ops`] using the sequencer's key.
    ///
    /// Useful when signing tx built by other sequencers (e.g. withdraw). Does
    /// not mutate sequencer state.
    pub fn sign_tx(&mut self, tx: &Ops) -> Result<Ed25519Signature, Error> {
        self.sequencer.do_sign_tx(tx)
    }

    /// Enqueue a [`SignedOps`] associated with a [`MsgId`] for posting.
    ///
    /// Synchronously records the tx as pending and queues a
    /// `post_transaction` future onto the drive loop's in-flight pool — the
    /// post runs the next time the drive loop polls `next_event`. The
    /// returned [`PublishReceipt`] reflects the queued state, not a network
    /// acknowledgement.
    pub fn submit_signed_tx(
        &mut self,
        tx: SignedOps<Unverified, StandardMode>,
        msg_id: MsgId,
    ) -> Result<PublishReceipt, Error> {
        self.sequencer.do_submit_signed_tx(tx, msg_id)
    }

    /// Update the channel's config.
    ///
    /// For an existing channel the sequencer's signing key must be on the
    /// channel's current accredited list (at any position) and the channel's
    /// `configuration_threshold` must be 1 — this one-shot helper does not
    /// collect signatures from other key holders. Multi-sig channels are
    /// reconfigured with [`Self::prepare_channel_config`], collecting the
    /// signatures out-of-band, and [`Self::submit_channel_config`]. This
    /// overwrites the entire key list — include the sequencer's own key if
    /// it should remain authorized.
    ///
    /// `posting_timeframe` and `posting_timeout` control round-robin
    /// sequencer rotation (see Mantle spec). Pass `0` for both to keep a
    /// single fixed sequencer at index 0.
    ///
    /// First funds the transaction from the node's wallet
    /// ([`SequencerConfig::funding`](super::SequencerConfig::funding)) and
    /// signs the funded hash. Enqueues the config tx onto the drive loop's
    /// in-flight pool — the post runs the next time the drive loop polls
    /// `next_event`. The returned [`PublishResult`](super::PublishResult)
    /// reflects the queued state, not a network acknowledgement. The signed tx
    /// is also returned for callers that want to observe finalization via
    /// the event stream.
    pub async fn channel_config(
        &mut self,
        keys: VerifiedChannelKeys,
        posting_timeframe: SlotTimeframe,
        posting_timeout: SlotTimeout,
        configuration_threshold: u16,
    ) -> Result<(PublishReceipt, SignedOps<Unverified, StandardMode>), Error> {
        self.sequencer
            .do_channel_config(
                keys,
                posting_timeframe,
                posting_timeout,
                configuration_threshold,
            )
            .await
    }

    /// Register a program by its verification key: one funded
    /// `ProgramRegister` op, no signature. Registering a key already
    /// registered has no effect, so repeating the call is safe. The
    /// sequencer re-posts and re-funds the tx until it finalizes; the
    /// registration is reported as `ObservedOp::ProgramRegister` when its
    /// block joins the canonical chain and as `FinalizedOp::ProgramRegister`
    /// once final.
    pub async fn register_program(
        &mut self,
        verification_key: ProgramVerificationKey,
    ) -> Result<(ProgramRegisterInfo, SequencerCheckpoint), Error> {
        self.sequencer.do_register_program(verification_key).await
    }

    /// Build and fund a channel-config tx for external multi-sig signing.
    ///
    /// The multi-sig counterpart of [`Self::channel_config`]: instead of
    /// signing with the sequencer's own key, it hands back a
    /// [`PreparedChannelConfig`] carrying the funded tx, the `sign_payload`
    /// each accredited key must sign, and the channel's current accredited
    /// keys / `configuration_threshold`. The caller collects a signature from
    /// each required key holder over `sign_payload`, then submits the
    /// fully-signed tx via [`Self::submit_channel_config`]. Does not mutate
    /// sequencer state.
    ///
    /// The config-lineage parent is auto-detected exactly as in
    /// [`Self::channel_config`], so the prepared config extends the current
    /// config tip. For an unclaimed channel the returned accredited-key list
    /// is empty and the threshold `0` — submit with no signatures.
    pub async fn prepare_channel_config(
        &mut self,
        keys: VerifiedChannelKeys,
        posting_timeframe: SlotTimeframe,
        posting_timeout: SlotTimeout,
        configuration_threshold: u16,
    ) -> Result<PreparedChannelConfig, Error> {
        self.sequencer
            .do_prepare_channel_config(
                keys,
                posting_timeframe,
                posting_timeout,
                configuration_threshold,
            )
            .await
    }

    /// Submit a [`PreparedChannelConfig`] with its externally-collected
    /// signatures.
    ///
    /// `signatures` must be indexed against
    /// [`PreparedChannelConfig::accredited_keys`], with at most one signature
    /// per index. Assembles the fully-signed config tx and
    /// enqueues it for posting
    /// on the drive loop's in-flight pool — the returned [`PublishReceipt`]
    /// reflects the queued state, not a network acknowledgement.
    pub fn submit_channel_config(
        &mut self,
        prepared: PreparedChannelConfig,
        signatures: IndexedSignatures,
    ) -> Result<PublishReceipt, Error> {
        self.sequencer
            .do_submit_channel_config(prepared, signatures)
    }

    /// The channel's program notes a new step may consume at the current
    /// tip, with their paths against the view's root. Async counterpart:
    /// [`super::SequencerClient::program_notes`].
    #[must_use]
    pub fn program_notes(&self) -> ProgramNotesView {
        self.sequencer.program_notes()
    }
}
