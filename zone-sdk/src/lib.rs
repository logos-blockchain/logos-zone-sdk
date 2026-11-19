//! Logos blockchain zone SDK.
//!
//! A Rust client for working with a Logos channel, built around the
//! [`sequencer`] subsystem: drive your own sequencer that publishes
//! inscriptions to a channel, tracks pending/finalized state, and surfaces
//! chain events.
//!
//! There is no separate read-only client: to only observe a channel, run a
//! [`sequencer::ZoneSequencer`] with a signing key that is **not** in the
//! channel's accredited keys. Inscription posting is gated on holding the
//! round-robin turn, so such a sequencer never publishes or reposts anything —
//! while still delivering finalized txs, channel updates and the
//! non-finalized channel view through its events. Before emitting
//! [`sequencer::Event::Ready`], the instance backfills the finalized history
//! it has not seen yet: from genesis on a cold start, or from the restored
//! [`sequencer::SequencerCheckpoint`]'s slot when resuming. Construction
//! still requires a [`sequencer::FundingConfig`]; for a read-only instance
//! pass a placeholder — funding is only exercised by publish-type calls,
//! which such a sequencer never makes.
//!
//! The sequencer talks to a Logos node through the [`adapter`] module's
//! [`adapter::Node`] trait; an HTTP implementation is provided as
//! [`adapter::NodeHttpClient`].
//!
//! # Quick start (sequencer)
//!
//! The sequencer is owned by a single drive task. Two command surfaces:
//!
//! - [`sequencer::SequencerHandle`] (sync, drive-loop only) — obtained via
//!   [`sequencer::ZoneSequencer::handle`]. Borrows the sequencer mutably so it
//!   can only be used from the drive task. Every state-mutating method returns
//!   the resulting [`sequencer::SequencerCheckpoint`] inline so the caller can
//!   persist outbox + checkpoint atomically.
//! - [`sequencer::SequencerClient`] (async, cross-task) — obtained via
//!   [`sequencer::ZoneSequencer::client`]. Cheap-to-clone; routes publish/admin
//!   commands through the actor's request channel and vends subscription
//!   receivers off cloned senders. Useful for service-style integrations where
//!   publish calls originate from tasks other than the drive loop. The drive
//!   loop must still be polled for client publish awaits to resolve.
//!
//! ```ignore
//! use lb_zone_sdk::{
//!     CommonHttpClient,
//!     adapter::NodeHttpClient,
//!     sequencer::{Event, FundingConfig, ZoneSequencer},
//! };
//! # use lb_core::mantle::ops::channel::ChannelId;
//! # use lb_key_management_system_service::keys::Ed25519Key;
//! # async fn run(channel_id: ChannelId, signing_key: Ed25519Key, funding: FundingConfig) {
//! let node = NodeHttpClient::new(CommonHttpClient::new(None), "http://localhost:8080".parse().unwrap());
//! // `funding.funding_pk` is a wallet key the connected node controls (its
//! // configured funding wallet); the node builds and proves the fee transfer.
//! let mut sequencer = ZoneSequencer::init(channel_id, signing_key, node, funding, None);
//!
//! // Cross-task surface: clone and move into any task. Carries both
//! // publish/admin methods and subscription receivers.
//! let client = sequencer.client();
//! let _ready_rx      = client.subscribe_ready();
//! let _checkpoint_rx = client.subscribe_checkpoint();
//!
//! loop {
//!     match sequencer.next_event().await {
//!         Event::BlocksProcessed { checkpoint, channel_update, deposits, finalized } => {
//!             let _ = (checkpoint, channel_update, deposits, finalized);
//!         }
//!         Event::Ready                             => {}
//!         Event::TurnNotification { notification } => { let _ = notification; }
//!     }
//! }
//! # }
//! ```
//!
//! See the [`sequencer`] module for the full event vocabulary.

pub mod adapter;
pub mod sequencer;
#[cfg(test)]
mod test_support;

// Logos blockchain crates a zone builds against, re-exported so a zone can
// depend on this crate alone and move to a new node version with one bump.
pub use lb_binary_codec as binary_codec;
pub use lb_common_http_client as common_http_client;
pub use lb_core as core;
pub use lb_groth16 as groth16;
pub use lb_http_api_common as http_api_common;
pub use lb_key_management_system_service as key_management_system_service;
#[cfg(feature = "testing")]
pub use lb_testing_framework as testing_framework;
#[cfg(feature = "testing")]
pub use testing_framework_app;
#[cfg(feature = "testing")]
pub use testing_framework_core;

/// Types appearing in the [`adapter::Node`] trait's method signatures and in
/// [`ZoneMessage`], re-exported from the crates that define them.
///
/// An external backend implementation only needs to depend on this crate:
/// everything required to write an `impl Node` — request/response bodies,
/// stream item types, ids, and the error type — is importable from here. The
/// stream alias is [`adapter::BoxStream`]; the message types themselves
/// ([`ZoneMessage`], [`ZoneBlock`], [`Deposit`], [`Withdraw`]) live at the
/// crate root.
pub mod node_types {
    pub use lb_common_http_client::{
        ApiBlock, BlockInfo, ChainServiceInfo, Error, Events, ProcessedBlockEvent, Slot, TimeInfo,
    };
    pub use lb_core::{
        crypto::Hash,
        header::HeaderId,
        mantle::{
            SignedOps, TxHash, Value,
            channel::ChannelState,
            notes::{InputNullifiers, OutputCommitments, ProgramId, derive_program_output_nonce},
            ops::{
                OpId, ProgramNoteOpening,
                channel::{
                    ChannelId, MsgId,
                    deposit::Metadata,
                    inscribe::{Inscription, user_step_id},
                    program_step::{program_deposit_id, program_deposits_hash},
                },
            },
            programs::{ProgramVerificationKey, derive_program_id, program_step_id},
            transactions::states::Unverified,
        },
    };
    pub use lb_http_api_common::bodies::{
        mantle::LimitsResponseBody,
        wallet::fund::{WalletFundRequestBody, WalletFundResponseBody},
    };
}

use std::sync::Arc;

pub use lb_common_http_client::{CommonHttpClient, Slot};
use lb_core::{
    crypto::Hash,
    mantle::{
        SignedOps, TxHash,
        ledger::verification_mode::VerificationMode,
        notes::{InputNullifiers, OutputCommitments},
        ops::{
            OpProofRef, OpRef, StepProof,
            channel::{
                MsgId,
                deposit::Metadata,
                inscribe::{Inscription, InscriptionOp, MiniBlocks},
            },
        },
        transactions::states::VerificationState,
    },
};
pub use lb_key_management_system_service::keys::UnverifiedEd25519PublicKey;

/// A message from a zone channel, included/finalized in Bedrock
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneMessage {
    /// A zone block published to a channel
    Block(ZoneBlock),
    /// A deposit operation submitted to a channel
    Deposit(Deposit),
    /// An withdraw operation submitted to a channel
    Withdraw(Withdraw),
}

/// A zone block from a zone channel, included/finalized in Bedrock
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneBlock {
    /// The unique identifier of this inscription.
    pub id: MsgId,
    /// The opaque inscription data.
    pub data: Inscription,
    /// The public key of the signer of this zone block.
    pub signer: UnverifiedEd25519PublicKey,
    /// The steps of this zone block.
    pub steps: InscriptionSteps,
}

/// The steps of an inscription with their proofs, one per step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InscriptionSteps {
    pub mini_blocks: MiniBlocks,
    pub proofs: Arc<[StepProof]>,
}

impl InscriptionSteps {
    pub(crate) fn of(op: &InscriptionOp, proof: OpProofRef) -> Self {
        let OpProofRef::ChannelInscribe(proof) = proof else {
            unreachable!("a signed inscription carries an inscription proof")
        };
        Self {
            mini_blocks: op.mini_blocks.clone(),
            proofs: proof.step_proofs.as_slice().into(),
        }
    }
}

/// The ops of `tx` with their proofs, in op order.
pub(crate) fn ops_with_proofs<State: VerificationState, Mode: VerificationMode>(
    tx: &SignedOps<State, Mode>,
) -> impl Iterator<Item = (OpRef<'_>, OpProofRef<'_>)> {
    tx.op_refs_iter().zip(tx.op_proof_refs_iter())
}

/// The inscriptions of `tx` with their steps, in op order.
pub(crate) fn inscribes<State: VerificationState, Mode: VerificationMode>(
    tx: &SignedOps<State, Mode>,
) -> impl Iterator<Item = (&InscriptionOp, InscriptionSteps)> {
    ops_with_proofs(tx).filter_map(|(op, proof)| match op {
        OpRef::ChannelInscribe(inscribe) => Some((inscribe, InscriptionSteps::of(inscribe, proof))),
        _ => None,
    })
}

/// A deposit from a zone channel, included/finalized in Bedrock
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    /// The transaction hash containing this deposit op.
    pub tx_hash: TxHash,
    /// The `op_id` of the deposit op: its stable identity within the tx,
    /// matching `DepositInfo::op_id` on the sequencer side.
    pub op_id: Hash,
    /// The channel notes the deposit created, as commitments, sourced from
    /// the block's events. Their values and holders are private.
    pub outputs: OutputCommitments,
    /// Opaque metadata associated with this deposit
    pub metadata: Metadata,
}

/// An withdrawal from a zone channel, included/finalized in Bedrock
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdraw {
    /// The transaction hash containing this withdraw op.
    pub tx_hash: TxHash,
    /// The `op_id` of the withdraw op: its stable identity within the tx.
    pub op_id: Hash,
    /// The nullifiers of the channel notes the holder withdraws.
    pub inputs: InputNullifiers,
    /// The commitments of the ledger notes it creates, released at its due
    /// slot.
    pub outputs: OutputCommitments,
}

impl Deposit {
    #[must_use]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}
