use std::{collections::HashSet, num::NonZero, sync::Arc};

use lb_core::{
    header::HeaderId,
    mantle::{
        Op, SignedOps,
        channel::{SlotTimeframe, SlotTimeout},
        ledger::verification_mode::StandardMode,
        notes::{NoteCommitment, NoteNullifier},
        ops::{
            ChannelInscribeProof, OpProof, OpProofRef, OpRef, StepProof,
            channel::{
                MsgId, UnverifiedChannelKeys, VerifiedChannelKeys,
                config::ChannelConfigOp,
                deposit::{DepositOp, Metadata},
                inscribe::{Inscription, InscriptionOp, MiniBlocks},
            },
            program::ProgramRegisterOp,
        },
        programs::{ProgramVerificationKey, derive_program_id},
        traits::Hashable as _,
        transactions::{OpProofs, Ops, TxList, states::Unverified},
    },
};
use lb_groth16::Fr;
use lb_key_management_system_service::keys::Ed25519Key;
use tokio::sync::{mpsc, watch};

use super::{
    super::{
        block_fetch::ViewBefore,
        block_states::{BlockChannelTx, ChannelTxKind},
        types::{ConfigInfo, FinalizedOp, InscriptionInfo, ProgramRegisterInfo, SequencerConfig},
        zone_sequencer::track_pending_tx,
    },
    *,
};
use crate::{
    InscriptionSteps, inscribes,
    test_support::{
        FORK_DIGEST, MockNode, StreamEnd, StreamScript, api_block, funding_config, header_id,
        inscribe_op, live_event, observed_deposit_ids, scripts, single_key_channel_state,
        unverified_tx_with_ops,
    },
};

#[tokio::test]
async fn prepare_submit_deposit_and_inscription() {
    // Init a sequencer
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let (node, mut posted_txs) = MockNode::with_posted_channel();
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    // Drive sequencer until ready
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    // Prepare a deposit op
    let deposit_op = DepositOp {
        channel_id,
        inputs: [NoteNullifier(Fr::from(1u64))].into(),
        outputs: [NoteCommitment(Fr::from(2u64))].into(),
        commitment_merkle_root: Fr::from(3u64),
        excess_value: 0,
        metadata: Metadata::new_unchecked(b"to Alice".to_vec()),
    };

    // Build a `MantleTx` via the handle
    let (tx, msg_id, _inscription_sig) = sequencer
        .handle()
        .prepare_tx(
            Ops::new(FORK_DIGEST, [Op::ChannelDeposit(deposit_op.clone())]),
            Inscription::new_unchecked(b"Mint 10 to Alice".to_vec()),
        )
        .unwrap();
    assert_eq!(tx.inner().len(), 2);
    assert_eq!(tx.inner()[0], Op::ChannelDeposit(deposit_op));
    assert!(matches!(tx.inner()[1], Op::ChannelInscribe(_)));

    // The holder's ZkTransfer is out of the SDK's hands: sample proofs stand
    // in for it.
    let signed_tx = SignedOps::from_ops_with_sample_proofs(tx);

    // Submit via the handle (mutates state + queues post to in_flight).
    let (result, checkpoint) = sequencer
        .handle()
        .submit_signed_tx(signed_tx.clone(), msg_id)
        .unwrap();
    assert_eq!(result.inscription_id(), signed_tx.hash());
    assert_eq!(checkpoint.last_msg_id, msg_id);

    // The post lives in `in_flight` until the drive loop polls it.
    // Drive `next_event` concurrently with the recv so the post future
    // runs and MockNode delivers to `posted_txs`.
    tokio::select! {
        tx = posted_txs.recv() => assert_eq!(tx.unwrap(), signed_tx),
        () = async {
            loop {
                drop(sequencer.next_event().await);
            }
        } => unreachable!(),
    }
}

/// A prepared tx pins the parent at prepare time; a publish in between
/// takes that position, so the stale tx is refused instead of competing.
#[tokio::test]
async fn submit_signed_tx_refuses_a_parent_with_a_pending_child() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let (node, _posted_txs) = MockNode::with_posted_channel();
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    let (tx, msg_id, inscription_sig) = sequencer
        .handle()
        .prepare_tx(
            Ops::new(FORK_DIGEST, TxList::new_unchecked(Vec::new())),
            Inscription::new_unchecked(b"prepared first".to_vec()),
        )
        .unwrap();
    let signed_tx = SignedOps::from_parts(
        tx,
        OpProofs::from([OpProof::ChannelInscribe(
            ChannelInscribeProof::without_steps(inscription_sig),
        )]),
    )
    .expect("a valid inscription-only tx");

    sequencer
        .handle()
        .publish(Inscription::new_unchecked(b"published in between".to_vec()))
        .await
        .unwrap();

    let result = sequencer.handle().submit_signed_tx(signed_tx, msg_id);
    assert!(
        matches!(result, Err(Error::ChannelStateChanged(_))),
        "stale parent must be refused, got {result:?}"
    );
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 1);
}

/// A hand-built tx chained on a message whose continuation is already mined
/// is refused at submit like one whose continuation is pending: the entry
/// would pend on a passed position, re-posted and refused by the node until
/// the expiry shed. On the publish tip it is accepted and the receipt names
/// the parent it chains on.
#[tokio::test]
async fn submit_signed_tx_refuses_a_parent_with_a_mined_child() {
    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key).await;

    // Block 1 mines entry 1 on root: the publish parent is entry 1 now.
    let mined = inscribe_op(channel_id, MsgId::root(), b"1");
    let mined_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(mined.clone())]);
    let lib = sequencer.state.as_ref().unwrap().lib();
    sequencer.state.as_mut().unwrap().process_block(
        header_id(1),
        lib,
        lib,
        std::iter::empty(),
        vec![BlockChannelTx::new(
            Arc::new(mined_tx.clone()),
            mined_tx.hash(),
            ChannelTxKind::Inscription(InscriptionInfo {
                tx_hash: mined_tx.hash(),
                parent_msg: MsgId::root(),
                this_msg: mined.id(),
                payload: mined.inscription.clone(),
                signer: Some(mined.signer),
                steps: InscriptionSteps::default(),
            }),
        )],
        vec![],
    );
    sequencer.current_tip = Some(header_id(1));
    assert_eq!(sequencer.compute_publish_parent(), mined.id());

    let behind = inscribe_op(channel_id, MsgId::root(), b"behind the tip");
    let behind_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(behind.clone())]);
    let result = sequencer.handle().submit_signed_tx(behind_tx, behind.id());
    assert!(
        matches!(result, Err(Error::ChannelStateChanged(_))),
        "a parent with a mined child must be refused, got {result:?}"
    );
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 0);

    let on_tip = inscribe_op(channel_id, mined.id(), b"on the tip");
    let on_tip_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(on_tip.clone())]);
    let (result, _) = sequencer
        .handle()
        .submit_signed_tx(on_tip_tx, on_tip.id())
        .expect("a tx on the publish tip is accepted");
    assert_eq!(result.tx.inscription().parent_msg, mined.id());
    assert_eq!(result.tx.inscription().this_msg, on_tip.id());
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 1);
}

/// A hand-built config chains on the mined config tip or on a config of
/// ours still pending; any other parent can never land and is refused at
/// submit.
#[tokio::test]
async fn submit_signed_tx_refuses_an_unknown_config_parent() {
    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key.clone()).await;
    let config_on = |parent: MsgId| {
        ChannelConfigOp::new(
            channel_id,
            parent,
            VerifiedChannelKeys::try_from(vec![key.public_key()]).unwrap(),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            NonZero::<u16>::MIN,
        )
        .unwrap()
    };
    let tip = sequencer.compute_publish_parent();

    let unknown_tx =
        unverified_tx_with_ops(vec![Op::ChannelConfig(config_on(MsgId::from([9; 32])))]);
    let result = sequencer.handle().submit_signed_tx(unknown_tx, tip);
    assert!(
        matches!(result, Err(Error::ChannelStateChanged(_))),
        "a config parent the channel never produced must be refused, got {result:?}"
    );
    assert!(
        sequencer
            .checkpoint()
            .is_none_or(|checkpoint| checkpoint.pending_txs.is_empty()),
        "refused config must not be tracked"
    );

    let on_tip = config_on(MsgId::root());
    let on_tip_id = on_tip.id();
    let on_tip_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(on_tip)]);
    sequencer
        .handle()
        .submit_signed_tx(on_tip_tx, tip)
        .expect("a config on the config tip is accepted");

    let chained_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(config_on(on_tip_id))]);
    sequencer
        .handle()
        .submit_signed_tx(chained_tx, tip)
        .expect("a config on a pending config of ours is accepted");
}

/// A gap block's deposit surfaces once, in order, even when the first
/// backfill failed, the stream reconnected and the chain switched to
/// another fork and back before the re-delivered event backfills the gap.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "Test function.")]
async fn gap_deposits_surface_after_a_failed_backfill_and_a_fork_switch() {
    use std::{
        collections::HashMap,
        sync::{Arc, atomic::AtomicUsize},
    };

    use lb_core::mantle::ops::{OpId as _, channel::deposit::Metadata};

    use crate::test_support::{deposit_event, inscribe_op};

    // G(0) <- B1(A) <- B2(Y, D2) <- B3(D3)   canonical in the end
    //             \- C(Z)                    canonical in between
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let deposit = |n: u32| {
        let op = DepositOp {
            channel_id,
            inputs: [NoteNullifier(Fr::from(n))].into(),
            outputs: [NoteCommitment(Fr::from(1000 + u64::from(n)))].into(),
            commitment_merkle_root: Fr::from(7u64),
            excess_value: 0,
            metadata: Metadata::new_unchecked(vec![u8::try_from(n).unwrap()]),
        };
        let tx = unverified_tx_with_ops(vec![Op::ChannelDeposit(op.clone())]);
        let event = deposit_event(&tx, &op);
        (op.op_id(), tx, event)
    };
    let a = inscribe_op(channel_id, MsgId::root(), b"a");
    let y = inscribe_op(channel_id, a.id(), b"y");
    let z = inscribe_op(channel_id, a.id(), b"z");
    let (y_id, z_id) = (y.id(), z.id());
    let (d2, d2_tx, d2_event) = deposit(2);
    let (d3, d3_tx, d3_event) = deposit(3);
    let b1 = api_block(
        1,
        0,
        1,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(a)])],
    );
    let b2 = api_block(
        2,
        1,
        2,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(y)]), d2_tx],
    );
    let c = api_block(
        9,
        1,
        2,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(z)])],
    );
    let b3 = api_block(3, 2, 3, vec![d3_tx]);
    let node = MockNode {
        scripts: scripts(vec![
            StreamScript {
                events: vec![live_event(&b1), live_event(&b3)],
                then: StreamEnd::Hang,
            },
            StreamScript {
                events: vec![live_event(&c), live_event(&b3)],
                then: StreamEnd::Hang,
            },
        ]),
        blocks: vec![b2],
        block_fetch_failures: Arc::new(AtomicUsize::new(1)),
        events: HashMap::from([(header_id(2), d2_event), (header_id(3), d3_event)]),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    let msg_ids = |txs: &[ChannelUpdateTx]| {
        txs.iter()
            .filter_map(|tx| tx.inscription().map(|info| info.this_msg))
            .collect::<Vec<_>>()
    };

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut before = Vec::new();
    let (update, deposits) = loop {
        let event = tokio::time::timeout_at(deadline, sequencer.next_event())
            .await
            .expect("B3 lands after the reconnect and the fork switch");
        let Event::BlocksProcessed {
            channel_update,
            observed,
            ..
        } = event
        else {
            continue;
        };
        let deposits = observed_deposit_ids(&observed);
        if deposits.contains(&d2) {
            break (channel_update, deposits);
        }
        before.push(channel_update);
    };

    assert_eq!(sequencer.current_tip, Some(header_id(3)));
    assert!(
        before.iter().all(|u| !msg_ids(u.adopted()).contains(&y_id)),
        "Y is only adopted with the gap"
    );
    let switched_to_fork = before.last().expect("C was processed before B3");
    assert_eq!(msg_ids(switched_to_fork.adopted()), vec![z_id]);
    assert_eq!(
        deposits,
        vec![d2, d3],
        "gap deposit first, then the live block's"
    );
    assert_eq!(msg_ids(update.adopted()), vec![y_id]);
    assert_eq!(msg_ids(update.orphaned()), vec![z_id]);
}

/// Drive a sequencer with `stale_refund_slots = window` through a
/// publish and two LIB advances; returns how many fund calls the node
/// saw within `for_at_most` and the checkpoint published last. Posts
/// are no signal: the resubmit pass re-posts every unmined entry on each
/// tick regardless.
async fn drive_stale_publish(
    window: u64,
    for_at_most: std::time::Duration,
) -> (usize, SequencerCheckpoint) {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let (up_tx, up_rx) = watch::channel(true);
    let (fees_tx, mut fees_rx) = mpsc::channel(16);
    let lib_event =
        |block: &lb_common_http_client::ApiBlock, lib: u8, lib_slot: u64| ProcessedBlockEvent {
            block: block.clone(),
            tip: block.header.id,
            tip_slot: block.header.slot,
            lib: header_id(lib),
            lib_slot: Slot::from(lib_slot),
        };
    let b1 = api_block(1, 0, 1, Vec::new());
    let b2 = api_block(2, 1, 2, Vec::new());
    let b3 = api_block(3, 2, 9, Vec::new());
    // The second connection is gated behind `up` so the publish is in
    // before the LIB advances age it.
    let node = MockNode {
        up: Some(up_rx),
        funding_priority_fees: Some(fees_tx),
        scripts: scripts(vec![
            StreamScript {
                events: vec![live_event(&b1)],
                then: StreamEnd::Hang,
            },
            StreamScript {
                events: vec![lib_event(&b2, 1, 1), lib_event(&b3, 2, 8)],
                then: StreamEnd::Hang,
            },
        ]),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        resubmit_interval: std::time::Duration::from_millis(20),
        stale_refund_slots: window,
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    let client = sequencer.client();

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }
    let publish = client.publish(Inscription::new_unchecked(b"stale".to_vec()));
    tokio::select! {
        result = publish => drop(result.expect("publish is accepted after Ready")),
        () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
    }
    up_tx.send(false).unwrap();

    let deadline = tokio::time::Instant::now() + for_at_most;
    let reconnect = tokio::time::sleep(std::time::Duration::from_millis(100));
    tokio::pin!(reconnect);
    let mut fund_calls = 0;
    loop {
        tokio::select! {
            () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
            () = &mut reconnect => up_tx.send(true).unwrap(),
            Some(_) = fees_rx.recv() => fund_calls += 1,
            () = tokio::time::sleep_until(deadline) => break,
        }
        if fund_calls >= 2 {
            break;
        }
    }
    assert_eq!(
        sequencer.state.as_ref().unwrap().pending_publish_count(),
        1,
        "a rebuild replaces the entry, it never duplicates it"
    );
    let checkpoint = sequencer
        .subscribe_checkpoint()
        .borrow()
        .clone()
        .expect("a checkpoint was published");
    (fund_calls, checkpoint)
}

/// An own publish unmined past the window is re-funded once the LIB has
/// moved past it, and the checkpoint published right after carries the
/// rebuilt entry: its funding stamp is the LIB slot of the re-fund, not
/// of the publish.
#[tokio::test]
async fn stale_publish_is_refunded() {
    let (fund_calls, checkpoint) = drive_stale_publish(1, std::time::Duration::from_secs(5)).await;
    assert_eq!(fund_calls, 2, "the publish's funding, then the rebuild's");
    assert_eq!(checkpoint.funding.len(), 1);
    assert_eq!(
        checkpoint.funding[0].funded_at,
        Slot::from(8),
        "the checkpoint was republished after the re-fund"
    );
}

fn sample_steps() -> InscriptionSteps {
    let op = InscriptionOp::sample_with_step();
    InscriptionSteps {
        proofs: ChannelInscribeProof::decode_context(&op)
            .into_iter()
            .map(StepProof::sample_for)
            .collect(),
        mini_blocks: op.mini_blocks,
    }
}

#[tokio::test]
async fn submit_prepared_inscription_carries_the_steps_and_their_proofs() {
    let mut sequencer = ready_sequencer_with_channel(
        Some(single_key_channel_state()),
        Ed25519Key::from_bytes(&[0; 32]),
    )
    .await;
    let steps = sample_steps();

    let prepared = sequencer
        .handle()
        .prepare_inscription(
            Inscription::new_unchecked(b"steps".to_vec()),
            steps.mini_blocks.clone(),
        )
        .expect("a ready sequencer prepares an inscription");
    let (result, checkpoint) = sequencer
        .handle()
        .submit_prepared_inscription(prepared.clone(), steps.proofs.to_vec())
        .await
        .expect("a prepared inscription with fitting proofs is published");

    let info = result.tx.inscription();
    assert_eq!(info.this_msg, prepared.id());
    assert_eq!(info.steps, steps);
    let (_, pending) = &checkpoint.pending_txs[0];
    let (inscribe, pending_steps) = inscribes(pending)
        .next()
        .expect("the pending tx carries the inscription");
    assert_eq!(inscribe, &prepared);
    assert_eq!(pending_steps, steps);
}

#[tokio::test]
async fn submit_prepared_inscription_refuses_misfit_proofs_and_a_moved_tip() {
    let mut sequencer = ready_sequencer_with_channel(
        Some(single_key_channel_state()),
        Ed25519Key::from_bytes(&[0; 32]),
    )
    .await;
    let steps = sample_steps();
    let prepared = sequencer
        .handle()
        .prepare_inscription(
            Inscription::new_unchecked(b"steps".to_vec()),
            steps.mini_blocks.clone(),
        )
        .expect("a ready sequencer prepares an inscription");

    let missing_one = steps.proofs[1..].to_vec();
    assert!(matches!(
        sequencer
            .handle()
            .submit_prepared_inscription(prepared.clone(), missing_one)
            .await,
        Err(Error::InvalidStepProofs(_))
    ));
    let wrong_kinds = steps.proofs.iter().rev().cloned().collect();
    assert!(matches!(
        sequencer
            .handle()
            .submit_prepared_inscription(prepared.clone(), wrong_kinds)
            .await,
        Err(Error::InvalidStepProofs(_))
    ));

    sequencer
        .handle()
        .publish(Inscription::new_unchecked(b"first".to_vec()))
        .await
        .expect("a plain publish takes the tip");
    assert!(matches!(
        sequencer
            .handle()
            .submit_prepared_inscription(prepared, steps.proofs.to_vec())
            .await,
        Err(Error::ChannelStateChanged(_))
    ));
}

/// The pre-funding ops of a publish survive a checkpoint round trip
/// through serde and a restore, so a restored sequencer can still re-fund
/// what it restored.
#[tokio::test]
async fn funding_record_survives_a_checkpoint_round_trip() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let config = SequencerConfig::new(funding_config());
    let mut sequencer = ZoneSequencer::init_with_config(
        channel_id,
        sequencer_key.clone(),
        MockNode::default(),
        config.clone(),
        None,
    );
    let client = sequencer.client();
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }
    let publish = client.publish(Inscription::new_unchecked(b"restored".to_vec()));
    let (result, checkpoint) = tokio::select! {
        result = publish => result.expect("publish is accepted after Ready"),
        () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
    };
    let tx_hash = result.inscription_id();
    assert_eq!(checkpoint.funding.len(), 1);
    assert_eq!(checkpoint.funding[0].tx_hash, tx_hash);
    assert!(checkpoint.funding[0].pre_fund.is_some());

    let json = serde_json::to_string(&checkpoint).expect("checkpoint serializes");
    let restored_checkpoint: SequencerCheckpoint =
        serde_json::from_str(&json).expect("checkpoint deserializes");
    let restored = ZoneSequencer::init_with_config(
        channel_id,
        sequencer_key,
        MockNode::default(),
        config,
        Some(restored_checkpoint),
    );

    let state = restored.state.as_ref().expect("restored state");
    let entry = state.pending_inscription(&tx_hash).expect("restored");
    assert!(
        entry.pre_fund.is_some(),
        "the restored entry keeps its pre-funding ops"
    );
    assert_eq!(
        entry.funded_at,
        Some(checkpoint.funding[0].funded_at),
        "and its stamp"
    );
}

#[tokio::test]
async fn disabled_refund_window_never_refunds() {
    let (fund_calls, checkpoint) = drive_stale_publish(0, std::time::Duration::from_secs(1)).await;
    assert_eq!(fund_calls, 1);
    assert_eq!(checkpoint.funding[0].funded_at, Slot::from(0));
}

#[tokio::test]
async fn cancelled_next_event_resumes_the_pulled_block() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let first_block = api_block(1, 0, 1, Vec::new());
    let second_block = api_block(2, 1, 2, Vec::new());
    let (gate_tx, gate_rx) = watch::channel(true);
    let (calls_tx, mut calls_rx) = mpsc::unbounded_channel();
    let node = MockNode {
        scripts: scripts(vec![StreamScript {
            events: vec![live_event(&first_block), live_event(&second_block)],
            then: StreamEnd::Hang,
        }]),
        channel_state_gate: Some(gate_rx),
        channel_state_calls: Some(calls_tx),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    assert!(matches!(
        sequencer.next_event().await,
        Event::BlocksProcessed { .. }
    ));
    assert!(matches!(
        sequencer.next_event().await,
        Event::TurnNotification { .. }
    ));

    while calls_rx.try_recv().is_ok() {}
    gate_tx.send(false).unwrap();

    {
        let next_event = sequencer.next_event();
        tokio::pin!(next_event);

        tokio::select! {
            call = calls_rx.recv() => {
                call.expect("channel-state call should be observed");
            }
            event = &mut next_event => {
                panic!("block processing completed while its node request was gated: {event:?}");
            }
        }
    }

    assert_eq!(
        sequencer
            .pending_block_event
            .as_ref()
            .map(|event| event.block.header.id),
        Some(header_id(2))
    );

    gate_tx.send(true).unwrap();
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(1), sequencer.next_event())
        .await
        .expect("the retained block should resume after cancellation");

    assert!(matches!(resumed, Event::BlocksProcessed { .. }));
    assert_eq!(sequencer.current_tip, Some(header_id(2)));
    assert!(sequencer.pending_block_event.is_none());

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), sequencer.next_event(),)
            .await
            .is_err(),
        "the resumed block must not be emitted twice"
    );
}

#[tokio::test]
async fn cancelled_finalized_backfill_restarts_without_partial_state() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let first_block = api_block(1, 0, 1, Vec::new());
    let second_block = api_block(2, 1, 2, Vec::new());
    let second_event = ProcessedBlockEvent {
        block: second_block.clone(),
        tip: second_block.header.id,
        tip_slot: second_block.header.slot,
        lib: first_block.header.id,
        lib_slot: first_block.header.slot,
    };
    let (gate_tx, gate_rx) = watch::channel(true);
    let (calls_tx, mut calls_rx) = mpsc::unbounded_channel();
    let node = MockNode {
        scripts: scripts(vec![StreamScript {
            events: vec![live_event(&first_block), second_event],
            then: StreamEnd::Hang,
        }]),
        immutable: vec![first_block.clone()],
        immutable_blocks_gate: Some(gate_rx),
        immutable_blocks_calls: Some(calls_tx),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    assert!(matches!(
        sequencer.next_event().await,
        Event::BlocksProcessed { .. }
    ));
    assert!(matches!(
        sequencer.next_event().await,
        Event::TurnNotification { .. }
    ));

    while calls_rx.try_recv().is_ok() {}
    gate_tx.send(false).unwrap();

    {
        let next_event = sequencer.next_event();
        tokio::pin!(next_event);

        tokio::select! {
            call = calls_rx.recv() => {
                call.expect("immutable-blocks call should be observed");
            }
            event = &mut next_event => {
                panic!("finalized backfill completed while its node request was gated: {event:?}");
            }
        }
    }

    assert_eq!(sequencer.lib_slot, Slot::genesis());
    assert_eq!(sequencer.current_tip, Some(first_block.header.id));
    assert_eq!(
        sequencer
            .pending_block_event
            .as_ref()
            .map(|event| event.block.header.id),
        Some(second_block.header.id)
    );

    gate_tx.send(true).unwrap();
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(1), sequencer.next_event())
        .await
        .expect("the finalized backfill should resume after cancellation");

    assert!(matches!(resumed, Event::BlocksProcessed { .. }));
    assert_eq!(sequencer.lib_slot, first_block.header.slot);
    assert_eq!(sequencer.current_tip, Some(second_block.header.id));
    assert!(sequencer.pending_block_event.is_none());
}

/// A `SequencerClient::publish` issued while the node is down (reconnect
/// in progress) must resolve promptly with [`Error::Unavailable`] —
/// funding needs the node — instead of blocking until connectivity is
/// restored. Once the node is back and `Ready` is re-announced,
/// publishing works again.
#[tokio::test]
async fn client_publish_fails_fast_during_reconnect_and_recovers() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let (up_tx, up_rx) = watch::channel(true);
    let (mut node, mut posted_txs) = MockNode::with_posted_channel();
    node.up = Some(up_rx);
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        resubmit_interval: std::time::Duration::from_millis(20),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    let client = sequencer.client();

    // Drive until the sequencer has emitted `Ready`.
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    // After `Ready` on this single-key channel the turn-to-write watch is
    // true; the stream drop clears it, giving a deterministic signal that
    // the sequencer observed the disconnect before we publish.
    let mut turn_rx = client.subscribe_turn_to_write();
    assert!(
        turn_rx.borrow_and_update().our_turn_to_write,
        "single-key channel must report our turn after Ready"
    );

    // Take the node down: the live stream ends and the sequencer enters
    // reconnect (subsequent `block_stream` calls error).
    up_tx.send(false).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if !turn_rx.borrow_and_update().our_turn_to_write {
                break;
            }
            tokio::select! {
                changed = turn_rx.changed() => changed.unwrap(),
                () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
            }
        }
    })
    .await
    .expect("stream drop must clear turn-to-write");

    // A client publish while the node is down must resolve promptly. We
    // drive `next_event` concurrently; the publish is serviced from inside
    // `wait_reconnect_delay` while the node is still down. With the old
    // behavior the request would never be drained during reconnect and this
    // would hang (caught by the timeout).
    let publish = client.publish(Inscription::new_unchecked(b"during-reconnect".to_vec()));
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = publish => result,
            () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
        }
    })
    .await
    .expect("client publish must resolve during reconnect, not block on connectivity");
    assert!(
        matches!(result, Err(Error::Unavailable { .. })),
        "publish while disconnected must fail fast, got {result:?}"
    );

    // Bring the node back up and wait for the re-announced `Ready`.
    up_tx.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if matches!(sequencer.next_event().await, Event::Ready) {
                break;
            }
        }
    })
    .await
    .expect("Ready should be re-announced after reconnect");

    // Publishing works again and the inscription is posted.
    let publish = client.publish(Inscription::new_unchecked(b"after-reconnect".to_vec()));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = publish => result,
            () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
        }
    })
    .await
    .expect("client publish must resolve after reconnect")
    .expect("publish should succeed after reconnect");
    let posted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::select! {
            tx = posted_txs.recv() => tx,
            () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
        }
    })
    .await
    .expect("inscription should be posted after reconnect")
    .expect("posted_txs channel should be open");

    assert!(
        posted
            .op_refs()
            .into_iter()
            .any(|op| matches!(op, OpRef::ChannelInscribe(_))),
        "posted tx should carry the inscription published during reconnect"
    );
}

/// `TurnNotification` reaches `next_event` callers and the events
/// broadcast once each, in the same order, after the block that changed
/// the turn; the turn watch flips as soon as the change is detected.
#[tokio::test]
async fn next_event_yields_turn_notifications() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let (up_tx, up_rx) = watch::channel(true);
    let (mut node, _posted_txs) = MockNode::with_posted_channel();
    node.up = Some(up_rx);
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        resubmit_interval: std::time::Duration::from_millis(20),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    let mut events_rx = sequencer.subscribe_events();
    let mut turn_rx = sequencer.subscribe_turn_to_write();
    turn_rx.mark_unchanged();

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    // The watch already reflects the turn before either channel delivers
    // the event.
    assert!(turn_rx.has_changed().unwrap());
    assert!(turn_rx.borrow_and_update().our_turn_to_write);

    // Single-key channel: the block that made us ready also made it our
    // turn. `BlocksProcessed` comes first, then the turn.
    let first = sequencer.next_event().await;
    assert!(
        matches!(first, Event::BlocksProcessed { .. }),
        "block event should precede the turn change, got {first:?}"
    );
    let second = sequencer.next_event().await;
    let Event::TurnNotification { notification } = second else {
        panic!("expected TurnNotification after the block event, got {second:?}");
    };
    assert!(notification.our_turn_to_write);

    // The broadcast carries the same events, once each, in the same order.
    let mut broadcast = Vec::new();
    while let Ok(event) = events_rx.try_recv() {
        broadcast.push(event);
    }
    let kinds: Vec<_> = broadcast
        .iter()
        .map(|event| match event {
            Event::Ready => "ready",
            Event::BlocksProcessed { .. } => "block",
            Event::TurnNotification { notification } if notification.our_turn_to_write => {
                "our turn"
            }
            Event::TurnNotification { .. } => "not our turn",
        })
        .collect();
    assert_eq!(
        kinds,
        ["not our turn", "block", "ready", "block", "our turn"],
        "broadcast: {broadcast:?}"
    );

    // A stream drop clears the turn; that change is returned too, and
    // broadcast exactly once.
    up_tx.send(false).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Event::TurnNotification { notification } = sequencer.next_event().await
                && !notification.our_turn_to_write
            {
                break;
            }
        }
    })
    .await
    .expect("stream drop must yield a not-our-turn notification via next_event");
    let mut cleared = 0;
    while let Ok(event) = events_rx.try_recv() {
        if let Event::TurnNotification { notification } = event {
            assert!(!notification.our_turn_to_write);
            cleared += 1;
        }
    }
    assert_eq!(
        cleared, 1,
        "the cleared turn must be broadcast exactly once"
    );
}

/// The turn is re-evaluated on its own slot boundary: with no block after
/// the first one, `next_event` still yields the alternating turn changes.
#[tokio::test]
async fn turn_notification_fires_on_timeframe_boundary_without_blocks() {
    assert_turns_alternate_without_blocks(1, 0).await;
}

/// Same for the timeout rotation, anchored at the last landed inscription.
#[tokio::test]
async fn turn_notification_fires_on_timeout_boundary_without_blocks() {
    assert_turns_alternate_without_blocks(0, 1).await;
}

async fn assert_turns_alternate_without_blocks(posting_timeframe: u32, posting_timeout: u32) {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let mut channel = single_key_channel_state();
    channel.accredited_keys = UnverifiedChannelKeys::try_from(vec![
        sequencer_key.public_key().into_unverified(),
        Ed25519Key::from_bytes(&[1; 32])
            .public_key()
            .into_unverified(),
    ])
    .unwrap()
    .into();
    channel.posting_timeframe = posting_timeframe.into();
    channel.posting_timeout = posting_timeout.into();
    let node = MockNode {
        channel_state: Some(channel),
        slot_duration: core::time::Duration::from_millis(100),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        resubmit_interval: core::time::Duration::from_secs(600),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    let started = std::time::Instant::now();
    let mut turns = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while turns.len() < 4 {
            if let Event::TurnNotification { notification } = sequencer.next_event().await {
                turns.push(notification.our_turn_to_write);
            }
        }
    })
    .await
    .expect("turn changes must arrive without blocks");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "turn changes should follow the 100ms slots, took {:?}",
        started.elapsed()
    );
    assert!(
        turns.windows(2).all(|pair| pair[0] != pair[1]),
        "a two-key channel rotating every slot alternates: {turns:?}"
    );
}

/// With a publish margin the turn watch closes before the rotation, at
/// the same slot `can_publish_inscription_now` starts refusing.
#[tokio::test]
async fn turn_notification_closes_with_the_publish_margin() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let mut channel = single_key_channel_state();
    channel.posting_timeframe = 4u32.into();
    let node = MockNode {
        channel_state: Some(channel),
        slot_duration: core::time::Duration::from_millis(300),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        min_slots_remaining_in_turn: 3,
        resubmit_interval: std::time::Duration::from_secs(600),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    // Single key: every turn is ours, open for the first two of its four
    // slots and closed for the last two. The notification at Ready is an
    // observation mid-turn; the first close is the first boundary.
    let mut seen = 0;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while seen < 4 {
            let Event::TurnNotification { notification } = sequencer.next_event().await else {
                continue;
            };
            if seen == 0 && notification.our_turn_to_write {
                continue;
            }
            assert_eq!(
                notification.our_turn_to_write,
                sequencer.can_publish_inscription_now(),
                "watch and publish gate disagree: {notification:?}"
            );
            let current = notification.current_slot.unwrap();
            let expected = if notification.our_turn_to_write {
                notification.starting_slot.unwrap()
            } else {
                notification.ends_at_slot.unwrap() - 3 + 1
            };
            assert_eq!(
                current, expected,
                "flipped at the wrong slot: {notification:?}"
            );
            seen += 1;
        }
    })
    .await
    .expect("turn changes must arrive without blocks");
}

/// A `submit_signed_tx` bundle chains subsequent publishes off its last
/// inscription — the config in it moves only the config lineage.
/// Otherwise the next publish claims the same channel position as the
/// bundle and the two race, permanently invalidating one side.
#[tokio::test]
async fn publish_after_bundle_chains_on_the_bundle_inscription_tip() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let node = MockNode::default();
    let mut sequencer = ZoneSequencer::init(
        channel_id,
        sequencer_key.clone(),
        node,
        funding_config(),
        None,
    );

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    let inscribe = InscriptionOp {
        channel_id,
        inscription: Inscription::new_unchecked(b"bundle".to_vec()),
        parent: MsgId::root(),
        signer: sequencer_key.public_key().into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let config = ChannelConfigOp::new(
        channel_id,
        MsgId::root(),
        VerifiedChannelKeys::try_from(vec![sequencer_key.public_key()]).unwrap(),
        SlotTimeframe::from(0u32),
        SlotTimeout::from(0u32),
        NonZero::<u16>::MIN,
    )
    .unwrap();
    let inscribe_msg = inscribe.id();
    let bundle = unverified_tx_with_ops(vec![
        Op::ChannelInscribe(inscribe),
        Op::ChannelConfig(config),
    ]);

    let (result, _cp) = sequencer
        .handle()
        .submit_signed_tx(bundle, inscribe_msg)
        .expect("bundle submit should be accepted");
    assert_eq!(
        result.tx.inscription().this_msg,
        inscribe_msg,
        "the bundle's resulting tip is its inscription"
    );

    let (published, _cp) = sequencer
        .handle()
        .publish(Inscription::new_unchecked(b"after-bundle".to_vec()))
        .await
        .expect("publish after bundle should be accepted");
    assert_eq!(
        published.tx.inscription().parent_msg,
        inscribe_msg,
        "the next publish must chain after the pending bundle's inscription"
    );
}

#[tokio::test]
async fn config_only_block_orphans_pending_inscription_but_keeps_message_tip() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    let config_op = ChannelConfigOp::new(
        channel_id,
        MsgId::root(),
        VerifiedChannelKeys::try_from(vec![Ed25519Key::from_bytes(&[0; 32]).public_key()]).unwrap(),
        SlotTimeframe::from(0u32),
        SlotTimeout::from(0u32),
        NonZero::<u16>::MIN,
    )
    .unwrap();
    let config_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(config_op)]);
    let config_hash = config_tx.hash();
    let config_block = api_block(2, 1, 2, vec![config_tx]);

    // Second connection (the config block) is gated behind `up` so it
    // cannot be consumed before the publish is in.
    let (up_tx, up_rx) = watch::channel(true);
    let node = MockNode {
        up: Some(up_rx),
        scripts: scripts(vec![
            StreamScript {
                events: vec![live_event(&api_block(1, 0, 1, Vec::new()))],
                then: StreamEnd::Hang,
            },
            StreamScript {
                events: vec![live_event(&config_block)],
                then: StreamEnd::Hang,
            },
        ]),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        resubmit_interval: std::time::Duration::from_millis(20),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);
    let client = sequencer.client();

    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    let publish = client.publish(Inscription::new_unchecked(b"survives-config".to_vec()));
    let (result, _checkpoint) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            result = publish => result,
            () = async { loop { drop(sequencer.next_event().await); } } => unreachable!(),
        }
    })
    .await
    .expect("publish must resolve")
    .expect("publish should be accepted after Ready");
    let p_hash = result.inscription_id();

    // Keep driving between the toggles so the down-edge is observed. The
    // config block is recognized by its config entering `adopted`; that
    // `BlocksProcessed` carries the state to assert on.
    up_tx.send(false).unwrap();
    let (checkpoint, update) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let toggle = async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            up_tx.send(true).unwrap();
        };
        let drive = async {
            loop {
                if let Event::BlocksProcessed {
                    checkpoint,
                    channel_update,
                    ..
                } = sequencer.next_event().await
                    && channel_update
                        .adopted()
                        .iter()
                        .any(|tx| tx.tx_hash() == config_hash)
                {
                    return (checkpoint, channel_update);
                }
            }
        };
        let ((), out) = tokio::join!(toggle, drive);
        out
    })
    .await
    .expect("the config-only block must be processed");

    assert_history_matches_update(&sequencer, &update);

    // The config changes the channel view, so the pending inscription is
    // shed and reported orphaned (to be resubmitted against the new view).
    assert!(update.orphaned().iter().any(|tx| tx.tx_hash() == p_hash));
    assert!(checkpoint.pending_txs.iter().all(|(h, _)| *h != p_hash));
    assert!(
        update
            .canonical_chain()
            .is_some_and(|mut c| c.all(|tx| tx.tx_hash() != p_hash))
    );
    // The chaining pointer resets to the (unchanged) message tip so the
    // resubmit re-posts there. Nothing was mined, so the tip is root.
    assert_eq!(
        checkpoint.last_msg_id,
        MsgId::root(),
        "the pointer resets to the message tip (root)"
    );
}

#[test]
fn track_pending_tx_tracks_a_plain_inscription_as_pending() {
    let channel_id = ChannelId::from([2u8; 32]);
    let inscribe_op = InscriptionOp {
        channel_id,
        inscription: Inscription::new_unchecked(b"hello".to_vec()),
        parent: MsgId::root(),
        signer: Ed25519Key::from_bytes(&[0; 32])
            .public_key()
            .into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let mantle_tx = Ops::new(FORK_DIGEST, [Op::ChannelInscribe(inscribe_op)]);
    let tx_hash = mantle_tx.hash();
    let signed_tx = SignedOps::from_ops_with_sample_proofs(mantle_tx);

    let mut state = TxState::new(HeaderId::from([0; 32]), MsgId::root());
    track_pending_tx(&mut state, signed_tx, channel_id).unwrap();

    assert!(
        state.pending_inscription(&tx_hash).is_some(),
        "plain inscription should be in pending inscriptions"
    );
}

#[test]
fn track_pending_tx_falls_back_to_other_when_no_inscribe_for_channel() {
    // Inscribe for a different channel: should fall back to pending_other
    // (treated as opaque).
    let our_channel = ChannelId::from([3u8; 32]);
    let other_channel = ChannelId::from([4u8; 32]);
    let inscribe_op = InscriptionOp {
        channel_id: other_channel,
        inscription: Inscription::new_unchecked(b"hello".to_vec()),
        parent: MsgId::root(),
        signer: Ed25519Key::from_bytes(&[0; 32])
            .public_key()
            .into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let mantle_tx = Ops::new(FORK_DIGEST, [Op::ChannelInscribe(inscribe_op)]);
    let tx_hash = mantle_tx.hash();
    let signed_tx = SignedOps::from_ops_with_sample_proofs(mantle_tx);

    let mut state = TxState::new(HeaderId::from([0; 32]), MsgId::root());
    track_pending_tx(&mut state, signed_tx, our_channel).unwrap();

    assert!(
        state.pending_inscription(&tx_hash).is_none(),
        "wrong-channel tx should not be in pending inscriptions"
    );
    assert!(
        state.pending_other_contains(&tx_hash),
        "wrong-channel tx should be in pending_other"
    );
}

/// Cold start with a channel inscription and a deposit at slot 0
/// (genesis), and the node's LIB far enough that the replay takes two
/// batches. The genesis slot is included in the backfill and emitted in a
/// `Finalized` state change (regression guard for the off-by-one where
/// `backfill_from = lib_slot + 1` skipped it), and the checkpoint published
/// after the first batch already carries the deposit's note with LIB at the
/// last replayed block, so a restart from it loses nothing.
#[tokio::test]
async fn cold_start_backfills_genesis_slot() {
    use std::collections::HashMap;

    use lb_core::mantle::ops::channel::deposit::Metadata;

    use crate::test_support::deposit_event;

    let channel_id = ChannelId::from([7; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    // A signed tx with a single ChannelInscribe on our channel at
    // genesis (parent_msg = root).
    let inscribe = InscriptionOp {
        channel_id,
        parent: MsgId::root(),
        inscription: Inscription::new_unchecked(Vec::new()),
        signer: sequencer_key.public_key().into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let expected_msg_id = inscribe.id();
    let genesis_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(inscribe)]);
    let genesis_tx_hash = genesis_tx.hash();
    let deposit = DepositOp {
        channel_id,
        inputs: [NoteNullifier(Fr::from(1u64))].into(),
        outputs: [NoteCommitment(Fr::from(1001u64))].into(),
        commitment_merkle_root: Fr::from(7u64),
        excess_value: 0,
        metadata: Metadata::new_unchecked(vec![1u8]),
    };
    let deposit_tx = unverified_tx_with_ops(vec![Op::ChannelDeposit(deposit.clone())]);

    let genesis_block = api_block(1, 0, 0, vec![genesis_tx, deposit_tx.clone()]);
    // LIB at slot 150: the replay runs as two 100-slot batches.
    let lib_block = api_block(2, 1, 150, Vec::new());
    // Empty live block so the block stream advances and the sequencer
    // signals `Ready`, giving the test a clean exit signal.
    let live_block = api_block(3, 2, 151, Vec::new());

    let node = MockNode {
        lib: lib_block.header.id,
        lib_slot: lib_block.header.slot,
        tip: lib_block.header.id,
        scripts: scripts(vec![StreamScript {
            events: vec![ProcessedBlockEvent {
                block: live_block.clone(),
                tip: live_block.header.id,
                tip_slot: live_block.header.slot,
                lib: lib_block.header.id,
                lib_slot: lib_block.header.slot,
            }],
            then: StreamEnd::Hang,
        }]),
        immutable: vec![genesis_block.clone(), lib_block.clone()],
        events: HashMap::from([(
            genesis_block.header.id,
            deposit_event(&deposit_tx, &deposit),
        )]),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    let mut finalized_items: Vec<FinalizedTx> = Vec::new();
    let mut checkpoints = Vec::new();
    loop {
        match sequencer.next_event().await {
            Event::Ready => break,
            Event::BlocksProcessed {
                finalized,
                checkpoint,
                ..
            } => {
                assert!(
                    sequencer.channel_history().is_none(),
                    "finalized backfill does not know the live branch yet"
                );
                finalized_items.extend(finalized);
                checkpoints.push(checkpoint);
            }
            Event::TurnNotification { .. } => {}
        }
    }

    assert_genesis_inscription_finalized(&finalized_items, genesis_tx_hash, expected_msg_id);
    assert!(checkpoints.len() >= 2, "one checkpoint per backfill batch");
    assert_eq!(
        checkpoints[0].lib, genesis_block.header.id,
        "LIB follows the replay"
    );
    assert_eq!(checkpoints[0].lib_slot, Slot::from(100));
    assert_eq!(checkpoints[1].lib, lib_block.header.id);
}

/// The complete mined configuration reaches `Event::BlocksProcessed`'s
/// finalized items during a cold-start backfill: a config accrediting two
/// keys, then one removing the second, each with its exact key set, across
/// two backfill batches.
#[tokio::test]
async fn cold_start_backfill_finalizes_configs_with_their_keys() {
    let channel_id = ChannelId::from([7; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let peer_key = Ed25519Key::from_bytes(&[1; 32]);
    let config = |parent: MsgId, keys: Vec<_>| {
        ChannelConfigOp::new(
            channel_id,
            parent,
            VerifiedChannelKeys::try_from(keys).unwrap(),
            SlotTimeframe::from(3u32),
            SlotTimeout::from(0u32),
            NonZero::<u16>::MIN,
        )
        .unwrap()
    };
    let accredit = config(
        MsgId::root(),
        vec![sequencer_key.public_key(), peer_key.public_key()],
    );
    let remove = config(accredit.id(), vec![sequencer_key.public_key()]);
    let accredit_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(accredit.clone())]);
    let remove_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(remove.clone())]);

    let genesis_block = api_block(1, 0, 0, vec![accredit_tx.clone()]);
    // Slot 120 falls in the second 100-slot batch.
    let remove_block = api_block(2, 1, 120, vec![remove_tx.clone()]);
    let lib_block = api_block(3, 2, 150, Vec::new());
    let live_block = api_block(4, 3, 151, Vec::new());

    let node = MockNode {
        lib: lib_block.header.id,
        lib_slot: lib_block.header.slot,
        tip: lib_block.header.id,
        scripts: scripts(vec![StreamScript {
            events: vec![ProcessedBlockEvent {
                block: live_block.clone(),
                tip: live_block.header.id,
                tip_slot: live_block.header.slot,
                lib: lib_block.header.id,
                lib_slot: lib_block.header.slot,
            }],
            then: StreamEnd::Hang,
        }]),
        immutable: vec![genesis_block, remove_block, lib_block.clone()],
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    let mut configs: Vec<ConfigInfo> = Vec::new();
    loop {
        match sequencer.next_event().await {
            Event::Ready => break,
            Event::BlocksProcessed { finalized, .. } => {
                configs.extend(
                    finalized
                        .iter()
                        .flat_map(|tx| &tx.ops)
                        .filter_map(|op| match op {
                            FinalizedOp::Config(info) => Some(info.clone()),
                            _ => None,
                        }),
                );
            }
            Event::TurnNotification { .. } => {}
        }
    }

    assert_eq!(configs.len(), 2, "both configs finalized: {configs:?}");
    assert_eq!(configs[0].tx_hash, accredit_tx.hash());
    assert_eq!(configs[0].parent_msg, MsgId::root());
    assert_eq!(configs[0].this_msg, accredit.id());
    assert_eq!(
        configs[0].config, accredit,
        "the mined config, keys included"
    );
    assert_eq!(configs[0].config.keys().len(), 2);
    assert_eq!(configs[1].tx_hash, remove_tx.hash());
    assert_eq!(configs[1].parent_msg, accredit.id());
    assert_eq!(configs[1].this_msg, remove.id());
    assert_eq!(
        configs[1].config, remove,
        "the removal, with the one key left"
    );
    assert_eq!(configs[1].config.keys().len(), 1);
}

/// Cold start over finalized history that is empty but for a block at
/// genesis and one deep in, as on a chain whose slots follow the wall clock.
/// A wide `backfill_batch_slots` replays both inscriptions in a few node reads.
#[tokio::test]
async fn cold_start_backfill_reads_configured_batch_slots() {
    const LIB_SLOT: u64 = 1_000_000;
    const BATCH_SLOTS: u64 = 10_000;

    let channel_id = ChannelId::from([7; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    let genesis_inscribe = inscribe_op(channel_id, MsgId::root(), b"genesis");
    let deep_inscribe = inscribe_op(channel_id, genesis_inscribe.id(), b"deep");
    let genesis_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(genesis_inscribe.clone())]);
    let deep_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(deep_inscribe.clone())]);

    let genesis_block = api_block(1, 0, 0, vec![genesis_tx]);
    let deep_block = api_block(2, 1, LIB_SLOT - 1_234, vec![deep_tx]);
    let lib_block = api_block(3, 2, LIB_SLOT, Vec::new());
    let live_block = api_block(4, 3, LIB_SLOT + 1, Vec::new());

    let (calls_tx, mut calls_rx) = mpsc::unbounded_channel();
    let node = MockNode {
        lib: lib_block.header.id,
        lib_slot: lib_block.header.slot,
        tip: lib_block.header.id,
        scripts: scripts(vec![StreamScript {
            events: vec![ProcessedBlockEvent {
                block: live_block.clone(),
                tip: live_block.header.id,
                tip_slot: live_block.header.slot,
                lib: lib_block.header.id,
                lib_slot: lib_block.header.slot,
            }],
            then: StreamEnd::Hang,
        }]),
        immutable: vec![genesis_block, deep_block, lib_block.clone()],
        immutable_blocks_calls: Some(calls_tx),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        backfill_batch_slots: BATCH_SLOTS,
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer =
        ZoneSequencer::init_with_config(channel_id, sequencer_key, node, config, None);

    let mut inscriptions = Vec::new();
    loop {
        match sequencer.next_event().await {
            Event::Ready => break,
            Event::BlocksProcessed { finalized, .. } => {
                inscriptions.extend(finalized.iter().flat_map(|tx| &tx.ops).filter_map(
                    |op| match op {
                        FinalizedOp::Inscription(info) => Some(info.this_msg),
                        _ => None,
                    },
                ));
            }
            Event::TurnNotification { .. } => {}
        }
    }

    assert_eq!(
        inscriptions,
        vec![genesis_inscribe.id(), deep_inscribe.id()]
    );
    assert_eq!(sequencer.lib_slot, lib_block.header.slot);

    let mut reads = 0u64;
    while calls_rx.try_recv().is_ok() {
        reads += 1;
    }
    // Slots `0..=LIB_SLOT`, `BATCH_SLOTS + 1` per batch (inclusive at both ends).
    assert_eq!(reads, (LIB_SLOT + 1).div_ceil(BATCH_SLOTS + 1));
}

/// The one finalized tx with `tx_hash` carries a single root inscription
/// with `msg_id`.
fn assert_genesis_inscription_finalized(items: &[FinalizedTx], tx_hash: TxHash, msg_id: MsgId) {
    let inscriptions: Vec<_> = items.iter().filter(|t| t.tx_hash == tx_hash).collect();
    assert_eq!(
        inscriptions.len(),
        1,
        "expected exactly one finalized inscription tx from genesis backfill"
    );
    let t = inscriptions[0];
    assert_eq!(t.ops.len(), 1);
    match &t.ops[0] {
        FinalizedOp::Inscription(info) => {
            assert_eq!(info.tx_hash, tx_hash);
            assert_eq!(info.parent_msg, MsgId::root());
            assert_eq!(info.this_msg, msg_id);
        }
        other => panic!("expected Inscription, got {other:?}"),
    }
}

/// The finalized config tip must survive the real persistence path —
/// `build_checkpoint` → serde → `init_with_config` — not just the in-state
/// setter. A config-free resume must leave it intact, surfaced through the
/// checkpoint the sequencer re-emits.
#[tokio::test]
async fn finalized_config_survives_checkpoint_persistence_and_resume() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);
    let finalized_config = MsgId::from([9; 32]);

    // `build_checkpoint` captures the finalized config tip.
    let mut state = TxState::new(header_id(0), MsgId::root());
    state.set_finalized_config(finalized_config);
    let cp = build_checkpoint(&state, MsgId::root(), Slot::genesis());
    assert_eq!(
        cp.finalized_config, finalized_config,
        "build_checkpoint saves it"
    );

    // It survives serde (and `serde(default)` does not clobber a set value).
    let json = serde_json::to_string(&cp).expect("serialize checkpoint");
    let cp: SequencerCheckpoint = serde_json::from_str(&json).expect("deserialize checkpoint");
    assert_eq!(
        cp.finalized_config, finalized_config,
        "serde round-trips it"
    );

    // `init_with_config` restores it; a config-free resume keeps it.
    let genesis_block = api_block(0, 0, 0, Vec::new());
    let live_block = api_block(1, 0, 1, Vec::new());
    let node = MockNode {
        lib: header_id(0),
        tip: header_id(0),
        immutable: vec![genesis_block],
        scripts: scripts(vec![StreamScript {
            events: vec![live_event(&live_block)],
            then: StreamEnd::Hang,
        }]),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), Some(cp));

    let restored = loop {
        match sequencer.next_event().await {
            Event::BlocksProcessed { checkpoint, .. } => {
                break checkpoint.finalized_config;
            }
            Event::Ready | Event::TurnNotification { .. } => {}
        }
    };
    assert_eq!(
        restored, finalized_config,
        "resume restores finalized_config through the checkpoint"
    );
}

/// A config finalized during downtime, replayed by the resume backfill,
/// must refine `finalized_config` past the (stale) checkpoint seed —
/// exercising the backfill's config arm, not just the seed.
#[tokio::test]
async fn resume_backfill_refines_finalized_config_from_a_replayed_config() {
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    // A pure config sits in the finalized history the backfill replays.
    let config_op = ChannelConfigOp::new(
        channel_id,
        MsgId::root(),
        VerifiedChannelKeys::try_from(vec![Ed25519Key::from_bytes(&[0; 32]).public_key()]).unwrap(),
        SlotTimeframe::from(0u32),
        SlotTimeout::from(0u32),
        NonZero::<u16>::MIN,
    )
    .unwrap();
    let config_id = config_op.id();
    let config_tx = unverified_tx_with_ops(vec![Op::ChannelConfig(config_op)]);
    // The config finalized during downtime at slot 1 — above the checkpoint
    // LIB (genesis), so the resume backfill must replay it.
    let config_block = api_block(1, 0, 1, vec![config_tx]);

    // The checkpoint's finalized_config is stale; the backfill must move it.
    let stale = MsgId::from([1; 32]);
    let mut state = TxState::new(header_id(0), MsgId::root());
    state.set_finalized_config(stale);
    let cp = build_checkpoint(&state, MsgId::root(), Slot::genesis());

    // A live block at slot 2 whose LIB is the config block (slot 1), so the
    // backfill catches up [genesis..=slot 1] and replays the config.
    let live_block = api_block(2, 1, 2, Vec::new());
    let event = ProcessedBlockEvent {
        block: live_block.clone(),
        tip: live_block.header.id,
        tip_slot: live_block.header.slot,
        lib: header_id(1),
        lib_slot: Slot::from(1),
    };
    let node = MockNode {
        lib: header_id(1),
        tip: header_id(1),
        immutable: vec![config_block],
        scripts: scripts(vec![StreamScript {
            events: vec![event],
            then: StreamEnd::Hang,
        }]),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), Some(cp));

    let restored = loop {
        match sequencer.next_event().await {
            Event::BlocksProcessed { checkpoint, .. } => {
                break checkpoint.finalized_config;
            }
            Event::Ready | Event::TurnNotification { .. } => {}
        }
    };
    assert_eq!(
        restored, config_id,
        "backfill refines finalized_config to the replayed config"
    );
}

/// A pending publish re-funded under a new hash whose original finalized
/// during downtime: the resume backfill retires it by message id, as the
/// live path does, or it is re-funded every window from then on.
#[tokio::test]
async fn resume_backfill_retires_a_pending_entry_finalized_under_another_hash() {
    use lb_core::mantle::ops::transfer::TransferOp;

    use crate::test_support::inscribe_op;
    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    let m = inscribe_op(channel_id, MsgId::root(), b"m");
    let m_id = m.id();
    let original = unverified_tx_with_ops(vec![
        Op::ChannelInscribe(m.clone()),
        Op::Transfer(TransferOp::new(
            [NoteNullifier(Fr::from(1u64))].into(),
            [NoteCommitment(Fr::from(50u64))].into(),
            Fr::from(0u64),
            0,
        )),
    ]);
    let rebuilt = unverified_tx_with_ops(vec![Op::ChannelInscribe(m)]);
    assert_ne!(original.hash(), rebuilt.hash());
    // The original finalized at slot 1, above the checkpoint LIB (genesis).
    let block = api_block(1, 0, 1, vec![original]);

    let mut state = TxState::new(header_id(0), MsgId::root());
    state
        .submit_inscription(
            rebuilt,
            MsgId::root(),
            m_id,
            Inscription::new_unchecked(b"m".to_vec()),
        )
        .unwrap();
    let cp = build_checkpoint(&state, MsgId::root(), Slot::genesis());
    assert_eq!(cp.pending_txs.len(), 1);

    let live_block = api_block(2, 1, 2, Vec::new());
    let event = ProcessedBlockEvent {
        block: live_block.clone(),
        tip: live_block.header.id,
        tip_slot: live_block.header.slot,
        lib: header_id(1),
        lib_slot: Slot::from(1),
    };
    // The network LIB is past the checkpoint's, so the resume backfill runs
    // over slot 1 before the stream opens.
    let node = MockNode {
        lib: header_id(1),
        tip: header_id(1),
        lib_slot: Slot::from(1),
        immutable: vec![block],
        scripts: scripts(vec![StreamScript {
            events: vec![event],
            then: StreamEnd::Hang,
        }]),
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), Some(cp));

    let checkpoint = loop {
        match sequencer.next_event().await {
            Event::BlocksProcessed { checkpoint, .. } => break checkpoint,
            Event::Ready | Event::TurnNotification { .. } => {}
        }
    };
    assert!(
        checkpoint.pending_txs.is_empty(),
        "the entry landed under another hash and is retired"
    );
}

/// Realistic stream-gap scenario, driven end-to-end through the public
/// `ZoneSequencer` event loop.
///
/// Chain: G <- B1 <- B2 <- B3, one canonical branch, LIB at genesis.
/// The live stream delivers B1 (inscription A) and drops. B2 (inscription
/// Y, child of A) is mined during the outage. The stream resumes at B3;
/// the sequencer self-heals by backfilling B2.
///
/// Per the [`Event::Ready`] / [`ChannelUpdate`] contract, catch-up deltas
/// surface on the next `BlocksProcessed` once the stream resumes — so Y
/// must be reported as `adopted`. A consumer mirroring the channel from
/// `ChannelUpdate` otherwise silently misses Y until finalization.
#[tokio::test]
async fn stream_gap_surfaces_backfilled_inscriptions_as_adopted() {
    use std::time::Duration;

    use tokio::time::timeout;

    let channel_id = ChannelId::from([0; 32]);
    let sequencer_key = Ed25519Key::from_bytes(&[0; 32]);

    let a = InscriptionOp {
        channel_id,
        parent: MsgId::root(),
        inscription: Inscription::new_unchecked(b"a".to_vec()),
        signer: sequencer_key.public_key().into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let a_id = a.id();
    let y = InscriptionOp {
        channel_id,
        parent: a_id,
        inscription: Inscription::new_unchecked(b"y".to_vec()),
        signer: sequencer_key.public_key().into_unverified(),
        mini_blocks: MiniBlocks::default(),
    };
    let y_id = y.id();

    let b1 = api_block(
        1,
        0,
        1,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(a)])],
    );
    let b2 = api_block(
        2,
        1,
        2,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(y)])],
    );
    let b3 = api_block(3, 2, 3, Vec::new());

    let node = MockNode {
        scripts: scripts(vec![
            StreamScript {
                events: vec![live_event(&b1)],
                then: StreamEnd::End,
            },
            StreamScript {
                events: vec![live_event(&b3)],
                then: StreamEnd::Hang,
            },
        ]),
        blocks: vec![b2],
        ..MockNode::default()
    };
    let mut sequencer =
        ZoneSequencer::init(channel_id, sequencer_key, node, funding_config(), None);

    // Phase 1: drive until B1's channel update adopts A (Ready and turn
    // notifications interleave).
    let adopted = timeout(Duration::from_secs(10), async {
        loop {
            if let Event::BlocksProcessed { channel_update, .. } = sequencer.next_event().await
                && !channel_update.adopted().is_empty()
            {
                return channel_update.adopted().to_vec();
            }
        }
    })
    .await
    .expect("timed out waiting for B1's channel update");
    assert!(
        adopted
            .iter()
            .any(|t| t.inscription().is_some_and(|i| i.this_msg == a_id)),
        "sanity: A is adopted from the live B1"
    );

    // Phase 2: stream #1 has ended — a disconnect. `next_event`
    // reconnects internally and resumes at B3; the canonical backfill
    // fetches the missed B2. The first `BlocksProcessed` after the
    // reconnect is B3's ingestion and must carry Y as adopted.
    let update = timeout(Duration::from_secs(10), async {
        loop {
            if let Event::BlocksProcessed { channel_update, .. } = sequencer.next_event().await {
                return channel_update;
            }
        }
    })
    .await
    .expect("timed out waiting for the post-reconnect BlocksProcessed");
    assert!(
        update
            .adopted()
            .iter()
            .any(|t| t.inscription().is_some_and(|i| i.this_msg == y_id)),
        "inscription mined during the stream gap must surface as adopted on the next \
             BlocksProcessed after reconnect; got {update:?}",
    );
}

/// A competing mined transaction displaces the entire custom pending chain.
/// Every orphan must retain all its inscriptions so a caller can republish
/// them.
#[tokio::test]
async fn custom_orphans_keep_all_inscriptions_in_chain_order() {
    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key).await;

    let mut parent = MsgId::root();
    let mut submitted = Vec::new();
    for payloads in [[b"a", b"b"], [b"c", b"d"]] {
        let first = inscribe_op(channel_id, parent, payloads[0]);
        let second = inscribe_op(channel_id, first.id(), payloads[1]);
        parent = second.id();
        let tx = unverified_tx_with_ops(vec![
            Op::ChannelInscribe(first),
            Op::ChannelInscribe(second),
        ]);
        sequencer
            .handle()
            .submit_signed_tx(tx.clone(), parent)
            .unwrap();
        submitted.push(tx);
    }

    let competing = inscribe_op(channel_id, MsgId::root(), b"winner");
    let block = api_block(
        2,
        1,
        2,
        vec![unverified_tx_with_ops(vec![Op::ChannelInscribe(competing)])],
    );
    let result = sequencer
        .process_block_event(&live_event(&block))
        .await
        .unwrap();
    let (update, ..) = sequencer.apply_block_result(result);

    assert_eq!(update.orphaned().len(), submitted.len());
    for (orphan, original) in update.orphaned().iter().zip(&submitted) {
        let ChannelUpdateTx::Custom(tx) = orphan else {
            panic!("all inscriptions must be reported together, got {orphan:?}");
        };
        assert_eq!(tx, original, "orphans retain their bytes and chain order");
    }
    assert!(
        sequencer
            .state
            .as_ref()
            .unwrap()
            .all_pending_txs()
            .iter()
            .all(|(hash, _)| submitted.iter().all(|tx| tx.hash() != *hash))
    );
}

/// The variant follows `orphaned`: nothing orphaned is an extension,
/// otherwise a conflict whose prefix is the view at the tip after the shed
/// passes, so it excludes what they orphaned.
#[tokio::test]
async fn update_variant_follows_orphaned() {
    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key).await;
    let info_of = |op: &InscriptionOp| InscriptionInfo {
        tx_hash: unverified_tx_with_ops(vec![Op::ChannelInscribe(op.clone())]).hash(),
        parent_msg: op.parent,
        this_msg: op.id(),
        payload: op.inscription.clone(),
        signer: Some(op.signer),
        steps: InscriptionSteps::default(),
    };
    let result = |adopted: Vec<ChannelUpdateTx>,
                  orphaned: Vec<ChannelUpdateTx>,
                  view_before: ViewBefore| BlockEventResult {
        finalized_items: Vec::new(),
        channel_update: Some(ChannelUpdateInfo {
            orphaned,
            adopted,
            new_channel_tip: MsgId::root(),
        }),
        view_before,
        observed: Vec::new(),
    };
    let hashes =
        |txs: &[ChannelUpdateTx]| txs.iter().map(ChannelUpdateTx::tx_hash).collect::<Vec<_>>();

    // Block 1 on LIB mines entry 1; the view at the tip is that entry.
    let mined = inscribe_op(channel_id, MsgId::root(), b"1");
    let mined_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(mined.clone())]);
    let lib = sequencer.state.as_ref().unwrap().lib();
    sequencer.state.as_mut().unwrap().process_block(
        header_id(1),
        lib,
        lib,
        std::iter::empty(),
        vec![BlockChannelTx::new(
            Arc::new(mined_tx.clone()),
            mined_tx.hash(),
            ChannelTxKind::Inscription(info_of(&mined)),
        )],
        vec![],
    );
    sequencer.current_tip = Some(header_id(1));
    let adopted = ChannelUpdateTx::Inscription(info_of(&inscribe_op(channel_id, mined.id(), b"3")));

    let (update, ..) = sequencer.apply_block_result(result(
        vec![adopted.clone()],
        Vec::new(),
        ViewBefore::new(&[], HashSet::new()),
    ));
    assert!(matches!(update, ChannelUpdate::Extension { adopted } if adopted.len() == 1));

    // A pending entry chaining off the mined tip is shed by the passes.
    let stale = inscribe_op(channel_id, MsgId::root(), b"2");
    let stale_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(stale.clone())]);
    sequencer
        .state
        .as_mut()
        .unwrap()
        .submit_inscription(
            stale_tx,
            MsgId::root(),
            stale.id(),
            stale.inscription.clone(),
        )
        .unwrap();
    let orphaned_entry = ChannelUpdateTx::Inscription(info_of(&stale));

    let (update, ..) = sequencer.apply_block_result(result(
        vec![adopted.clone()],
        vec![orphaned_entry.clone()],
        ViewBefore::new(&[info_of(&mined), info_of(&stale)], HashSet::new()),
    ));
    let ChannelUpdate::Conflict {
        common_prefix,
        adopted: got,
        orphaned,
    } = update
    else {
        panic!("an orphaned entry makes a conflict")
    };
    assert_eq!(
        hashes(&common_prefix),
        hashes(&[ChannelUpdateTx::Inscription(info_of(&mined))]),
        "the view at the tip, without the shed entry"
    );
    assert_eq!(hashes(&got), hashes(&[adopted]));
    assert_eq!(hashes(&orphaned), hashes(&[orphaned_entry]));
}

// TODO(private-utxo): re-type with an inscription whose step consumes a note.
#[cfg(any())]
/// A pending bundle whose transfer input is gone from the branch on a block
/// that moves no message (a deposit reorged out changes no lineage entry) is
/// kept while the deposit may re-land, then expires un-refunded: a fresh fee
/// note brings no deposit back, and the bundle would otherwise be re-funded
/// and re-posted forever while holding the publish parent.
#[tokio::test]
async fn dead_input_bundle_expires_without_a_lineage_change() {
    use lb_core::mantle::transactions::MantleTxBuilder;

    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key).await;
    assert_eq!(sequencer.current_tip, Some(header_id(1)));
    let window = sequencer.config.stale_refund_slots;
    assert!(window > 0, "fixture: the refund window is on");

    // A withdraw bundle on the channel tip spending a note the channel does
    // not hold on this branch, funded at slot 0.
    let (_, utxo) = utxo_with_sk();
    let withdraw_op = ChannelWithdrawOp {
        channel_id,
        inputs: BoundedInputs::from(utxo.id()).into(),
    };
    let transfer_op = lb_core::mantle::ops::channel::channel_transfer::ChannelTransferOp {
        channel_id,
        inputs: BoundedInputs::from(utxo.id()).into(),
        outputs: Outputs::new([utxo.note]),
    };
    let inscribe = inscribe_op(channel_id, MsgId::root(), b"withdraw");
    let bundle = unverified_tx_with_ops(vec![
        Op::ChannelTransfer(transfer_op),
        Op::ChannelWithdraw(withdraw_op),
        Op::ChannelInscribe(inscribe.clone()),
    ]);
    let bundle_hash = bundle.hash();
    let state = sequencer.state.as_mut().unwrap();
    track_pending_tx(state, bundle, channel_id).unwrap();
    state.stamp_funding(&bundle_hash, Slot::from(0), Some(MantleTxBuilder::new()));
    state.mark_pending_inscription_posted(&bundle_hash);
    sequencer.last_msg_id = inscribe.id();
    let silent = || BlockEventResult {
        finalized_items: Vec::new(),
        channel_update: None,
        view_before: ViewBefore::new(&[], HashSet::new()),
        deposits: Vec::new(),
    };

    // Inside the window the bundle is kept: the deposit may come back.
    sequencer.lib_slot = Slot::from(window / 2);
    let (update, ..) = sequencer.apply_block_result(silent());
    assert!(
        matches!(update, ChannelUpdate::Extension { .. }),
        "kept: {update:?}"
    );
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 1);
    assert!(
        sequencer
            .state
            .as_ref()
            .unwrap()
            .refund_candidates(header_id(1), Slot::from(window * 2), window, usize::MAX)
            .is_empty(),
        "a dead-input bundle is never re-funded"
    );

    // Past it, the bundle expires and is reported orphaned.
    sequencer.lib_slot = Slot::from(window * 2);
    let (update, ..) = sequencer.apply_block_result(silent());
    let ChannelUpdate::Conflict { orphaned, .. } = update else {
        panic!("the dead bundle must be reported orphaned, got {update:?}")
    };
    assert_eq!(
        orphaned
            .iter()
            .map(ChannelUpdateTx::tx_hash)
            .collect::<Vec<_>>(),
        vec![bundle_hash]
    );
    assert!(matches!(orphaned[0], ChannelUpdateTx::AtomicWithdraw(_)));
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 0);
    assert_eq!(
        sequencer.last_msg_id,
        MsgId::root(),
        "the publish parent falls back to the channel tip"
    );
}

/// A pending entry whose parent is neither the channel tip nor another
/// pending entry is shed on a block that moves no message. Restored from a
/// checkpoint after the block taking its parent finalized, such an entry is
/// off the pending suffix, so it is never posted, and the first event's diff
/// is silent about finalized history: without a shed it would stay pending
/// for good, unreported.
#[tokio::test]
async fn off_suffix_pending_entry_is_shed_without_a_lineage_change() {
    let channel_id = ChannelId::from([0; 32]);
    let key = Ed25519Key::from_bytes(&[0; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, key).await;
    assert_eq!(sequencer.current_tip, Some(header_id(1)));

    // Chained on a message that is not the tip (root) and not pending.
    let taken = MsgId::from([7u8; 32]);
    let stranded = inscribe_op(channel_id, taken, b"queued out of turn");
    let stranded_tx = unverified_tx_with_ops(vec![Op::ChannelInscribe(stranded.clone())]);
    let stranded_hash = stranded_tx.hash();
    sequencer
        .state
        .as_mut()
        .unwrap()
        .submit_inscription(stranded_tx, taken, stranded.id(), stranded.inscription)
        .unwrap();
    assert!(
        sequencer
            .state
            .as_ref()
            .unwrap()
            .pending_txs(header_id(1))
            .is_empty(),
        "fixture: off the suffix, the entry is never posted"
    );

    let (update, ..) = sequencer.apply_block_result(BlockEventResult {
        finalized_items: Vec::new(),
        channel_update: None,
        view_before: ViewBefore::new(&[], HashSet::new()),
        observed: Vec::new(),
    });
    let ChannelUpdate::Conflict { orphaned, .. } = update else {
        panic!("the stranded entry must be reported orphaned, got {update:?}")
    };
    assert_eq!(
        orphaned
            .iter()
            .map(ChannelUpdateTx::tx_hash)
            .collect::<Vec<_>>(),
        vec![stranded_hash]
    );
    assert_eq!(sequencer.state.as_ref().unwrap().pending_publish_count(), 0);
    assert_eq!(sequencer.last_msg_id, MsgId::root());
}

fn assert_history_matches_update(sequencer: &ZoneSequencer<MockNode>, update: &ChannelUpdate) {
    let history = sequencer
        .channel_history()
        .expect("live history is available");
    let expected = update
        .canonical_chain()
        .expect("conflict update contains the surviving history");

    assert_eq!(
        history
            .iter()
            .map(ChannelUpdateTx::tx_hash)
            .collect::<Vec<_>>(),
        expected.map(ChannelUpdateTx::tx_hash).collect::<Vec<_>>()
    );
}

async fn ready_sequencer_with_channel(
    channel: Option<ChannelState>,
    sequencer_key: Ed25519Key,
) -> ZoneSequencer<MockNode> {
    let (mut node, _posted_txs) = MockNode::with_posted_channel();
    node.channel_state = channel;
    let mut sequencer = ZoneSequencer::init(
        ChannelId::from([0; 32]),
        sequencer_key,
        node,
        funding_config(),
        None,
    );
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }
    sequencer
}

/// The config op's signature must claim our key's index in the *current*
/// accredited list — not index 0 — or the ledger rejects the update as
/// `InvalidSignature` whenever the sequencer is not the leading key.
#[tokio::test]
async fn channel_config_signs_with_own_current_accredited_index() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let leading_key = Ed25519Key::from_bytes(&[0; 32]);
    let channel = ChannelState {
        accredited_keys: UnverifiedChannelKeys::new_unchecked(vec![
            leading_key.public_key().into_unverified(),
            own_key.public_key().into_unverified(),
        ])
        .into(),
        ..single_key_channel_state()
    };
    let mut sequencer = ready_sequencer_with_channel(Some(channel), own_key.clone()).await;

    let (_receipt, signed_ops) = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await
        .expect("config update from an accredited non-leading key must build");

    assert_eq!(
        config_op_of(&signed_ops).parent(),
        MsgId::root(),
        "parent must equal the channel's config tip"
    );
    let OpProofRef::ChannelMultiSigProof(proof) =
        signed_ops.first().expect("config op proof present").proof()
    else {
        panic!("config op must carry a multi-sig proof");
    };
    let signatures = proof.signatures();
    assert_eq!(signatures.len(), 1);
    let (key_index, signature) = signatures
        .first_key_value()
        .expect("the proof holds one signature");
    assert_eq!(
        *key_index, 1,
        "signature must claim the signer's position in the current accredited list"
    );
    own_key
        .public_key()
        .into_unverified()
        .verify(signed_ops.hash().as_signing_bytes(), signature)
        .expect("signature must verify against the claimed key over the funded tx hash");
}

/// Configuring an unclaimed channel requires no signatures (the ledger
/// skips the check), so the proof must stay empty — a superfluous
/// signature would also break the node wallet's fee prediction.
#[tokio::test]
async fn channel_config_on_unclaimed_channel_carries_empty_proof() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, own_key.clone()).await;

    let (_receipt, signed_ops) = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await
        .expect("claiming an unclaimed channel must build");

    let OpProofRef::ChannelMultiSigProof(proof) =
        signed_ops.first().expect("config op proof present").proof()
    else {
        panic!("config op must carry a multi-sig proof");
    };
    assert!(proof.signatures().is_empty());
    assert_eq!(
        config_op_of(&signed_ops).parent(),
        MsgId::root(),
        "claiming an unclaimed channel must be rooted at ZERO"
    );
}

/// A sequencer whose key is not on the current accredited list cannot
/// produce a verifiable config signature; fail locally instead of
/// submitting a transaction that silently dies at block assembly.
#[tokio::test]
async fn channel_config_fails_when_not_accredited() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let mut sequencer =
        ready_sequencer_with_channel(Some(single_key_channel_state()), own_key.clone()).await;

    let error = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await
        .expect_err("config update from a non-accredited key must fail locally");
    assert!(
        error.to_string().contains("accredited"),
        "unexpected error: {error}"
    );
}

/// A config the ledger would reject (a zero threshold, or a configuration
/// threshold above the key count) fails locally, before it is funded.
#[tokio::test]
async fn channel_config_rejects_an_ill_formed_config() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, own_key.clone()).await;

    for (configuration_threshold, reason) in [
        (2, "exceeds the 1 accredited keys"),
        (0, "configuration_threshold must be at least 1"),
    ] {
        let error = sequencer
            .handle()
            .channel_config(
                VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
                SlotTimeframe::from(0u32),
                SlotTimeout::from(0u32),
                configuration_threshold,
            )
            .await
            .expect_err("an ill-formed config must fail locally");
        assert!(
            error.to_string().contains(reason),
            "unexpected error: {error}"
        );
    }
}

/// `configuration_threshold > 1` needs signatures the sequencer cannot
/// collect; reject early with a clear error.
#[tokio::test]
async fn channel_config_rejects_multi_sig_threshold() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let channel = ChannelState {
        accredited_keys: UnverifiedChannelKeys::new_unchecked(vec![
            own_key.public_key().into_unverified(),
            Ed25519Key::from_bytes(&[0; 32])
                .public_key()
                .into_unverified(),
        ])
        .into(),
        configuration_threshold: 2,
        ..single_key_channel_state()
    };
    let mut sequencer = ready_sequencer_with_channel(Some(channel), own_key.clone()).await;

    let error = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await
        .expect_err("multi-sig threshold config update must fail locally");
    assert!(
        error.to_string().contains("single-signer"),
        "unexpected error: {error}"
    );
}

fn config_op_of(tx: &SignedOps<Unverified, StandardMode>) -> ChannelConfigOp {
    tx.op_refs()
        .iter()
        .find_map(|op| match *op {
            OpRef::ChannelConfig(config) => Some(config.clone()),
            _ => None,
        })
        .expect("tx should carry a config op")
}

/// A configuration extends the mined config tip, never a config of ours
/// still in flight: the proof is built for the mined key set, so pairing
/// it with a pending config's id would produce a tx the ledger can only
/// reject. A config position has one pending continuation, so a second
/// config on the same mined tip is refused until the first lands or
/// expires.
#[tokio::test]
async fn a_second_config_on_a_pending_config_position_is_refused() {
    let own_key = Ed25519Key::from_bytes(&[7; 32]);
    let mut sequencer = ready_sequencer_with_channel(None, own_key.clone()).await;

    let (_receipt, first_tx) = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(0u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await
        .expect("first config should be accepted");
    let second = sequencer
        .handle()
        .channel_config(
            VerifiedChannelKeys::new_unchecked(vec![own_key.public_key()]),
            SlotTimeframe::from(1u32),
            SlotTimeout::from(0u32),
            1,
        )
        .await;

    assert_eq!(
        config_op_of(&first_tx).parent(),
        MsgId::root(),
        "the config claiming an unclaimed channel must be rooted at ZERO"
    );
    assert!(
        matches!(second, Err(Error::ChannelStateChanged(_))),
        "the position is taken while the first config pends: {second:?}"
    );
}

fn sample_program_key() -> ProgramVerificationKey {
    ProgramRegisterOp::sample().verification_key
}

/// A registration is one funded `ProgramRegister` op with no proof, tracked
/// like an own tx: in the checkpoint's pending set with a funding record
/// that can rebuild it.
#[tokio::test]
async fn register_program_submits_an_unproven_op_and_tracks_it() {
    let mut sequencer = ready_sequencer_with_channel(
        Some(single_key_channel_state()),
        Ed25519Key::from_bytes(&[0; 32]),
    )
    .await;
    let key = sample_program_key();

    let (info, checkpoint) = sequencer
        .handle()
        .register_program(key.clone())
        .await
        .expect("a valid key registers");

    assert_eq!(info.program_id, derive_program_id(&key));
    assert_eq!(info.verification_key, key);
    let (hash, tx) = checkpoint
        .pending_txs
        .iter()
        .find(|(hash, _)| *hash == info.tx_hash)
        .expect("the registration is pending");
    let ops: Vec<_> = tx.op_refs_iter().collect();
    let [op] = ops.as_slice() else {
        panic!("one op before funding, got {ops:?}");
    };
    assert!(matches!(op, OpRef::ProgramRegister(register) if register.verification_key == key));
    assert!(matches!(
        tx.first().expect("one op").proof(),
        OpProofRef::None(_)
    ));
    let funding = checkpoint
        .funding
        .iter()
        .find(|record| record.tx_hash == *hash)
        .expect("the registration has a funding record");
    assert!(
        funding.pre_fund.is_some(),
        "a registration can be re-funded"
    );
}

/// A key the ledger would reject is refused before anything is funded.
#[tokio::test]
async fn register_program_refuses_a_key_off_the_curve() {
    let mut sequencer = ready_sequencer_with_channel(
        Some(single_key_channel_state()),
        Ed25519Key::from_bytes(&[0; 32]),
    )
    .await;
    // Canonical bytes, yet no point has x = 0.
    let mut bytes = sample_program_key().to_bytes();
    bytes[..32].fill(0);
    let off_curve = ProgramVerificationKey::try_from_bytes(&bytes).expect("decodes");

    let error = sequencer
        .handle()
        .register_program(off_curve)
        .await
        .expect_err("an off-curve key is refused");
    assert!(matches!(error, Error::InvalidProgramKey(_)), "{error:?}");
    assert!(
        sequencer
            .subscribe_checkpoint()
            .borrow()
            .as_ref()
            .is_none_or(|checkpoint| checkpoint.pending_txs.is_empty()),
        "nothing was submitted"
    );
}

/// Anyone's registration is reported when its block joins the canonical
/// chain, and again when it finalizes.
#[tokio::test]
async fn program_registration_is_observed_then_finalized() {
    let channel_id = ChannelId::from([7; 32]);
    let key = sample_program_key();
    let register_tx = unverified_tx_with_ops(vec![Op::ProgramRegister(ProgramRegisterOp {
        verification_key: key.clone(),
    })]);
    let b1 = api_block(1, 0, 1, vec![register_tx.clone()]);
    let b2 = api_block(2, 1, 2, Vec::new());
    let finalizing = ProcessedBlockEvent {
        block: b2.clone(),
        tip: b2.header.id,
        tip_slot: b2.header.slot,
        lib: b1.header.id,
        lib_slot: b1.header.slot,
    };
    let node = MockNode {
        immutable: vec![b1.clone()],
        scripts: scripts(vec![StreamScript {
            events: vec![live_event(&b1), finalizing],
            then: StreamEnd::Hang,
        }]),
        ..MockNode::default()
    };
    let mut sequencer = ZoneSequencer::init(
        channel_id,
        Ed25519Key::from_bytes(&[0; 32]),
        node,
        funding_config(),
        None,
    );

    let mut observed_programs = Vec::new();
    let mut finalized_programs = Vec::new();
    while finalized_programs.is_empty() {
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), sequencer.next_event())
            .await
            .expect("both blocks are served");
        if let Event::BlocksProcessed {
            observed,
            finalized,
            ..
        } = event
        {
            observed_programs.extend(observed.into_iter().filter_map(|op| match op {
                ObservedOp::ProgramRegister(program) => Some(program),
                ObservedOp::Deposit(_) => None,
            }));
            finalized_programs.extend(finalized.iter().flat_map(|tx| &tx.ops).filter_map(|op| {
                match op {
                    FinalizedOp::ProgramRegister(program) => Some(program.clone()),
                    _ => None,
                }
            }));
        }
    }

    let expected = ProgramRegisterInfo {
        tx_hash: register_tx.hash(),
        program_id: derive_program_id(&key),
        verification_key: key,
    };
    assert_eq!(observed_programs, vec![expected.clone()]);
    assert_eq!(finalized_programs, vec![expected]);
}

/// An own registration carries no channel op, so only the tracked hash
/// marks it mined: once its block finalizes it leaves the pending set.
#[tokio::test]
async fn own_registration_leaves_pending_when_its_block_finalizes() {
    let channel_id = ChannelId::from([0; 32]);
    let key = sample_program_key();
    // The mock funds without a fee transfer, so the tx the sequencer builds
    // is the bare op under the fixture fork digest.
    let register_tx = unverified_tx_with_ops(vec![Op::ProgramRegister(ProgramRegisterOp {
        verification_key: key.clone(),
    })]);
    let b1 = api_block(1, 0, 1, Vec::new());
    let b2 = api_block(2, 1, 2, vec![register_tx.clone()]);
    let b3 = api_block(3, 2, 3, Vec::new());
    let finalizing = ProcessedBlockEvent {
        block: b3.clone(),
        tip: b3.header.id,
        tip_slot: b3.header.slot,
        lib: b2.header.id,
        lib_slot: b2.header.slot,
    };
    let (up_tx, up_rx) = watch::channel(true);
    let node = MockNode {
        channel_state: Some(single_key_channel_state()),
        up: Some(up_rx),
        immutable: vec![b2.clone()],
        scripts: scripts(vec![
            StreamScript {
                events: vec![live_event(&b1)],
                then: StreamEnd::Hang,
            },
            StreamScript {
                events: vec![live_event(&b2), finalizing],
                then: StreamEnd::Hang,
            },
        ]),
        ..MockNode::default()
    };
    let config = SequencerConfig {
        reconnect_delay: std::time::Duration::from_millis(20),
        ..SequencerConfig::new(funding_config())
    };
    let mut sequencer = ZoneSequencer::init_with_config(
        channel_id,
        Ed25519Key::from_bytes(&[0; 32]),
        node,
        config,
        None,
    );
    loop {
        if matches!(sequencer.next_event().await, Event::Ready) {
            break;
        }
    }

    let (info, checkpoint) = sequencer
        .handle()
        .register_program(key)
        .await
        .expect("a valid key registers");
    assert_eq!(
        info.tx_hash,
        register_tx.hash(),
        "the mock funds the bare op"
    );
    assert_eq!(checkpoint.pending_txs.len(), 1);

    // Drop the connection, then come back on the stream that mines and
    // finalizes the registration.
    up_tx.send(false).unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let reconnect = tokio::time::sleep(std::time::Duration::from_millis(100));
    tokio::pin!(reconnect);
    loop {
        let event = tokio::select! {
            event = sequencer.next_event() => event,
            () = &mut reconnect => {
                up_tx.send(true).unwrap();
                continue;
            }
            () = tokio::time::sleep_until(deadline) => panic!("the registration finalizes"),
        };
        if let Event::BlocksProcessed {
            checkpoint,
            finalized,
            ..
        } = event
            && finalized.iter().any(|tx| tx.tx_hash == info.tx_hash)
        {
            assert!(
                checkpoint.pending_txs.is_empty(),
                "the finalized registration is no longer pending: {:?}",
                checkpoint.pending_txs
            );
            assert!(checkpoint.funding.is_empty());
            break;
        }
    }
}
