//! The channel's commitment MMR with the program notes in it: what a program
//! step consumes, each with the Merkle path its spend proof needs, kept
//! current as the channel's note set grows.

use std::collections::{HashMap, HashSet};

use lb_core::{
    events::{BlockEvent, Event, Events},
    mantle::{
        SignedOps,
        ledger::verification_mode::StandardMode,
        note_set::{CommitmentMmr, NoteSetIndex},
        notes::{NoteCommitment, NoteNullifier, ProgramId, derive_note_nullifier},
        ops::{
            OpProofRef, OpRef,
            channel::{
                ChannelId,
                inscribe::{InscriptionOp, Step},
            },
            proof_program_step::{ProgramNoteOpening, StepProof},
        },
        transactions::states::Unverified,
    },
};
use lb_groth16::Fr;
use lb_key_management_system_service::keys::ZkKey;
use lb_mmr::{MerklePath, PushWithPathsError};
use rpds::HashTrieMapSync;

use super::types::{ProgramNote, ProgramNotesCheckpoint, ProgramNotesView};

/// What a block does to the channel's note set: the commitments it appends
/// and the nullifiers it consumes, in execution order, and the program notes
/// among the appended, with their program and opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNoteSet {
    pub commitments: Vec<NoteCommitment>,
    pub nullifiers: Vec<NoteNullifier>,
    pub created: HashMap<NoteCommitment, (ProgramId, ProgramNoteOpening)>,
}

impl BlockNoteSet {
    /// The channel's update among a block's events, with `created` the
    /// program notes the block's steps publish; `None` when the block left
    /// the set as it was.
    pub fn from_events(
        events: &Events,
        channel_id: ChannelId,
        created: HashMap<NoteCommitment, (ProgramId, ProgramNoteOpening)>,
    ) -> Option<Self> {
        let update = events.iter().find_map(|event| match event {
            Event::Block(BlockEvent::NoteSetUpdated(update))
                if update.note_set == NoteSetIndex::Channel(channel_id) =>
            {
                Some(update)
            }
            _ => None,
        })?;
        Some(Self {
            commitments: update.commitments.clone(),
            nullifiers: update.nullifiers.clone(),
            created,
        })
    }
}

/// Whether a transaction can append to the channel's note set: a deposit on
/// it, or an inscription on it that carries steps. A withdrawal only
/// consumes, and never a program note, so it moves neither the root nor the
/// tracked set.
pub fn touches_note_set(tx: &SignedOps<Unverified, StandardMode>, channel_id: ChannelId) -> bool {
    tx.op_refs_iter().any(|op| match op {
        OpRef::ChannelInscribe(inscribe) => {
            inscribe.channel_id == channel_id && inscribe.steps_len() > 0
        }
        OpRef::ChannelDeposit(deposit) => deposit.channel_id == channel_id,
        _ => false,
    })
}

/// The program notes the block's program steps create, with their program
/// and the openings their proofs publish, keyed by commitment.
pub fn program_notes_created(
    txs: &[SignedOps<Unverified, StandardMode>],
    channel_id: ChannelId,
) -> HashMap<NoteCommitment, (ProgramId, ProgramNoteOpening)> {
    txs.iter()
        .flat_map(|tx| tx.op_refs_iter().zip(tx.op_proof_refs_iter()))
        .filter_map(|(op, proof)| match (op, proof) {
            (OpRef::ChannelInscribe(inscribe), OpProofRef::ChannelInscribe(proof))
                if inscribe.channel_id == channel_id =>
            {
                Some((inscribe, proof))
            }
            _ => None,
        })
        .flat_map(|(inscribe, proof)| {
            inscribe
                .steps()
                .zip(proof.step_proofs.iter())
                .filter_map(|(step, proof)| match (step, proof) {
                    (Step::Program(step), StepProof::ProgramStep(proof)) => Some(
                        step.program_outputs.iter().copied().zip(
                            proof
                                .program_notes
                                .iter()
                                .map(|opening| (step.program_id, *opening)),
                        ),
                    ),
                    _ => None,
                })
                .flatten()
        })
        .collect()
}

/// The program notes the transaction's program steps consume.
pub fn program_step_inputs(
    tx: &SignedOps<Unverified, StandardMode>,
) -> impl Iterator<Item = NoteNullifier> + '_ {
    tx.op_refs_iter()
        .filter_map(|op| match op {
            OpRef::ChannelInscribe(inscribe) => Some(inscribe),
            _ => None,
        })
        .flat_map(InscriptionOp::steps)
        .filter_map(|step| match step {
            Step::Program(step) => Some(step.inputs.iter().copied()),
            _ => None,
        })
        .flatten()
}

impl ProgramNotesView {
    /// The view of an empty set: the empty MMR's root and no notes.
    #[must_use]
    pub fn empty() -> Self {
        ProgramNoteSet::default().view(&ProgramNoteSet::default())
    }
}

/// The channel's commitment MMR and the program notes in it, each with its
/// path at the MMR's root. Persistent: a block's set shares what it did not
/// change with its parent's.
#[derive(Debug, Clone, Default)]
pub struct ProgramNoteSet {
    commitments: CommitmentMmr,
    notes: HashTrieMapSync<NoteCommitment, ProgramNote>,
}

impl ProgramNoteSet {
    /// The set after `block`: every appended commitment advances the paths,
    /// the new program notes join with theirs, and the consumed ones leave.
    pub fn apply(&self, block: &BlockNoteSet) -> Result<Self, PushWithPathsError> {
        let mut notes: Vec<ProgramNote> = self.notes.values().cloned().collect();
        let mut paths: Vec<MerklePath> = notes.iter().map(|note| note.path.clone()).collect();
        let mut commitments = self.commitments.clone();
        let nullifier_key = ZkKey::zero().nullifier_key();
        for commitment in &block.commitments {
            let (next, path) = commitments.push_with_paths(*commitment, &mut paths)?;
            commitments = next;
            if let Some((program, opening)) = block.created.get(commitment) {
                notes.push(ProgramNote {
                    commitment: *commitment,
                    program: *program,
                    opening: *opening,
                    nullifier: derive_note_nullifier(commitment, &nullifier_key),
                    path: path.clone(),
                });
                paths.push(path);
            }
        }
        let consumed: HashSet<NoteNullifier> = block.nullifiers.iter().copied().collect();
        let notes = notes
            .into_iter()
            .zip(paths)
            .filter(|(note, _)| !consumed.contains(&note.nullifier))
            .map(|(mut note, path)| {
                note.path = path;
                (note.commitment, note)
            })
            .collect();
        Ok(Self { commitments, notes })
    }

    /// The MMR root the notes' paths are against.
    #[must_use]
    pub fn root(&self) -> Fr {
        self.commitments.frontier_root()
    }

    pub fn contains(&self, commitment: &NoteCommitment) -> bool {
        self.notes.contains_key(commitment)
    }

    pub fn notes(&self) -> impl Iterator<Item = &ProgramNote> {
        self.notes.values()
    }

    pub fn note(&self, commitment: &NoteCommitment) -> Option<&ProgramNote> {
        self.notes.get(commitment)
    }

    /// The set at `self`'s root keeping only the notes also in `tip`: what a
    /// step naming `self`'s root may consume once `tip` is the chain.
    #[must_use]
    pub fn still_in(&self, tip: &Self) -> Self {
        Self {
            commitments: self.commitments.clone(),
            notes: self
                .notes
                .iter()
                .filter(|(commitment, _)| tip.contains(commitment))
                .map(|(commitment, note)| (*commitment, note.clone()))
                .collect(),
        }
    }

    /// The set without the notes of `spent`.
    #[must_use]
    pub fn without(&self, spent: &HashSet<NoteNullifier>) -> Self {
        if spent.is_empty() {
            return self.clone();
        }
        Self {
            commitments: self.commitments.clone(),
            notes: self
                .notes
                .iter()
                .filter(|(_, note)| !spent.contains(&note.nullifier))
                .map(|(commitment, note)| (*commitment, note.clone()))
                .collect(),
        }
    }

    /// The root of the set extended with `appended`, and the paths of
    /// `inputs` against it: what a step at that position of a transaction
    /// is proven against.
    pub fn extended(
        &self,
        appended: &[NoteCommitment],
        inputs: &[&ProgramNote],
    ) -> Result<(Fr, Vec<MerklePath>), PushWithPathsError> {
        let mut paths: Vec<MerklePath> = inputs.iter().map(|note| note.path.clone()).collect();
        let mut commitments = self.commitments.clone();
        for commitment in appended {
            commitments = commitments.push_with_paths(*commitment, &mut paths)?.0;
        }
        Ok((commitments.frontier_root(), paths))
    }

    /// The set at `self`'s root, split into the notes also in `finalized`
    /// and the rest.
    #[must_use]
    pub fn view(&self, finalized: &Self) -> ProgramNotesView {
        let (finalized, unfinalized) = self
            .notes()
            .cloned()
            .partition(|note| finalized.contains(&note.commitment));
        ProgramNotesView {
            root: self.root(),
            finalized,
            unfinalized,
        }
    }

    #[must_use]
    pub fn to_checkpoint(&self) -> ProgramNotesCheckpoint {
        ProgramNotesCheckpoint {
            commitments: self.commitments.clone(),
            notes: self.notes().cloned().collect(),
        }
    }

    #[must_use]
    pub fn from_checkpoint(checkpoint: ProgramNotesCheckpoint) -> Self {
        Self {
            commitments: checkpoint.commitments,
            notes: checkpoint
                .notes
                .into_iter()
                .map(|note| (note.commitment, note))
                .collect(),
        }
    }
}

/// Fixtures of a program's notes, shared by the tests of the modules that
/// layer the set.
#[cfg(test)]
pub(super) mod fixtures {
    use lb_core::mantle::{
        notes::{NoteCommitment, NoteNullifier, ProgramId, derive_note_nullifier},
        ops::proof_program_step::{ProgramNoteOpening, StepProof, StepProofShape},
    };
    use lb_groth16::Fr;
    use lb_key_management_system_service::keys::{ZkKey, ZkPublicKey};

    use super::BlockNoteSet;

    pub fn program() -> ProgramId {
        Fr::from(7u64)
    }

    pub fn opening(seed: u64) -> ProgramNoteOpening {
        ProgramNoteOpening {
            value: seed,
            nonce: Fr::from(seed),
            stake_public_key: ZkPublicKey::new(Fr::from(seed)),
            data: Fr::from(seed),
        }
    }

    pub fn commitment(seed: u64) -> NoteCommitment {
        opening(seed).note(program()).commitment()
    }

    pub fn nullifier(seed: u64) -> NoteNullifier {
        derive_note_nullifier(&commitment(seed), &ZkKey::zero().nullifier_key())
    }

    /// A foreign commitment of the channel, not a note of the program.
    pub fn foreign(seed: u64) -> NoteCommitment {
        NoteCommitment(Fr::from(1_000 + seed))
    }

    /// A block creating the program notes `created` and consuming the ones
    /// in `consumed`, with `foreign` other commitments appended first.
    pub fn block(foreign: &[u64], created: &[u64], consumed: &[u64]) -> BlockNoteSet {
        BlockNoteSet {
            commitments: foreign
                .iter()
                .map(|seed| self::foreign(*seed))
                .chain(created.iter().map(|seed| commitment(*seed)))
                .collect(),
            nullifiers: consumed.iter().map(|seed| nullifier(*seed)).collect(),
            created: created
                .iter()
                .map(|seed| (commitment(*seed), (program(), opening(*seed))))
                .collect(),
        }
    }

    /// The opening the sample proof of a one-note program step carries.
    pub fn sample_opening() -> ProgramNoteOpening {
        let StepProof::ProgramStep(proof) =
            StepProof::sample_for(StepProofShape::ProgramStep { program_notes: 1 })
        else {
            panic!("a program step shape samples a program step proof");
        };
        proof.program_notes[0]
    }
}

#[cfg(test)]
mod tests {
    use lb_core::{
        crypto::ZkHasher,
        mantle::{
            Op,
            note_set::NoteSetUpdate,
            ops::channel::{
                MsgId,
                inscribe::{MiniBlock, MiniBlocks},
                program_step::ProgramStep,
            },
        },
    };

    use super::{
        fixtures::{self, block, commitment, nullifier, opening, program},
        *,
    };
    use crate::test_support::{inscribe_op, unverified_tx_with_ops};

    #[test]
    fn apply_tracks_paths_through_later_appends_and_drops_the_consumed() {
        let set = ProgramNoteSet::default()
            .apply(&block(&[1], &[1, 2], &[]))
            .unwrap();
        let notes: Vec<_> = set.notes().collect();
        assert_eq!(notes.len(), 2);
        for note in &notes {
            assert!(
                note.path.verify::<ZkHasher>(note.commitment.0, set.root()),
                "a new note's path is against the set's root"
            );
            assert_eq!(note.nullifier, nullifier(note.opening.value));
        }

        // Foreign appends move the root; the tracked paths follow it.
        let grown = set.apply(&block(&[2, 3], &[], &[])).unwrap();
        assert_ne!(grown.root(), set.root());
        for note in grown.notes() {
            assert!(
                note.path
                    .verify::<ZkHasher>(note.commitment.0, grown.root())
            );
            assert!(!note.path.verify::<ZkHasher>(note.commitment.0, set.root()));
        }

        // A consumed note leaves; the other keeps a valid path.
        let spent = grown.apply(&block(&[], &[], &[1])).unwrap();
        let left: Vec<_> = spent.notes().collect();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].commitment, commitment(2));
        assert!(
            left[0]
                .path
                .verify::<ZkHasher>(commitment(2).0, spent.root())
        );
        assert_eq!(spent.root(), grown.root(), "consuming appends nothing");
    }

    #[test]
    fn view_splits_by_the_finalized_set_and_checkpoints_round_trip() {
        let finalized = ProgramNoteSet::default()
            .apply(&block(&[], &[1], &[]))
            .unwrap();
        let branch = finalized.apply(&block(&[], &[2], &[])).unwrap();
        let view = branch.view(&finalized);
        assert_eq!(view.root, branch.root());
        assert_eq!(
            view.finalized
                .iter()
                .map(|n| n.commitment)
                .collect::<Vec<_>>(),
            [commitment(1)]
        );
        assert_eq!(
            view.unfinalized
                .iter()
                .map(|n| n.commitment)
                .collect::<Vec<_>>(),
            [commitment(2)]
        );

        let restored = ProgramNoteSet::from_checkpoint(branch.to_checkpoint());
        assert_eq!(restored.root(), branch.root());
        assert_eq!(restored.view(&finalized), view);
    }

    #[test]
    fn program_notes_created_reads_the_openings_off_the_step_proofs() {
        let channel_id = ChannelId::from([1; 32]);
        let sample = fixtures::sample_opening();
        let ours = ProgramStep {
            program_id: program(),
            program_outputs: [sample.note(program()).commitment()].into(),
            ..ProgramStep::sample()
        };
        // Another program's step: its note is tracked under its own program.
        let theirs = ProgramStep::sample();
        let mut op = inscribe_op(channel_id, MsgId::root(), b"steps");
        op.mini_blocks = MiniBlocks::from([MiniBlock::try_from(vec![
            Step::Program(theirs.clone()),
            Step::Program(ours.clone()),
        ])
        .unwrap()]);
        let other_channel = inscribe_op(ChannelId::from([2; 32]), MsgId::root(), b"x");
        let txs = vec![
            unverified_tx_with_ops(vec![Op::ChannelInscribe(op)]),
            unverified_tx_with_ops(vec![Op::ChannelInscribe(other_channel)]),
        ];

        let created = program_notes_created(&txs, channel_id);
        assert_eq!(created.len(), 2);
        assert_eq!(
            created.get(&ours.program_outputs.as_slice()[0]),
            Some(&(program(), sample))
        );
        assert_eq!(
            created
                .get(&theirs.program_outputs.as_slice()[0])
                .map(|(program, _)| *program),
            Some(theirs.program_id)
        );
        assert!(
            program_notes_created(&txs, ChannelId::from([2; 32])).is_empty(),
            "the other channel's inscription carries no step"
        );

        assert_eq!(
            program_step_inputs(&txs[0]).count(),
            2,
            "both steps consume their sample input"
        );
        assert!(touches_note_set(&txs[0], channel_id));
        assert!(!touches_note_set(&txs[1], ChannelId::from([2; 32])));
    }

    #[test]
    fn from_events_picks_the_channel_update() {
        let channel_id = ChannelId::from([1; 32]);
        let update = |id: ChannelId| {
            Event::Block(BlockEvent::NoteSetUpdated(NoteSetUpdate {
                note_set: NoteSetIndex::Channel(id),
                nullifiers: vec![nullifier(3)],
                commitments: vec![NoteCommitment(Fr::from(5u64)), commitment(1)],
            }))
        };
        let events: Events = [update(ChannelId::from([2; 32])), update(channel_id)]
            .into_iter()
            .collect();
        let created = HashMap::from([(commitment(1), (program(), opening(1)))]);
        let block = BlockNoteSet::from_events(&events, channel_id, created.clone())
            .expect("the channel's update is among the events");
        assert_eq!(
            block.commitments,
            [NoteCommitment(Fr::from(5u64)), commitment(1)]
        );
        assert_eq!(block.nullifiers, [nullifier(3)]);
        assert_eq!(block.created, created);
        assert!(
            BlockNoteSet::from_events(&events, ChannelId::from([3; 32]), HashMap::new()).is_none()
        );
    }

    #[test]
    fn still_in_keeps_the_root_and_drops_what_the_tip_consumed() {
        let base = ProgramNoteSet::default()
            .apply(&block(&[1], &[1, 2], &[]))
            .unwrap();
        let tip = base.apply(&block(&[2], &[3], &[1])).unwrap();
        let spend = base.still_in(&tip);
        assert_eq!(spend.root(), base.root());
        assert_eq!(
            spend
                .notes()
                .map(|note| note.commitment)
                .collect::<Vec<_>>(),
            [commitment(2)],
            "note 1 is consumed at the tip and note 3 is not in the base yet"
        );
        assert!(
            spend
                .note(&commitment(2))
                .unwrap()
                .path
                .verify::<ZkHasher>(commitment(2).0, spend.root())
        );
    }

    #[test]
    fn without_drops_the_spent_notes() {
        let set = ProgramNoteSet::default()
            .apply(&block(&[], &[1, 2], &[]))
            .unwrap();
        let rest = set.without(&HashSet::from([nullifier(1)]));
        assert_eq!(
            rest.notes().map(|note| note.commitment).collect::<Vec<_>>(),
            [commitment(2)]
        );
        assert_eq!(rest.root(), set.root());
    }

    #[test]
    fn extended_proves_the_inputs_against_the_root_the_buffer_makes() {
        let set = ProgramNoteSet::default()
            .apply(&block(&[1], &[1, 2], &[]))
            .unwrap();
        let appended = [fixtures::foreign(2), commitment(3)];
        let inputs = [set.note(&commitment(2)).unwrap()];
        let (root, paths) = set.extended(&appended, &inputs).unwrap();
        let expected = appended
            .iter()
            .fold(set.commitments.clone(), |mmr, commitment| {
                mmr.push_with_paths(*commitment, &mut []).unwrap().0
            })
            .frontier_root();
        assert_eq!(root, expected);
        assert_ne!(root, set.root());
        assert!(paths[0].verify::<ZkHasher>(commitment(2).0, root));
        let (unextended, paths) = set.extended(&[], &inputs).unwrap();
        assert_eq!(unextended, set.root());
        assert_eq!(paths, [inputs[0].path.clone()]);
    }
}
