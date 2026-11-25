//! The program steps of an inscription: built on the sequencer's tracked
//! program notes at the position the ledger verifies them, each with the
//! witness of its `ZkProgramSpend`, which is proven off the drive loop.

use std::collections::HashSet;

use ark_ff::PrimeField as _;
use lb_core::mantle::{
    Note, Value,
    notes::{
        InputNullifiers, NoteCommitment, NoteNullifier, OutputCommitments, ProgramId,
        derive_program_output_nonce,
    },
    ops::{
        OpId as _, StepProof,
        channel::{
            ChannelId, MsgId,
            inscribe::{Inscription, InscriptionOp, MiniBlock, MiniBlocks, Step},
            program_step::{ProgramDeposit, ProgramStep, program_deposits_hash},
        },
        proof_program_step::{
            ProgramNoteOpening, ProgramProof, ProgramStepProof, ZkProgramSpendProof,
        },
    },
    programs::{SpendInputFields, SpendOutputFields, program_step_id},
};
use lb_groth16::{AdditiveGroup as _, Fr};
use lb_key_management_system_service::keys::{Ed25519Key, ZkKey, ZkPublicKey};
use lb_mmr::MerklePath;
use lb_program_spend::{
    MAX_INPUTS, MAX_OUTPUTS, ZkProgramSpendChainInputsData, ZkProgramSpendInputNoteData,
    ZkProgramSpendOutputNoteData, ZkProgramSpendWalletInputsData, ZkProgramSpendWitnessInputsData,
    check_bounds,
};

use super::{
    program_notes::ProgramNoteSet,
    tx_builder::inscription_op,
    types::{Error, ProgramNote},
};

/// A note of the program a step creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramOutput {
    pub value: Value,
    pub stake_public_key: ZkPublicKey,
    pub data: Fr,
    /// The program's choice of nonce, which a step consuming nothing must
    /// make. A step consuming a note has every output nonce derived from
    /// its first input, so the nonce is left out or equals the derivation.
    pub nonce: Option<Fr>,
}

/// A user note a step pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserOutput {
    pub public_key: ZkPublicKey,
    pub stake_public_key: ZkPublicKey,
    pub value: Value,
    /// As [`ProgramOutput::nonce`].
    pub nonce: Option<Fr>,
}

/// A program step for the sequencer to build: what it consumes and creates.
/// Its value balances: the inputs plus the program deposits before it in
/// its mini-block pay the outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramStepRequest {
    pub program_id: ProgramId,
    /// The program notes it consumes, among the ones
    /// [`ZoneSequencer::program_notes`](super::ZoneSequencer::program_notes)
    /// lists.
    pub inputs: Vec<NoteCommitment>,
    /// The notes of the program it creates, appended before `outputs`.
    pub program_outputs: Vec<ProgramOutput>,
    /// The user notes it pays.
    pub outputs: Vec<UserOutput>,
    /// The zone message of the step.
    pub inscription: Inscription,
}

/// A step of a mini-block: one a user's node built and proved, a user step
/// or a program deposit, or one of the program for the sequencer to build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a user's step is carried with its proof as given"
)]
pub enum StepRequest {
    User { step: Step, proof: StepProof },
    Program(ProgramStepRequest),
}

/// The steps of a mini-block, in the order they apply.
pub type MiniBlockRequest = Vec<StepRequest>;

/// An inscription with its program steps built: the op to submit, and per
/// step what its proof is made of.
#[derive(Debug, Clone)]
pub struct PreparedProgramInscription {
    pub op: InscriptionOp,
    /// One per step of `op`, in order.
    pub steps: Vec<PreparedStep>,
}

/// What a step of a [`PreparedProgramInscription`] has towards its proof.
#[derive(Debug, Clone)]
pub enum PreparedStep {
    /// A user's step, proven as given.
    User(StepProof),
    /// A program step built by the sequencer, whose spend
    /// [`prove_program_step`] proves and whose program proof the zone adds.
    Program(PreparedProgramStep),
}

/// A program step the sequencer built, with the witness of its spend.
#[derive(Debug, Clone)]
pub struct PreparedProgramStep {
    /// The index of the step over the mini-blocks of the inscription.
    pub index: usize,
    /// The `ZkProgramSpend` witness, bound to the inscription's op id.
    pub witness: Box<ZkProgramSpendWitnessInputsData>,
    /// The openings of the notes of the program the step creates, which
    /// its proof publishes.
    pub program_notes: Vec<ProgramNoteOpening>,
    /// The openings of every note the step creates, the program's first.
    pub outputs: Vec<Note>,
    /// The public inputs of the program proof: the step id, the hash of the
    /// deposits the step consumes and the op id.
    pub program_inputs: [Fr; 3],
}

impl PreparedProgramInscription {
    /// The program steps of the inscription, in order.
    pub fn program_steps(&self) -> impl Iterator<Item = &PreparedProgramStep> {
        self.steps.iter().filter_map(|step| match step {
            PreparedStep::Program(prepared) => Some(prepared),
            PreparedStep::User(_) => None,
        })
    }

    /// The proofs of the steps for
    /// [`SequencerHandle::submit_prepared_inscription`](super::SequencerHandle::submit_prepared_inscription),
    /// from the spend and program proofs of the program steps, in their
    /// order.
    pub fn step_proofs(
        &self,
        program_proofs: Vec<(ZkProgramSpendProof, ProgramProof)>,
    ) -> Result<Vec<StepProof>, Error> {
        let program_steps = self.program_steps().count();
        if program_proofs.len() != program_steps {
            return Err(Error::InvalidStepProofs(format!(
                "{} proofs for {program_steps} program steps",
                program_proofs.len()
            )));
        }
        let mut program_proofs = program_proofs.into_iter();
        Ok(self
            .steps
            .iter()
            .map(|step| match step {
                PreparedStep::User(proof) => proof.clone(),
                PreparedStep::Program(prepared) => {
                    let (spend_proof, program_proof) = program_proofs
                        .next()
                        .expect("one proof pair per program step, counted above");
                    StepProof::ProgramStep(ProgramStepProof {
                        spend_proof,
                        program_proof,
                        program_notes: prepared.program_notes.clone(),
                    })
                }
            })
            .collect())
    }
}

/// Proves the spend of a program step. Takes seconds of CPU: run it off
/// the drive loop.
pub fn prove_program_step(prepared: &PreparedProgramStep) -> Result<ZkProgramSpendProof, Error> {
    let (proof, _) = lb_program_spend::prove((*prepared.witness).clone().into())
        .map_err(|error| Error::Prover(error.to_string()))?;
    Ok(ZkProgramSpendProof::new(proof))
}

/// Builds the inscription of `data` with `mini_blocks` on `parent`, its
/// program steps spending `spend`'s notes at the root `spend` is at.
pub(super) fn build_program_inscription(
    channel_id: ChannelId,
    signing_key: &Ed25519Key,
    data: Inscription,
    parent: MsgId,
    spend: &ProgramNoteSet,
    mini_blocks: Vec<MiniBlockRequest>,
) -> Result<PreparedProgramInscription, Error> {
    let mut builder = Builder {
        spend,
        buffer: Vec::new(),
        consumed: HashSet::new(),
        index: 0,
        steps: Vec::new(),
    };
    let mini_blocks = mini_blocks
        .into_iter()
        .map(|mini_block| builder.mini_block(mini_block))
        .collect::<Result<Vec<_>, _>>()?;
    let mini_blocks = MiniBlocks::try_from_iter(mini_blocks)
        .map_err(|error| Error::InvalidProgramStep(format!("too many mini-blocks: {error}")))?;
    let op = inscription_op(channel_id, signing_key, data, parent, mini_blocks);
    // The message of the program spends and the third input of the program
    // proofs.
    let op_id = Fr::from_le_bytes_mod_order(&op.op_id());
    let mut steps = builder.steps;
    for step in &mut steps {
        if let PreparedStep::Program(prepared) = step {
            prepared.witness.chain.msg = op_id;
            prepared.program_inputs[2] = op_id;
        }
    }
    Ok(PreparedProgramInscription { op, steps })
}

// Walks the steps of an inscription as the ledger does: every step's
// outputs join the buffer the next program steps are proven behind, and a
// program step consumes the deposits of its mini-block since the last one.
struct Builder<'a> {
    spend: &'a ProgramNoteSet,
    buffer: Vec<NoteCommitment>,
    consumed: HashSet<NoteNullifier>,
    index: usize,
    steps: Vec<PreparedStep>,
}

impl<'a> Builder<'a> {
    fn mini_block(&mut self, steps: MiniBlockRequest) -> Result<MiniBlock, Error> {
        let mut built = Vec::with_capacity(steps.len());
        let mut deposits: Vec<ProgramDeposit> = Vec::new();
        for request in steps {
            let step = match request {
                StepRequest::User { step, proof } => {
                    self.check_user_step(&step, &proof)?;
                    match &step {
                        Step::ProgramDeposit(deposit) => deposits.push(deposit.clone()),
                        Step::Program(_) => deposits.clear(),
                        Step::User(_) => {}
                    }
                    self.steps.push(PreparedStep::User(proof));
                    step
                }
                StepRequest::Program(request) => {
                    let (step, prepared) = self.program_step(request, &deposits)?;
                    deposits.clear();
                    self.steps.push(PreparedStep::Program(prepared));
                    Step::Program(step)
                }
            };
            self.buffer.extend(step.outputs().iter().copied());
            self.index += 1;
            built.push(step);
        }
        if let Some(deposit) = deposits.first() {
            return Err(self.invalid(&format!(
                "a deposit to program {:?} is left unconsumed at the end of its mini-block",
                deposit.program_id
            )));
        }
        MiniBlock::try_from(built)
            .map_err(|error| Error::InvalidProgramStep(format!("mini-block: {error}")))
    }

    fn invalid(&self, reason: &str) -> Error {
        Error::InvalidProgramStep(format!("step {}: {reason}", self.index))
    }

    // A user's step carries the proof of its kind and consumes no note of
    // the inscription's program steps.
    fn check_user_step(&mut self, step: &Step, proof: &StepProof) -> Result<(), Error> {
        let fits = match step {
            Step::User(_) | Step::ProgramDeposit(_) => matches!(proof, StepProof::ZkTransfer(_)),
            Step::Program(_) => matches!(proof, StepProof::ProgramStep(_)),
        };
        if !fits {
            return Err(self.invalid("the proof is not of the step's kind"));
        }
        for nullifier in step.inputs().iter() {
            if !self.consumed.insert(*nullifier) {
                return Err(self.invalid(&format!("consumes {nullifier:?} twice")));
            }
        }
        Ok(())
    }

    fn program_step(
        &mut self,
        request: ProgramStepRequest,
        deposits: &[ProgramDeposit],
    ) -> Result<(ProgramStep, PreparedProgramStep), Error> {
        if let Some(deposit) = deposits
            .iter()
            .find(|deposit| deposit.program_id != request.program_id)
        {
            return Err(self.invalid(&format!(
                "consumes a deposit to another program {:?}",
                deposit.program_id
            )));
        }
        let paid_value = deposits
            .iter()
            .try_fold(0, |paid: Value, deposit| paid.checked_add(deposit.value))
            .ok_or_else(|| self.invalid("the paid value overflows"))?;
        check_bounds(
            request.inputs.len(),
            request.program_outputs.len() + request.outputs.len(),
        )
        .map_err(|error| self.invalid(&error.to_string()))?;
        let inputs = self.inputs(&request)?;
        self.check_balance(&request, &inputs, paid_value)?;

        let first_input = inputs.first().map(|note| &note.nullifier);
        let (program_notes, outputs) =
            created_notes(&request, first_input).map_err(|reason| self.invalid(&reason))?;
        let input_notes: Vec<Note> = inputs
            .iter()
            .map(|note| note.opening.note(note.program))
            .collect();
        let (tx_commitment_root, paths) = self
            .spend
            .extended(&self.buffer, &inputs)
            .map_err(|error| self.invalid(&format!("the channel's note set is full: {error}")))?;
        let step = ProgramStep {
            program_id: request.program_id,
            inputs: InputNullifiers::try_from_iter(inputs.iter().map(|note| note.nullifier))
                .map_err(|error| self.invalid(&error.to_string()))?,
            program_outputs: OutputCommitments::try_from_iter(
                outputs[..program_notes.len()].iter().map(Note::commitment),
            )
            .map_err(|error| self.invalid(&error.to_string()))?,
            outputs: OutputCommitments::try_from_iter(
                outputs[program_notes.len()..].iter().map(Note::commitment),
            )
            .map_err(|error| self.invalid(&error.to_string()))?,
            commitment_merkle_root: self.spend.root(),
            program_step_id: step_id(&input_notes, &outputs),
            inscription: request.inscription,
        };
        let witness = ZkProgramSpendWitnessInputsData {
            wallet: wallet_inputs(&input_notes, &paths, &outputs),
            chain: ZkProgramSpendChainInputsData {
                inputs_active: core::array::from_fn(|i| i < inputs.len()),
                outputs_active: core::array::from_fn(|j| j < outputs.len()),
                outputs_of_program: core::array::from_fn(|j| j < program_notes.len()),
                tx_commitment_root,
                program_id: request.program_id,
                paid_value,
                msg: Fr::ZERO,
            },
        };
        let prepared = PreparedProgramStep {
            index: self.index,
            witness: Box::new(witness),
            program_notes,
            outputs,
            program_inputs: [
                step.program_step_id,
                program_deposits_hash(&deposits.iter().collect::<Vec<_>>()),
                Fr::ZERO,
            ],
        };
        Ok((step, prepared))
    }

    // The spendable notes of the step's program the step consumes, each
    // once in the inscription.
    fn inputs(&mut self, request: &ProgramStepRequest) -> Result<Vec<&'a ProgramNote>, Error> {
        let spend = self.spend;
        let mut inputs = Vec::with_capacity(request.inputs.len());
        for commitment in &request.inputs {
            let note = spend.note(commitment).ok_or_else(|| {
                self.invalid(&format!(
                    "consumes {commitment:?}, not a spendable program note of the channel"
                ))
            })?;
            if note.program != request.program_id {
                return Err(self.invalid(&format!(
                    "consumes {commitment:?}, a note of program {:?}",
                    note.program
                )));
            }
            if !self.consumed.insert(note.nullifier) {
                return Err(self.invalid(&format!("consumes {commitment:?} twice")));
            }
            inputs.push(note);
        }
        Ok(inputs)
    }

    fn check_balance(
        &self,
        request: &ProgramStepRequest,
        inputs: &[&ProgramNote],
        paid_value: Value,
    ) -> Result<(), Error> {
        let overflow = || self.invalid("the value overflows");
        let consumed = inputs
            .iter()
            .try_fold(paid_value, |total: Value, note| {
                total.checked_add(note.opening.value)
            })
            .ok_or_else(overflow)?;
        let created = request
            .program_outputs
            .iter()
            .map(|output| output.value)
            .chain(request.outputs.iter().map(|output| output.value))
            .try_fold(0, |total: Value, value| total.checked_add(value))
            .ok_or_else(overflow)?;
        if consumed != created {
            return Err(self.invalid(&format!("consumes {consumed} and creates {created}")));
        }
        Ok(())
    }
}

// The notes the step creates, the program's first, with the nonce the spend
// fixes or the program chose.
fn created_notes(
    request: &ProgramStepRequest,
    first_input: Option<&NoteNullifier>,
) -> Result<(Vec<ProgramNoteOpening>, Vec<Note>), String> {
    let holder = ZkKey::zero().to_public_key();
    let program_notes = request
        .program_outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            Ok(ProgramNoteOpening {
                value: output.value,
                nonce: output_nonce(first_input, index, output.value, &holder, output.nonce)?,
                stake_public_key: output.stake_public_key,
                data: output.data,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let user_notes = request
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let index = index + program_notes.len();
            Ok(Note {
                value: output.value,
                nonce: output_nonce(
                    first_input,
                    index,
                    output.value,
                    &output.public_key,
                    output.nonce,
                )?,
                public_key: output.public_key,
                stake_public_key: output.stake_public_key,
                program: Fr::ZERO,
                data: Fr::ZERO,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let outputs = program_notes
        .iter()
        .map(|opening| opening.note(request.program_id))
        .chain(user_notes)
        .collect();
    Ok((program_notes, outputs))
}

// The nonce of the output at `index`: the derivation from the first input
// when the step consumes a note, which a chosen nonce must equal, else the
// program's choice, which it must make.
fn output_nonce(
    first_input: Option<&NoteNullifier>,
    index: usize,
    value: Value,
    public_key: &ZkPublicKey,
    chosen: Option<Fr>,
) -> Result<Fr, String> {
    match (first_input, chosen) {
        (Some(first_input), chosen) => {
            let derived = derive_program_output_nonce(first_input, index, value, public_key);
            if chosen.is_some_and(|nonce| nonce != derived) {
                return Err(format!(
                    "the nonce of output {index} is derived from the first input"
                ));
            }
            Ok(derived)
        }
        (None, Some(nonce)) => Ok(nonce),
        (None, None) => Err(format!(
            "a step consuming nothing names the nonce of output {index}"
        )),
    }
}

// The id of the step consuming `inputs` and creating `outputs`.
fn step_id(inputs: &[Note], outputs: &[Note]) -> Fr {
    let input_fields: [SpendInputFields; MAX_INPUTS] = core::array::from_fn(|i| {
        inputs
            .get(i)
            .map_or_else(SpendInputFields::inactive, |note| SpendInputFields {
                active: true,
                value: note.value,
                nonce: note.nonce,
                public_key: note.public_key,
                stake_public_key: note.stake_public_key,
                data: note.data,
            })
    });
    let output_fields: [SpendOutputFields; MAX_OUTPUTS] = core::array::from_fn(|j| {
        outputs
            .get(j)
            .map_or_else(SpendOutputFields::inactive, SpendOutputFields::of)
    });
    program_step_id(&input_fields, &output_fields)
}

// The wallet's part of the witness: the inputs with their paths, and the
// outputs.
fn wallet_inputs(
    inputs: &[Note],
    paths: &[MerklePath],
    outputs: &[Note],
) -> ZkProgramSpendWalletInputsData {
    ZkProgramSpendWalletInputsData {
        inputs: core::array::from_fn(|i| {
            inputs.get(i).zip(paths.get(i)).map_or_else(
                ZkProgramSpendInputNoteData::inactive,
                |(note, path)| ZkProgramSpendInputNoteData {
                    stake_public_key: *note.stake_public_key.as_fr(),
                    nonce: note.nonce,
                    value: note.value,
                    data: note.data,
                    path_and_selectors: core::array::from_fn(|level| {
                        path.path_and_selectors(level).into()
                    }),
                },
            )
        }),
        outputs: core::array::from_fn(|j| {
            outputs
                .get(j)
                .map_or_else(ZkProgramSpendOutputNoteData::inactive, |note| {
                    ZkProgramSpendOutputNoteData {
                        public_key: *note.public_key.as_fr(),
                        stake_public_key: *note.stake_public_key.as_fr(),
                        nonce: note.nonce,
                        value: note.value,
                        program: note.program,
                        data: note.data,
                    }
                })
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use lb_core::mantle::{
        note_set::CommitmentMmr,
        ops::{channel::inscribe::UserStep, proof_program_step::StepProofShape},
    };
    use lb_program_spend::{ZkProgramSpendPublic, ZkProgramSpendVerifierInput};

    use super::{
        super::{
            program_notes::{
                BlockNoteSet,
                fixtures::{block, commitment, foreign, nullifier, opening, program},
            },
            tx_builder::check_step_proofs,
        },
        *,
    };

    fn channel() -> ChannelId {
        ChannelId::from([3; 32])
    }

    fn key() -> Ed25519Key {
        Ed25519Key::from_bytes(&[5; 32])
    }

    fn parent() -> MsgId {
        MsgId::from([9u8; 32])
    }

    fn pk(seed: u64) -> ZkPublicKey {
        ZkPublicKey::new(Fr::from(seed))
    }

    fn holder() -> ZkPublicKey {
        ZkKey::zero().to_public_key()
    }

    fn chosen_nonce(value: Value) -> Fr {
        Fr::from(1_000 + value)
    }

    /// The channel's set: the program's notes 2 and 3 behind a foreign
    /// commitment.
    fn spend_set() -> ProgramNoteSet {
        ProgramNoteSet::default()
            .apply(&block(&[1], &[2, 3], &[]))
            .unwrap()
    }

    /// The root of [`spend_set`]'s MMR extended with `buffer`, built from
    /// the leaves.
    fn extended_root(buffer: &[NoteCommitment]) -> Fr {
        [foreign(1), commitment(2), commitment(3)]
            .iter()
            .chain(buffer)
            .fold(CommitmentMmr::new(), |mmr, commitment| {
                mmr.push(*commitment).unwrap()
            })
            .frontier_root()
    }

    fn transfer_proof() -> StepProof {
        StepProof::sample_for(StepProofShape::ZkTransfer)
    }

    fn user_outputs() -> [NoteCommitment; 2] {
        [
            NoteCommitment(Fr::from(0x24u64)),
            NoteCommitment(Fr::from(0x25u64)),
        ]
    }

    fn user_step() -> StepRequest {
        StepRequest::User {
            step: Step::User(UserStep {
                inputs: [NoteNullifier(Fr::from(0x23u64))].into(),
                outputs: user_outputs().into(),
                commitment_merkle_root: Fr::from(0x26u64),
                inscription: Inscription::new_unchecked(b"user".to_vec()),
            }),
            proof: transfer_proof(),
        }
    }

    /// A deposit of `value`, spending a note of its own.
    fn deposit(program_id: ProgramId, value: Value) -> StepRequest {
        StepRequest::User {
            step: Step::ProgramDeposit(ProgramDeposit {
                program_id,
                value,
                inputs: [NoteNullifier(Fr::from(0x100 + value))].into(),
                outputs: [NoteCommitment(Fr::from(0x200 + value))].into(),
                ..ProgramDeposit::sample()
            }),
            proof: transfer_proof(),
        }
    }

    fn program_step(
        inputs: &[u64],
        program_outputs: &[Value],
        outputs: &[(u64, Value)],
    ) -> StepRequest {
        StepRequest::Program(ProgramStepRequest {
            program_id: program(),
            inputs: inputs.iter().map(|seed| commitment(*seed)).collect(),
            // A step consuming nothing names its nonces: `chosen_nonce`.
            program_outputs: program_outputs
                .iter()
                .map(|value| ProgramOutput {
                    value: *value,
                    stake_public_key: pk(77),
                    data: Fr::from(11u64),
                    nonce: inputs.is_empty().then(|| chosen_nonce(*value)),
                })
                .collect(),
            outputs: outputs
                .iter()
                .map(|(seed, value)| UserOutput {
                    public_key: pk(*seed),
                    stake_public_key: pk(*seed + 100),
                    value: *value,
                    nonce: inputs.is_empty().then(|| chosen_nonce(*value)),
                })
                .collect(),
            inscription: Inscription::new_unchecked(b"program".to_vec()),
        })
    }

    fn build(
        spend: &ProgramNoteSet,
        mini_blocks: Vec<MiniBlockRequest>,
    ) -> Result<PreparedProgramInscription, Error> {
        build_program_inscription(
            channel(),
            &key(),
            Inscription::new_unchecked(b"zone block".to_vec()),
            parent(),
            spend,
            mini_blocks,
        )
    }

    fn program_draft(
        built: &PreparedProgramInscription,
        index: usize,
    ) -> (&ProgramStep, &PreparedProgramStep) {
        let Some(Step::Program(step)) = built.op.steps().nth(index) else {
            panic!("step {index} is a program step");
        };
        let Some(PreparedStep::Program(prepared)) = built.steps.get(index) else {
            panic!("step {index} has a program prepared");
        };
        (step, prepared)
    }

    fn rejection(result: Result<PreparedProgramInscription, Error>) -> String {
        match result {
            Err(Error::InvalidProgramStep(reason)) => reason,
            Err(error) => panic!("another error: {error}"),
            Ok(_) => panic!("the inscription builds"),
        }
    }

    /// A program step is built on the spend set's notes and proven behind
    /// the outputs of the steps before it, naming the set's root. Its
    /// outputs are the program's notes first, with the nonces derived from
    /// its first input.
    #[test]
    fn builds_a_program_step_at_its_position_in_the_inscription() {
        let spend = spend_set();
        let built = build(
            &spend,
            vec![vec![user_step(), program_step(&[2, 3], &[4], &[(5, 1)])]],
        )
        .unwrap();
        assert_eq!(built.op.channel_id, channel());
        assert_eq!(built.op.parent, parent());
        assert_eq!(built.op.steps_len(), 2);
        let Some(PreparedStep::User(proof)) = built.steps.first() else {
            panic!("the user's step keeps its proof");
        };
        assert_eq!(*proof, transfer_proof());

        let (step, prepared) = program_draft(&built, 1);
        assert_eq!(prepared.index, 1);
        assert_eq!(step.program_id, program());
        assert_eq!(step.inputs.as_slice(), [nullifier(2), nullifier(3)]);
        assert_eq!(
            step.commitment_merkle_root,
            spend.root(),
            "the step names the root of the spend set"
        );
        assert_eq!(
            prepared.witness.chain.tx_commitment_root,
            extended_root(&user_outputs()),
            "the spend is proven behind the outputs of the user's step"
        );
        assert_ne!(prepared.witness.chain.tx_commitment_root, spend.root());

        assert_eq!(prepared.program_notes.len(), 1);
        assert_eq!(prepared.outputs.len(), 2);
        assert_eq!(
            prepared.outputs[0],
            prepared.program_notes[0].note(program())
        );
        assert_eq!(
            prepared.outputs[0].nonce,
            derive_program_output_nonce(&nullifier(2), 0, 4, &holder())
        );
        assert_eq!(
            prepared.outputs[1],
            Note {
                value: 1,
                nonce: derive_program_output_nonce(&nullifier(2), 1, 1, &pk(5)),
                public_key: pk(5),
                stake_public_key: pk(105),
                program: Fr::ZERO,
                data: Fr::ZERO,
            },
            "a user note keeps the staking key it was given"
        );
        assert_eq!(
            step.program_outputs.as_slice(),
            [prepared.outputs[0].commitment()]
        );
        assert_eq!(step.outputs.as_slice(), [prepared.outputs[1].commitment()]);

        let op_id = Fr::from_le_bytes_mod_order(&built.op.op_id());
        assert_eq!(
            prepared.program_inputs,
            [step.program_step_id, program_deposits_hash(&[]), op_id]
        );
        assert_eq!(prepared.witness.chain.msg, op_id);
        assert_eq!(prepared.witness.chain.paid_value, 0);
        assert_eq!(prepared.witness.chain.program_id, program());
        assert_eq!(
            prepared.witness.chain.inputs_active,
            [true, true, false, false]
        );
        assert_eq!(
            prepared.witness.chain.outputs_active[..3],
            [true, true, false]
        );
        assert_eq!(
            prepared.witness.chain.outputs_of_program[..2],
            [true, false]
        );
    }

    /// A step after program deposits consumes their value, with their hash
    /// as the second input of its program proof. Consuming no note, its
    /// outputs carry the nonces the program chose.
    #[test]
    fn a_step_after_deposits_is_paid_their_value() {
        let built = build(
            &spend_set(),
            vec![vec![
                user_step(),
                deposit(program(), 50),
                deposit(program(), 6),
                program_step(&[], &[56], &[]),
            ]],
        )
        .unwrap();
        let (step, prepared) = program_draft(&built, 3);
        assert_eq!(step.inputs.as_slice(), []);
        assert_eq!(prepared.witness.chain.paid_value, 56);
        assert_eq!(prepared.witness.chain.inputs_active, [false; MAX_INPUTS]);
        let deposits: Vec<&ProgramDeposit> = built
            .op
            .steps()
            .filter_map(|step| match step {
                Step::ProgramDeposit(deposit) => Some(deposit),
                _ => None,
            })
            .collect();
        assert_eq!(deposits.len(), 2);
        assert_eq!(prepared.program_inputs[1], program_deposits_hash(&deposits));
        assert_eq!(
            prepared.outputs[0].nonce,
            chosen_nonce(56),
            "a step consuming nothing uses the nonce the program chose"
        );
        let buffer: Vec<NoteCommitment> = user_outputs()
            .into_iter()
            .chain(
                deposits
                    .iter()
                    .flat_map(|deposit| deposit.outputs.iter().copied()),
            )
            .collect();
        assert_eq!(
            prepared.witness.chain.tx_commitment_root,
            extended_root(&buffer),
            "the spend is proven behind the deposits' change too"
        );
    }

    /// The steps of a later mini-block are proven behind the outputs of
    /// the earlier ones, and a note is consumed once in the inscription.
    #[test]
    fn later_mini_blocks_build_on_the_earlier_outputs() {
        let built = build(
            &spend_set(),
            vec![
                vec![program_step(&[2], &[2], &[])],
                vec![program_step(&[3], &[], &[(5, 3)])],
            ],
        )
        .unwrap();
        assert_eq!(built.op.mini_blocks.len(), 2);
        let (first, first_draft) = program_draft(&built, 0);
        let (_, second_draft) = program_draft(&built, 1);
        assert_eq!(
            first_draft.witness.chain.tx_commitment_root,
            extended_root(&[])
        );
        assert_eq!(
            second_draft.witness.chain.tx_commitment_root,
            extended_root(first.program_outputs.as_slice())
        );
        assert_eq!(
            rejection(build(
                &spend_set(),
                vec![
                    vec![program_step(&[2], &[2], &[])],
                    vec![program_step(&[2], &[2], &[])],
                ],
            )),
            format!("step 1: consumes {:?} twice", commitment(2))
        );
    }

    #[test]
    fn rejects_a_step_the_ledger_would() {
        let spend = spend_set();
        assert_eq!(
            rejection(build(&spend, vec![vec![program_step(&[9], &[9], &[])]])),
            format!(
                "step 0: consumes {:?}, not a spendable program note of the channel",
                commitment(9)
            )
        );
        let other = Fr::from(8u64);
        let foreign_note = opening(4).note(other).commitment();
        let with_other = spend
            .apply(&BlockNoteSet {
                commitments: vec![foreign_note],
                nullifiers: vec![],
                created: HashMap::from([(foreign_note, (other, opening(4)))]),
            })
            .unwrap();
        let mut request = program_step(&[], &[4], &[]);
        let StepRequest::Program(step) = &mut request else {
            unreachable!()
        };
        step.inputs = vec![foreign_note];
        assert_eq!(
            rejection(build(&with_other, vec![vec![request]])),
            format!("step 0: consumes {foreign_note:?}, a note of program {other:?}")
        );
        assert_eq!(
            rejection(build(&spend, vec![vec![program_step(&[2], &[1], &[])]])),
            "step 0: consumes 2 and creates 1"
        );
        assert_eq!(
            rejection(build(
                &spend,
                vec![vec![deposit(other, 5), program_step(&[], &[5], &[])]]
            )),
            format!("step 1: consumes a deposit to another program {other:?}")
        );
        assert_eq!(
            rejection(build(&spend, vec![vec![deposit(program(), 5)]])),
            format!(
                "step 1: a deposit to program {:?} is left unconsumed at the end of its mini-block",
                program()
            )
        );
        assert!(rejection(build(&spend, vec![vec![]])).starts_with("mini-block:"));
        let five = ProgramNoteSet::default()
            .apply(&block(&[], &[1, 2, 3, 4, 5], &[]))
            .unwrap();
        assert_eq!(
            rejection(build(
                &five,
                vec![vec![program_step(&[1, 2, 3, 4, 5], &[15], &[])]]
            )),
            "step 0: a ZkProgramSpend spends at most 4 notes: got 5"
        );
        let mut unnamed = program_step(&[], &[5], &[]);
        let StepRequest::Program(step) = &mut unnamed else {
            unreachable!()
        };
        step.program_outputs[0].nonce = None;
        assert_eq!(
            rejection(build(&spend, vec![vec![deposit(program(), 5), unnamed]])),
            "step 1: a step consuming nothing names the nonce of output 0"
        );
        let mut fixed = program_step(&[2], &[2], &[]);
        let StepRequest::Program(step) = &mut fixed else {
            unreachable!()
        };
        step.program_outputs[0].nonce = Some(Fr::from(9u64));
        assert_eq!(
            rejection(build(&spend, vec![vec![fixed]])),
            "step 0: the nonce of output 0 is derived from the first input"
        );
        let misfit = StepRequest::User {
            step: Step::ProgramDeposit(ProgramDeposit::sample()),
            proof: StepProof::sample_for(StepProofShape::ProgramStep { program_notes: 0 }),
        };
        assert_eq!(
            rejection(build(&spend, vec![vec![misfit]])),
            "step 0: the proof is not of the step's kind"
        );
    }

    /// The step proofs interleave the users' proofs with the program
    /// steps' assembled ones, in step order, as `submit_prepared_inscription`
    /// checks them.
    #[test]
    fn step_proofs_fit_the_steps() {
        let built = build(
            &spend_set(),
            vec![vec![user_step(), program_step(&[2], &[2], &[])]],
        )
        .unwrap();
        let StepProof::ProgramStep(sample) =
            StepProof::sample_for(StepProofShape::ProgramStep { program_notes: 1 })
        else {
            panic!("a program step shape samples a program step proof");
        };
        let proofs = built
            .step_proofs(vec![(sample.spend_proof, sample.program_proof)])
            .unwrap();
        assert_eq!(proofs[0], transfer_proof());
        let (_, prepared) = program_draft(&built, 1);
        assert_eq!(
            proofs[1],
            StepProof::ProgramStep(ProgramStepProof {
                spend_proof: sample.spend_proof,
                program_proof: sample.program_proof,
                program_notes: prepared.program_notes.clone(),
            })
        );
        check_step_proofs(&built.op, &proofs).unwrap();
        assert!(matches!(
            built.step_proofs(vec![]),
            Err(Error::InvalidStepProofs(_))
        ));
    }

    /// The spend proof verifies against the public inputs the ledger
    /// derives from the op: the step's nullifiers, commitments and id, the
    /// root extended with the buffer before the step, and the op id.
    #[test]
    fn the_spend_proof_verifies_against_what_the_ledger_reads_from_the_op() {
        let built = build(
            &spend_set(),
            vec![vec![user_step(), program_step(&[2, 3], &[4], &[(5, 1)])]],
        )
        .unwrap();
        let (step, prepared) = program_draft(&built, 1);
        let proof = prove_program_step(prepared).unwrap();
        let outputs = step.outputs();
        let public = ZkProgramSpendVerifierInput::new(&ZkProgramSpendPublic {
            inputs: &step
                .inputs
                .iter()
                .map(|nullifier| nullifier.0)
                .collect::<Vec<_>>(),
            outputs: &outputs
                .iter()
                .map(|commitment| commitment.0)
                .collect::<Vec<_>>(),
            outputs_of_program: &(0..outputs.len())
                .map(|output| output < outputs.program_outputs().len())
                .collect::<Vec<_>>(),
            tx_commitment_root: extended_root(&user_outputs()),
            program_id: step.program_id,
            paid_value: 0,
            program_step_id: step.program_step_id,
            msg: Fr::from_le_bytes_mod_order(&built.op.op_id()),
        })
        .unwrap();
        assert!(lb_program_spend::verify(proof.as_proof(), &public).unwrap());
    }
}
