use std::collections::HashSet;

use lb_core::{
    crypto::ZkHasher,
    mantle::{
        Note, Value,
        notes::{NoteCommitment, ProgramId},
        ops::StepProof,
        programs::ProgramVerificationKey,
    },
};
use lb_groth16::{
    CompressedGroth16Proof, Fr,
    test_utils::{three_input_prove, three_input_setup},
};
use lb_key_management_system_service::keys::ZkPublicKey;
use lb_zone_sdk::{
    node_types::ProgramProof,
    sequencer::{
        Error as SequencerError, ProgramInscription, ProgramOutput, ProgramStepSpec, StepSpec,
        prove_program_step,
    },
};
use tokio::time::{sleep, timeout};
use tracing::warn;

use super::{
    Duration, Inscription, PublishDeadline, PublishResult, SequencerClient, Step, StepError,
    StepResult, ZoneWorld, ensure_zone_transactions_included, log_step_error,
    register_program_with_retry, remember_published_zone_message, zone_step_error,
};
use crate::cucumber::{steps::TARGET, zone::ZoneProgram};

/// Registers a toy program through the sequencer, its circuit seeded from
/// `program_alias`, and remembers the registration under the alias, its tx
/// under the same alias.
pub async fn register_zone_program(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: &str,
    program_alias: String,
) -> StepResult {
    let circuit_seed = circuit_seed(&program_alias);
    let (verification_key, _) = three_input_setup(circuit_seed);
    let verification_key =
        ProgramVerificationKey::try_from(&verification_key).map_err(|error| {
            StepError::LogicalError {
                message: format!("The toy circuit's key is not a program key: {error}"),
            }
        })?;
    let client = log_step_error(step, world.zone.sequencer_client(sequencer_alias))?;
    let (info, checkpoint) = register_program_with_retry(
        client,
        &verification_key,
        PublishDeadline::from_now(Duration::from_secs(120)),
    )
    .await
    .map_err(|error| StepError::LogicalError {
        message: format!("Zone register_program failed: {error}"),
    })?;

    world
        .zone
        .set_latest_checkpoint_for(sequencer_alias, checkpoint.clone());
    world
        .zone
        .remember_checkpoint(format!("{program_alias}_CHECKPOINT"), checkpoint);
    world
        .node
        .remember_submitted_transaction(program_alias.clone(), info.tx_hash);
    world
        .zone
        .remember_program(program_alias, ZoneProgram { info, circuit_seed });
    Ok(())
}

/// Publishes a zone block carrying one step of `program_alias`'s program:
/// consuming every note of the program the sequencer tracks when
/// `consume_tracked`, else nothing, and creating one note of the program
/// worth what it consumed. The sequencer builds and proves the spend, the
/// toy circuit proves the program. The block is remembered under
/// `block_alias` with the notes its step created.
pub async fn publish_program_step(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: &str,
    block_alias: String,
    program_alias: &str,
    consume_tracked: bool,
) -> StepResult {
    let program = world.zone.program(program_alias)?.clone();
    let client = log_step_error(step, world.zone.sequencer_client(sequencer_alias))?.clone();
    let node = log_step_error(
        step,
        world.zone_node_http_client_for_sequencer(sequencer_alias),
    )?;
    let payload = Inscription::new_unchecked(block_alias.clone().into_bytes());
    let (result, created) = publish_program_step_with_retry(
        &client,
        &payload,
        &program,
        consume_tracked,
        PublishDeadline::from_now(Duration::from_mins(3)),
    )
    .await?;
    ensure_zone_transactions_included(&node, &[result.inscription_id()], Duration::from_mins(3))
        .await
        .map_err(|error| zone_step_error(step, &error))?;

    world
        .node
        .remember_submitted_transaction(block_alias.clone(), result.inscription_id());
    remember_published_zone_message(
        world,
        sequencer_alias,
        block_alias.clone(),
        payload,
        &result,
    );
    world.zone.remember_program_outputs(block_alias, created);
    Ok(())
}

/// Waits until the program notes the sequencer tracks are exactly
/// `expected`, each with a path against the view's root.
pub async fn wait_for_tracked_program_notes(
    client: &SequencerClient,
    expected: &[NoteCommitment],
    duration: Duration,
) -> StepResult {
    let expected: HashSet<NoteCommitment> = expected.iter().copied().collect();
    timeout(duration, async {
        loop {
            let view = client
                .program_notes()
                .await
                .map_err(|error| StepError::LogicalError {
                    message: format!("Zone program_notes failed: {error}"),
                })?;
            let notes: Vec<_> = view.finalized.iter().chain(&view.unfinalized).collect();
            let tracked: HashSet<NoteCommitment> =
                notes.iter().map(|note| note.commitment).collect();
            if tracked == expected {
                for note in notes {
                    if !note.path.verify::<ZkHasher>(note.commitment.0, view.root) {
                        return Err(StepError::LogicalError {
                            message: format!(
                                "Tracked program note {:?} has no valid path against the root",
                                note.commitment
                            ),
                        });
                    }
                }
                return Ok(());
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| StepError::LogicalError {
        message: format!("Timed out waiting for the sequencer to track {expected:?}"),
    })?
}

// Builds, proves and submits the step until it lands in the pending set: a
// note the sequencer tracks becomes spendable a few blocks after its
// creation, and the publish tip may move under a built inscription.
async fn publish_program_step_with_retry(
    client: &SequencerClient,
    payload: &Inscription,
    program: &ZoneProgram,
    consume_tracked: bool,
    deadline: PublishDeadline,
) -> Result<(PublishResult, Vec<NoteCommitment>), StepError> {
    loop {
        if deadline.is_expired() {
            return Err(StepError::LogicalError {
                message: "Timed out publishing a program step".to_owned(),
            });
        }
        if let Some(published) =
            try_publish_program_step(client, payload, program, consume_tracked).await?
        {
            return Ok(published);
        }
        sleep(Duration::from_millis(500)).await;
    }
}

// One attempt at the step; `None` when it is to be tried again.
async fn try_publish_program_step(
    client: &SequencerClient,
    payload: &Inscription,
    program: &ZoneProgram,
    consume_tracked: bool,
) -> Result<Option<(PublishResult, Vec<NoteCommitment>)>, StepError> {
    let inputs = if consume_tracked {
        tracked_inputs(client, program.info.program_id).await?
    } else {
        Vec::new()
    };
    if consume_tracked && inputs.is_empty() {
        return Ok(None);
    }
    let spec = step_spec(program, payload, inputs);
    let Some(built) = prepare_built(client, payload, spec).await else {
        return Ok(None);
    };
    let (proofs, created) = prove_step(&built, program).await?;
    Ok(submit_built(client, &built, proofs)
        .await
        .map(|result| (result, created)))
}

// The inscription built on the sequencer's current state; `None` when it
// refuses the step for now, such as a note not yet deep enough to spend.
async fn prepare_built(
    client: &SequencerClient,
    payload: &Inscription,
    spec: ProgramStepSpec,
) -> Option<ProgramInscription> {
    client
        .prepare_program_inscription(payload.clone(), vec![vec![StepSpec::Program(spec)]])
        .await
        .inspect_err(|error| {
            warn!(target: TARGET, "Zone prepare_program_inscription failed, retrying: {error}");
        })
        .ok()
}

// The built inscription submitted with its proofs; `None` when the publish
// tip moved under it or the submission failed, to rebuild.
async fn submit_built(
    client: &SequencerClient,
    built: &ProgramInscription,
    proofs: Vec<StepProof>,
) -> Option<PublishResult> {
    match client
        .submit_prepared_inscription(built.op.clone(), proofs)
        .await
    {
        Ok((result, _checkpoint)) => Some(result),
        Err(SequencerError::ChannelStateChanged(reason)) => {
            warn!(target: TARGET, "The publish tip moved under the program step, rebuilding: {reason}");
            None
        }
        Err(error) => {
            warn!(target: TARGET, "Zone submit_prepared_inscription failed, retrying: {error}");
            None
        }
    }
}

// The notes of the program the sequencer tracks, with their values.
async fn tracked_inputs(
    client: &SequencerClient,
    program_id: ProgramId,
) -> Result<Vec<(NoteCommitment, Value)>, StepError> {
    let view = client
        .program_notes()
        .await
        .map_err(|error| StepError::LogicalError {
            message: format!("Zone program_notes failed: {error}"),
        })?;
    Ok(view
        .finalized
        .iter()
        .chain(&view.unfinalized)
        .filter(|note| note.program == program_id)
        .map(|note| (note.commitment, note.opening.value))
        .collect())
}

// A step consuming `inputs` and creating one note of the program worth
// their value.
fn step_spec(
    program: &ZoneProgram,
    payload: &Inscription,
    inputs: Vec<(NoteCommitment, Value)>,
) -> ProgramStepSpec {
    let value: Value = inputs.iter().map(|(_, value)| value).sum();
    ProgramStepSpec {
        program_id: program.info.program_id,
        inputs: inputs
            .into_iter()
            .map(|(commitment, _)| commitment)
            .collect(),
        program_outputs: vec![ProgramOutput {
            value,
            stake_public_key: ZkPublicKey::new(Fr::from(program.circuit_seed)),
            data: Fr::from(value),
        }],
        outputs: Vec::new(),
        inscription: payload.clone(),
    }
}

// The step proofs of the built inscription, the spend proven by the
// sequencer's prover and the program by the toy circuit, and the notes its
// program step creates.
async fn prove_step(
    built: &ProgramInscription,
    program: &ZoneProgram,
) -> Result<(Vec<StepProof>, Vec<NoteCommitment>), StepError> {
    let draft = built
        .program_steps()
        .next()
        .cloned()
        .ok_or_else(|| StepError::LogicalError {
            message: "The built inscription carries no program step".to_owned(),
        })?;
    let proving = draft.clone();
    let spend_proof = tokio::task::spawn_blocking(move || prove_program_step(&proving))
        .await
        .map_err(|error| StepError::LogicalError {
            message: format!("The spend prover task failed: {error}"),
        })?
        .map_err(|error| StepError::LogicalError {
            message: format!("The spend proof failed: {error}"),
        })?;
    let (_, proving_key) = three_input_setup(program.circuit_seed);
    let program_proof = three_input_prove(&proving_key, draft.program_inputs, program.circuit_seed);
    let program_proof = ProgramProof::new(
        CompressedGroth16Proof::try_from(&program_proof).map_err(|error| {
            StepError::LogicalError {
                message: format!("The program proof does not compress: {error:?}"),
            }
        })?,
    );
    let proofs = built
        .step_proofs(vec![(spend_proof, program_proof)])
        .map_err(|error| StepError::LogicalError {
            message: format!("The step proofs do not fit: {error}"),
        })?;
    Ok((proofs, draft.outputs.iter().map(Note::commitment).collect()))
}

// A seed of the toy circuit, stable per program alias.
fn circuit_seed(program_alias: &str) -> u64 {
    program_alias.bytes().fold(0x5eedu64, |seed, byte| {
        seed.wrapping_mul(31).wrapping_add(u64::from(byte))
    })
}
