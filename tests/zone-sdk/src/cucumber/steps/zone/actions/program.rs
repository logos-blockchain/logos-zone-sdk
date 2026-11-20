use std::collections::HashSet;

use lb_common_http_client::CommonHttpClient;
use lb_core::{
    crypto::ZkHasher,
    mantle::{
        Note, Value,
        gas::GasCost,
        note_set::NoteSetIndex,
        notes::{NoteCommitment, ProgramId},
        ops::{
            StepProof,
            channel::{ChannelId, deposit::Metadata, inscribe::Step},
        },
        programs::ProgramVerificationKey,
    },
};
use lb_groth16::{
    CompressedGroth16Proof, Fr,
    test_utils::{three_input_prove, three_input_setup},
};
use lb_http_api_common::bodies::{
    channel::{
        ChannelDepositRequestBody, ChannelDepositResponseBody, ChannelStepRequestBody,
        ChannelWithdrawRequestBody, ProgramDepositBody,
    },
    wallet::import::WalletImportNoteRequestBody,
};
use lb_key_management_system_service::keys::ZkPublicKey;
use lb_testing_framework::NodeHttpClient;
use lb_zone_sdk::{
    node_types::ProgramProof,
    sequencer::{
        Error as SequencerError, PreparedProgramInscription, ProgramOutput, ProgramStepRequest,
        StepRequest, UserOutput, prove_program_step,
    },
};
use tokio::time::{sleep, timeout};
use tracing::warn;

use super::{
    Duration, Inscription, PublishDeadline, PublishResult, SequencerClient, Step as GherkinStep,
    StepError, StepResult, ZoneWorld, ensure_zone_transactions_included, log_step_error,
    register_program_with_retry, remember_published_zone_message, zone_step_error,
};
use crate::cucumber::{steps::TARGET, zone::ZoneProgram};

/// Registers a toy program through the sequencer, its circuit seeded from
/// `program_alias`, and remembers the registration under the alias, its tx
/// under the same alias.
pub async fn register_zone_program(
    world: &mut ZoneWorld,
    step: &GherkinStep,
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

/// Deposits `amount` from `wallet_name`'s ledger notes into the channel of
/// `sequencer_alias` through the wallet's node, which funds and proves the
/// deposit. The tx is remembered under `alias`, the channel note it creates
/// too.
pub async fn deposit_into_channel(
    world: &mut ZoneWorld,
    step: &GherkinStep,
    wallet_name: &str,
    sequencer_alias: &str,
    amount: Value,
    alias: String,
) -> StepResult {
    let holder = holder_key(world, wallet_name)?;
    let node = holder_node(world, wallet_name)?;
    let channel_id = world.zone.sequencer_channel_id(sequencer_alias)?;
    let body = ChannelDepositRequestBody {
        tip: None,
        channel_id,
        amount,
        holder_public_key: holder,
        metadata: Metadata::new_unchecked(alias.clone().into_bytes()),
        change_public_key: holder,
        funding_public_keys: vec![holder],
        max_tx_fee: GasCost::new(u64::MAX),
    };
    let url = node
        .base_url()
        .join("channel/deposit")
        .map_err(|error| StepError::LogicalError {
            message: format!("Bad node url: {error}"),
        })?;
    let client = CommonHttpClient::new(None);
    let response: ChannelDepositResponseBody =
        retry_until_spendable("channel deposit", || client.post(url.clone(), &body)).await?;
    ensure_zone_transactions_included(&node, &[response.hash], Duration::from_mins(3))
        .await
        .map_err(|error| zone_step_error(step, &error))?;
    world
        .node
        .remember_submitted_transaction(alias.clone(), response.hash);
    world
        .zone
        .remember_channel_note(alias, response.holder_note);
    Ok(())
}

/// Builds a program deposit of `amount` from `wallet_name`'s channel notes
/// through the wallet's node, paying the program of `program_alias`, and
/// remembers the step with its proof under `step_alias` for a zone block to
/// carry.
pub async fn pay_into_program(
    world: &mut ZoneWorld,
    wallet_name: &str,
    sequencer_alias: &str,
    amount: Value,
    program_alias: &str,
    step_alias: String,
) -> StepResult {
    let holder = holder_key(world, wallet_name)?;
    let node = holder_node(world, wallet_name)?;
    let channel_id = world.zone.sequencer_channel_id(sequencer_alias)?;
    let program_id = world.zone.program(program_alias)?.info.program_id;
    let body = || ChannelStepRequestBody {
        tip: None,
        channel_id,
        appended: Vec::new(),
        payments: Vec::new(),
        program_deposit: Some(ProgramDepositBody {
            program_id,
            value: amount,
            intent: Fr::from(1u64),
        }),
        inscription: Inscription::new_unchecked(step_alias.clone().into_bytes()),
        change_public_key: holder,
        holder_public_keys: vec![holder],
    };
    let response = retry_until_spendable("program deposit", || node.channel_step(body())).await?;
    world.zone.remember_user_step(
        step_alias,
        response.step,
        StepProof::ZkTransfer(response.proof),
    );
    Ok(())
}

/// What the program step of a zone block does.
pub enum ProgramBlockContent {
    /// Collects the program deposit of the user step published before it
    /// into one note of the program.
    Collect { user_step: String },
    /// Consumes every note of the program the sequencer tracks and pays
    /// their value to `wallet`, whose node imports the note before the block
    /// is submitted; the note is remembered under `payout`.
    PayOut { wallet: String, payout: String },
}

/// Publishes a zone block carrying one step of `program_alias`'s program with
/// `content`. The sequencer builds and proves the spend, the toy circuit
/// proves the program. The block is remembered under `block_alias` with the
/// program notes its step created.
pub async fn publish_program_block(
    world: &mut ZoneWorld,
    step: &GherkinStep,
    sequencer_alias: &str,
    block_alias: String,
    program_alias: &str,
    content: ProgramBlockContent,
) -> StepResult {
    let program = world.zone.program(program_alias)?.clone();
    let client = log_step_error(step, world.zone.sequencer_client(sequencer_alias))?.clone();
    let node = log_step_error(
        step,
        world.zone_node_http_client_for_sequencer(sequencer_alias),
    )?;
    let channel_id = world.zone.sequencer_channel_id(sequencer_alias)?;
    let payload = Inscription::new_unchecked(block_alias.clone().into_bytes());
    let plan = match &content {
        ProgramBlockContent::Collect { user_step } => {
            let (step, proof) = world.zone.user_step(user_step)?;
            BlockPlan::Collect { step, proof }
        }
        ProgramBlockContent::PayOut { wallet, .. } => BlockPlan::PayOut {
            payee: holder_key(world, wallet)?,
            payee_node: holder_node(world, wallet)?,
            channel_id,
        },
    };
    let (result, created, payouts) = publish_program_block_with_retry(
        &client,
        &payload,
        &program,
        &plan,
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
    if let ProgramBlockContent::PayOut { payout, .. } = content {
        let note = payouts
            .first()
            .copied()
            .ok_or_else(|| StepError::LogicalError {
                message: "The payout step paid no note".to_owned(),
            })?;
        world.zone.remember_channel_note(payout, note);
    }
    Ok(())
}

/// Withdraws the channel note `note_alias` of `wallet_name` through the
/// wallet's node and remembers the tx under `tx_alias`.
pub async fn withdraw_channel_note(
    world: &mut ZoneWorld,
    wallet_name: &str,
    sequencer_alias: &str,
    note_alias: &str,
    tx_alias: String,
) -> StepResult {
    let holder = holder_key(world, wallet_name)?;
    let node = holder_node(world, wallet_name)?;
    let channel_id = world.zone.sequencer_channel_id(sequencer_alias)?;
    let note = world.zone.channel_note(note_alias)?;
    let body = || ChannelWithdrawRequestBody {
        tip: None,
        channel_id,
        notes: vec![note.commitment()],
        change_public_key: holder,
        funding_public_keys: vec![holder],
        max_tx_fee: GasCost::new(u64::MAX),
    };
    let response =
        retry_until_spendable("channel withdrawal", || node.channel_withdraw(body())).await?;
    world
        .node
        .remember_submitted_transaction(tx_alias, response.hash);
    Ok(())
}

/// Waits until the ledger notes of `wallet_name` include one worth `value`.
pub async fn wait_for_wallet_note(
    world: &ZoneWorld,
    wallet_name: &str,
    value: Value,
    duration: Duration,
) -> StepResult {
    let holder = holder_key(world, wallet_name)?;
    let node = holder_node(world, wallet_name)?;
    timeout(duration, async {
        loop {
            match node.wallet_balance(holder, None).await {
                Ok(balance) if balance.notes.values().any(|note| *note == value) => return,
                Ok(_) => {}
                Err(error) => {
                    warn!(target: TARGET, "Wallet balance request failed, retrying: {error}");
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| StepError::LogicalError {
        message: format!("Timed out waiting for wallet '{wallet_name}' to hold a note of {value}"),
    })
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

// The program step of a block, resolved from the world.
#[expect(
    clippy::large_enum_variant,
    reason = "a user's step is carried with its proof as given"
)]
enum BlockPlan {
    Collect {
        step: Step,
        proof: StepProof,
    },
    PayOut {
        payee: ZkPublicKey,
        payee_node: NodeHttpClient,
        channel_id: ChannelId,
    },
}

// Builds, proves and submits the block until it lands in the pending set: a
// note the sequencer tracks becomes spendable a few blocks after its
// creation, and the publish tip may move under a built inscription. Returns
// the publish result, the program notes created and the user notes paid.
async fn publish_program_block_with_retry(
    client: &SequencerClient,
    payload: &Inscription,
    program: &ZoneProgram,
    plan: &BlockPlan,
    deadline: PublishDeadline,
) -> Result<(PublishResult, Vec<NoteCommitment>, Vec<Note>), StepError> {
    loop {
        if deadline.is_expired() {
            return Err(StepError::LogicalError {
                message: "Timed out publishing a program step".to_owned(),
            });
        }
        if let Some(published) = try_publish_program_block(client, payload, program, plan).await? {
            return Ok(published);
        }
        sleep(Duration::from_millis(500)).await;
    }
}

// One attempt at the block; `None` when it is to be tried again.
async fn try_publish_program_block(
    client: &SequencerClient,
    payload: &Inscription,
    program: &ZoneProgram,
    plan: &BlockPlan,
) -> Result<Option<(PublishResult, Vec<NoteCommitment>, Vec<Note>)>, StepError> {
    let program_id = program.info.program_id;
    let mini_block = match plan {
        BlockPlan::Collect { step, proof } => {
            let Step::ProgramDeposit(deposit) = step else {
                return Err(StepError::LogicalError {
                    message: "The user step to collect is not a program deposit".to_owned(),
                });
            };
            vec![
                StepRequest::User {
                    step: step.clone(),
                    proof: proof.clone(),
                },
                StepRequest::Program(program_step(
                    program,
                    payload,
                    Vec::new(),
                    vec![program_note(program, deposit.value)],
                    Vec::new(),
                )),
            ]
        }
        BlockPlan::PayOut { payee, .. } => {
            let inputs = tracked_inputs(client, program_id).await?;
            if inputs.is_empty() {
                return Ok(None);
            }
            let value = inputs.iter().map(|(_, value)| value).sum();
            vec![StepRequest::Program(program_step(
                program,
                payload,
                inputs
                    .into_iter()
                    .map(|(commitment, _)| commitment)
                    .collect(),
                Vec::new(),
                vec![UserOutput {
                    public_key: *payee,
                    stake_public_key: *payee,
                    value,
                    nonce: None,
                }],
            ))]
        }
    };
    let Some(built) = prepare_built(client, payload, mini_block).await else {
        return Ok(None);
    };
    let (proofs, created, paid) = prove_block(&built, program).await?;
    // A payee's wallet adopts a note it knows the opening of when the note
    // is appended, so it learns the payout before the block lands.
    if let BlockPlan::PayOut {
        payee_node,
        channel_id,
        ..
    } = plan
    {
        for note in &paid {
            import_channel_note(payee_node, *channel_id, *note).await?;
        }
    }
    Ok(submit_built(client, &built, proofs)
        .await
        .map(|result| (result, created, paid)))
}

// The program notes of the program the sequencer tracks, with their values.
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

// A note of the program worth `value`, with a nonce of the program's choosing:
// the collecting step consumes nothing, so the spend fixes none.
fn program_note(program: &ZoneProgram, value: Value) -> ProgramOutput {
    ProgramOutput {
        value,
        stake_public_key: ZkPublicKey::new(Fr::from(program.circuit_seed)),
        data: Fr::from(value),
        nonce: Some(Fr::from(program.circuit_seed ^ value)),
    }
}

fn program_step(
    program: &ZoneProgram,
    payload: &Inscription,
    inputs: Vec<NoteCommitment>,
    program_outputs: Vec<ProgramOutput>,
    outputs: Vec<UserOutput>,
) -> ProgramStepRequest {
    ProgramStepRequest {
        program_id: program.info.program_id,
        inputs,
        program_outputs,
        outputs,
        inscription: payload.clone(),
    }
}

// The inscription built on the sequencer's current state; `None` when it
// refuses the step for now, such as a note not yet deep enough to spend.
async fn prepare_built(
    client: &SequencerClient,
    payload: &Inscription,
    mini_block: Vec<StepRequest>,
) -> Option<PreparedProgramInscription> {
    client
        .prepare_program_inscription(payload.clone(), vec![mini_block])
        .await
        .inspect_err(|error| {
            warn!(target: TARGET, "Zone prepare_program_inscription failed, retrying: {error}");
        })
        .ok()
}

// The step proofs of the built inscription, the spend proven by the
// sequencer's prover and the program by the toy circuit, with the program
// notes and the user notes its program step creates.
async fn prove_block(
    built: &PreparedProgramInscription,
    program: &ZoneProgram,
) -> Result<(Vec<StepProof>, Vec<NoteCommitment>, Vec<Note>), StepError> {
    let prepared =
        built
            .program_steps()
            .next()
            .cloned()
            .ok_or_else(|| StepError::LogicalError {
                message: "The built inscription carries no program step".to_owned(),
            })?;
    let proving = prepared.clone();
    let spend_proof = tokio::task::spawn_blocking(move || prove_program_step(&proving))
        .await
        .map_err(|error| StepError::LogicalError {
            message: format!("The spend prover task failed: {error}"),
        })?
        .map_err(|error| StepError::LogicalError {
            message: format!("The spend proof failed: {error}"),
        })?;
    let (_, proving_key) = three_input_setup(program.circuit_seed);
    let program_proof =
        three_input_prove(&proving_key, prepared.program_inputs, program.circuit_seed);
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
    let program_notes = prepared.program_notes.len();
    let created = prepared.outputs[..program_notes]
        .iter()
        .map(Note::commitment)
        .collect();
    let paid = prepared.outputs[program_notes..].to_vec();
    Ok((proofs, created, paid))
}

// The built inscription submitted with its proofs; `None` when the publish
// tip moved under it or the submission failed, to rebuild.
async fn submit_built(
    client: &SequencerClient,
    built: &PreparedProgramInscription,
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

// Registers the opening of a channel note with the wallet of `node`.
async fn import_channel_note(
    node: &NodeHttpClient,
    channel_id: ChannelId,
    note: Note,
) -> Result<(), StepError> {
    CommonHttpClient::new(None)
        .import_note(
            node.base_url().clone(),
            WalletImportNoteRequestBody {
                note,
                note_set: NoteSetIndex::Channel(channel_id),
            },
        )
        .await
        .map_err(|error| StepError::LogicalError {
            message: format!("Importing the payout note failed: {error}"),
        })
}

// Retries a node request until the wallet can spend the notes it needs,
// which takes a few blocks after they land.
async fn retry_until_spendable<Response, Request>(
    label: &str,
    request: impl Fn() -> Request + Send + Sync,
) -> Result<Response, StepError>
where
    Response: Send,
    Request: Future<Output = Result<Response, lb_common_http_client::Error>> + Send,
{
    let mut last_error = None;
    timeout(Duration::from_mins(3), async {
        loop {
            match request().await {
                Ok(response) => return response,
                Err(error) => last_error = Some(error),
            }
            sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| StepError::LogicalError {
        message: format!(
            "Timed out waiting for the {label} to succeed, last error: {last_error:?}"
        ),
    })
}

fn holder_key(world: &ZoneWorld, wallet_name: &str) -> Result<ZkPublicKey, StepError> {
    world.node.resolve_wallet(wallet_name)?.public_key()
}

fn holder_node(world: &ZoneWorld, wallet_name: &str) -> Result<NodeHttpClient, StepError> {
    let node_name = world.node.resolve_wallet_node_name(wallet_name)?;
    world.node.resolve_node_http_client(&node_name)
}

// A seed of the toy circuit, stable per program alias.
fn circuit_seed(program_alias: &str) -> u64 {
    program_alias.bytes().fold(0x5eedu64, |seed, byte| {
        seed.wrapping_mul(31).wrapping_add(u64::from(byte))
    })
}
