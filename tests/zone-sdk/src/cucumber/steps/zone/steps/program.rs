use super::{
    Duration, ProgramBlockContent, Step, StepResult, ZoneWorld, deposit_into_channel,
    log_step_error, pay_into_program, publish_program_block, register_zone_program,
    wait_for_finalized_program, wait_for_finalized_program_via_sequencer,
    wait_for_observed_program, wait_for_tracked_program_notes, wait_for_wallet_note, when,
    withdraw_channel_note, zone_step_error,
};

#[when(expr = "sequencer {string} registers zone program {string}")]
async fn step_register_zone_program(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    program_alias: String,
) -> StepResult {
    register_zone_program(world, step, &sequencer_alias, program_alias).await
}

#[cucumber::then(
    expr = "sequencer {string} observes program registration {string} in {int} seconds"
)]
async fn step_sequencer_observes_program(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    program_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    let program_id = world.zone.program(&program_alias)?.info.program_id;
    let events = log_step_error(step, world.zone.sequencer_events_mut(&sequencer_alias))?;
    wait_for_observed_program(events, program_id, Duration::from_secs(timeout_seconds))
        .await
        .map_err(|error| zone_step_error(step, &error))
}

#[cucumber::then(
    expr = "sequencer {string} finalizes program registration {string} in {int} seconds"
)]
async fn step_sequencer_finalizes_program(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    program_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    let program_id = world.zone.program(&program_alias)?.info.program_id;
    let events = log_step_error(step, world.zone.sequencer_events_mut(&sequencer_alias))?;
    wait_for_finalized_program_via_sequencer(
        events,
        program_id,
        Duration::from_secs(timeout_seconds),
    )
    .await
    .map_err(|error| zone_step_error(step, &error))
}

#[cucumber::then(
    expr = "the zone indexer returns finalized program registration {string} in {int} seconds"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn step_zone_indexer_returns_finalized_program(
    world: &mut ZoneWorld,
    step: &Step,
    program_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    let program_id = world.zone.program(&program_alias)?.info.program_id;
    let indexer = log_step_error(step, world.zone.indexer())?;
    wait_for_finalized_program(indexer, program_id, Duration::from_secs(timeout_seconds))
        .await
        .map_err(|error| zone_step_error(step, &error))
}

#[when(
    expr = "wallet {string} deposits {int} LGO into the channel of sequencer {string} as {string}"
)]
async fn step_deposit_into_channel(
    world: &mut ZoneWorld,
    step: &Step,
    wallet_name: String,
    amount: u64,
    sequencer_alias: String,
    alias: String,
) -> StepResult {
    deposit_into_channel(world, step, &wallet_name, &sequencer_alias, amount, alias).await
}

#[when(
    expr = "wallet {string} pays {int} LGO of its channel notes to program {string} of sequencer {string} as step {string}"
)]
async fn step_pay_into_program(
    world: &mut ZoneWorld,
    wallet_name: String,
    amount: u64,
    program_alias: String,
    sequencer_alias: String,
    step_alias: String,
) -> StepResult {
    pay_into_program(
        world,
        &wallet_name,
        &sequencer_alias,
        amount,
        &program_alias,
        step_alias,
    )
    .await
}

#[when(
    expr = "sequencer {string} publishes zone block {string} with step {string} and a step of program {string} collecting it"
)]
async fn step_publish_collecting_block(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    block_alias: String,
    holder_step: String,
    program_alias: String,
) -> StepResult {
    publish_program_block(
        world,
        step,
        &sequencer_alias,
        block_alias,
        &program_alias,
        ProgramBlockContent::Collect { holder_step },
    )
    .await
}

#[when(
    expr = "sequencer {string} publishes zone block {string} with a step of program {string} paying its notes to wallet {string} as {string}"
)]
async fn step_publish_payout_block(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    block_alias: String,
    program_alias: String,
    wallet: String,
    payout: String,
) -> StepResult {
    publish_program_block(
        world,
        step,
        &sequencer_alias,
        block_alias,
        &program_alias,
        ProgramBlockContent::PayOut { wallet, payout },
    )
    .await
}

#[when(
    expr = "wallet {string} withdraws channel note {string} from the channel of sequencer {string} as {string}"
)]
async fn step_withdraw_channel_note(
    world: &mut ZoneWorld,
    wallet_name: String,
    note_alias: String,
    sequencer_alias: String,
    tx_alias: String,
) -> StepResult {
    withdraw_channel_note(world, &wallet_name, &sequencer_alias, &note_alias, tx_alias).await
}

#[cucumber::then(expr = "wallet {string} holds a ledger note of {int} LGO in {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn step_wallet_holds_note(
    world: &mut ZoneWorld,
    wallet_name: String,
    value: u64,
    timeout_seconds: u64,
) -> StepResult {
    wait_for_wallet_note(
        world,
        &wallet_name,
        value,
        Duration::from_secs(timeout_seconds),
    )
    .await
}

/// The program's notes the sequencer tracks are exactly the ones the block's
/// step created, each with a path against the channel's root.
#[cucumber::then(
    expr = "sequencer {string} tracks the program notes zone block {string} created in {int} seconds"
)]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn step_sequencer_tracks_program_notes(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    block_alias: String,
    timeout_seconds: u64,
) -> StepResult {
    let expected = world.zone.program_outputs(&block_alias)?.to_vec();
    let client = log_step_error(step, world.zone.sequencer_client(&sequencer_alias))?.clone();
    wait_for_tracked_program_notes(&client, &expected, Duration::from_secs(timeout_seconds)).await
}
