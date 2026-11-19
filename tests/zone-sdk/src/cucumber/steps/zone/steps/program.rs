use super::{
    Duration, Step, StepResult, ZoneWorld, log_step_error, publish_program_step,
    register_zone_program, wait_for_finalized_program, wait_for_finalized_program_via_sequencer,
    wait_for_observed_program, wait_for_tracked_program_notes, when, zone_step_error,
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
    expr = "sequencer {string} publishes zone block {string} with a step of program {string} creating a note"
)]
async fn step_publish_program_step_creating(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    block_alias: String,
    program_alias: String,
) -> StepResult {
    publish_program_step(
        world,
        step,
        &sequencer_alias,
        block_alias,
        &program_alias,
        false,
    )
    .await
}

#[when(
    expr = "sequencer {string} publishes zone block {string} with a step of program {string} consuming its notes"
)]
async fn step_publish_program_step_consuming(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: String,
    block_alias: String,
    program_alias: String,
) -> StepResult {
    publish_program_step(
        world,
        step,
        &sequencer_alias,
        block_alias,
        &program_alias,
        true,
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
