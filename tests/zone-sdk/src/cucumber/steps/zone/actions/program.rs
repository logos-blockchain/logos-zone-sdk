use lb_core::mantle::ops::program::ProgramRegisterOp;

use super::{
    Duration, PublishDeadline, Step, StepError, StepResult, ZoneWorld, log_step_error,
    register_program_with_retry,
};

/// Registers the node's sample program key through the sequencer and
/// remembers the registration under `program_alias`, its tx under the same
/// alias.
pub(in super::super) async fn register_zone_program(
    world: &mut ZoneWorld,
    step: &Step,
    sequencer_alias: &str,
    program_alias: String,
) -> StepResult {
    let client = log_step_error(step, world.zone.sequencer_client(sequencer_alias))?;
    let (info, checkpoint) = register_program_with_retry(
        client,
        &ProgramRegisterOp::sample().verification_key,
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
    world.zone.remember_program(program_alias, info);
    Ok(())
}
