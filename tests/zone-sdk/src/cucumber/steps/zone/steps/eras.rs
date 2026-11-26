use lb_http_api_common::TimeInfo;
use tokio::time::Instant;

use super::{Duration, Step, StepError, StepResult, ZoneWorld, when};

/// Waits until the node's clock is within `slots` of the first slot of the
/// last scheduled era, so that what the scenario submits next is pending
/// when the era changes. Fails if the boundary has already passed.
#[when(expr = "node {string} is {int} slots before the era boundary in {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn step_node_is_slots_before_the_era_boundary(
    world: &mut ZoneWorld,
    step: &Step,
    node_name: String,
    slots: u64,
    timeout_seconds: u64,
) -> StepResult {
    wait_for_slots_before_the_boundary(world, step, &node_name, slots, timeout_seconds).await?;
    Ok(())
}

/// Waits until the node's clock is halfway through the last slot of the era
/// before the last scheduled one. A block of a slot is built at the slot's
/// tick, so what the scenario submits next is funded under the old era yet
/// no block of it can carry it: the first block of the new era refuses it.
#[when(expr = "node {string} is in the last slot before the era boundary in {int} seconds")]
#[expect(
    clippy::needless_pass_by_ref_mut,
    reason = "Cucumber step functions require `&mut World` as the first parameter"
)]
async fn step_node_is_in_the_last_slot_before_the_era_boundary(
    world: &mut ZoneWorld,
    step: &Step,
    node_name: String,
    timeout_seconds: u64,
) -> StepResult {
    let slot_duration =
        wait_for_slots_before_the_boundary(world, step, &node_name, 1, timeout_seconds).await?;
    tokio::time::sleep(slot_duration / 2).await;
    Ok(())
}

/// Polls the node until its slot is within `slots` of the boundary; returns
/// the slot duration of the era before it.
async fn wait_for_slots_before_the_boundary(
    world: &ZoneWorld,
    step: &Step,
    node_name: &str,
    slots: u64,
    timeout_seconds: u64,
) -> Result<Duration, StepError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let client = world.node.resolve_node_http_client(node_name)?;
    loop {
        let time = tokio::time::timeout_at(deadline, client.time_info())
            .await
            .map_err(|_| StepError::Timeout {
                message: format!(
                    "Step `{}`: node '{node_name}' time query exceeded {timeout_seconds}s",
                    step.value
                ),
            })?
            .map_err(|error| StepError::StepFail {
                message: format!(
                    "Step `{}` error: node '{node_name}' time query failed: {error}",
                    step.value
                ),
            })?;
        let boundary = last_era_first_slot(&time).ok_or_else(|| StepError::LogicalError {
            message: format!("node '{node_name}' reports no era after the genesis era"),
        })?;
        let current = time.current_slot;
        if current >= boundary {
            return Err(StepError::LogicalError {
                message: format!(
                    "node '{node_name}' is at slot {current}, past the era boundary at slot {boundary}"
                ),
            });
        }
        if current + slots >= boundary {
            return time
                .era_timings
                .values()
                .next()
                .map(|timing| timing.slot_duration)
                .ok_or_else(|| StepError::LogicalError {
                    message: format!("node '{node_name}' reports no era timing"),
                });
        }
        if Instant::now() >= deadline {
            return Err(StepError::Timeout {
                message: format!(
                    "node '{node_name}' did not reach {slots} slots before the era boundary at \
                     slot {boundary} within {timeout_seconds}s; last slot {current}"
                ),
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The first slot of the last era the node reports: each era runs from its
/// first epoch to the next era's at its own epoch length. `None` for a chain
/// of one era.
fn last_era_first_slot(time: &TimeInfo) -> Option<u64> {
    let eras: Vec<_> = time.era_timings.iter().collect();
    let (before_last, _) = eras.split_at(eras.len().checked_sub(1)?);
    if before_last.is_empty() {
        return None;
    }
    let first_slot = before_last
        .iter()
        .zip(eras.iter().skip(1))
        .map(|(era, next)| {
            let (first_epoch, timing) = *era;
            let (next_epoch, _) = *next;
            u64::from(next_epoch - first_epoch) * timing.slots_per_epoch.get()
        })
        .sum();
    Some(first_slot)
}
