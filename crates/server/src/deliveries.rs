//! The retry loop of the webhook delivery queue: failed deliveries are attempted again when
//! their backoff expires, and old finished deliveries are pruned.

use std::time::Duration;

use chrono::Utc;
use nanobom_domain::{deliveries, notifications::Notifier};
use sea_orm::DatabaseConnection;

use crate::metrics;

/// How often due deliveries are looked for. The shortest backoff is one minute, so a retry
/// comes at most this late.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Deliveries attempted per tick, so that a receiver that times out (15 seconds per attempt)
/// holds a tick for about a minute at most; the others wait for the next tick.
const RETRIES_PER_TICK: u64 = 4;

/// Ticks between two prunings of old deliveries (an hour at the default interval).
const TICKS_PER_PRUNING: u32 = 120;

/// Starts the loop that retries due deliveries every `interval`.
pub fn start(
    database: DatabaseConnection,
    notifier: Notifier,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut ticks = 0_u32;
        loop {
            ticker.tick().await;
            if ticks.is_multiple_of(TICKS_PER_PRUNING) {
                prune(&database).await;
            }
            ticks = ticks.wrapping_add(1);
            match notifier.retry_due(&database, RETRIES_PER_TICK).await {
                Ok(outcomes) => metrics::record_deliveries(&outcomes),
                Err(error) => tracing::error!(%error, "retrying webhook deliveries failed"),
            }
        }
    })
}

async fn prune(database: &DatabaseConnection) {
    match deliveries::prune(database, Utc::now().fixed_offset()).await {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "old webhook deliveries deleted"),
        Err(error) => tracing::warn!(%error, "deleting old webhook deliveries failed"),
    }
}
