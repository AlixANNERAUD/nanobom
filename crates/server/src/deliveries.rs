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
            let pruning = ticks.is_multiple_of(TICKS_PER_PRUNING);
            ticks = ticks.wrapping_add(1);
            // In a task of its own, so that a panic ends this tick only and the loop goes on.
            let (database, notifier) = (database.clone(), notifier.clone());
            let pass = tokio::spawn(async move { tick(&database, &notifier, pruning).await });
            match pass.await {
                Ok(()) => {}
                Err(error) if error.is_panic() => {
                    tracing::error!(%error, "retrying webhook deliveries panicked; the loop continues");
                }
                Err(error) => tracing::warn!(%error, "retrying webhook deliveries was cancelled"),
            }
        }
    })
}

/// One pass of the loop: prunes when asked, then attempts the due deliveries.
async fn tick(database: &DatabaseConnection, notifier: &Notifier, pruning: bool) {
    if pruning {
        prune(database).await;
    }
    match notifier.retry_due(database, RETRIES_PER_TICK).await {
        Ok(outcomes) => metrics::record_deliveries(&outcomes),
        Err(error) => tracing::error!(%error, "retrying webhook deliveries failed"),
    }
}

async fn prune(database: &DatabaseConnection) {
    match deliveries::prune(database, Utc::now().fixed_offset()).await {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "old webhook deliveries deleted"),
        Err(error) => tracing::warn!(%error, "deleting old webhook deliveries failed"),
    }
}
