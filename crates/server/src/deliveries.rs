//! The retry loop of the delivery queue (webhooks and emails): failed deliveries are attempted
//! again when their backoff expires, and old finished deliveries are pruned.
//!
//! First attempts are made by the run worker right after a run; this loop only picks up what
//! is due afterwards (retries, and deliveries whose first attempt a restart cut short). It
//! attempts a few deliveries per tick, one after the other, so a receiver that hangs delays the
//! queue by a tick rather than blocking it. Attempts claim their row first
//! ([`deliveries::claim`]), so the loop and the worker never post the same delivery at once.

use std::time::Duration;

use chrono::Utc;
use nanobom_domain::{deliveries, notifications::Notifier};
use reqwest::Url;
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
                    tracing::error!(%error, "retrying deliveries panicked; the loop continues");
                }
                Err(error) => tracing::warn!(%error, "retrying deliveries was cancelled"),
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
        Err(error) => tracing::error!(%error, "retrying deliveries failed"),
    }
}

/// Abandons the pending emails when the instance has no SMTP server any more
/// (`NANOBOM_SMTP_URL` removed): nothing could send them. Call it at startup.
pub async fn cancel_unsendable_emails(database: &DatabaseConnection, email: bool) {
    if email {
        return;
    }
    match deliveries::cancel_pending_emails(database).await {
        Ok(0) => {}
        Ok(count) => tracing::info!(
            count,
            "pending emails abandoned: no SMTP server is configured"
        ),
        Err(error) => tracing::warn!(%error, "abandoning pending emails failed"),
    }
}

/// Abandons the pending deliveries to a failure webhook address that is not the configured one
/// any more (`NANOBOM_FAILURE_WEBHOOK_URL` changed or removed). Call it at startup.
pub async fn cancel_outdated_failures(
    database: &DatabaseConnection,
    failure_webhook: Option<&Url>,
) {
    let url = failure_webhook.map(Url::as_str);
    match deliveries::cancel_pending_failures(database, url).await {
        Ok(0) => {}
        Ok(count) => tracing::info!(
            count,
            "pending deliveries to a former failure webhook address abandoned"
        ),
        Err(error) => tracing::warn!(%error, "abandoning outdated failure deliveries failed"),
    }
}

async fn prune(database: &DatabaseConnection) {
    match deliveries::prune(database, Utc::now().fixed_offset()).await {
        Ok(0) => {}
        Ok(count) => tracing::info!(count, "old deliveries deleted"),
        Err(error) => tracing::warn!(%error, "deleting old deliveries failed"),
    }
}
