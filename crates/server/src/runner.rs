//! The run queue: runs requested by the schedule, by users or after uploads execute one at a
//! time in the background, then notifications are sent and metrics updated.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use croner::Cron;
use nanobom_domain::{
    evaluation::{Evaluator, RunOutcome, Scope, Trigger},
    notifications::{self, Notifier},
};
use nanobom_osv::VulnerabilitySource;
use reqwest::Url;
use sea_orm::DatabaseConnection;
use tokio::sync::Notify;

use crate::metrics;

/// A run to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunRequest {
    pub trigger: Trigger,
    pub scope: Scope,
    pub triggered_by: Option<i64>,
}

/// Where notifications go.
#[derive(Debug, Clone)]
pub struct NotificationSettings {
    pub public_url: Url,
    pub failure_webhook: Option<Url>,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<RunRequest>>,
    /// Requests queued or running.
    pending: AtomicUsize,
    wake: Notify,
    idle: Notify,
}

/// A handle to the run queue.
#[derive(Clone, Default)]
pub struct Runner {
    shared: Arc<Shared>,
}

impl Runner {
    /// Starts the worker that executes requested runs.
    pub fn start<S: VulnerabilitySource + 'static>(
        database: DatabaseConnection,
        evaluator: Arc<Evaluator<S>>,
        notifier: Notifier,
        settings: NotificationSettings,
    ) -> Self {
        let runner = Self::default();
        let shared = Arc::clone(&runner.shared);
        tokio::spawn(async move {
            loop {
                let next = shared.queue.lock().expect("not poisoned").pop_front();
                let Some(request) = next else {
                    shared.wake.notified().await;
                    continue;
                };
                match evaluator
                    .run(request.trigger, request.scope, request.triggered_by)
                    .await
                {
                    Ok(outcome) => {
                        finish(&database, &notifier, &settings, &outcome).await;
                    }
                    Err(error) => {
                        tracing::error!(%error, "the run could not be recorded");
                        metrics::record_failed_run();
                    }
                }
                if shared.pending.fetch_sub(1, Ordering::SeqCst) == 1 {
                    shared.idle.notify_waiters();
                }
            }
        });
        runner
    }

    /// Queues a run. A request for a scope that is already waiting is merged with it.
    pub fn request(&self, request: RunRequest) -> bool {
        let mut queue = self.shared.queue.lock().expect("not poisoned");
        if queue.iter().any(|queued| queued.scope == request.scope) {
            return false;
        }
        queue.push_back(request);
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        drop(queue);
        self.shared.wake.notify_one();
        true
    }

    /// Waits until every queued run has finished.
    pub async fn wait_until_idle(&self) {
        loop {
            let idle = self.shared.idle.notified();
            if self.shared.pending.load(Ordering::SeqCst) == 0 {
                return;
            }
            idle.await;
        }
    }
}

/// Notifications and metrics after a run.
async fn finish(
    database: &DatabaseConnection,
    notifier: &Notifier,
    settings: &NotificationSettings,
    outcome: &RunOutcome,
) {
    metrics::record_run(outcome);
    metrics::refresh_open_findings(database).await;
    if outcome.succeeded() {
        match notifications::new_findings_deliveries(database, outcome, &settings.public_url).await
        {
            Ok(deliveries) => {
                if let Err(error) = notifier.deliver(database, deliveries).await {
                    tracing::error!(%error, "recording webhook deliveries failed");
                }
            }
            Err(error) => tracing::error!(%error, "preparing webhook deliveries failed"),
        }
    } else if let (Some(url), Some(payload)) = (
        &settings.failure_webhook,
        notifications::run_failed_payload(outcome, &settings.public_url),
    ) {
        match notifier.post(url.as_str(), &payload).await {
            Ok(_) => tracing::info!(run = outcome.run_id, "failure webhook delivered"),
            Err(error) => tracing::error!(%error, "failure webhook delivery failed"),
        }
    }
}

/// Parses the schedule: a cron expression, or `off`.
pub fn parse_schedule(schedule: &str) -> Result<Option<Cron>, String> {
    let schedule = schedule.trim();
    if schedule.eq_ignore_ascii_case("off") || schedule.is_empty() {
        return Ok(None);
    }
    schedule
        .parse::<Cron>()
        .map(Some)
        .map_err(|error| format!("invalid NANOBOM_SCHEDULE {schedule:?}: {error}"))
}

/// Requests a run of every project at each occurrence of the schedule (UTC).
pub fn start_schedule(runner: Runner, schedule: Cron) {
    tokio::spawn(async move {
        loop {
            let now = Utc::now();
            let next = match schedule.find_next_occurrence(&now, false) {
                Ok(next) => next,
                Err(error) => {
                    tracing::error!(%error, "the schedule has no next occurrence; scheduled runs stop");
                    return;
                }
            };
            tracing::info!(next = %next.to_rfc3339(), "next scheduled run");
            let delay = (next - now).to_std().unwrap_or(Duration::ZERO);
            tokio::time::sleep(delay).await;
            runner.request(RunRequest {
                trigger: Trigger::Scheduled,
                scope: Scope::All,
                triggered_by: None,
            });
        }
    });
}
