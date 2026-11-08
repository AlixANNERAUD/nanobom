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
    exploitation::{self, Feeds},
    notifications::{self, Notifier},
};
use nanobom_osv::VulnerabilitySource;
use reqwest::Url;
use sea_orm::DatabaseConnection;
use tokio::sync::{Notify, oneshot};

use crate::metrics;

/// A run to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunRequest {
    pub trigger: Trigger,
    pub scope: Scope,
    pub triggered_by: Option<i64>,
}

/// Longest time the exploitation data is refreshed for after a run, while uploads wait.
pub const EXPLOITATION_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);

/// Where notifications go, and how long the work after a run may hold waiting uploads.
#[derive(Debug, Clone)]
pub struct NotificationSettings {
    pub public_url: Url,
    pub failure_webhook: Option<Url>,
    /// Days without an SBOM after which a project is stale (0: never).
    pub stale_after_days: u32,
    /// Longest refresh of the exploitation data after a run (`EXPLOITATION_REFRESH_TIMEOUT`);
    /// a refresh taking longer is abandoned and counts as failed.
    pub exploitation_refresh_timeout: Duration,
}

/// A request waiting in the queue, with whoever waits for its outcome.
struct Queued {
    request: RunRequest,
    waiters: Vec<oneshot::Sender<RunOutcome>>,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<VecDeque<Queued>>,
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
        feeds: Option<Arc<Feeds>>,
    ) -> Self {
        let runner = Self::default();
        let shared = Arc::clone(&runner.shared);
        tokio::spawn(async move {
            loop {
                let next = shared.queue.lock().expect("not poisoned").pop_front();
                let Some(Queued { request, waiters }) = next else {
                    shared.wake.notified().await;
                    continue;
                };
                match evaluator
                    .run(request.trigger, request.scope, request.triggered_by)
                    .await
                {
                    Ok(outcome) => {
                        // The exploitation data comes before the waiters: an upload waiting
                        // with `fail_on=exploited` needs the CVEs first seen in this run.
                        record(&database, &settings, feeds.as_deref(), &outcome).await;
                        for waiter in waiters {
                            // A waiter that gave up has dropped its receiver.
                            let _ = waiter.send(outcome.clone());
                        }
                        // Gauges and webhooks can be slow; nobody waits for them.
                        notify(&database, &notifier, &settings, &outcome).await;
                    }
                    // Dropping the waiters releases them without an outcome.
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
        if merge(&mut queue, request).is_some() {
            return false;
        }
        queue.push_back(Queued {
            request,
            waiters: Vec::new(),
        });
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        drop(queue);
        self.shared.wake.notify_one();
        true
    }

    /// Queues a run and waits for the outcome of a run of its scope that starts after this
    /// call: the request merges with a waiting request of the same scope, while a run of that
    /// scope already in progress does not count (it is not in the queue), so the request is
    /// queued anew behind it. Returns `None` when `timeout` elapses first, or when the run could
    /// not be recorded; the run itself still happens.
    pub async fn request_and_wait(
        &self,
        request: RunRequest,
        timeout: Duration,
    ) -> Option<RunOutcome> {
        let (sender, receiver) = oneshot::channel();
        let queued_anew = {
            let mut queue = self.shared.queue.lock().expect("not poisoned");
            match merge(&mut queue, request) {
                Some(queued) => {
                    queued.waiters.push(sender);
                    false
                }
                None => {
                    queue.push_back(Queued {
                        request,
                        waiters: vec![sender],
                    });
                    self.shared.pending.fetch_add(1, Ordering::SeqCst);
                    true
                }
            }
        };
        if queued_anew {
            self.shared.wake.notify_one();
        }
        tokio::time::timeout(timeout, receiver).await.ok()?.ok()
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

/// Merges a request into a waiting request of the same scope, returned, if there is one. A
/// scheduled request makes the waiting one scheduled, so that the notifications only scheduled
/// runs send (stale projects) are not lost to a manual request queued just before.
fn merge(queue: &mut VecDeque<Queued>, request: RunRequest) -> Option<&mut Queued> {
    let queued = queue
        .iter_mut()
        .find(|queued| queued.request.scope == request.scope)?;
    if request.trigger == Trigger::Scheduled {
        queued.request.trigger = Trigger::Scheduled;
        queued.request.triggered_by = None;
    }
    Some(queued)
}

/// What a waiting upload needs after a run: the run's metric and, when the run succeeded, the
/// exploitation data of its scope, refreshed within `settings.exploitation_refresh_timeout`.
async fn record(
    database: &DatabaseConnection,
    settings: &NotificationSettings,
    feeds: Option<&Feeds>,
    outcome: &RunOutcome,
) {
    metrics::record_run(outcome);
    let Some(feeds) = feeds.filter(|_| outcome.succeeded()) else {
        return;
    };
    let refresh = exploitation::refresh(database, feeds, outcome.scope);
    match tokio::time::timeout(settings.exploitation_refresh_timeout, refresh).await {
        Ok(Ok(summary)) => tracing::info!(
            cves = summary.cves,
            known_exploited = summary.known_exploited,
            "exploitation data refreshed"
        ),
        Ok(Err(error)) => {
            tracing::warn!(%error, "refreshing exploitation data failed");
            metrics::record_exploitation_refresh_failure();
        }
        Err(_) => {
            tracing::warn!(
                seconds = settings.exploitation_refresh_timeout.as_secs(),
                "refreshing exploitation data took too long; the previous data is kept"
            );
            metrics::record_exploitation_refresh_failure();
        }
    }
}

/// Instance-wide gauges and notifications after a run, once its waiters are answered.
async fn notify(
    database: &DatabaseConnection,
    notifier: &Notifier,
    settings: &NotificationSettings,
    outcome: &RunOutcome,
) {
    metrics::refresh_open_findings(database).await;
    metrics::refresh_known_exploited(database).await;
    metrics::refresh_stale_projects(database, settings.stale_after_days).await;
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
        if outcome.trigger == Trigger::Scheduled {
            match notifications::stale_deliveries(
                database,
                settings.stale_after_days,
                &settings.public_url,
            )
            .await
            {
                Ok(deliveries) => {
                    if let Err(error) = notifier.deliver(database, deliveries).await {
                        tracing::error!(%error, "recording webhook deliveries failed");
                    }
                }
                Err(error) => tracing::error!(%error, "preparing stale project deliveries failed"),
            }
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
