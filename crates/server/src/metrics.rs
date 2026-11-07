//! Prometheus metrics. Labels stay instance-wide (no organization or project) to keep their
//! number small.

use std::{sync::OnceLock, time::Duration};

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use nanobom_domain::{evaluation::RunOutcome, findings};
use nanobom_entity::runs;
use nanobom_osv::Severity;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// The recorder, installed on first use.
pub fn handle() -> &'static PrometheusHandle {
    HANDLE.get_or_init(|| {
        let handle = PrometheusBuilder::new()
            .set_buckets_for_metric(
                Matcher::Full("nanobom_run_duration_seconds".to_owned()),
                &[1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0],
            )
            .expect("buckets are not empty")
            .install_recorder()
            .expect("no other metrics recorder is installed");
        describe();
        let upkeep = handle.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    upkeep.run_upkeep();
                }
            });
        }
        handle
    })
}

fn describe() {
    describe_gauge!(
        "nanobom_open_findings",
        "Open findings across the instance, by severity"
    );
    describe_gauge!(
        "nanobom_last_successful_run_timestamp_seconds",
        "Unix time at which the last successful run started"
    );
    describe_histogram!(
        "nanobom_run_duration_seconds",
        metrics::Unit::Seconds,
        "Duration of runs"
    );
    describe_counter!("nanobom_runs_total", "Runs, by status");
    describe_counter!("nanobom_run_failures_total", "Runs that could not complete");
    describe_counter!(
        "nanobom_osv_request_errors_total",
        "Failed requests to OSV, by kind, retries included"
    );
}

/// Records a finished run.
pub fn record_run(outcome: &RunOutcome) {
    handle();
    histogram!("nanobom_run_duration_seconds").record(outcome.duration_seconds);
    if outcome.succeeded() {
        counter!("nanobom_runs_total", "status" => "succeeded").increment(1);
        #[allow(clippy::cast_precision_loss)]
        gauge!("nanobom_last_successful_run_timestamp_seconds")
            .set(outcome.started_at.timestamp() as f64);
    } else {
        record_failed_run();
    }
}

pub fn record_failed_run() {
    handle();
    counter!("nanobom_runs_total", "status" => "failed").increment(1);
    counter!("nanobom_run_failures_total").increment(1);
}

/// Updates the open findings gauges from the database.
pub async fn refresh_open_findings(database: &DatabaseConnection) {
    handle();
    match findings::open_counts(database).await {
        Ok(counts) => {
            for severity in Severity::DESCENDING {
                #[allow(clippy::cast_precision_loss)]
                gauge!("nanobom_open_findings", "severity" => severity.as_str())
                    .set(counts.get(severity) as f64);
            }
        }
        Err(error) => tracing::warn!(%error, "counting open findings failed"),
    }
}

/// Sets the gauges from the database at startup.
pub async fn initialize(database: &DatabaseConnection) {
    refresh_open_findings(database).await;
    match runs::Entity::find()
        .filter(runs::Column::Status.eq("succeeded"))
        .order_by_desc(runs::Column::StartedAt)
        .one(database)
        .await
    {
        Ok(Some(run)) => {
            #[allow(clippy::cast_precision_loss)]
            gauge!("nanobom_last_successful_run_timestamp_seconds")
                .set(run.started_at.timestamp() as f64);
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "reading the last run failed"),
    }
}
