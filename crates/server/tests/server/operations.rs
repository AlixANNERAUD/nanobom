//! Runs started by uploads, failure notifications, health and metrics.

use crate::common::{
    TestServer, body_json, body_text, sbom_document, server, server_with_exploitation, user,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use nanobom::{
    deliveries, healthcheck,
    runner::{self, NotificationSettings, RunRequest, Waited},
};
use nanobom_domain::{
    access::Actor,
    evaluation::{self, Scope, Trigger},
    findings::{self, Filter},
    notifications::{self, Notifier},
    organizations, projects, tokens,
};
use nanobom_entity::{exploitation, runs, webhook_deliveries};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait};
use serde_json::json;
use std::{
    task::{Context, Waker},
    time::Duration,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn lodash_advisory() -> serde_json::Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

#[tokio::test]
async fn uploads_start_a_run_of_their_project() {
    let server = server(&[]).await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    server.runner.wait_until_idle().await;

    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let findings = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].vulnerability_id, "GHSA-35jh-r3h4-6jhm");
}

/// Uploads the lodash SBOM to a new organization and waits for the run it starts; returns the
/// organization's owner and identifier.
async fn upload_lodash(server: &TestServer) -> (Actor, i64) {
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    server.runner.wait_until_idle().await;
    (owner, organization.id)
}

#[tokio::test]
async fn runs_refresh_exploitation_data() {
    let feeds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"vulnerabilities": [
                {"cveID": "CVE-2021-23337", "dateAdded": "2022-03-01", "dueDate": "2022-03-22",
                 "knownRansomwareCampaignUse": "Unknown"}
            ]})),
        )
        .expect(1)
        .mount(&feeds)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"cve": "CVE-2021-23337", "epss": "0.5", "percentile": "0.9", "date": "2026-11-08"}
        ]})))
        .expect(1)
        .mount(&feeds)
        .await;
    let kev_url = format!("{}/kev.json", feeds.uri());
    let epss_url = format!("{}/epss", feeds.uri());
    let server = server_with_exploitation(&["--kev-url", &kev_url, "--epss-url", &epss_url]).await;
    upload_lodash(&server).await;

    let row = exploitation::Entity::find_by_id("CVE-2021-23337")
        .one(&server.database)
        .await
        .unwrap()
        .expect("exploitation data is stored");
    assert!(row.known_exploited);
    assert_eq!(row.kev_due_date.as_deref(), Some("2022-03-22"));
    assert_eq!(row.epss_score, Some(0.5));
}

/// The value of an unlabelled metric on `/metrics`, 0 while it was never recorded.
async fn metric(server: &TestServer, name: &str) -> f64 {
    let response = server
        .send(Request::get("/metrics").body(Body::empty()).unwrap())
        .await;
    let text = body_text(response).await;
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .map_or(0.0, |value| value.parse().expect("a number"))
}

const REFRESH_FAILURES: &str = "nanobom_exploitation_refresh_failures_total";

#[tokio::test]
async fn a_failing_feed_does_not_fail_the_run() {
    let feeds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&feeds)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&feeds)
        .await;
    let kev_url = format!("{}/kev.json", feeds.uri());
    let epss_url = format!("{}/epss", feeds.uri());
    let server = server_with_exploitation(&["--kev-url", &kev_url, "--epss-url", &epss_url]).await;
    let failures = metric(&server, REFRESH_FAILURES).await;
    upload_lodash(&server).await;

    assert!(
        exploitation::Entity::find()
            .all(&server.database)
            .await
            .unwrap()
            .is_empty()
    );
    let findings = nanobom_entity::findings::Entity::find()
        .all(&server.database)
        .await
        .unwrap();
    assert_eq!(findings.len(), 1, "the run recorded its finding");
    assert_eq!(findings[0].status, "open");
    let runs = runs::Entity::find().all(&server.database).await.unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].status, "succeeded");
    assert_eq!(metric(&server, REFRESH_FAILURES).await, failures + 1.0);
}

#[tokio::test]
async fn a_kev_outage_still_refreshes_epss_and_counts_as_a_failure() {
    let feeds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&feeds)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [
            {"cve": "CVE-2021-23337", "epss": "0.5", "percentile": "0.9", "date": "2026-11-08"}
        ]})))
        .expect(1)
        .mount(&feeds)
        .await;
    let kev_url = format!("{}/kev.json", feeds.uri());
    let epss_url = format!("{}/epss", feeds.uri());
    let server = server_with_exploitation(&["--kev-url", &kev_url, "--epss-url", &epss_url]).await;
    let failures = metric(&server, REFRESH_FAILURES).await;
    upload_lodash(&server).await;

    let row = exploitation::Entity::find_by_id("CVE-2021-23337")
        .one(&server.database)
        .await
        .unwrap()
        .expect("the EPSS score is stored");
    assert_eq!(row.epss_score, Some(0.5));
    assert!(!row.known_exploited);
    assert_eq!(row.kev_checked_at, None, "KEV was not checked");
    assert_eq!(metric(&server, REFRESH_FAILURES).await, failures + 1.0);
}

#[tokio::test]
async fn gauges_count_known_exploited_findings_and_stale_projects() {
    let feeds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"vulnerabilities": [
                {"cveID": "CVE-2021-23337", "dateAdded": "2022-03-01"}
            ]})),
        )
        .mount(&feeds)
        .await;
    Mock::given(method("GET"))
        .and(path("/epss"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&feeds)
        .await;
    let kev_url = format!("{}/kev.json", feeds.uri());
    let epss_url = format!("{}/epss", feeds.uri());
    let server = server_with_exploitation(&[
        "--kev-url",
        &kev_url,
        "--epss-url",
        &epss_url,
        "--stale-after-days",
        "30",
    ])
    .await;
    let (owner, organization) = upload_lodash(&server).await;
    for (slug, days) in [("old", 40), ("recent", 10)] {
        let project = projects::create(&server.database, &owner, organization, slug, slug)
            .await
            .unwrap();
        let mut active: nanobom_entity::projects::ActiveModel = project.into();
        active.last_upload_at = Set(Some(
            (Utc::now() - chrono::Duration::days(days)).fixed_offset(),
        ));
        active.update(&server.database).await.unwrap();
    }
    // The gauges are computed after each run.
    server.runner.request(RunRequest {
        trigger: Trigger::Manual,
        scope: Scope::All,
        triggered_by: None,
    });
    server.runner.wait_until_idle().await;

    assert_eq!(
        metric(&server, "nanobom_open_findings_known_exploited").await,
        1.0
    );
    assert_eq!(metric(&server, "nanobom_stale_projects").await, 1.0);
}

#[tokio::test]
async fn failed_runs_call_the_failure_webhook() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/failures"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;
    let failure_webhook = format!("{}/failures", receiver.uri());
    let server = server(&["--failure-webhook-url", &failure_webhook]).await;
    server.source.set_failing(true);
    server.runner.request(RunRequest {
        trigger: Trigger::Scheduled,
        scope: Scope::All,
        triggered_by: None,
    });
    server.runner.wait_until_idle().await;
    let requests = receiver.received_requests().await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["event"], "run.failed");
    assert_eq!(payload["scope"], "all");
    assert!(payload["error"].as_str().unwrap().contains("unreachable"));
}

#[tokio::test]
async fn a_run_that_panics_is_recorded_as_failed_and_notified() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/failures"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;
    let failure_webhook = format!("{}/failures", receiver.uri());
    let server = server(&["--failure-webhook-url", &failure_webhook]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    server.source.panic_once();
    let waited = server
        .runner
        .request_and_wait(
            RunRequest {
                trigger: Trigger::Manual,
                scope: Scope::Organization(organization.id),
                triggered_by: Some(owner.user_id),
            },
            Duration::from_secs(10),
        )
        .await;
    let Waited::Finished(outcome) = waited else {
        panic!("the run is closed with an outcome: {waited:?}");
    };
    assert_eq!(
        outcome.error.as_deref(),
        Some(evaluation::STOPPED_UNEXPECTEDLY)
    );
    server.runner.wait_until_idle().await;

    let run = runs::Entity::find_by_id(outcome.run_id)
        .one(&server.database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.status, "failed");
    assert!(run.finished_at.is_some());
    assert_eq!(run.error.as_deref(), Some(evaluation::STOPPED_UNEXPECTEDLY));
    let requests = receiver.received_requests().await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["event"], "run.failed");
    assert_eq!(payload["run"]["id"], outcome.run_id);
    assert_eq!(payload["scope"], "organization");
    assert_eq!(payload["error"], evaluation::STOPPED_UNEXPECTEDLY);
}

#[tokio::test]
async fn runs_interrupted_by_a_restart_are_closed_at_startup() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/failures"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&receiver)
        .await;
    let failure_webhook = format!("{}/failures", receiver.uri());
    let server = server(&["--failure-webhook-url", &failure_webhook]).await;
    let interrupted = runs::ActiveModel {
        trigger: Set("scheduled".to_owned()),
        scope: Set("all".to_owned()),
        organization_id: Set(None),
        project_id: Set(None),
        triggered_by_user_id: Set(None),
        started_at: Set(Utc::now().fixed_offset()),
        finished_at: Set(None),
        status: Set("running".to_owned()),
        error: Set(None),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();

    let options = crate::common::options(&["--failure-webhook-url", &failure_webhook]);
    let settings = NotificationSettings {
        public_url: options.public_url.clone(),
        failure_webhook: options.failure_webhook_url.clone(),
        stale_after_days: options.stale_after_days,
        exploitation_refresh_timeout: runner::EXPLOITATION_REFRESH_TIMEOUT,
    };
    runner::close_interrupted_runs(&server.database, &settings).await;

    let run = runs::Entity::find_by_id(interrupted.id)
        .one(&server.database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.status, "failed");
    assert!(run.finished_at.is_some());
    // Queued, not posted: an unreachable receiver cannot hold the startup.
    assert!(receiver.received_requests().await.unwrap().is_empty());
    let queued = webhook_deliveries::Entity::find()
        .one(&server.database)
        .await
        .unwrap()
        .expect("the failure webhook is queued");
    assert_eq!(queued.event, "run.failed");
    assert_eq!(queued.attempts, 0);

    let retries = deliveries::start(
        server.database.clone(),
        Notifier::new().unwrap(),
        Duration::from_millis(20),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while receiver.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the retry loop delivers it");
    retries.abort();
    let requests = receiver.received_requests().await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["event"], "run.failed");
    assert_eq!(payload["run"]["id"], interrupted.id);
    assert_eq!(payload["run"]["trigger"], "scheduled");
}

#[tokio::test]
async fn failed_webhook_deliveries_are_retried() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/failures"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&receiver)
        .await;
    Mock::given(method("POST"))
        .and(path("/failures"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;
    let failure_webhook = format!("{}/failures", receiver.uri());
    let server = server(&["--failure-webhook-url", &failure_webhook]).await;
    server.source.set_failing(true);
    server.runner.request(RunRequest {
        trigger: Trigger::Scheduled,
        scope: Scope::All,
        triggered_by: None,
    });
    server.runner.wait_until_idle().await;
    assert_eq!(receiver.received_requests().await.unwrap().len(), 1);
    let pending = webhook_deliveries::Entity::find()
        .one(&server.database)
        .await
        .unwrap()
        .expect("the delivery is recorded");
    assert_eq!(pending.organization_id, None);
    assert_eq!(pending.event, "run.failed");
    assert_eq!(pending.attempts, 1);
    assert_eq!(
        pending.last_status.as_deref(),
        Some("503 Service Unavailable")
    );

    // Skip the backoff rather than wait a minute.
    let mut active: webhook_deliveries::ActiveModel = pending.into();
    active.next_attempt_at = Set(Some(Utc::now().fixed_offset()));
    active.update(&server.database).await.unwrap();
    let retries = deliveries::start(
        server.database.clone(),
        Notifier::new().unwrap(),
        Duration::from_millis(20),
    );
    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let delivery = webhook_deliveries::Entity::find()
                .one(&server.database)
                .await
                .unwrap()
                .unwrap();
            if delivery.delivered_at.is_some() {
                return delivery;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the delivery is retried");
    retries.abort();
    assert_eq!(delivered.attempts, 2);
    assert_eq!(delivered.next_attempt_at, None);
    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);

    let response = server
        .send(Request::get("/metrics").body(Body::empty()).unwrap())
        .await;
    let text = body_text(response).await;
    for line in [
        "nanobom_webhook_deliveries_total{outcome=\"retried\"} 1",
        "nanobom_webhook_deliveries_total{outcome=\"delivered\"} 1",
    ] {
        assert!(text.contains(line), "{line} is missing from:\n{text}");
    }
}

#[tokio::test]
async fn scheduled_runs_notify_stale_projects_once() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/stale"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;
    let server = server(&["--stale-after-days", "30"]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &server.database,
        &owner,
        organization.id,
        &notifications::Webhook {
            url: format!("{}/stale", receiver.uri()),
            minimum_severity: Severity::Critical,
            enabled: true,
            exploited_only: true,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    let project = projects::create(&server.database, &owner, organization.id, "web", "Web")
        .await
        .unwrap();
    let mut active: nanobom_entity::projects::ActiveModel = project.into();
    active.last_upload_at = Set(Some(
        (Utc::now() - chrono::Duration::days(40)).fixed_offset(),
    ));
    active.update(&server.database).await.unwrap();

    let scheduled = RunRequest {
        trigger: Trigger::Scheduled,
        scope: Scope::All,
        triggered_by: None,
    };
    // A manual run does not notify.
    server.runner.request(RunRequest {
        trigger: Trigger::Manual,
        ..scheduled
    });
    server.runner.wait_until_idle().await;
    assert!(receiver.received_requests().await.unwrap().is_empty());

    server.runner.request(scheduled);
    server.runner.wait_until_idle().await;
    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["event"], "projects.stale");
    assert_eq!(payload["organization"]["slug"], "acme");
    assert_eq!(payload["projects"][0]["project"], "web");
    assert!(payload["projects"][0]["last_upload_at"].is_string());

    server.runner.request(scheduled);
    server.runner.wait_until_idle().await;
    assert_eq!(receiver.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_scheduled_request_merged_into_a_manual_one_still_notifies_stale_projects() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/stale"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;
    let server = server(&["--stale-after-days", "30", "--run-after-upload", "false"]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &server.database,
        &owner,
        organization.id,
        &notifications::Webhook {
            url: format!("{}/stale", receiver.uri()),
            minimum_severity: Severity::Critical,
            enabled: true,
            exploited_only: true,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    let stale = projects::create(&server.database, &owner, organization.id, "old", "Old")
        .await
        .unwrap();
    let mut active: nanobom_entity::projects::ActiveModel = stale.into();
    active.last_upload_at = Set(Some(
        (Utc::now() - chrono::Duration::days(40)).fixed_offset(),
    ));
    active.update(&server.database).await.unwrap();
    // A project with components, whose run the paused source holds in progress.
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let web = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    server.source.pause();
    server.runner.request(RunRequest {
        trigger: Trigger::Manual,
        scope: Scope::Project(web.id),
        triggered_by: None,
    });
    server.source.query_started().await;

    let scheduled = RunRequest {
        trigger: Trigger::Scheduled,
        scope: Scope::All,
        triggered_by: None,
    };
    assert!(server.runner.request(RunRequest {
        trigger: Trigger::Manual,
        ..scheduled
    }));
    assert!(
        !server.runner.request(scheduled),
        "merged with the manual request"
    );
    server.source.resume();
    server.runner.wait_until_idle().await;
    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "the merged run counts as scheduled");
    let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(payload["event"], "projects.stale");
    assert_eq!(payload["projects"][0]["project"], "old");
}

/// The outcome of a run that was waited for and finished.
fn finished(waited: Waited) -> nanobom_domain::evaluation::RunOutcome {
    match waited {
        Waited::Finished(outcome) => outcome,
        other => panic!("the run did not finish: {other:?}"),
    }
}

#[tokio::test]
async fn duplicate_requests_for_a_waiting_scope_are_merged() {
    let server = server(&[]).await;
    let request = RunRequest {
        trigger: Trigger::Manual,
        scope: Scope::Organization(1),
        triggered_by: None,
    };
    // The worker may already have taken the first request; the merge only applies to
    // requests still waiting, so queue two behind a third.
    server.runner.request(RunRequest {
        scope: Scope::All,
        ..request
    });
    let first = server.runner.request(request);
    let second = server.runner.request(request);
    assert!(first || second);
    server.runner.wait_until_idle().await;
}

#[tokio::test]
async fn waiting_requests_wait_for_a_run_that_starts_after_them() {
    let server = server(&["--run-after-upload", "false"]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let request = RunRequest {
        trigger: Trigger::Upload,
        scope: Scope::Project(project.id),
        triggered_by: None,
    };
    let timeout = Duration::from_secs(30);

    // A run of the project in progress, held by the source.
    server.source.pause();
    let runner = server.runner.clone();
    let in_progress = tokio::spawn(async move { runner.request_and_wait(request, timeout).await });
    server.source.query_started().await;

    // Polling once queues the request: the first is queued anew behind the run in progress,
    // the second merges with it, and so does a plain request.
    let mut context = Context::from_waker(Waker::noop());
    let mut first = Box::pin(server.runner.request_and_wait(request, timeout));
    assert!(first.as_mut().poll(&mut context).is_pending());
    let mut second = Box::pin(server.runner.request_and_wait(request, timeout));
    assert!(second.as_mut().poll(&mut context).is_pending());
    assert!(
        !server.runner.request(request),
        "merged with the queued request"
    );

    server.source.resume();
    let in_progress = finished(in_progress.await.unwrap());
    let first = finished(first.await);
    let second = finished(second.await);
    assert_ne!(
        first.run_id, in_progress.run_id,
        "a run started after the request"
    );
    assert_eq!(
        first.run_id, second.run_id,
        "merged requests share their run"
    );
    assert!(first.succeeded());
    server.runner.wait_until_idle().await;
    assert_eq!(
        nanobom_entity::runs::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn a_panic_in_a_run_does_not_stop_the_worker() {
    let server = server(&["--run-after-upload", "false"]).await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let request = RunRequest {
        trigger: Trigger::Manual,
        scope: Scope::Project(project.id),
        triggered_by: None,
    };
    let timeout = Duration::from_secs(30);

    // The waiter learns that the run failed, well before the timeout.
    server.source.panic_once();
    let started = std::time::Instant::now();
    let waited = server.runner.request_and_wait(request, timeout).await;
    assert!(
        matches!(&waited, Waited::Finished(outcome) if !outcome.succeeded()),
        "{waited:?}"
    );
    assert!(started.elapsed() < timeout);
    server.runner.wait_until_idle().await;

    let outcome = finished(server.runner.request_and_wait(request, timeout).await);
    assert!(outcome.succeeded());
    assert_eq!(outcome.new_findings.len(), 1);
    server.runner.wait_until_idle().await;
}

#[tokio::test]
async fn health_and_metrics_are_served() {
    let server = server(&[]).await;
    let response = server
        .send(Request::get("/healthz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "ok");

    server.runner.request(RunRequest {
        trigger: Trigger::Scheduled,
        scope: Scope::All,
        triggered_by: None,
    });
    server.runner.wait_until_idle().await;
    let response = server
        .send(Request::get("/metrics").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let text = body_text(response).await;
    for name in [
        "nanobom_open_findings",
        "nanobom_last_successful_run_timestamp_seconds",
        "nanobom_run_duration_seconds",
        "nanobom_runs_total",
    ] {
        assert!(text.contains(name), "{name} is missing from:\n{text}");
    }
}

#[tokio::test]
async fn the_healthcheck_command_asks_a_running_server() {
    let server = server(&[]).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = server.router.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
    });
    let url = healthcheck::local_url(address).unwrap();
    healthcheck::check(&url, Duration::from_secs(5))
        .await
        .expect("the server is healthy");

    let unhealthy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/healthz"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&unhealthy)
        .await;
    let url = format!("{}/healthz", unhealthy.uri()).parse().unwrap();
    assert!(
        healthcheck::check(&url, Duration::from_secs(5))
            .await
            .is_err()
    );
}

#[test]
fn the_healthcheck_reaches_servers_listening_everywhere_over_loopback() {
    let url = |address: &str| {
        healthcheck::local_url(address.parse().unwrap())
            .unwrap()
            .to_string()
    };
    assert_eq!(url("0.0.0.0:8080"), "http://127.0.0.1:8080/healthz");
    assert_eq!(url("[::]:9000"), "http://[::1]:9000/healthz");
    assert_eq!(url("192.0.2.7:8080"), "http://192.0.2.7:8080/healthz");
}

#[tokio::test]
async fn responses_carry_security_headers_and_are_compressed() {
    let server = server(&[]).await;
    let response = server
        .send(
            Request::get("/login")
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(headers[header::REFERRER_POLICY], "same-origin");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "frame-ancestors 'none'"
    );
    assert_eq!(headers[header::CONTENT_ENCODING], "gzip");
}
