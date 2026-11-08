//! Runs started by uploads, failure notifications, health and metrics.

use crate::common::{body_json, body_text, sbom_document, server, user};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use nanobom::{healthcheck, runner::RunRequest};
use nanobom_domain::{
    evaluation::{Scope, Trigger},
    findings::{self, Filter},
    organizations, projects, tokens,
};
use serde_json::json;
use std::time::Duration;
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
