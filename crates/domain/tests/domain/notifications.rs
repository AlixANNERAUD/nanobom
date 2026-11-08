//! Organization webhooks: settings, permissions, grouping, filtering and delivery.

use nanobom_domain::{
    Error,
    access::{Actor, Role},
    evaluation::{NewFinding, RunOutcome, Scope, Trigger},
    memberships, notifications, organizations, testing,
    users::{self, NewUser},
};
use nanobom_osv::Severity;
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn actor(database: &sea_orm::DatabaseConnection, username: &str) -> Actor {
    Actor::from_user(
        &users::create(
            database,
            NewUser {
                username: username.to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap(),
    )
}

fn finding(organization: i64, slug: &str, severity: Severity, id: &str) -> NewFinding {
    NewFinding {
        finding_id: 7,
        organization_id: organization,
        organization_slug: slug.to_owned(),
        project_slug: "web".to_owned(),
        purl: "pkg:npm/lodash@4.17.20".to_owned(),
        vulnerability_id: id.to_owned(),
        aliases: vec!["CVE-2021-23337".to_owned()],
        summary: Some("Command Injection in lodash".to_owned()),
        severity,
        cvss_score: Some(7.2),
        reopened: false,
    }
}

fn outcome(new_findings: Vec<NewFinding>, error: Option<&str>) -> RunOutcome {
    RunOutcome {
        run_id: 42,
        scope: Scope::All,
        trigger: Trigger::Scheduled,
        started_at: chrono::Utc::now().fixed_offset(),
        duration_seconds: 1.5,
        error: error.map(str::to_owned),
        component_count: 3,
        vulnerability_count: 2,
        new_findings,
        fixed_findings: 0,
    }
}

#[tokio::test]
async fn only_admins_configure_webhooks_and_urls_are_checked() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let member = actor(&database, "member").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    memberships::add(&database, &owner, organization, "member", Role::Member)
        .await
        .unwrap();
    assert!(matches!(
        notifications::set(
            &database,
            &member,
            organization,
            "https://example.org/hook",
            Severity::High,
            true
        )
        .await,
        Err(Error::Forbidden)
    ));
    for url in ["ftp://example.org/hook", "not a url", "https://"] {
        assert!(matches!(
            notifications::set(&database, &owner, organization, url, Severity::High, true).await,
            Err(Error::Invalid(_))
        ));
    }
    let webhook = notifications::set(
        &database,
        &owner,
        organization,
        "https://hooks.example.org/nanobom",
        Severity::High,
        true,
    )
    .await
    .unwrap();
    assert_eq!(webhook.minimum_severity, Severity::High);
    let updated = notifications::set(
        &database,
        &owner,
        organization,
        "https://hooks.example.org/other",
        Severity::Critical,
        false,
    )
    .await
    .unwrap();
    assert!(!updated.enabled);
    assert_eq!(
        notifications::get(&database, &owner, organization)
            .await
            .unwrap()
            .unwrap()
            .url,
        "https://hooks.example.org/other"
    );
    notifications::delete(&database, &owner, organization)
        .await
        .unwrap();
    assert!(
        notifications::get(&database, &owner, organization)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn new_findings_are_grouped_per_organization_and_filtered_by_severity() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let quiet = organizations::create(&database, &owner, "quiet", "Quiet")
        .await
        .unwrap();
    let silent = organizations::create(&database, &owner, "silent", "Silent")
        .await
        .unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/acme"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    notifications::set(
        &database,
        &owner,
        acme.id,
        &format!("{}/acme", server.uri()),
        Severity::High,
        true,
    )
    .await
    .unwrap();
    notifications::set(
        &database,
        &owner,
        quiet.id,
        &format!("{}/quiet", server.uri()),
        Severity::Critical,
        true,
    )
    .await
    .unwrap();

    let run = outcome(
        vec![
            finding(acme.id, "acme", Severity::Critical, "GHSA-1"),
            finding(acme.id, "acme", Severity::High, "GHSA-2"),
            finding(acme.id, "acme", Severity::Low, "GHSA-3"),
            finding(quiet.id, "quiet", Severity::High, "GHSA-4"),
            finding(silent.id, "silent", Severity::Critical, "GHSA-5"),
        ],
        None,
    );
    let public_url = "https://nanobom.example.org/".parse().unwrap();
    let deliveries = notifications::new_findings_deliveries(&database, &run, &public_url)
        .await
        .unwrap();
    assert_eq!(
        deliveries.len(),
        1,
        "quiet is below its minimum, silent has no webhook"
    );
    let payload = &deliveries[0].payload;
    assert_eq!(payload.event, "findings.new");
    assert_eq!(payload.count, 2);
    assert_eq!(payload.highest_severity, Severity::Critical);
    assert_eq!(
        payload.organization.url,
        "https://nanobom.example.org/organizations/acme"
    );
    assert_eq!(
        payload.findings[0].url,
        "https://nanobom.example.org/findings/7"
    );

    notifications::Notifier::new()
        .unwrap()
        .deliver(&database, deliveries)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["event"], "findings.new");
    assert_eq!(body["findings"][0]["vulnerability"], "GHSA-1");
    assert_eq!(body["findings"][0]["severity"], "critical");
    assert_eq!(body["run"]["trigger"], "scheduled");
    let webhook = notifications::get(&database, &owner, acme.id)
        .await
        .unwrap()
        .unwrap();
    assert!(webhook.last_delivery_at.is_some());
    assert_eq!(
        webhook.last_delivery_status.as_deref(),
        Some("204 No Content")
    );
}

#[tokio::test]
async fn failed_deliveries_are_recorded() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &database,
        &owner,
        acme.id,
        "http://127.0.0.1:9/hook",
        Severity::Unknown,
        true,
    )
    .await
    .unwrap();
    let run = outcome(
        vec![finding(acme.id, "acme", Severity::Low, "GHSA-1")],
        None,
    );
    let deliveries = notifications::new_findings_deliveries(
        &database,
        &run,
        &"http://localhost/".parse().unwrap(),
    )
    .await
    .unwrap();
    notifications::Notifier::new()
        .unwrap()
        .deliver(&database, deliveries)
        .await
        .unwrap();
    let webhook = notifications::get(&database, &owner, acme.id)
        .await
        .unwrap()
        .unwrap();
    assert!(webhook.last_delivery_status.unwrap().starts_with("failed"));
}

#[test]
fn failed_runs_have_a_failure_payload() {
    let public_url = "https://nanobom.example.org/".parse().unwrap();
    assert!(notifications::run_failed_payload(&outcome(vec![], None), &public_url).is_none());
    let payload = notifications::run_failed_payload(
        &outcome(vec![], Some("querying vulnerabilities failed: timeout")),
        &public_url,
    )
    .unwrap();
    assert_eq!(payload.event, "run.failed");
    assert_eq!(payload.scope, "all");
    assert_eq!(payload.run.id, 42);
    assert!(payload.error.contains("timeout"));
}
