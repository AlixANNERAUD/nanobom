//! Organization webhooks: settings, permissions, grouping, filtering and delivery.

use nanobom_domain::{
    Error,
    access::{Actor, Role},
    deliveries::{self, Channel, Outcome, State},
    evaluation::{NewFinding, RunOutcome, Scope, Trigger},
    memberships, notifications, organizations, testing,
    users::{self, NewUser},
};
use nanobom_entity::{exploitation, findings, vulnerabilities};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};
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
        project_id: 0,
        project_slug: "web".to_owned(),
        version_id: 0,
        version: String::new(),
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
            &notifications::Webhook {
                url: "https://example.org/hook".into(),
                minimum_severity: Severity::High,
                enabled: true,
                exploited_only: false,
                format: notifications::Format::Json
            }
        )
        .await,
        Err(Error::Forbidden)
    ));
    for url in ["ftp://example.org/hook", "not a url", "https://"] {
        assert!(matches!(
            notifications::set(
                &database,
                &owner,
                organization,
                &notifications::Webhook {
                    url: url.into(),
                    minimum_severity: Severity::High,
                    enabled: true,
                    exploited_only: false,
                    format: notifications::Format::Json
                }
            )
            .await,
            Err(Error::Invalid(_))
        ));
    }
    let webhook = notifications::set(
        &database,
        &owner,
        organization,
        &notifications::Webhook {
            url: "https://hooks.example.org/nanobom".into(),
            minimum_severity: Severity::High,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    assert_eq!(webhook.minimum_severity, Severity::High);
    let updated = notifications::set(
        &database,
        &owner,
        organization,
        &notifications::Webhook {
            url: "https://hooks.example.org/other".into(),
            minimum_severity: Severity::Critical,
            enabled: false,
            exploited_only: false,
            format: notifications::Format::Json,
        },
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
        &notifications::Webhook {
            url: format!("{}/acme", server.uri()),
            minimum_severity: Severity::High,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    notifications::set(
        &database,
        &owner,
        quiet.id,
        &notifications::Webhook {
            url: format!("{}/quiet", server.uri()),
            minimum_severity: Severity::Critical,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
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
    let deliveries = notifications::new_findings_deliveries(&database, &run, &public_url, false)
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

    let outcomes = notifications::Notifier::new()
        .unwrap()
        .deliver(&database, deliveries)
        .await
        .unwrap();
    assert_eq!(outcomes, [(Channel::Webhook, Outcome::Delivered)]);
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["event"], "findings.new");
    assert_eq!(body["findings"][0]["vulnerability"], "GHSA-1");
    assert_eq!(body["findings"][0]["severity"], "critical");
    assert_eq!(body["run"]["trigger"], "scheduled");
    let recent = deliveries::recent(&database, &owner, acme.id, 10)
        .await
        .unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].event, "findings.new");
    assert_eq!(recent[0].state, State::Delivered);
    assert_eq!(recent[0].attempts, 1);
    assert_eq!(recent[0].last_status.as_deref(), Some("204 No Content"));
}

#[tokio::test]
async fn failed_deliveries_are_recorded_for_a_retry() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &database,
        &owner,
        acme.id,
        &notifications::Webhook {
            url: "http://127.0.0.1:9/hook".into(),
            minimum_severity: Severity::Unknown,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
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
        false,
    )
    .await
    .unwrap();
    let before = chrono::Utc::now();
    let outcomes = notifications::Notifier::new()
        .unwrap()
        .deliver(&database, deliveries)
        .await
        .unwrap();
    assert_eq!(outcomes, [(Channel::Webhook, Outcome::Retried)]);
    let recent = deliveries::recent(&database, &owner, acme.id, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].state, State::Pending);
    assert_eq!(recent[0].attempts, 1);
    assert!(recent[0].last_status.is_some());
    let next = recent[0].next_attempt_at.unwrap();
    assert!(next >= before + deliveries::RETRY_DELAYS[0]);
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

/// An organization with a project, an enabled webhook and a CVE in the catalog.
struct Exploited {
    database: DatabaseConnection,
    owner: Actor,
    organization: i64,
    project: i64,
}

impl Exploited {
    async fn new(minimum: Severity, exploited_only: bool) -> Self {
        let database = testing::database().await;
        let owner = actor(&database, "owner").await;
        let organization = organizations::create(&database, &owner, "acme", "Acme")
            .await
            .unwrap()
            .id;
        let project =
            nanobom_domain::projects::create(&database, &owner, organization, "web", "Web")
                .await
                .unwrap()
                .id;
        notifications::set(
            &database,
            &owner,
            organization,
            &notifications::Webhook {
                url: "http://127.0.0.1:9/hook".into(),
                minimum_severity: minimum,
                enabled: true,
                exploited_only,
                format: notifications::Format::Json,
            },
        )
        .await
        .unwrap();
        exploitation::ActiveModel {
            cve_id: Set("CVE-2021-23337".to_owned()),
            known_exploited: Set(true),
            kev_date_added: Set(Some("2022-03-01".to_owned())),
            kev_due_date: Set(Some("2022-03-22".to_owned())),
            kev_ransomware: Set(false),
            epss_score: Set(Some(0.75)),
            epss_percentile: Set(Some(0.98)),
            ..Default::default()
        }
        .insert(&database)
        .await
        .unwrap();
        Self {
            database,
            owner,
            organization,
            project,
        }
    }

    /// A finding of the vulnerability `id` (with the aliases given) and its status.
    async fn finding(&self, id: &str, aliases: &[&str], severity: &str, status: &str) -> i64 {
        vulnerabilities::ActiveModel {
            id: Set(id.to_owned()),
            modified: Set(chrono::Utc::now().fixed_offset()),
            summary: Set(Some(format!("About {id}"))),
            aliases: Set(serde_json::to_string(aliases).unwrap()),
            severity: Set(severity.to_owned()),
            cvss_score: Set(Some(5.0)),
            record: Set("{}".to_owned()),
            fetched_at: Set(chrono::Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(&self.database)
        .await
        .unwrap();
        findings::ActiveModel {
            project_id: Set(self.project),
            version_id: Set(Some(
                testing::latest_version(&self.database, self.project).await,
            )),
            purl: Set(format!("pkg:npm/{id}@1.0.0")),
            ecosystem: Set("npm".to_owned()),
            vulnerability_id: Set(id.to_owned()),
            status: Set(status.to_owned()),
            severity: Set(severity.to_owned()),
            first_seen_at: Set(chrono::Utc::now().fixed_offset()),
            last_seen_at: Set(chrono::Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(&self.database)
        .await
        .unwrap()
        .id
    }

    async fn notified(&self, id: i64) -> bool {
        findings::Entity::find_by_id(id)
            .one(&self.database)
            .await
            .unwrap()
            .unwrap()
            .exploited_notified_at
            .is_some()
    }

    async fn deliveries(
        &self,
        new_findings: Vec<nanobom_domain::evaluation::NewFinding>,
    ) -> Vec<notifications::Delivery<notifications::NewFindingsPayload>> {
        notifications::new_findings_deliveries(
            &self.database,
            &outcome(new_findings, None),
            &"https://nanobom.example.org/".parse().unwrap(),
            false,
        )
        .await
        .unwrap()
    }

    fn new_finding(
        &self,
        id: i64,
        vulnerability: &str,
        aliases: &[&str],
        severity: Severity,
    ) -> NewFinding {
        NewFinding {
            finding_id: id,
            organization_id: self.organization,
            organization_slug: "acme".to_owned(),
            project_id: 0,
            project_slug: "web".to_owned(),
            version_id: 0,
            version: String::new(),
            purl: format!("pkg:npm/{vulnerability}@1.0.0"),
            vulnerability_id: vulnerability.to_owned(),
            aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
            summary: None,
            severity,
            cvss_score: None,
            reopened: false,
        }
    }
}

#[tokio::test]
async fn known_exploited_findings_pass_the_minimum_severity() {
    let fixture = Exploited::new(Severity::Critical, false).await;
    let low = fixture
        .finding("GHSA-low", &["CVE-2021-23337"], "low", "open")
        .await;
    let high = fixture.finding("GHSA-high", &[], "high", "open").await;
    let deliveries = fixture
        .deliveries(vec![
            fixture.new_finding(low, "GHSA-low", &["CVE-2021-23337"], Severity::Low),
            fixture.new_finding(high, "GHSA-high", &[], Severity::High),
        ])
        .await;
    assert_eq!(deliveries.len(), 1);
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 1, "the high one is below the minimum");
    assert_eq!(payload.known_exploited_count, 1);
    assert_eq!(payload.findings[0].vulnerability, "GHSA-low");
    assert_eq!(payload.findings[0].reason, "new");
    assert!(
        fixture.notified(low).await,
        "not notified again as exploited"
    );
    assert!(!fixture.notified(high).await);
}

#[tokio::test]
async fn exploited_only_webhooks_deliver_known_exploited_findings_only() {
    let fixture = Exploited::new(Severity::Unknown, true).await;
    let exploited = fixture
        .finding("CVE-2021-23337", &[], "medium", "open")
        .await;
    let other = fixture.finding("GHSA-other", &[], "critical", "open").await;
    let mut reopened = fixture.new_finding(exploited, "CVE-2021-23337", &[], Severity::Medium);
    reopened.reopened = true;
    let deliveries = fixture
        .deliveries(vec![
            reopened,
            fixture.new_finding(other, "GHSA-other", &[], Severity::Critical),
        ])
        .await;
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 1);
    assert_eq!(payload.findings[0].vulnerability, "CVE-2021-23337");
    assert_eq!(payload.findings[0].reason, "reopened");
    assert!(payload.findings[0].reopened);

    // Nothing exploited: nothing delivered, although a critical finding is new.
    let fixture = Exploited::new(Severity::Unknown, true).await;
    let other = fixture.finding("GHSA-other", &[], "critical", "open").await;
    assert!(
        fixture
            .deliveries(vec![fixture.new_finding(
                other,
                "GHSA-other",
                &[],
                Severity::Critical
            )])
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn an_open_finding_newly_exploited_is_notified_once() {
    let fixture = Exploited::new(Severity::Critical, false).await;
    let existing = fixture
        .finding("GHSA-old", &["CVE-2021-23337"], "low", "open")
        .await;
    let ignored = fixture
        .finding("GHSA-ignored", &["CVE-2021-23337"], "low", "ignored")
        .await;
    let fixed = fixture
        .finding("GHSA-fixed", &["CVE-2021-23337"], "low", "fixed")
        .await;

    let deliveries = fixture.deliveries(vec![]).await;
    assert_eq!(deliveries.len(), 1);
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 1);
    let delivered = &payload.findings[0];
    assert_eq!(delivered.vulnerability, "GHSA-old");
    assert_eq!(delivered.reason, "exploited");
    assert!(!delivered.reopened && delivered.known_exploited);
    assert_eq!(delivered.component, "pkg:npm/GHSA-old@1.0.0");
    assert_eq!(delivered.summary.as_deref(), Some("About GHSA-old"));
    assert_eq!(
        delivered.url,
        format!("https://nanobom.example.org/findings/{existing}")
    );
    assert!(fixture.notified(existing).await);
    assert!(!fixture.notified(ignored).await);
    assert!(!fixture.notified(fixed).await);

    assert!(fixture.deliveries(vec![]).await.is_empty(), "only once");
}

#[tokio::test]
async fn exploited_findings_are_delivered_in_the_order_they_were_found() {
    let fixture = Exploited::new(Severity::Unknown, false).await;
    let first = fixture
        .finding("GHSA-first", &["CVE-2021-23337"], "low", "open")
        .await;
    fixture
        .finding("GHSA-second", &["CVE-2021-23337"], "low", "open")
        .await;
    // Updated last: PostgreSQL now holds its row after the second one.
    findings::ActiveModel {
        id: Set(first),
        last_seen_at: Set(chrono::Utc::now().fixed_offset()),
        ..Default::default()
    }
    .update(&fixture.database)
    .await
    .unwrap();

    let deliveries = fixture.deliveries(vec![]).await;
    let delivered: Vec<&str> = deliveries[0]
        .payload
        .findings
        .iter()
        .map(|finding| finding.vulnerability.as_str())
        .collect();
    assert_eq!(delivered, ["GHSA-first", "GHSA-second"]);
}

#[tokio::test]
async fn exploited_findings_are_marked_even_without_a_webhook() {
    let fixture = Exploited::new(Severity::Unknown, false).await;
    notifications::delete(&fixture.database, &fixture.owner, fixture.organization)
        .await
        .unwrap();
    let existing = fixture
        .finding("GHSA-old", &["CVE-2021-23337"], "low", "open")
        .await;
    assert!(fixture.deliveries(vec![]).await.is_empty());
    assert!(fixture.notified(existing).await);

    // A webhook enabled afterwards does not replay it.
    notifications::set(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        &notifications::Webhook {
            url: "http://127.0.0.1:9/hook".into(),
            minimum_severity: Severity::Unknown,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    assert!(fixture.deliveries(vec![]).await.is_empty());
}

#[tokio::test]
async fn payloads_carry_exploitation_data() {
    let fixture = Exploited::new(Severity::Unknown, false).await;
    let exploited = fixture
        .finding("GHSA-old", &["CVE-2021-23337"], "high", "open")
        .await;
    let plain = fixture.finding("GHSA-plain", &[], "high", "open").await;
    let deliveries = fixture
        .deliveries(vec![
            fixture.new_finding(exploited, "GHSA-old", &["CVE-2021-23337"], Severity::High),
            fixture.new_finding(plain, "GHSA-plain", &[], Severity::High),
        ])
        .await;
    let body = serde_json::to_value(&deliveries[0].payload).unwrap();
    assert_eq!(body["count"], 2);
    assert_eq!(body["known_exploited_count"], 1);
    let first = &body["findings"][0];
    assert_eq!(first["reason"], "new");
    assert_eq!(first["known_exploited"], true);
    assert_eq!(first["kev_due_date"], "2022-03-22");
    assert_eq!(first["epss"], 0.75);
    assert_eq!(first["epss_percentile"], 0.98);
    let second = &body["findings"][1];
    assert_eq!(second["known_exploited"], false);
    assert!(second["kev_due_date"].is_null());
    assert!(second["epss"].is_null() && second["epss_percentile"].is_null());
}

#[tokio::test]
async fn exploitation_data_follows_its_finding_when_new_and_open_findings_mix() {
    let fixture = Exploited::new(Severity::Unknown, false).await;
    let plain = fixture.finding("GHSA-plain", &[], "high", "open").await;
    let existing = fixture
        .finding("GHSA-old", &["CVE-2021-23337"], "low", "open")
        .await;
    let deliveries = fixture
        .deliveries(vec![fixture.new_finding(
            plain,
            "GHSA-plain",
            &[],
            Severity::High,
        )])
        .await;
    let body = serde_json::to_value(&deliveries[0].payload).unwrap();
    assert_eq!(body["count"], 2);
    let new = &body["findings"][0];
    assert_eq!(new["vulnerability"], "GHSA-plain");
    assert_eq!(new["reason"], "new");
    assert_eq!(new["known_exploited"], false);
    assert!(new["epss"].is_null());
    let exploited = &body["findings"][1];
    assert_eq!(exploited["vulnerability"], "GHSA-old");
    assert_eq!(exploited["reason"], "exploited");
    assert_eq!(exploited["known_exploited"], true);
    assert_eq!(exploited["kev_due_date"], "2022-03-22");
    assert_eq!(exploited["epss"], 0.75);
    assert!(fixture.notified(existing).await);
    assert!(!fixture.notified(plain).await);
}
