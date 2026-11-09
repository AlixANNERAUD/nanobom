//! Uploads to named project versions: creation, the latest flag, the cap, inheritance of the
//! latest version's triage, notifications and counts across versions.

use std::sync::Arc;

use chrono::{Duration, Utc};
use nanobom_domain::{
    Error, Problem,
    access::Actor,
    evaluation::{Evaluator, RunOutcome, Scope, Trigger},
    findings::{self, EventKind, Filter, Justification, Status},
    inventory::{self, UploadOutcome, UploadSource},
    notifications::{self, Format, Payload, Webhook},
    organizations, projects, testing,
    testing::FakeSource,
    tokens,
    users::{self, NewUser},
    versions,
};
use nanobom_entity::{finding_events, findings as findings_entity, project_versions};
use nanobom_osv::Severity;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder,
};
use serde_json::json;

const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";
const EXPRESS: &str = "pkg:npm/express@4.18.2";

struct Fixture {
    database: DatabaseConnection,
    source: Arc<FakeSource>,
    evaluator: Evaluator<FakeSource>,
    owner: Actor,
    organization: i64,
    secret: String,
}

impl Fixture {
    async fn new() -> Self {
        let database = testing::database().await;
        let owner = users::create(
            &database,
            NewUser {
                username: "owner".to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap();
        let owner = Actor::from_user(&owner);
        let organization = organizations::create(&database, &owner, "acme", "Acme")
            .await
            .unwrap()
            .id;
        let secret = tokens::create(&database, &owner, organization, None, "CI")
            .await
            .unwrap()
            .secret;
        let source = Arc::new(FakeSource::default());
        source.publish(
            json!({
                "id": "GHSA-35jh-r3h4-6jhm",
                "modified": "2024-01-01T00:00:00Z",
                "aliases": ["CVE-2021-23337"],
                "database_specific": {"severity": "HIGH"}
            }),
            &[LODASH],
        );
        source.publish(
            json!({
                "id": "GHSA-xvch-5gv4-984h",
                "modified": "2024-01-01T00:00:00Z",
                "aliases": ["CVE-2021-44906"],
                "database_specific": {"severity": "CRITICAL"}
            }),
            &[MINIMIST],
        );
        let evaluator = Evaluator::new(database.clone(), Arc::clone(&source));
        Self {
            database,
            source,
            evaluator,
            owner,
            organization,
            secret,
        }
    }

    /// Uploads an SBOM of these package URLs to `acme/web`, at `version`.
    async fn try_upload(
        &self,
        version: Option<&str>,
        latest: Option<bool>,
        purls: &[&str],
    ) -> nanobom_domain::Result<UploadOutcome> {
        let token = tokens::authenticate(&self.database, &self.secret)
            .await
            .unwrap()
            .unwrap();
        let components: Vec<_> = purls
            .iter()
            .map(|purl| json!({"type": "library", "name": purl, "purl": purl}))
            .collect();
        let document = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": components,
        });
        inventory::ingest(
            &self.database,
            &token,
            "acme",
            "web",
            inventory::parse(document.to_string().as_bytes()).unwrap(),
            UploadSource {
                version: version.map(str::to_owned),
                latest,
                ..UploadSource::default()
            },
        )
        .await
    }

    async fn upload(
        &self,
        version: Option<&str>,
        latest: Option<bool>,
        purls: &[&str],
    ) -> UploadOutcome {
        self.try_upload(version, latest, purls).await.unwrap()
    }

    async fn run(&self) -> RunOutcome {
        self.evaluator
            .run(Trigger::Scheduled, Scope::All, None)
            .await
            .unwrap()
    }

    /// The versions of the project, by creation.
    async fn versions(&self) -> Vec<project_versions::Model> {
        project_versions::Entity::find()
            .order_by_asc(project_versions::Column::Id)
            .all(&self.database)
            .await
            .unwrap()
    }

    /// The name of the latest version, checking that there is exactly one.
    async fn latest(&self) -> String {
        let latest: Vec<String> = self
            .versions()
            .await
            .into_iter()
            .filter(|version| version.latest)
            .map(|version| version.name)
            .collect();
        assert_eq!(latest.len(), 1, "exactly one latest version: {latest:?}");
        latest[0].clone()
    }

    async fn findings(&self, project_id: i64, version: &str) -> Vec<findings::Finding> {
        findings::list_in_version(
            &self.database,
            &self.owner,
            project_id,
            Some(version),
            &Filter::default(),
        )
        .await
        .unwrap()
    }
}

#[test]
fn version_names_are_checked() {
    for (name, expected) in [
        ("2.4", "2.4"),
        (" 2.4\t", "2.4"),
        ("release/2.4", "release/2.4"),
        ("1.0.0+build.5", "1.0.0+build.5"),
        ("v1_2-RC.1", "v1_2-RC.1"),
    ] {
        assert_eq!(versions::validate_name(name).unwrap(), expected);
    }
    let longest = "a".repeat(versions::MAXIMUM_NAME_LENGTH);
    assert_eq!(versions::validate_name(&longest).unwrap(), longest);
    for name in [
        "",
        "   ",
        "1.0 beta",
        "2.4é",
        "a;b",
        "a".repeat(versions::MAXIMUM_NAME_LENGTH + 1).as_str(),
    ] {
        assert!(
            matches!(
                versions::validate_name(name),
                Err(Error::Invalid(Problem::InvalidVersionName { maximum: 64 }))
            ),
            "{name:?}"
        );
    }
    assert_eq!(
        Problem::InvalidVersionName { maximum: 64 }.to_string(),
        "the version must be 1 to 64 characters: letters, digits, '.', '_', '+', '/' or '-'"
    );
}

#[tokio::test]
async fn uploads_create_versions_and_move_the_latest_flag() {
    let fixture = Fixture::new().await;
    let first = fixture.upload(None, None, &[EXPRESS]).await;
    assert!(first.project_created);
    assert_eq!(first.version, "");
    assert!(first.version_created);
    assert_eq!(fixture.latest().await, "");

    // The first upload naming a version creates it, and it becomes the latest.
    let created = fixture.upload(Some("2.4"), None, &[EXPRESS]).await;
    assert!(!created.project_created);
    assert_eq!(created.version, "2.4");
    assert!(created.version_created);
    assert_eq!(fixture.latest().await, "2.4");
    let again = fixture.upload(Some("2.4"), None, &[EXPRESS]).await;
    assert!(!again.version_created);
    assert_eq!(again.version_id, created.version_id);

    // A maintenance version created with latest=false leaves the flag where it is.
    let maintenance = fixture.upload(Some("2.3"), Some(false), &[EXPRESS]).await;
    assert!(maintenance.version_created);
    assert_eq!(fixture.latest().await, "2.4");
    // Without `latest`, an existing version keeps its flag; with true, it takes it.
    fixture.upload(Some("2.3"), None, &[EXPRESS]).await;
    assert_eq!(fixture.latest().await, "2.4");
    fixture.upload(Some("2.3"), Some(true), &[EXPRESS]).await;
    assert_eq!(fixture.latest().await, "2.3");
    // latest=false on an existing version does not leave the project without one.
    fixture.upload(Some("2.3"), Some(false), &[EXPRESS]).await;
    assert_eq!(fixture.latest().await, "2.3");
    // Names are case-sensitive, and the unnamed version can take the flag back.
    assert!(
        fixture
            .upload(Some("V2.3"), Some(false), &[EXPRESS])
            .await
            .version_created
    );
    fixture.upload(None, Some(true), &[EXPRESS]).await;
    assert_eq!(fixture.latest().await, "");

    let listed = versions::list(&fixture.database, &fixture.owner, first.project_id)
        .await
        .unwrap();
    let names: Vec<&str> = listed.iter().map(|version| version.name.as_str()).collect();
    assert_eq!(names, ["V2.3", "2.3", "2.4", ""], "newest first");
    assert!(listed.iter().all(|version| version.active));
    assert!(
        listed
            .iter()
            .all(|version| version.last_upload_at.is_some())
    );

    // An invalid name stores nothing.
    let uploads = inventory::uploads(&fixture.database, &fixture.owner, first.project_id)
        .await
        .unwrap()
        .len();
    assert!(matches!(
        fixture
            .try_upload(Some("2.4 final"), None, &[EXPRESS])
            .await,
        Err(Error::Invalid(Problem::InvalidVersionName { .. }))
    ));
    assert_eq!(
        inventory::uploads(&fixture.database, &fixture.owner, first.project_id)
            .await
            .unwrap()
            .len(),
        uploads
    );
}

#[tokio::test]
async fn a_project_created_by_an_upload_starts_with_its_version() {
    let fixture = Fixture::new().await;
    let outcome = fixture.upload(Some("1.0"), Some(false), &[EXPRESS]).await;
    assert!(outcome.project_created);
    assert!(outcome.version_created);
    let versions = fixture.versions().await;
    assert_eq!(versions.len(), 1, "no unnamed version next to it");
    assert_eq!(versions[0].name, "1.0");
    assert!(versions[0].latest, "the only version is the latest");
}

#[tokio::test]
async fn a_project_created_in_the_interface_takes_the_first_version_named() {
    let fixture = Fixture::new().await;
    let project = projects::create(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        "web",
        "Web",
    )
    .await
    .unwrap();
    let outcome = fixture.upload(Some("main"), Some(false), &[EXPRESS]).await;
    assert!(!outcome.project_created);
    assert!(outcome.version_created);
    assert_eq!(outcome.project_id, project.id);
    let versions = fixture.versions().await;
    assert_eq!(
        versions.len(),
        1,
        "the empty unnamed version is renamed, not kept"
    );
    assert_eq!(versions[0].name, "main");
    assert!(versions[0].latest, "the only version is the latest");

    // An unnamed version that received an upload is kept.
    let fixture = Fixture::new().await;
    projects::create(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        "web",
        "Web",
    )
    .await
    .unwrap();
    fixture.upload(None, None, &[EXPRESS]).await;
    fixture.upload(Some("main"), None, &[EXPRESS]).await;
    let names: Vec<String> = fixture
        .versions()
        .await
        .into_iter()
        .map(|version| version.name)
        .collect();
    assert_eq!(names, ["", "main"]);
}

#[tokio::test]
async fn active_versions_are_capped() {
    let fixture = Fixture::new().await;
    let outcome = fixture.upload(None, None, &[EXPRESS]).await;
    let now = Utc::now().fixed_offset();
    for number in 1..versions::MAXIMUM_ACTIVE {
        project_versions::ActiveModel {
            project_id: Set(outcome.project_id),
            name: Set(format!("1.{number}")),
            latest: Set(false),
            active: Set(true),
            created_at: Set(now),
            last_upload_at: Set(None),
            dependencies_partial: Set(false),
            ..Default::default()
        }
        .insert(&fixture.database)
        .await
        .unwrap();
    }
    let refused = fixture.try_upload(Some("2.0"), None, &[EXPRESS]).await;
    assert!(
        matches!(
            refused,
            Err(Error::Conflict(Problem::TooManyVersions { maximum: 50 }))
        ),
        "{refused:?}"
    );
    assert_eq!(
        Problem::TooManyVersions { maximum: 50 }.to_string(),
        "this project already has 50 active versions: upload to an existing version instead"
    );
    assert_eq!(fixture.versions().await.len(), 50);
    assert_eq!(fixture.latest().await, "");
    // Existing versions still take uploads.
    fixture.upload(Some("1.49"), None, &[EXPRESS]).await;
    fixture.upload(None, None, &[EXPRESS]).await;
}

#[tokio::test]
async fn uploads_creating_the_same_version_at_once_share_it() {
    let fixture = Fixture::new().await;
    fixture.upload(None, None, &[EXPRESS]).await;
    let (left, right) = tokio::join!(
        fixture.try_upload(Some("3.0"), None, &[EXPRESS]),
        fixture.try_upload(Some("3.0"), None, &[LODASH]),
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left.version_id, right.version_id);
    assert!(
        left.version_created != right.version_created,
        "one creates it"
    );
    let names: Vec<String> = fixture
        .versions()
        .await
        .into_iter()
        .map(|version| version.name)
        .collect();
    assert_eq!(names, ["", "3.0"]);
    assert_eq!(fixture.latest().await, "3.0");
}

#[tokio::test]
async fn a_new_version_inherits_the_triage_of_the_latest() {
    let fixture = Fixture::new().await;
    let project = fixture
        .upload(Some("1.0"), None, &[LODASH, MINIMIST, EXPRESS])
        .await
        .project_id;
    fixture.run().await;
    let original = fixture.findings(project, "1.0").await;
    let lodash = original
        .iter()
        .find(|finding| finding.purl == LODASH)
        .unwrap()
        .clone();
    let expiry = (Utc::now() + Duration::days(30)).fixed_offset();
    findings::ignore(
        &fixture.database,
        &fixture.owner,
        lodash.id,
        "only used by the build",
        Some(Justification::CodeNotReachable),
        Some(expiry),
    )
    .await
    .unwrap();

    // 2.0 no longer has minimist: its copy is fixed by the run, without being announced.
    let outcome = fixture.upload(Some("2.0"), None, &[LODASH, EXPRESS]).await;
    let copies = fixture.findings(project, "2.0").await;
    assert_eq!(copies.len(), 2, "open and ignored findings are copied");
    let copy = copies
        .iter()
        .find(|finding| finding.purl == LODASH)
        .unwrap();
    assert_ne!(copy.id, lodash.id);
    assert_eq!(copy.version, "2.0");
    assert_eq!(copy.status, Status::Ignored);
    assert_eq!(
        copy.ignore_reason.as_deref(),
        Some("only used by the build")
    );
    assert_eq!(
        copy.ignore_justification,
        Some(Justification::CodeNotReachable)
    );
    assert_eq!(
        copy.ignore_expires_at.map(|time| time.timestamp()),
        Some(expiry.timestamp())
    );
    assert_eq!(copy.first_seen_at, lodash.first_seen_at);
    assert_eq!(copy.severity, Severity::High);
    // One event says where the copy comes from; the original's history stays with it.
    let detail = findings::detail(&fixture.database, &fixture.owner, copy.id)
        .await
        .unwrap();
    assert_eq!(detail.events.len(), 1);
    assert_eq!(detail.events[0].kind, EventKind::Inherited);
    assert_eq!(detail.events[0].reason.as_deref(), Some("1.0"));
    assert_eq!(detail.events[0].token.as_deref(), Some("CI"));
    assert_eq!(detail.finding.version, "2.0");

    let run = fixture.run().await;
    assert!(run.succeeded());
    assert_eq!(
        run.new_findings,
        Vec::new(),
        "inherited findings are not new"
    );
    assert_eq!(run.fixed_findings, 1);
    let after = fixture.findings(project, "2.0").await;
    let status_of = |purl: &str| {
        after
            .iter()
            .find(|finding| finding.purl == purl)
            .unwrap()
            .status
    };
    assert_eq!(status_of(LODASH), Status::Ignored);
    assert_eq!(status_of(MINIMIST), Status::Fixed);
    // The original version is untouched, and keeps its own triage.
    let original = fixture.findings(project, "1.0").await;
    assert!(
        original
            .iter()
            .all(|finding| finding.status != Status::Fixed)
    );
    // Restoring the copy does not restore the original.
    findings::restore(&fixture.database, &fixture.owner, copy.id)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .findings(project, "1.0")
            .await
            .iter()
            .find(|finding| finding.purl == LODASH)
            .unwrap()
            .status,
        Status::Ignored
    );

    // Fixed findings are not inherited.
    fixture.upload(Some("3.0"), None, &[EXPRESS]).await;
    let inherited: Vec<String> = fixture
        .findings(project, "3.0")
        .await
        .into_iter()
        .map(|finding| finding.purl)
        .collect();
    assert_eq!(inherited, [LODASH]);
    assert!(outcome.version_created);
}

/// Enables a JSON webhook for every finding.
async fn webhook(fixture: &Fixture) {
    notifications::set(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        &Webhook {
            url: "https://hooks.example.org/nanobom".to_owned(),
            minimum_severity: Severity::Unknown,
            enabled: true,
            exploited_only: false,
            format: Format::Json,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn a_vulnerability_new_in_several_versions_is_announced_once() {
    let fixture = Fixture::new().await;
    webhook(&fixture).await;
    fixture.upload(None, None, &[EXPRESS]).await;
    fixture.upload(Some("2.0"), None, &[EXPRESS]).await;
    fixture.upload(Some("1.0"), Some(false), &[EXPRESS]).await;
    let first = fixture.run().await;
    assert_eq!(first.new_findings, Vec::new());

    fixture.source.publish(
        json!({
            "id": "GHSA-rv95-896h-c2vc",
            "modified": "2024-03-01T00:00:00Z",
            "summary": "Open redirect in express",
            "database_specific": {"severity": "MODERATE"}
        }),
        &[EXPRESS],
    );
    let run = fixture.run().await;
    assert_eq!(run.new_findings.len(), 3, "one finding per version");
    let deliveries = notifications::new_findings_deliveries(
        &fixture.database,
        &run,
        &"https://nanobom.example.org/".parse().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 1);
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 1);
    assert_eq!(payload.findings.len(), 1);
    let entry = &payload.findings[0];
    assert_eq!(entry.vulnerability, "GHSA-rv95-896h-c2vc");
    assert_eq!(entry.versions, ["", "1.0", "2.0"]);
    assert_eq!(entry.reason, "new");
    // The link is the finding of the latest version.
    let latest = run
        .new_findings
        .iter()
        .find(|finding| finding.version == "2.0")
        .unwrap();
    assert_eq!(
        entry.url,
        format!("https://nanobom.example.org/findings/{}", latest.finding_id)
    );
    let json: serde_json::Value = serde_json::from_str(&payload.render(Format::Json)).unwrap();
    assert_eq!(json["findings"][0]["versions"], json!(["", "1.0", "2.0"]));
    let slack = payload.render(Format::Slack);
    assert!(
        slack.contains("Versions: `unnamed version`, `1.0`, `2.0`"),
        "{slack}"
    );
}

/// The `findings.new` deliveries of a run, to the fixture's webhook.
async fn run_deliveries(
    fixture: &Fixture,
    run: &RunOutcome,
) -> Vec<notifications::Delivery<notifications::NewFindingsPayload>> {
    notifications::new_findings_deliveries(
        &fixture.database,
        run,
        &"https://nanobom.example.org/".parse().unwrap(),
        false,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn each_affected_component_is_its_own_entry() {
    const NESTED: &str = "pkg:npm/lodash@4.17.15";
    let fixture = Fixture::new().await;
    webhook(&fixture).await;
    fixture.upload(None, None, &[LODASH, NESTED]).await;
    fixture.run().await;

    // A project that never names versions: one entry per finding, without a versions line.
    fixture.source.publish(
        json!({
            "id": "GHSA-p6mc-m468-83gw",
            "modified": "2024-03-01T00:00:00Z",
            "database_specific": {"severity": "HIGH"}
        }),
        &[LODASH, NESTED],
    );
    let run = fixture.run().await;
    assert_eq!(run.new_findings.len(), 2);
    let deliveries = run_deliveries(&fixture, &run).await;
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 2);
    let mut components: Vec<&str> = payload
        .findings
        .iter()
        .map(|finding| finding.component.as_str())
        .collect();
    components.sort_unstable();
    assert_eq!(components, [NESTED, LODASH]);
    assert!(
        payload
            .findings
            .iter()
            .all(|finding| finding.versions == [""])
    );
    assert!(!payload.render(Format::Slack).contains("Versions:"));

    // In two versions: still one entry per component, each listing both versions.
    fixture.upload(Some("2.0"), None, &[LODASH, NESTED]).await;
    fixture.run().await;
    fixture.source.publish(
        json!({
            "id": "GHSA-29mw-wpgm-hmr9",
            "modified": "2024-04-01T00:00:00Z",
            "database_specific": {"severity": "MODERATE"}
        }),
        &[LODASH, NESTED],
    );
    let run = fixture.run().await;
    assert_eq!(run.new_findings.len(), 4);
    let deliveries = run_deliveries(&fixture, &run).await;
    let payload = &deliveries[0].payload;
    assert_eq!(payload.count, 2);
    let mut components: Vec<&str> = Vec::new();
    for finding in &payload.findings {
        let component = finding.component.as_str();
        components.push(component);
        assert_eq!(finding.versions, ["", "2.0"]);
        let latest = run
            .new_findings
            .iter()
            .find(|new| new.version == "2.0" && new.purl == component)
            .unwrap();
        assert_eq!(
            finding.url,
            format!("https://nanobom.example.org/findings/{}", latest.finding_id)
        );
    }
    components.sort_unstable();
    assert_eq!(components, [NESTED, LODASH]);
}

#[tokio::test]
async fn entries_of_a_project_naming_versions_always_name_theirs() {
    let fixture = Fixture::new().await;
    webhook(&fixture).await;
    fixture.upload(None, None, &[EXPRESS]).await;
    fixture.upload(Some("2.0"), Some(false), &[LODASH]).await;
    fixture.run().await;
    fixture.source.publish(
        json!({
            "id": "GHSA-rv95-896h-c2vc",
            "modified": "2024-03-01T00:00:00Z",
            "database_specific": {"severity": "MODERATE"}
        }),
        &[EXPRESS],
    );
    let run = fixture.run().await;
    let deliveries = run_deliveries(&fixture, &run).await;
    let finding = &deliveries[0].payload.findings[0];
    assert_eq!(finding.versions, [""]);
    let slack = deliveries[0].payload.render(Format::Slack);
    assert!(slack.contains("Versions: `unnamed version`"), "{slack}");
    let json: serde_json::Value =
        serde_json::from_str(&deliveries[0].payload.render(Format::Json)).unwrap();
    assert!(json["findings"][0].get("project_names_versions").is_none());
}

#[tokio::test]
async fn known_exploited_findings_are_announced_once_per_project() {
    let fixture = Fixture::new().await;
    webhook(&fixture).await;
    fixture.upload(None, None, &[LODASH]).await;
    fixture.upload(Some("2.0"), None, &[LODASH]).await;
    fixture.run().await;
    // Both versions' findings are open and were never notified as exploited: the second one
    // was inherited before the first run, so it has no notification time either.
    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_date_added: Set(Some("2022-03-01".to_owned())),
        kev_due_date: Set(Some("2022-03-22".to_owned())),
        kev_ransomware: Set(false),
        ..Default::default()
    }
    .insert(&fixture.database)
    .await
    .unwrap();
    let run = fixture.run().await;
    assert_eq!(run.new_findings, Vec::new());
    let deliveries = notifications::new_findings_deliveries(
        &fixture.database,
        &run,
        &"https://nanobom.example.org/".parse().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 1);
    let findings = &deliveries[0].payload.findings;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].reason, "exploited");
    assert_eq!(findings[0].versions, ["", "2.0"]);
    let unnotified = findings_entity::Entity::find()
        .filter(findings_entity::Column::ExploitedNotifiedAt.is_null())
        .all(&fixture.database)
        .await
        .unwrap();
    assert_eq!(unnotified, Vec::new(), "every row is marked notified");
    // A version created now inherits the notification and is not announced again.
    fixture.upload(Some("3.0"), None, &[LODASH]).await;
    let run = fixture.run().await;
    let deliveries = notifications::new_findings_deliveries(
        &fixture.database,
        &run,
        &"https://nanobom.example.org/".parse().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 0);
}

#[tokio::test]
async fn project_counts_do_not_add_up_versions() {
    let fixture = Fixture::new().await;
    fixture.upload(None, None, &[LODASH, MINIMIST]).await;
    fixture.upload(Some("2.0"), None, &[LODASH, MINIMIST]).await;
    // Another version of lodash in 1.0: still the same issue, at its highest severity.
    fixture
        .upload(Some("1.0"), Some(false), &["pkg:npm/lodash@4.17.19"])
        .await;
    fixture.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-23337"],
            "database_specific": {"severity": "HIGH"}
        }),
        &[LODASH, "pkg:npm/lodash@4.17.19"],
    );
    fixture.run().await;
    let overview = findings::overview(&fixture.database, &fixture.owner, fixture.organization, 0)
        .await
        .unwrap();
    assert_eq!(overview.len(), 1);
    assert_eq!(overview[0].open.high, 1);
    assert_eq!(overview[0].open.critical, 1);
    assert_eq!(overview[0].open.total(), 2);
    assert_eq!(overview[0].ignored, 0);

    // Ignored in one version but open in another: still open.
    let project = overview[0].id;
    let minimist = fixture
        .findings(project, "2.0")
        .await
        .into_iter()
        .find(|finding| finding.purl == MINIMIST)
        .unwrap();
    findings::ignore(
        &fixture.database,
        &fixture.owner,
        minimist.id,
        "not reachable",
        None,
        None,
    )
    .await
    .unwrap();
    let overview = findings::overview(&fixture.database, &fixture.owner, fixture.organization, 0)
        .await
        .unwrap();
    assert_eq!(overview[0].open.critical, 1);
    assert_eq!(overview[0].ignored, 0);
    // Ignored in every version that has it: ignored once.
    let other = fixture
        .findings(project, "")
        .await
        .into_iter()
        .find(|finding| finding.purl == MINIMIST)
        .unwrap();
    findings::ignore(
        &fixture.database,
        &fixture.owner,
        other.id,
        "not reachable",
        None,
        None,
    )
    .await
    .unwrap();
    let overview = findings::overview(&fixture.database, &fixture.owner, fixture.organization, 0)
        .await
        .unwrap();
    assert_eq!(overview[0].open.critical, 0);
    assert_eq!(overview[0].ignored, 1);

    // Each version's own counts, for the versions list.
    let listed = versions::list(&fixture.database, &fixture.owner, project)
        .await
        .unwrap();
    let open: Vec<(&str, u64)> = listed
        .iter()
        .map(|version| (version.name.as_str(), version.open.total()))
        .collect();
    assert_eq!(open, [("1.0", 1), ("2.0", 1), ("", 1)]);
}

#[tokio::test]
async fn reads_name_a_version() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(None, None, &[LODASH]).await.project_id;
    fixture.upload(Some("2.0"), None, &[MINIMIST]).await;
    fixture.run().await;
    let purls = |findings: Vec<findings::Finding>| -> Vec<String> {
        findings.into_iter().map(|finding| finding.purl).collect()
    };
    // The latest by default.
    let open = Filter {
        statuses: vec![Status::Open],
        ..Filter::default()
    };
    assert_eq!(
        purls(
            findings::list(&fixture.database, &fixture.owner, project, &open)
                .await
                .unwrap()
        ),
        [MINIMIST]
    );
    assert_eq!(purls(fixture.findings(project, "").await), [LODASH]);
    let components = |version| {
        inventory::components_in_version(&fixture.database, &fixture.owner, project, version)
    };
    assert_eq!(components(Some("")).await.unwrap()[0].purl, LODASH);
    assert_eq!(components(None).await.unwrap()[0].purl, MINIMIST);
    assert!(matches!(
        components(Some("9.9")).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        findings::ecosystems_in_version(&fixture.database, &fixture.owner, project, Some("9.9"))
            .await,
        Err(Error::NotFound)
    ));
    // A missing version is not found even without a license policy to apply.
    assert!(matches!(
        nanobom_domain::licenses::violations_in_version(
            &fixture.database,
            &fixture.owner,
            project,
            Some("9.9"),
            0,
            10
        )
        .await,
        Err(Error::NotFound)
    ));
    // Events of inherited findings are readable as such.
    let inherited = finding_events::Entity::find()
        .filter(finding_events::Column::Kind.eq("inherited"))
        .all(&fixture.database)
        .await
        .unwrap();
    assert_eq!(inherited.len(), 0, "the unnamed version had no finding yet");
}
