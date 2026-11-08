//! The finding lifecycle across runs: opened, fixed, reopened, ignored, restored, expired, with
//! aliases merged and failed runs leaving everything untouched.

use std::sync::Arc;

use chrono::{Duration, Utc};
use nanobom_domain::{
    Error,
    access::{Actor, Role},
    evaluation::{self, Evaluator, Scope, Trigger},
    findings::{self, EventKind, Filter, Status},
    inventory::{self, ParsedSbom, UploadSource},
    memberships, organizations, testing,
    testing::FakeSource,
    tokens,
    users::{self, NewUser},
};
use nanobom_entity::{findings as finding_entity, runs};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};
use serde_json::json;

const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";

fn lodash_advisory(modified: &str) -> serde_json::Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": modified,
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
        }],
        "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
    })
}

/// The same lodash issue under another identifier, as a second database reports it.
fn lodash_alias() -> serde_json::Value {
    json!({
        "id": "CVE-2021-23337",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["GHSA-35jh-r3h4-6jhm"],
        "summary": "lodash command injection",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

fn minimist_advisory() -> serde_json::Value {
    json!({
        "id": "GHSA-xvch-5gv4-984h",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-44906"],
        "summary": "Prototype Pollution in minimist",
        "database_specific": {"severity": "CRITICAL"}
    })
}

fn sbom(purls: &[&str]) -> ParsedSbom {
    let components: Vec<_> = purls
        .iter()
        .map(|purl| {
            let (name, version) = purl.trim_start_matches("pkg:npm/").split_once('@').unwrap();
            json!({"type": "library", "name": name, "version": version, "purl": purl})
        })
        .collect();
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components
    });
    inventory::parse(document.to_string().as_bytes()).unwrap()
}

struct Fixture {
    database: DatabaseConnection,
    source: Arc<FakeSource>,
    evaluator: Evaluator<FakeSource>,
    owner: Actor,
    member: Actor,
    viewer: Actor,
    organization: i64,
    secret: String,
}

impl Fixture {
    async fn new() -> Self {
        let database = testing::database().await;
        let mut actors = Vec::new();
        for username in ["owner", "member", "viewer"] {
            let user = users::create(
                &database,
                NewUser {
                    username: username.to_owned(),
                    ..NewUser::default()
                },
                false,
            )
            .await
            .unwrap();
            actors.push(Actor::from_user(&user));
        }
        let organization = organizations::create(&database, &actors[0], "acme", "Acme")
            .await
            .unwrap()
            .id;
        memberships::add(&database, &actors[0], organization, "member", Role::Member)
            .await
            .unwrap();
        memberships::add(&database, &actors[0], organization, "viewer", Role::Viewer)
            .await
            .unwrap();
        let secret = tokens::create(&database, &actors[0], organization, None, "CI")
            .await
            .unwrap()
            .secret;
        let source = Arc::new(FakeSource::default());
        let evaluator = Evaluator::new(database.clone(), Arc::clone(&source));
        Self {
            database,
            source,
            evaluator,
            owner: actors[0],
            member: actors[1],
            viewer: actors[2],
            organization,
            secret,
        }
    }

    async fn upload(&self, purls: &[&str]) -> i64 {
        let token = tokens::authenticate(&self.database, &self.secret)
            .await
            .unwrap()
            .unwrap();
        inventory::ingest(
            &self.database,
            &token,
            "acme",
            "web",
            sbom(purls),
            UploadSource::default(),
        )
        .await
        .unwrap()
        .project_id
    }

    async fn run(&self) -> evaluation::RunOutcome {
        self.evaluator
            .run(Trigger::Scheduled, Scope::All, None)
            .await
            .unwrap()
    }

    async fn findings(&self, project: i64) -> Vec<findings::Finding> {
        findings::list(&self.database, &self.owner, project, &Filter::default())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn new_vulnerabilities_open_findings_with_merged_aliases() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    fixture.source.publish(lodash_alias(), &[LODASH]);
    fixture.source.publish(minimist_advisory(), &[MINIMIST]);
    let project = fixture.upload(&[LODASH, MINIMIST]).await;

    let outcome = fixture.run().await;
    assert!(outcome.succeeded());
    assert_eq!(outcome.component_count, 2);
    assert_eq!(outcome.new_findings.len(), 2, "aliases make one finding");
    let lodash = outcome
        .new_findings
        .iter()
        .find(|finding| finding.purl == LODASH)
        .unwrap();
    assert_eq!(lodash.vulnerability_id, "CVE-2021-23337");
    assert_eq!(lodash.aliases, ["GHSA-35jh-r3h4-6jhm"]);
    assert_eq!(
        lodash.severity,
        Severity::Critical,
        "the most severe alias wins"
    );
    assert_eq!(lodash.organization_slug, "acme");

    let findings = fixture.findings(project).await;
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|finding| finding.status == Status::Open)
    );
    let minimist = findings
        .iter()
        .find(|finding| finding.purl == MINIMIST)
        .unwrap();
    assert_eq!(minimist.severity, Severity::Critical);
    assert_eq!(minimist.component_name, "minimist");
    assert_eq!(minimist.component_version.as_deref(), Some("1.2.5"));

    let again = fixture.run().await;
    assert!(again.new_findings.is_empty());
    assert_eq!(again.fixed_findings, 0);
    assert_eq!(fixture.findings(project).await.len(), 2);
}

#[tokio::test]
async fn removed_components_and_narrowed_ranges_fix_findings_and_returns_reopen_them() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    fixture.source.publish(minimist_advisory(), &[MINIMIST]);
    let project = fixture.upload(&[LODASH, MINIMIST]).await;
    fixture.run().await;

    fixture.upload(&[MINIMIST]).await;
    let outcome = fixture.run().await;
    assert_eq!(outcome.fixed_findings, 1);
    let lodash = fixture
        .findings(project)
        .await
        .into_iter()
        .find(|finding| finding.purl == LODASH)
        .unwrap();
    assert_eq!(lodash.status, Status::Fixed);
    assert!(lodash.fixed_at.is_some());

    fixture.source.retract("GHSA-xvch-5gv4-984h", MINIMIST);
    let outcome = fixture.run().await;
    assert_eq!(outcome.fixed_findings, 1, "OSV no longer reports minimist");

    fixture.upload(&[LODASH, MINIMIST]).await;
    let outcome = fixture.run().await;
    assert_eq!(outcome.new_findings.len(), 1);
    assert!(outcome.new_findings[0].reopened);
    let detail = findings::detail(&fixture.database, &fixture.viewer, lodash.id)
        .await
        .unwrap();
    assert_eq!(detail.finding.status, Status::Open);
    let kinds: Vec<_> = detail.events.iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        [EventKind::Opened, EventKind::Fixed, EventKind::Reopened]
    );
    assert_eq!(detail.fixed_versions, ["4.17.21"]);
    assert_eq!(detail.references.len(), 1);
    assert_eq!(detail.organization_slug, "acme");
}

#[tokio::test]
async fn ignored_findings_keep_their_reason_and_expire() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;
    let finding = fixture.findings(project).await[0].id;
    let database = &fixture.database;

    assert!(matches!(
        findings::ignore(database, &fixture.viewer, finding, "not used", None, None).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        findings::ignore(database, &fixture.member, finding, "  ", None, None).await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        findings::ignore(
            database,
            &fixture.member,
            finding,
            "later",
            None,
            Some((Utc::now() - Duration::days(1)).fixed_offset())
        )
        .await,
        Err(Error::Invalid(_))
    ));
    let expiry = (Utc::now() + Duration::days(30)).fixed_offset();
    findings::ignore(
        database,
        &fixture.member,
        finding,
        "template helper is never called with user input",
        None,
        Some(expiry),
    )
    .await
    .unwrap();
    assert!(matches!(
        findings::ignore(database, &fixture.member, finding, "twice", None, None).await,
        Err(Error::Conflict(_))
    ));

    let outcome = fixture.run().await;
    assert!(outcome.new_findings.is_empty());
    let detail = findings::detail(database, &fixture.viewer, finding)
        .await
        .unwrap();
    assert_eq!(detail.finding.status, Status::Ignored);
    assert_eq!(detail.ignored_by.as_deref(), Some("member"));
    assert_eq!(
        detail.finding.ignore_reason.as_deref(),
        Some("template helper is never called with user input")
    );
    assert!(!detail.can_triage);

    // The expiry passes.
    let mut model: finding_entity::ActiveModel = finding_entity::Entity::find_by_id(finding)
        .one(database)
        .await
        .unwrap()
        .unwrap()
        .into();
    model.ignore_expires_at = Set(Some((Utc::now() - Duration::minutes(1)).fixed_offset()));
    model.update(database).await.unwrap();
    fixture.run().await;
    let detail = findings::detail(database, &fixture.member, finding)
        .await
        .unwrap();
    assert_eq!(detail.finding.status, Status::Open);
    assert!(detail.can_triage);
    let kinds: Vec<_> = detail.events.iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        [
            EventKind::Opened,
            EventKind::Ignored,
            EventKind::IgnoreExpired
        ]
    );
    assert_eq!(detail.events[1].actor.as_deref(), Some("member"));

    findings::ignore(
        database,
        &fixture.member,
        finding,
        "accepted risk",
        None,
        None,
    )
    .await
    .unwrap();
    findings::restore(database, &fixture.member, finding)
        .await
        .unwrap();
    let detail = findings::detail(database, &fixture.member, finding)
        .await
        .unwrap();
    assert_eq!(detail.finding.status, Status::Open);
    assert_eq!(detail.events.last().unwrap().kind, EventKind::Restored);
}

#[tokio::test]
async fn ignored_findings_that_disappear_are_fixed() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;
    let finding = fixture.findings(project).await[0].id;
    findings::ignore(
        &fixture.database,
        &fixture.owner,
        finding,
        "accepted",
        None,
        None,
    )
    .await
    .unwrap();
    fixture.upload(&[MINIMIST]).await;
    let outcome = fixture.run().await;
    assert_eq!(outcome.fixed_findings, 1);
    assert_eq!(fixture.findings(project).await[0].status, Status::Fixed);
}

#[tokio::test]
async fn the_oldest_finding_of_a_merged_alias_group_is_kept() {
    let fixture = Fixture::new().await;
    // Two records that do not know each other yet, reported one run apart, so they open two
    // findings. The first is under the identifier that sorts last, so that an index on
    // (project, package, identifier) would not put it first by accident.
    let mut advisory = lodash_advisory("2024-01-01T00:00:00Z");
    advisory["aliases"] = json!([]);
    fixture.source.publish(advisory, &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;
    let oldest = fixture.findings(project).await[0].id;

    let mut alias = lodash_alias();
    alias["aliases"] = json!([]);
    fixture.source.publish(alias, &[LODASH]);
    fixture.run().await;
    assert_eq!(fixture.findings(project).await.len(), 2);
    // Updating the oldest row moves it behind the other one in a PostgreSQL table, so an
    // unordered read would return the newer finding first.
    findings::ignore(
        &fixture.database,
        &fixture.owner,
        oldest,
        "accepted",
        None,
        None,
    )
    .await
    .unwrap();

    // The advisory now lists the other identifier as an alias: both are one group.
    fixture
        .source
        .publish(lodash_advisory("2024-06-01T00:00:00Z"), &[LODASH]);
    let outcome = fixture.run().await;
    assert_eq!(outcome.fixed_findings, 1, "the duplicate is closed");
    for finding in fixture.findings(project).await {
        let expected = if finding.id == oldest {
            Status::Ignored
        } else {
            Status::Fixed
        };
        assert_eq!(finding.status, expected, "finding {}", finding.id);
    }
}

#[tokio::test]
async fn failed_runs_change_nothing_and_are_recorded() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;

    fixture.upload(&[MINIMIST]).await;
    fixture.source.set_failing(true);
    let outcome = fixture.run().await;
    assert!(!outcome.succeeded());
    assert!(outcome.error.as_deref().unwrap().contains("unreachable"));
    assert_eq!(outcome.fixed_findings, 0);
    let findings = fixture.findings(project).await;
    assert_eq!(findings[0].status, Status::Open, "a failure is not a fix");

    let run = runs::Entity::find_by_id(outcome.run_id)
        .one(&fixture.database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.status, "failed");
    assert!(run.error.is_some());
    assert!(run.finished_at.is_some());
}

#[tokio::test]
async fn details_are_cached_and_refreshed_when_modified() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;
    fixture.run().await;
    assert_eq!(fixture.source.fetches(), ["GHSA-35jh-r3h4-6jhm"]);

    let mut updated = lodash_advisory("2024-06-01T00:00:00Z");
    updated["summary"] = json!("Command injection in lodash's template");
    fixture.source.publish(updated, &[LODASH]);
    fixture.run().await;
    assert_eq!(fixture.source.fetches().len(), 2);
    let findings = fixture.findings(project).await;
    assert_eq!(
        findings[0].summary.as_deref(),
        Some("Command injection in lodash's template")
    );
}

#[tokio::test]
async fn scoped_runs_only_touch_their_scope() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;
    let other = organizations::create(&fixture.database, &fixture.owner, "other", "Other")
        .await
        .unwrap();
    let outcome = fixture
        .evaluator
        .run(
            Trigger::Manual,
            Scope::Organization(other.id),
            Some(fixture.owner.user_id),
        )
        .await
        .unwrap();
    assert_eq!(outcome.component_count, 0);
    assert!(fixture.findings(project).await.is_empty());

    let outcome = fixture
        .evaluator
        .run(Trigger::Upload, Scope::Project(project), None)
        .await
        .unwrap();
    assert_eq!(outcome.new_findings.len(), 1);

    assert!(matches!(
        evaluation::authorize(&fixture.database, &fixture.viewer, Scope::Project(project)).await,
        Err(Error::Forbidden)
    ));
    evaluation::authorize(&fixture.database, &fixture.member, Scope::Project(project))
        .await
        .unwrap();
    evaluation::authorize(
        &fixture.database,
        &fixture.member,
        Scope::Organization(fixture.organization),
    )
    .await
    .unwrap();
    assert!(matches!(
        evaluation::authorize(&fixture.database, &fixture.owner, Scope::All).await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn findings_of_other_organizations_stay_hidden() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    let project = fixture.upload(&[LODASH]).await;

    let stranger = users::create(
        &fixture.database,
        NewUser {
            username: "stranger".to_owned(),
            ..NewUser::default()
        },
        true,
    )
    .await
    .unwrap();
    let stranger = Actor::from_user(&stranger);
    let personal = organizations::find(&fixture.database, &stranger, "stranger")
        .await
        .unwrap();
    let secret = tokens::create(&fixture.database, &stranger, personal.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let token = tokens::authenticate(&fixture.database, &secret)
        .await
        .unwrap()
        .unwrap();
    let strangers_project = inventory::ingest(
        &fixture.database,
        &token,
        "stranger",
        "app",
        sbom(&[LODASH]),
        UploadSource::default(),
    )
    .await
    .unwrap()
    .project_id;
    fixture.run().await;

    let mine = fixture.findings(project).await[0].id;
    let detail = findings::detail(&fixture.database, &fixture.owner, mine)
        .await
        .unwrap();
    assert!(
        detail.affected_components.is_empty(),
        "the stranger's project is not listed"
    );
    assert!(matches!(
        findings::detail(&fixture.database, &stranger, mine).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        findings::list(
            &fixture.database,
            &fixture.owner,
            strangers_project,
            &Filter::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        findings::ignore(&fixture.database, &stranger, mine, "mine now", None, None).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn filters_and_overview_count_by_severity() {
    let fixture = Fixture::new().await;
    fixture
        .source
        .publish(lodash_advisory("2024-01-01T00:00:00Z"), &[LODASH]);
    fixture.source.publish(minimist_advisory(), &[MINIMIST]);
    let project = fixture.upload(&[LODASH, MINIMIST]).await;
    fixture.run().await;

    let high = findings::list(
        &fixture.database,
        &fixture.viewer,
        project,
        &Filter {
            severities: vec![Severity::High],
            ..Filter::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].purl, LODASH);
    let ignored = findings::list(
        &fixture.database,
        &fixture.viewer,
        project,
        &Filter {
            statuses: vec![Status::Ignored],
            ecosystem: Some("npm".to_owned()),
            ..Filter::default()
        },
    )
    .await
    .unwrap();
    assert!(ignored.is_empty());
    assert_eq!(
        findings::ecosystems(&fixture.database, &fixture.viewer, project)
            .await
            .unwrap(),
        ["npm"]
    );

    findings::ignore(
        &fixture.database,
        &fixture.member,
        high[0].id,
        "accepted",
        None,
        None,
    )
    .await
    .unwrap();
    let overview = findings::overview(&fixture.database, &fixture.viewer, fixture.organization, 0)
        .await
        .unwrap();
    assert_eq!(overview.len(), 1);
    assert_eq!(overview[0].open.critical, 1);
    assert_eq!(overview[0].open.high, 0);
    assert_eq!(overview[0].ignored, 1);
    assert!(overview[0].last_upload_at.is_some());
    let counts = findings::open_counts(&fixture.database).await.unwrap();
    assert_eq!(counts.total(), 1);
}

#[tokio::test]
async fn recent_runs_cover_the_organization_and_hide_instance_errors() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(&[LODASH]).await;
    fixture.run().await;
    fixture
        .evaluator
        .run(
            Trigger::Manual,
            Scope::Project(project),
            Some(fixture.member.user_id),
        )
        .await
        .unwrap();
    fixture.source.set_failing(true);
    fixture.run().await;

    let runs =
        evaluation::recent_runs(&fixture.database, &fixture.viewer, fixture.organization, 10)
            .await
            .unwrap();
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].status, "failed");
    assert_eq!(
        runs[0].error.as_deref(),
        Some("the run could not complete"),
        "instance-wide errors are summarized for members"
    );
    assert_eq!(runs[1].scope, "project");
    assert_eq!(runs[1].trigger, "manual");
    let other = organizations::create(&fixture.database, &fixture.owner, "other", "Other")
        .await
        .unwrap();
    let runs = evaluation::recent_runs(&fixture.database, &fixture.owner, other.id, 10)
        .await
        .unwrap();
    assert_eq!(runs.len(), 2, "only instance-wide runs");
}

#[tokio::test]
async fn a_run_that_panics_can_be_closed_as_failed() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(&[LODASH]).await;
    let evaluator = Arc::new(Evaluator::new(
        fixture.database.clone(),
        Arc::clone(&fixture.source),
    ));
    fixture.source.panic_once();
    let run = tokio::spawn({
        let evaluator = Arc::clone(&evaluator);
        async move {
            evaluator
                .run(Trigger::Upload, Scope::Project(project), None)
                .await
        }
    })
    .await;
    assert!(run.unwrap_err().is_panic());

    let run_id = evaluator
        .take_unfinished_run()
        .expect("the run's row exists");
    assert_eq!(evaluator.take_unfinished_run(), None, "taken once");
    let row = runs::Entity::find_by_id(run_id)
        .one(&fixture.database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "running");

    let outcome = evaluation::fail_unfinished(&fixture.database, run_id)
        .await
        .unwrap()
        .expect("the run was running");
    assert_eq!(outcome.run_id, run_id);
    assert_eq!(outcome.scope, Scope::Project(project));
    assert_eq!(outcome.trigger, Trigger::Upload);
    assert_eq!(
        outcome.error.as_deref(),
        Some(evaluation::STOPPED_UNEXPECTEDLY)
    );
    let row = runs::Entity::find_by_id(run_id)
        .one(&fixture.database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "failed");
    assert!(row.finished_at.is_some());
    assert_eq!(row.error.as_deref(), Some(evaluation::STOPPED_UNEXPECTEDLY));
    assert!(
        evaluation::fail_unfinished(&fixture.database, run_id)
            .await
            .unwrap()
            .is_none(),
        "a finished run is left alone"
    );

    // A run that completes leaves nothing to close.
    evaluator
        .run(Trigger::Manual, Scope::All, None)
        .await
        .unwrap();
    assert_eq!(evaluator.take_unfinished_run(), None);
}

#[tokio::test]
async fn runs_left_running_by_a_restart_are_failed() {
    let fixture = Fixture::new().await;
    let finished = fixture.run().await;
    let started_at = Utc::now().fixed_offset();
    let interrupted = runs::ActiveModel {
        trigger: Set("manual".to_owned()),
        scope: Set("organization".to_owned()),
        organization_id: Set(Some(fixture.organization)),
        project_id: Set(None),
        triggered_by_user_id: Set(None),
        started_at: Set(started_at),
        finished_at: Set(None),
        status: Set("running".to_owned()),
        error: Set(None),
        ..Default::default()
    }
    .insert(&fixture.database)
    .await
    .unwrap();

    let outcomes = evaluation::fail_interrupted(&fixture.database)
        .await
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].run_id, interrupted.id);
    assert_eq!(outcomes[0].scope, Scope::Organization(fixture.organization));
    assert_eq!(outcomes[0].trigger, Trigger::Manual);
    assert!(!outcomes[0].succeeded());
    let rows = runs::Entity::find().all(&fixture.database).await.unwrap();
    let interrupted = rows.iter().find(|row| row.id == interrupted.id).unwrap();
    assert_eq!(interrupted.status, "failed");
    assert!(interrupted.finished_at.is_some());
    let finished = rows.iter().find(|row| row.id == finished.run_id).unwrap();
    assert_eq!(finished.status, "succeeded");
    assert_eq!(finished.error, None);

    assert!(
        evaluation::fail_interrupted(&fixture.database)
            .await
            .unwrap()
            .is_empty()
    );
}
