//! The vulnerability report of a project version.

use std::sync::Arc;

use chrono::Utc;
use nanobom_domain::{
    Error,
    access::Actor,
    evaluation::{Evaluator, Scope, Trigger},
    findings::{self, Filter, Justification, Status},
    inventory::{self, UploadSource},
    licenses::{self, Action, Policy, Rule},
    organizations, projects,
    report::{self, Licenses},
    testing::{self, FakeSource},
    tokens,
    users::{self, NewUser},
};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection};
use serde_json::json;

const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";
const LEFT_PAD: &str = "pkg:npm/left-pad@1.0.0";

async fn user(database: &DatabaseConnection, username: &str) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: username.to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    Actor::from_user(&user)
}

/// lodash and minimist under MIT, left-pad without a license, and a component without a
/// package URL, which nanobom skips.
fn sbom() -> inventory::ParsedSbom {
    let mit = json!([{ "license": { "id": "MIT" } }]);
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.20", "purl": LODASH, "licenses": mit},
            {"type": "library", "name": "minimist", "version": "1.2.5", "purl": MINIMIST, "licenses": mit},
            {"type": "library", "name": "left-pad", "version": "1.0.0", "purl": LEFT_PAD},
            {"type": "library", "name": "vendored", "version": "2.0"}
        ]
    });
    inventory::parse(document.to_string().as_bytes()).unwrap()
}

fn advisory(id: &str, cve: &str, package: &str, fixed: &str, vector: &str) -> serde_json::Value {
    json!({
        "id": id,
        "modified": "2024-01-01T00:00:00Z",
        "aliases": [cve],
        "summary": format!("Summary of {id}"),
        "severity": [{"type": "CVSS_V3", "score": vector}],
        "affected": [{"package": {"ecosystem": "npm", "name": package},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]
    })
}

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    organization: i64,
    project: i64,
}

/// `acme/web` version `1.0`, evaluated: lodash open (high, known exploited), minimist ignored
/// by the owner, left-pad fixed by a later run.
async fn fixture() -> Fixture {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    let secret = tokens::create(&database, &owner, organization, None, "CI")
        .await
        .unwrap()
        .secret;
    let token = tokens::authenticate(&database, &secret)
        .await
        .unwrap()
        .unwrap();
    let project = inventory::ingest(
        &database,
        &token,
        "acme",
        "web",
        sbom(),
        UploadSource {
            source_commit: Some("abc123".to_owned()),
            image_tag: Some("web:1.0".to_owned()),
            version: Some("1.0".to_owned()),
            latest: None,
        },
    )
    .await
    .unwrap()
    .project_id;

    let source = Arc::new(FakeSource::default());
    source.publish(
        advisory(
            "GHSA-35jh-r3h4-6jhm",
            "CVE-2021-23337",
            "lodash",
            "4.17.21",
            "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        ),
        &[LODASH],
    );
    source.publish(
        advisory(
            "GHSA-xvch-5gv4-984h",
            "CVE-2021-44906",
            "minimist",
            "1.2.6",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        &[MINIMIST],
    );
    source.publish(
        advisory(
            "GHSA-left-pad0-0000",
            "CVE-2020-0001",
            "left-pad",
            "1.0.1",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
        &[LEFT_PAD],
    );
    let evaluator = Evaluator::new(database.clone(), Arc::clone(&source));
    evaluator
        .run(Trigger::Upload, Scope::Project(project), None)
        .await
        .unwrap();
    source.retract("GHSA-left-pad0-0000", LEFT_PAD);
    evaluator
        .run(Trigger::Scheduled, Scope::All, None)
        .await
        .unwrap();

    let minimist = findings::list(&database, &owner, project, &Filter::default())
        .await
        .unwrap()
        .into_iter()
        .find(|finding| finding.purl == MINIMIST)
        .unwrap()
        .id;
    findings::ignore(
        &database,
        &owner,
        minimist,
        "Only used by the build",
        Some(Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();

    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_ransomware: Set(false),
        epss_score: Set(Some(0.5)),
        epss_percentile: Set(Some(0.97)),
        kev_checked_at: Set(Some(Utc::now().fixed_offset())),
        epss_checked_at: Set(Some(Utc::now().fixed_offset())),
        ..Default::default()
    }
    .insert(&database)
    .await
    .unwrap();
    Fixture {
        database,
        owner,
        organization,
        project,
    }
}

#[tokio::test]
async fn the_report_describes_a_version() {
    let fixture = fixture().await;
    let report = report::build(
        &fixture.database,
        &fixture.owner,
        "acme",
        "web",
        Some("1.0"),
        30,
    )
    .await
    .unwrap();

    assert_eq!(report.organization_name, "Acme");
    assert_eq!(report.project_slug, "web");
    assert_eq!(report.version, "1.0");
    assert!(report.latest && report.active && !report.stale);
    let upload = report.upload.as_ref().expect("the upload");
    assert_eq!(upload.source_commit.as_deref(), Some("abc123"));
    assert_eq!(upload.image_tag.as_deref(), Some("web:1.0"));
    assert_eq!(upload.components_without_purl, 1);
    assert_eq!(report.component_count, 3);
    assert!(report.last_evaluation.is_some());
    assert!(report.kev_checked_at.is_some() && report.epss_checked_at.is_some());

    assert_eq!(report.summary.open.total(), 1);
    assert_eq!(report.summary.open.get(Severity::High), 1);
    assert_eq!(report.summary.known_exploited, 1);
    assert_eq!(report.summary.ignored, 1);
    assert_eq!(report.summary.fixed_recently, 1);

    assert_eq!(report.open.len(), 1);
    let open = &report.open[0];
    assert_eq!(open.finding.vulnerability_id, "GHSA-35jh-r3h4-6jhm");
    assert_eq!(open.finding.aliases, ["CVE-2021-23337"]);
    assert!(open.finding.exploitation.known_exploited);
    assert_eq!(open.finding.exploitation.epss_percentile, Some(0.97));
    assert_eq!(open.fixed_versions, ["4.17.21"]);

    assert_eq!(report.assessed.len(), 1);
    let assessed = &report.assessed[0];
    assert_eq!(assessed.finding.purl, MINIMIST);
    assert_eq!(assessed.finding.status, Status::Ignored);
    assert_eq!(
        assessed.finding.ignore_reason.as_deref(),
        Some("Only used by the build")
    );
    assert_eq!(
        assessed.finding.ignore_justification,
        Some(Justification::CodeNotReachable)
    );
    assert_eq!(assessed.ignored_by.as_deref(), Some("owner"));
    assert!(assessed.ignored_at.is_some());

    let Licenses::Counts(counts) = &report.licenses else {
        panic!("no policy: counts by license");
    };
    assert_eq!(counts.groups, [("MIT".to_owned(), 2)]);
    assert_eq!(counts.other, 0);
    assert_eq!(counts.without, 1);

    // Without a version, the latest one, which `1.0` is.
    let latest = report::build(&fixture.database, &fixture.owner, "acme", "web", None, 30)
        .await
        .unwrap();
    assert_eq!(latest.version, "1.0");
    assert_eq!(latest.open, report.open);
}

#[tokio::test]
async fn a_policy_lists_the_violations() {
    let fixture = fixture().await;
    licenses::set_policy(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        &Policy {
            unlisted: Action::Allow,
            unknown: Action::Warn,
            rules: vec![Rule {
                license: "MIT".to_owned(),
                action: Action::Forbid,
            }],
        },
    )
    .await
    .unwrap();
    let report = report::build(&fixture.database, &fixture.owner, "acme", "web", None, 30)
        .await
        .unwrap();
    let Licenses::Policy(violations) = report.licenses else {
        panic!("a policy: its violations");
    };
    assert_eq!(violations.counts.forbidden, 2);
    assert_eq!(violations.counts.warned, 1);
    assert_eq!(violations.items[0].name, "lodash");
}

#[tokio::test]
async fn a_project_without_uploads_for_long_is_stale() {
    let fixture = fixture().await;
    let project = nanobom_entity::projects::ActiveModel {
        id: Set(fixture.project),
        last_upload_at: Set(Some(Utc::now().fixed_offset() - chrono::Duration::days(40))),
        ..Default::default()
    };
    project.update(&fixture.database).await.unwrap();
    let report = report::build(&fixture.database, &fixture.owner, "acme", "web", None, 30)
        .await
        .unwrap();
    assert!(report.stale);
    let report = report::build(&fixture.database, &fixture.owner, "acme", "web", None, 0)
        .await
        .unwrap();
    assert!(!report.stale, "0 turns staleness off");
}

#[tokio::test]
async fn readers_out_of_reach_find_nothing() {
    let fixture = fixture().await;
    let database = &fixture.database;
    assert!(matches!(
        report::build(database, &fixture.owner, "acme", "web", Some("2.0"), 30).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        report::build(database, &fixture.owner, "acme", "missing", None, 30).await,
        Err(Error::NotFound)
    ));

    let outsider = user(database, "outsider").await;
    organizations::create(database, &outsider, "other", "Other")
        .await
        .unwrap();
    assert!(matches!(
        report::build(database, &outsider, "acme", "web", None, 30).await,
        Err(Error::NotFound)
    ));

    // A token of another project of the organization reaches only that project.
    projects::create(database, &fixture.owner, fixture.organization, "api", "API")
        .await
        .unwrap();
    let secret = tokens::create(
        database,
        &fixture.owner,
        fixture.organization,
        Some("api"),
        "API",
    )
    .await
    .unwrap()
    .secret;
    let token = tokens::authenticate(database, &secret)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        report::build(database, &token, "acme", "web", None, 30).await,
        Err(Error::NotFound)
    ));
    assert!(
        report::build(database, &token, "acme", "api", None, 30)
            .await
            .is_ok()
    );

    // An organization token reads it, as a viewer would.
    let secret = tokens::create(
        database,
        &fixture.owner,
        fixture.organization,
        None,
        "Reports",
    )
    .await
    .unwrap()
    .secret;
    let token = tokens::authenticate(database, &secret)
        .await
        .unwrap()
        .unwrap();
    let report = report::build(database, &token, "acme", "web", None, 30)
        .await
        .unwrap();
    assert_eq!(report.assessed[0].ignored_by.as_deref(), Some("owner"));
}
