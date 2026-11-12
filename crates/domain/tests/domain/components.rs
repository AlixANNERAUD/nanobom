//! The components of a project version, a page at a time.

use std::sync::Arc;

use nanobom_domain::{
    Error,
    access::Actor,
    evaluation::{Evaluator, Scope, Trigger},
    findings::{self, Filter},
    inventory::{
        self, ComponentFilter, ComponentPage, ComponentQuery, DependencyKind, ListedComponent,
        UploadSource,
    },
    organizations,
    testing::{self, FakeSource},
    tokens,
    users::{self, NewUser},
};
use nanobom_osv::Severity;
use sea_orm::DatabaseConnection;
use serde_json::json;

const ALPHA: &str = "pkg:npm/alpha@1.0.0";
const BRAVO: &str = "pkg:npm/bravo@1.0.0";
const CHARLIE: &str = "pkg:npm/charlie@1.0.0";
const DELTA: &str = "pkg:npm/delta@1.0.0";
const FOXTROT: &str = "pkg:maven/org.example/Foxtrot@1.0";

const CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const MEDIUM: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";

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

/// Version `1.0`: the project depends on alpha and bravo, bravo on charlie; charlie and Foxtrot
/// give no license; one component has no package URL.
fn sbom() -> inventory::ParsedSbom {
    let mit = json!([{ "license": { "id": "MIT" } }]);
    let component = |name: &str, purl: &str, licensed: bool| {
        let mut component = json!({
            "type": "library", "bom-ref": purl, "name": name, "version": "1.0.0", "purl": purl
        });
        if licensed {
            component["licenses"] = mit.clone();
        }
        component
    };
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "app", "name": "web"}},
        "components": [
            component("alpha", ALPHA, true),
            component("bravo", BRAVO, true),
            component("charlie", CHARLIE, false),
            component("delta", DELTA, true),
            component("Foxtrot", FOXTROT, false),
            {"type": "library", "name": "vendored", "version": "2.0"}
        ],
        "dependencies": [
            {"ref": "app", "dependsOn": [ALPHA, BRAVO]},
            {"ref": BRAVO, "dependsOn": [CHARLIE]}
        ]
    });
    inventory::parse(document.to_string().as_bytes()).unwrap()
}

fn advisory(id: &str, package: &str, vector: &str) -> serde_json::Value {
    json!({
        "id": id,
        "modified": "2024-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": vector}],
        "affected": [{"package": {"ecosystem": "npm", "name": package},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}]
    })
}

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    project: i64,
    token: nanobom_entity::upload_tokens::Model,
}

/// `acme/web` version `1.0`, evaluated: bravo has a medium finding open, charlie a critical and
/// a medium one, delta a critical one the owner ignored.
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
            version: Some("1.0".to_owned()),
            ..UploadSource::default()
        },
    )
    .await
    .unwrap()
    .project_id;
    let source = Arc::new(FakeSource::default());
    source.publish(advisory("GHSA-bravo", "bravo", MEDIUM), &[BRAVO]);
    source.publish(advisory("GHSA-charlie-1", "charlie", CRITICAL), &[CHARLIE]);
    source.publish(advisory("GHSA-charlie-2", "charlie", MEDIUM), &[CHARLIE]);
    source.publish(advisory("GHSA-delta", "delta", CRITICAL), &[DELTA]);
    Evaluator::new(database.clone(), source)
        .run(Trigger::Upload, Scope::Project(project), None)
        .await
        .unwrap();
    let delta = findings::list(&database, &owner, project, &Filter::default())
        .await
        .unwrap()
        .into_iter()
        .find(|finding| finding.purl == DELTA)
        .unwrap()
        .id;
    findings::ignore(&database, &owner, delta, "Not shipped", None, None)
        .await
        .unwrap();
    Fixture {
        database,
        owner,
        project,
        token,
    }
}

async fn list(fixture: &Fixture, version: Option<&str>, query: ComponentQuery) -> ComponentPage {
    inventory::list_components(
        &fixture.database,
        &fixture.owner,
        fixture.project,
        version,
        &query,
    )
    .await
    .unwrap()
}

fn names(page: &ComponentPage) -> Vec<&str> {
    page.components
        .iter()
        .map(|component| component.name.as_str())
        .collect()
}

fn component<'a>(page: &'a ComponentPage, name: &str) -> &'a ListedComponent {
    page.components
        .iter()
        .find(|component| component.name == name)
        .unwrap_or_else(|| panic!("{name} is listed"))
}

#[tokio::test]
async fn components_are_listed_with_open_findings_first() {
    let fixture = fixture().await;
    let page = list(&fixture, Some("1.0"), ComponentQuery::default()).await;
    assert_eq!(page.version.name, "1.0");
    // Worst open finding first, then by name; delta's only finding is ignored.
    assert_eq!(
        names(&page),
        ["charlie", "bravo", "alpha", "delta", "org.example/Foxtrot"]
    );
    assert_eq!((page.total, page.matching, page.without_purl), (5, 5, 1));
    assert_eq!(
        (page.page, page.per_page),
        (1, inventory::COMPONENTS_PER_PAGE)
    );
    assert!(!page.has_next());

    let charlie = component(&page, "charlie");
    assert_eq!(charlie.open_findings, 2);
    assert_eq!(charlie.worst_severity, Some(Severity::Critical));
    assert_eq!(charlie.only_open_finding, None);
    assert_eq!(charlie.license, None);
    assert_eq!(charlie.dependency, DependencyKind::Transitive);
    let bravo = component(&page, "bravo");
    assert_eq!(bravo.open_findings, 1);
    assert_eq!(bravo.worst_severity, Some(Severity::Medium));
    assert!(bravo.only_open_finding.is_some());
    assert_eq!(bravo.dependency, DependencyKind::Direct);
    let delta = component(&page, "delta");
    assert_eq!(delta.open_findings, 0);
    assert_eq!(delta.worst_severity, None);
    assert_eq!(delta.only_open_finding, None);
    let alpha = component(&page, "alpha");
    assert_eq!(alpha.license.as_deref(), Some("MIT"));
    assert_eq!(alpha.purl, ALPHA);
    assert_eq!(alpha.ecosystem, "npm");
    assert_eq!(alpha.version.as_deref(), Some("1.0.0"));
    assert_eq!(alpha.dependency, DependencyKind::Direct);

    let finding = findings::detail(
        &fixture.database,
        &fixture.owner,
        bravo.only_open_finding.unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(finding.finding.purl, BRAVO);
}

#[tokio::test]
async fn components_are_paged_in_a_stable_order() {
    let fixture = fixture().await;
    let page = |number| ComponentQuery {
        page: number,
        per_page: 2,
        ..ComponentQuery::default()
    };
    let first = list(&fixture, None, page(1)).await;
    assert_eq!(names(&first), ["charlie", "bravo"]);
    assert!(first.has_next());
    assert_eq!(first.matching, 5);
    // Page 0 is the first page.
    assert_eq!(names(&list(&fixture, None, page(0)).await), names(&first));
    let second = list(&fixture, None, page(2)).await;
    assert_eq!(names(&second), ["alpha", "delta"]);
    assert!(second.has_next());
    let third = list(&fixture, None, page(3)).await;
    assert_eq!(names(&third), ["org.example/Foxtrot"]);
    assert_eq!(third.page, 3);
    assert!(!third.has_next());
    // A page past the last is the last one.
    let past = list(&fixture, None, page(4)).await;
    assert_eq!(names(&past), names(&third));
    assert_eq!(past.page, 3);
    assert_eq!(past.matching, 5);
    let far = list(&fixture, None, page(u64::MAX)).await;
    assert_eq!(far.page, 3);
    assert!(!far.has_next());

    let large = ComponentQuery {
        per_page: 10_000,
        ..ComponentQuery::default()
    };
    assert_eq!(
        list(&fixture, None, large).await.per_page,
        inventory::MAXIMUM_COMPONENTS_PER_PAGE
    );
}

#[tokio::test]
async fn components_are_filtered_by_name_and_findings_and_license() {
    let fixture = fixture().await;
    let by_name = |name: &str| ComponentQuery {
        name: name.to_owned(),
        ..ComponentQuery::default()
    };
    // Case-insensitive, anywhere in the name, the namespace included.
    let page = list(&fixture, None, by_name("  fOxT ")).await;
    assert_eq!(names(&page), ["org.example/Foxtrot"]);
    assert_eq!((page.matching, page.total), (1, 5));
    assert_eq!(
        names(&list(&fixture, None, by_name("EXAMPLE/")).await),
        ["org.example/Foxtrot"]
    );
    assert_eq!(
        names(&list(&fixture, None, by_name("rl")).await),
        ["charlie"]
    );
    // Wildcards are taken literally.
    assert!(
        list(&fixture, None, by_name("%"))
            .await
            .components
            .is_empty()
    );
    assert!(
        list(&fixture, None, by_name("_lpha"))
            .await
            .components
            .is_empty()
    );

    let open = list(
        &fixture,
        None,
        ComponentQuery {
            filter: ComponentFilter::WithOpenFindings,
            ..ComponentQuery::default()
        },
    )
    .await;
    // delta's finding is ignored, not open.
    assert_eq!(names(&open), ["charlie", "bravo"]);
    assert_eq!((open.matching, open.total), (2, 5));

    let unlicensed = list(
        &fixture,
        None,
        ComponentQuery {
            filter: ComponentFilter::WithoutLicense,
            ..ComponentQuery::default()
        },
    )
    .await;
    assert_eq!(names(&unlicensed), ["charlie", "org.example/Foxtrot"]);

    let both = list(
        &fixture,
        None,
        ComponentQuery {
            name: "CHAR".to_owned(),
            filter: ComponentFilter::WithOpenFindings,
            ..ComponentQuery::default()
        },
    )
    .await;
    assert_eq!(names(&both), ["charlie"]);
}

#[tokio::test]
async fn components_of_a_named_or_the_latest_version() {
    let fixture = fixture().await;
    // `2.0` becomes the latest; its SBOM has no dependency graph.
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "alpha", "version": "2.0.0", "purl": "pkg:npm/alpha@2.0.0"}
        ]
    });
    inventory::ingest(
        &fixture.database,
        &fixture.token,
        "acme",
        "web",
        inventory::parse(document.to_string().as_bytes()).unwrap(),
        UploadSource {
            version: Some("2.0".to_owned()),
            ..UploadSource::default()
        },
    )
    .await
    .unwrap();

    let latest = list(&fixture, None, ComponentQuery::default()).await;
    assert_eq!(latest.version.name, "2.0");
    assert_eq!(names(&latest), ["alpha"]);
    assert_eq!((latest.total, latest.without_purl), (1, 0));
    assert_eq!(latest.components[0].dependency, DependencyKind::Unknown);
    assert_eq!(latest.components[0].version.as_deref(), Some("2.0.0"));

    let older = list(&fixture, Some("1.0"), ComponentQuery::default()).await;
    assert_eq!(older.version.name, "1.0");
    assert_eq!(older.total, 5);

    let missing = inventory::list_components(
        &fixture.database,
        &fixture.owner,
        fixture.project,
        Some("9.9"),
        &ComponentQuery::default(),
    )
    .await;
    assert!(matches!(missing, Err(Error::NotFound)));
}

#[tokio::test]
async fn another_organization_cannot_list_the_components() {
    let fixture = fixture().await;
    let stranger = user(&fixture.database, "stranger").await;
    organizations::create(&fixture.database, &stranger, "other", "Other")
        .await
        .unwrap();
    let result = inventory::list_components(
        &fixture.database,
        &stranger,
        fixture.project,
        None,
        &ComponentQuery::default(),
    )
    .await;
    assert!(matches!(result, Err(Error::NotFound)));
}
