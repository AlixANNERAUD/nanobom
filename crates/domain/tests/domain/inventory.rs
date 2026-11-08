//! SBOM parsing with a document from each supported generator, upload tokens and intake.

use nanobom_domain::{
    Error,
    access::{Actor, Role},
    inventory::{self, ParsedSbom, UploadSource},
    memberships, organizations, projects, testing, tokens,
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;

fn sbom_document(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/sboms/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn purls(sbom: &ParsedSbom) -> Vec<&str> {
    sbom.components
        .iter()
        .map(|component| component.purl.as_str())
        .collect()
}

#[test]
fn parses_cargo_cyclonedx() {
    let sbom = inventory::parse(&sbom_document("cargo-cyclonedx.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.5");
    assert_eq!(
        purls(&sbom),
        ["pkg:cargo/itoa@1.0.18", "pkg:cargo/smallvec@1.6.0"]
    );
    assert_eq!(sbom.skipped_count, 0);
    let smallvec = &sbom.components[1];
    assert_eq!(smallvec.ecosystem, "cargo");
    assert_eq!(smallvec.name, "smallvec");
    assert_eq!(smallvec.version.as_deref(), Some("1.6.0"));
}

#[test]
fn parses_cyclonedx_npm() {
    let sbom = inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(
        purls(&sbom),
        [
            "pkg:npm/%40babel/helper-string-parser@7.25.9",
            "pkg:npm/lodash@4.17.20",
            "pkg:npm/minimist@1.2.5",
        ]
    );
    assert_eq!(sbom.components[0].name, "@babel/helper-string-parser");
}

#[test]
fn parses_cyclonedx_py() {
    let sbom = inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(
        purls(&sbom),
        ["pkg:pypi/idna@3.6", "pkg:pypi/urllib3@1.26.4"]
    );
}

#[test]
fn parses_syft_and_strips_qualifiers_for_queries() {
    let sbom = inventory::parse(&sbom_document("syft.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(sbom.components.len(), 15);
    assert_eq!(sbom.skipped_count, 0, "files and the OS are not packages");
    let busybox = sbom
        .components
        .iter()
        .find(|component| component.purl.starts_with("pkg:apk/alpine/busybox@"))
        .unwrap();
    assert_eq!(busybox.ecosystem, "apk");
    assert_eq!(busybox.name, "alpine/busybox");
    assert!(busybox.purl.contains("distro=alpine-3.19.0"));
    assert_eq!(busybox.query_purl, "pkg:apk/alpine/busybox@1.36.1-r15");
}

#[test]
fn reports_components_without_a_usable_purl() {
    let document = br#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"type": "library", "name": "vendored", "version": "1.0"},
            {"type": "library", "name": "broken", "purl": "not a purl"},
            {"type": "library", "name": "parent", "version": "2.0", "purl": "pkg:npm/parent@2.0",
             "components": [{"type": "library", "name": "child", "version": "3.0", "purl": "pkg:npm/child@3.0"}]},
            {"type": "library", "name": "parent", "version": "2.0", "purl": "pkg:npm/parent@2.0"}
        ]
    }"#;
    let sbom = inventory::parse(document).unwrap();
    assert_eq!(purls(&sbom), ["pkg:npm/child@3.0", "pkg:npm/parent@2.0"]);
    assert_eq!(sbom.skipped_count, 2);
    assert_eq!(sbom.skipped[0].name, "vendored");
    assert_eq!(sbom.skipped[0].reason, "no package URL");
    assert_eq!(sbom.skipped[1].name, "broken");
}

#[test]
fn rejects_documents_that_are_not_supported_cyclonedx() {
    for document in [
        &b"not json"[..],
        br#"{"spdxVersion": "SPDX-2.3"}"#,
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.2", "version": 1}"#,
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": 3}"#,
    ] {
        assert!(matches!(inventory::parse(document), Err(Error::Invalid(_))));
    }
}

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    viewer: Actor,
    organization: i64,
}

async fn setup() -> Fixture {
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
    let viewer = users::create(
        &database,
        NewUser {
            username: "viewer".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let viewer = Actor::from_user(&viewer);
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    memberships::add(&database, &owner, organization, "viewer", Role::Viewer)
        .await
        .unwrap();
    Fixture {
        database,
        owner,
        viewer,
        organization,
    }
}

#[tokio::test]
async fn tokens_are_shown_once_and_stored_hashed() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    assert!(created.secret.starts_with("nanobom_"));
    assert_eq!(created.secret.len(), "nanobom_".len() + 64);
    assert!(created.secret.starts_with(&created.token.prefix));

    let listed = tokens::list(database, &fixture.owner, fixture.organization)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_none());
    assert!(matches!(
        tokens::list(database, &fixture.viewer, fixture.organization).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        tokens::create(database, &fixture.viewer, fixture.organization, None, "x").await,
        Err(Error::Forbidden)
    ));

    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    assert!(token.last_used_at.is_some());
    assert_ne!(token.token_hash, created.secret);
    assert!(
        tokens::authenticate(database, "nanobom_wrong")
            .await
            .unwrap()
            .is_none()
    );

    tokens::revoke(database, &fixture.owner, created.token.id)
        .await
        .unwrap();
    assert!(
        tokens::authenticate(database, &created.secret)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn organization_tokens_create_projects_and_uploads_replace_components() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();

    let outcome = inventory::ingest(
        database,
        &token,
        "acme",
        "Web",
        inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap(),
        UploadSource {
            source_commit: Some("0123abcd".to_owned()),
            image_tag: None,
        },
    )
    .await
    .unwrap();
    assert!(outcome.project_created);
    assert_eq!(outcome.project, "web");
    assert_eq!(outcome.component_count, 3);

    let second = inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    assert!(!second.project_created);
    assert_eq!(second.project_id, outcome.project_id);

    let components = inventory::components(database, &fixture.viewer, outcome.project_id)
        .await
        .unwrap();
    let current: Vec<_> = components
        .iter()
        .map(|component| component.purl.as_str())
        .collect();
    assert_eq!(current, ["pkg:pypi/idna@3.6", "pkg:pypi/urllib3@1.26.4"]);

    let history = inventory::uploads(database, &fixture.viewer, outcome.project_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].source_commit.as_deref(), Some("0123abcd"));
    assert_eq!(history[1].component_count, 3);
    let project = projects::find(database, &fixture.viewer, fixture.organization, "web")
        .await
        .unwrap();
    assert!(project.last_upload_at.is_some());
}

#[tokio::test]
async fn project_tokens_only_reach_their_project() {
    let fixture = setup().await;
    let database = &fixture.database;
    projects::create(database, &fixture.owner, fixture.organization, "api", "API")
        .await
        .unwrap();
    projects::create(database, &fixture.owner, fixture.organization, "web", "Web")
        .await
        .unwrap();
    let created = tokens::create(
        database,
        &fixture.owner,
        fixture.organization,
        Some("api"),
        "API CI",
    )
    .await
    .unwrap();
    assert_eq!(created.token.project_slug.as_deref(), Some("api"));
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    let sbom = || inventory::parse(&sbom_document("cargo-cyclonedx.json")).unwrap();

    inventory::ingest(
        database,
        &token,
        "acme",
        "api",
        sbom(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "acme",
            "web",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "acme",
            "new",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    let other = organizations::create(database, &fixture.owner, "other", "Other")
        .await
        .unwrap();
    projects::create(database, &fixture.owner, other.id, "api", "API")
        .await
        .unwrap();
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "other",
            "api",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn search_finds_components_by_name_and_version_in_visible_organizations() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();

    let found = inventory::search(database, &fixture.viewer, "Lodash")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].organization_slug, "acme");
    assert_eq!(found[0].project_slug, "web");
    assert_eq!(found[0].version.as_deref(), Some("4.17.20"));
    assert_eq!(
        inventory::search(database, &fixture.viewer, "lodash 4.17")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        inventory::search(database, &fixture.viewer, "lodash@4.17.2")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        inventory::search(database, &fixture.viewer, "lodash 5")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        inventory::search(database, &fixture.viewer, "  ")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        inventory::search(database, &fixture.viewer, "lod_sh")
            .await
            .unwrap()
            .is_empty(),
        "wildcards in the query match themselves"
    );

    let outsider = users::create(
        database,
        NewUser {
            username: "outsider".to_owned(),
            ..NewUser::default()
        },
        true,
    )
    .await
    .unwrap();
    let outsider = Actor::from_user(&outsider);
    assert!(
        inventory::search(database, &outsider, "lodash")
            .await
            .unwrap()
            .is_empty()
    );
}
