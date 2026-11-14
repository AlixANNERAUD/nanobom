//! Public pages: turned on, replaced and off by those who manage projects, read with the key
//! alone, and showing only their allowlist.

use chrono::Utc;
use nanobom_domain::{
    Error,
    access::{Actor, Role},
    badges,
    findings::{self, Justification},
    memberships, organizations, projects, public_pages, testing,
    tokens::{self, Scope},
    users::{self, NewUser},
};
use nanobom_entity::{findings as findings_entity, project_versions, vulnerabilities};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};

/// Strings that must never reach a public page or its VEX document.
const ORGANIZATION_SLUG: &str = "initech-private";
const ORGANIZATION_NAME: &str = "Initech Private Holdings";
const TRIAGER: &str = "zelda-triager";
const TOKEN_NAME: &str = "token-gizmo-ci";
const REASON: &str = "internal note: ticket SEC-4242, ask Bob";
const TOKEN_REASON: &str = "imported from the scanner of team Falcon";

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    member: Actor,
    viewer: Actor,
    stranger: Actor,
    organization: i64,
    project: i64,
}

impl Fixture {
    async fn new() -> Self {
        let database = testing::database().await;
        let mut actors = Vec::new();
        for username in [TRIAGER, "member", "viewer", "stranger"] {
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
        let [owner, member, viewer, stranger] = actors.try_into().unwrap();
        let organization =
            organizations::create(&database, &owner, ORGANIZATION_SLUG, ORGANIZATION_NAME)
                .await
                .unwrap()
                .id;
        memberships::add(&database, &owner, organization, "member", Role::Member)
            .await
            .unwrap();
        memberships::add(&database, &owner, organization, "viewer", Role::Viewer)
            .await
            .unwrap();
        organizations::create(&database, &stranger, "globex", "Globex")
            .await
            .unwrap();
        let project = projects::create(&database, &owner, organization, "web", "Web shop")
            .await
            .unwrap()
            .id;
        Self {
            database,
            owner,
            member,
            viewer,
            stranger,
            organization,
            project,
        }
    }

    /// Marks the latest version of a project as uploaded to, as an upload would.
    async fn uploaded(&self, project: i64) {
        let version = testing::latest_version(&self.database, project).await;
        let version = project_versions::Entity::find_by_id(version)
            .one(&self.database)
            .await
            .unwrap()
            .unwrap();
        let mut version: project_versions::ActiveModel = version.into();
        version.last_upload_at = Set(Some(Utc::now().fixed_offset()));
        version.update(&self.database).await.unwrap();
    }

    /// An open finding of the latest version of a project, on its own component; returns its
    /// identifier.
    async fn finding(&self, project: i64, vulnerability_id: &str, severity: &str) -> i64 {
        if vulnerabilities::Entity::find_by_id(vulnerability_id)
            .one(&self.database)
            .await
            .unwrap()
            .is_none()
        {
            vulnerabilities::ActiveModel {
                id: Set(vulnerability_id.to_owned()),
                modified: Set(Utc::now().fixed_offset()),
                aliases: Set("[]".to_owned()),
                summary: Set(Some(format!("Summary of {vulnerability_id}"))),
                severity: Set(severity.to_owned()),
                record: Set("{}".to_owned()),
                fetched_at: Set(Utc::now().fixed_offset()),
                ..Default::default()
            }
            .insert(&self.database)
            .await
            .unwrap();
        }
        findings_entity::ActiveModel {
            project_id: Set(project),
            version_id: Set(Some(testing::latest_version(&self.database, project).await)),
            purl: Set(format!("pkg:npm/{}@1.0.0", vulnerability_id.to_lowercase())),
            ecosystem: Set("npm".to_owned()),
            vulnerability_id: Set(vulnerability_id.to_owned()),
            status: Set("open".to_owned()),
            severity: Set(severity.to_owned()),
            first_seen_at: Set(Utc::now().fixed_offset()),
            last_seen_at: Set(Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(&self.database)
        .await
        .unwrap()
        .id
    }
}

fn not_found<T: std::fmt::Debug>(result: Result<T, Error>) {
    assert!(matches!(result, Err(Error::NotFound)), "{result:?}");
}

#[tokio::test]
async fn those_who_manage_projects_turn_the_page_on_replace_it_and_turn_it_off() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;

    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
    let key = public_pages::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        Some(key.clone())
    );
    assert!(public_pages::page(database, &key, None, 0).await.is_ok());
    assert!(public_pages::vex(database, &key, None).await.is_ok());

    // Turning on a page that is on keeps its address.
    assert_eq!(
        public_pages::enable(database, &fixture.owner, project)
            .await
            .unwrap(),
        key
    );

    // A new address replaces the old one, which stops working at once.
    let replaced = public_pages::regenerate(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_ne!(replaced, key);
    not_found(public_pages::page(database, &key, None, 0).await);
    not_found(public_pages::vex(database, &key, None).await);
    assert!(
        public_pages::page(database, &replaced, None, 0)
            .await
            .is_ok()
    );

    public_pages::disable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
    not_found(public_pages::page(database, &replaced, None, 0).await);
    not_found(public_pages::vex(database, &replaced, None).await);
    // Turning off a page that is off does nothing, and a new address does not turn it on.
    public_pages::disable(database, &fixture.owner, project)
        .await
        .unwrap();
    not_found(public_pages::regenerate(database, &fixture.owner, project).await);
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn the_page_and_the_badge_have_independent_keys() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;

    // A badge does not publish the page.
    let badge = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    not_found(public_pages::page(database, &badge, None, 0).await);
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );

    let page = public_pages::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_ne!(page, badge);
    assert!(badges::summary(database, &page, None).await.is_err());

    // Renewing or revoking one leaves the other alone.
    let badge = badges::regenerate(database, &fixture.owner, project)
        .await
        .unwrap();
    assert!(public_pages::page(database, &page, None, 0).await.is_ok());
    badges::disable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert!(public_pages::page(database, &page, None, 0).await.is_ok());
    badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    public_pages::disable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert!(
        badges::key(database, &fixture.owner, project)
            .await
            .unwrap()
            .is_some_and(|key| key != badge)
    );
}

#[tokio::test]
async fn members_viewers_and_other_organizations_cannot_manage_the_page() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;

    for actor in [&fixture.member, &fixture.viewer] {
        assert!(matches!(
            public_pages::enable(database, actor, project).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            public_pages::key(database, actor, project).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            public_pages::regenerate(database, actor, project).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            public_pages::disable(database, actor, project).await,
            Err(Error::Forbidden)
        ));
    }
    not_found(public_pages::enable(database, &fixture.stranger, project).await);
    not_found(public_pages::key(database, &fixture.stranger, project).await);
    not_found(public_pages::regenerate(database, &fixture.stranger, project).await);
    not_found(public_pages::disable(database, &fixture.stranger, project).await);
    not_found(public_pages::enable(database, &fixture.owner, project + 1000).await);

    // A refused attempt changes nothing.
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
    let key = public_pages::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    let _ = public_pages::disable(database, &fixture.viewer, project).await;
    let _ = public_pages::regenerate(database, &fixture.member, project).await;
    assert_eq!(
        public_pages::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        Some(key)
    );
}

#[tokio::test]
async fn unknown_and_malformed_keys_and_unknown_versions_are_not_found() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let key = public_pages::enable(database, &fixture.owner, fixture.project)
        .await
        .unwrap();

    for unknown in [
        String::new(),
        "nanobom".to_owned(),
        "0123456789abcdef0123456789abcdef".to_owned(),
        key.to_uppercase(),
        format!("{key}0"),
    ] {
        not_found(public_pages::page(database, &unknown, None, 0).await);
        not_found(public_pages::vex(database, &unknown, None).await);
    }
    not_found(public_pages::page(database, &key, Some("9.9"), 0).await);
    not_found(public_pages::vex(database, &key, Some("9.9")).await);
    // The latest version by its name (the unnamed version) is found.
    assert!(
        public_pages::page(database, &key, Some(""), 0)
            .await
            .is_ok()
    );

    // Deleting the project removes its page.
    projects::delete(database, &fixture.owner, fixture.project)
        .await
        .unwrap();
    not_found(public_pages::page(database, &key, None, 0).await);
}

#[tokio::test]
async fn the_page_shows_its_own_project_and_version_only() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    fixture.uploaded(fixture.project).await;
    fixture
        .finding(fixture.project, "GHSA-0000-0000-0001", "critical")
        .await;
    let other = projects::create(database, &fixture.owner, fixture.organization, "api", "API")
        .await
        .unwrap()
        .id;
    fixture.uploaded(other).await;
    fixture.finding(other, "GHSA-0000-0000-0099", "high").await;
    // Another version of the same project.
    let older = project_versions::ActiveModel {
        project_id: Set(fixture.project),
        name: Set("0.9".to_owned()),
        latest: Set(false),
        active: Set(true),
        created_at: Set(Utc::now().fixed_offset()),
        last_upload_at: Set(Some(Utc::now().fixed_offset())),
        dependencies_partial: Set(false),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap()
    .id;
    findings_entity::ActiveModel {
        project_id: Set(fixture.project),
        version_id: Set(Some(older)),
        purl: Set("pkg:npm/older@0.9.0".to_owned()),
        ecosystem: Set("npm".to_owned()),
        vulnerability_id: Set("GHSA-0000-0000-0001".to_owned()),
        status: Set("open".to_owned()),
        severity: Set("critical".to_owned()),
        first_seen_at: Set(Utc::now().fixed_offset()),
        last_seen_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();

    let key = public_pages::enable(database, &fixture.owner, fixture.project)
        .await
        .unwrap();
    let page = public_pages::page(database, &key, None, 0).await.unwrap();
    assert_eq!(page.project_name, "Web shop");
    assert!(page.latest);
    assert_eq!(page.summary.open.critical, 1);
    assert_eq!(page.summary.open.high, 0);
    assert_eq!(page.open.len(), 1);
    assert_eq!(page.open[0].vulnerability_id, "GHSA-0000-0000-0001");
    assert_eq!(
        page.open[0].component.purl,
        "pkg:npm/ghsa-0000-0000-0001@1.0.0"
    );
    assert_eq!(
        page.open[0].summary.as_deref(),
        Some("Summary of GHSA-0000-0000-0001")
    );
    let json = serde_json::to_string(&page).unwrap();
    assert!(!json.contains("GHSA-0000-0000-0099"), "{json}");
    assert!(!json.contains("pkg:npm/older"), "{json}");
    let document =
        serde_json::to_string(&public_pages::vex(database, &key, None).await.unwrap()).unwrap();
    assert!(!document.contains("GHSA-0000-0000-0099"), "{document}");
    assert!(!document.contains("pkg:npm/older"), "{document}");

    // The other version, by name.
    let page = public_pages::page(database, &key, Some("0.9"), 0)
        .await
        .unwrap();
    assert_eq!(page.version, "0.9");
    assert!(!page.latest);
    assert_eq!(page.open.len(), 1);
    assert_eq!(page.open[0].component.purl, "pkg:npm/older@0.9.0");
}

#[tokio::test]
async fn reasons_triagers_tokens_and_the_organization_appear_nowhere() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    fixture.uploaded(fixture.project).await;
    fixture
        .finding(fixture.project, "GHSA-0000-0000-0001", "high")
        .await;
    let by_member = fixture
        .finding(fixture.project, "GHSA-0000-0000-0002", "critical")
        .await;
    let by_token = fixture
        .finding(fixture.project, "GHSA-0000-0000-0003", "medium")
        .await;
    findings::ignore(
        database,
        &fixture.owner,
        by_member,
        REASON,
        Some(Justification::CodeNotReachable),
        Some(Utc::now().fixed_offset() + chrono::Duration::days(30)),
    )
    .await
    .unwrap();
    // As a VEX import with an upload token records it.
    let token = tokens::create_with_scope(
        database,
        &fixture.owner,
        fixture.organization,
        None,
        TOKEN_NAME,
        Scope::Upload,
    )
    .await
    .unwrap();
    let row = findings_entity::Entity::find_by_id(by_token)
        .one(database)
        .await
        .unwrap()
        .unwrap();
    let mut row: findings_entity::ActiveModel = row.into();
    row.status = Set("ignored".to_owned());
    row.ignore_reason = Set(Some(TOKEN_REASON.to_owned()));
    row.ignore_justification = Set(Some("false_positive".to_owned()));
    row.ignored_by_upload_token_id = Set(Some(token.token.id));
    row.ignored_at = Set(Some(Utc::now().fixed_offset()));
    row.update(database).await.unwrap();

    let key = public_pages::enable(database, &fixture.owner, fixture.project)
        .await
        .unwrap();
    let page = public_pages::page(database, &key, None, 0).await.unwrap();
    assert_eq!(page.summary.ignored, 2);
    assert_eq!(page.assessed.len(), 2);
    let member = page
        .assessed
        .iter()
        .find(|finding| finding.vulnerability_id == "GHSA-0000-0000-0002")
        .unwrap();
    assert_eq!(member.justification, Some(Justification::CodeNotReachable));
    assert!(member.ignored_at.is_some());
    let token_ignore = page
        .assessed
        .iter()
        .find(|finding| finding.vulnerability_id == "GHSA-0000-0000-0003")
        .unwrap();
    assert_eq!(
        token_ignore.justification,
        Some(Justification::FalsePositive)
    );

    let document = public_pages::vex(database, &key, None).await.unwrap();
    assert!(document.metadata.component.bom_ref.is_none());
    assert_eq!(document.metadata.component.name, "Web shop");
    let member_statement = document
        .vulnerabilities
        .iter()
        .find(|vulnerability| vulnerability.id == "GHSA-0000-0000-0002")
        .unwrap();
    assert_eq!(member_statement.analysis.state, "not_affected");
    assert_eq!(
        member_statement.analysis.justification.as_deref(),
        Some("code_not_reachable")
    );
    assert!(
        document
            .vulnerabilities
            .iter()
            .all(|vulnerability| vulnerability.analysis.detail.is_none())
    );

    let page = serde_json::to_string(&page).unwrap();
    let document = serde_json::to_string(&document).unwrap();
    for secret in [
        REASON,
        TOKEN_REASON,
        TRIAGER,
        TOKEN_NAME,
        ORGANIZATION_SLUG,
        ORGANIZATION_NAME,
    ] {
        assert!(!page.contains(secret), "{secret} in {page}");
        assert!(!document.contains(secret), "{secret} in {document}");
    }
    // The members' export keeps them, so the test above would see a leak.
    let members = serde_json::to_string(
        &nanobom_domain::vex::export(database, &fixture.owner, ORGANIZATION_SLUG, "web", None)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(members.contains(REASON), "{members}");
    assert!(members.contains(ORGANIZATION_SLUG), "{members}");
}
