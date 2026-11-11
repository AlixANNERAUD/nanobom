//! Project badges: turned on, replaced and off by those who manage projects, and read with the
//! key alone.

use chrono::Utc;
use nanobom_domain::{
    Error,
    access::{Actor, Role},
    badges::{self, Summary},
    findings::{self, OpenSummary, SeverityCounts},
    memberships, organizations, projects, testing,
    users::{self, NewUser},
};
use nanobom_entity::{
    exploitation, findings as findings_entity, project_versions, vulnerabilities,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    member: Actor,
    viewer: Actor,
    stranger: Actor,
    project: i64,
}

impl Fixture {
    async fn new() -> Self {
        let database = testing::database().await;
        let mut actors = Vec::new();
        for username in ["owner", "member", "viewer", "stranger"] {
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
        let acme = organizations::create(&database, &owner, "acme", "Acme")
            .await
            .unwrap()
            .id;
        memberships::add(&database, &owner, acme, "member", Role::Member)
            .await
            .unwrap();
        memberships::add(&database, &owner, acme, "viewer", Role::Viewer)
            .await
            .unwrap();
        // The stranger owns another organization.
        organizations::create(&database, &stranger, "globex", "Globex")
            .await
            .unwrap();
        let project = projects::create(&database, &owner, acme, "web", "Web")
            .await
            .unwrap()
            .id;
        Self {
            database,
            owner,
            member,
            viewer,
            stranger,
            project,
        }
    }

    /// Marks the latest version as uploaded to, as an upload would.
    async fn uploaded(&self) {
        let version = testing::latest_version(&self.database, self.project).await;
        let version = project_versions::Entity::find_by_id(version)
            .one(&self.database)
            .await
            .unwrap()
            .unwrap();
        let mut version: project_versions::ActiveModel = version.into();
        version.last_upload_at = Set(Some(Utc::now().fixed_offset()));
        version.update(&self.database).await.unwrap();
    }

    /// A finding of the latest version, on its own component; returns its identifier.
    async fn finding(&self, vulnerability_id: &str, aliases: &[&str], severity: &str) -> i64 {
        vulnerabilities::ActiveModel {
            id: Set(vulnerability_id.to_owned()),
            modified: Set(Utc::now().fixed_offset()),
            aliases: Set(serde_json::to_string(aliases).unwrap()),
            severity: Set(severity.to_owned()),
            record: Set("{}".to_owned()),
            fetched_at: Set(Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(&self.database)
        .await
        .unwrap();
        findings_entity::ActiveModel {
            project_id: Set(self.project),
            version_id: Set(Some(
                testing::latest_version(&self.database, self.project).await,
            )),
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

#[tokio::test]
async fn those_who_manage_projects_turn_the_badge_on_replace_it_and_turn_it_off() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;

    assert_eq!(
        badges::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
    let key = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_eq!(key.len(), 32);
    assert!(
        key.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{key}"
    );
    assert_eq!(
        badges::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        Some(key.clone())
    );
    assert!(badges::summary(database, &key, None).await.is_ok());

    // A new address replaces the old one, which stops working at once.
    let replaced = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_ne!(replaced, key);
    assert!(matches!(
        badges::summary(database, &key, None).await,
        Err(Error::NotFound)
    ));
    assert!(badges::summary(database, &replaced, None).await.is_ok());

    badges::disable(database, &fixture.owner, project)
        .await
        .unwrap();
    assert_eq!(
        badges::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        None
    );
    assert!(matches!(
        badges::summary(database, &replaced, None).await,
        Err(Error::NotFound)
    ));
    // Turning off a badge that is off does nothing.
    badges::disable(database, &fixture.owner, project)
        .await
        .unwrap();
}

#[tokio::test]
async fn members_viewers_and_other_organizations_cannot_manage_the_badge() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;

    for actor in [&fixture.member, &fixture.viewer] {
        assert!(matches!(
            badges::enable(database, actor, project).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            badges::key(database, actor, project).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            badges::disable(database, actor, project).await,
            Err(Error::Forbidden)
        ));
    }
    assert!(matches!(
        badges::enable(database, &fixture.stranger, project).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        badges::key(database, &fixture.stranger, project).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        badges::disable(database, &fixture.stranger, project).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        badges::enable(database, &fixture.owner, project + 1000).await,
        Err(Error::NotFound)
    ));

    // A refused attempt changes nothing.
    let key = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();
    let _ = badges::disable(database, &fixture.viewer, project).await;
    let _ = badges::enable(database, &fixture.stranger, project).await;
    assert_eq!(
        badges::key(database, &fixture.owner, project)
            .await
            .unwrap(),
        Some(key)
    );
}

#[tokio::test]
async fn the_summary_counts_the_open_findings_of_the_version_like_the_project_page() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;
    let key = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();

    // Nothing uploaded yet: the counts are not known, not zero.
    assert_eq!(
        badges::summary(database, &key, None).await.unwrap(),
        Summary::NoSbom
    );

    fixture.uploaded().await;
    assert_eq!(
        badges::summary(database, &key, None).await.unwrap(),
        Summary::Findings(OpenSummary::default())
    );

    fixture
        .finding("GHSA-0000-0000-0001", &["CVE-2024-0001"], "critical")
        .await;
    let high = fixture.finding("GHSA-0000-0000-0002", &[], "high").await;
    fixture.finding("GHSA-0000-0000-0003", &[], "medium").await;
    exploitation::ActiveModel {
        cve_id: Set("CVE-2024-0001".to_owned()),
        known_exploited: Set(true),
        kev_ransomware: Set(false),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();

    let expected = findings::open_summary_in_version(database, &fixture.owner, project, None)
        .await
        .unwrap();
    assert_eq!(
        expected,
        OpenSummary {
            counts: SeverityCounts {
                critical: 1,
                high: 1,
                medium: 1,
                ..SeverityCounts::default()
            },
            known_exploited: 1,
        }
    );
    assert_eq!(
        badges::summary(database, &key, None).await.unwrap(),
        Summary::Findings(expected)
    );
    // The latest version by its name (the unnamed version) is the same.
    assert_eq!(
        badges::summary(database, &key, Some("")).await.unwrap(),
        Summary::Findings(expected)
    );

    // An ignored finding no longer counts.
    findings::ignore(database, &fixture.owner, high, "not reachable", None, None)
        .await
        .unwrap();
    let after = badges::summary(database, &key, None).await.unwrap();
    assert_eq!(
        after,
        Summary::Findings(
            findings::open_summary_in_version(database, &fixture.owner, project, None)
                .await
                .unwrap()
        )
    );
    let Summary::Findings(after) = after else {
        unreachable!()
    };
    assert_eq!(after.counts.high, 0);
    assert_eq!(after.counts.critical, 1);
}

#[tokio::test]
async fn the_summary_reads_a_named_version_and_hides_what_is_missing() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let project = fixture.project;
    fixture.uploaded().await;
    fixture.finding("GHSA-0000-0000-0001", &[], "high").await;
    let older = project_versions::ActiveModel {
        project_id: Set(project),
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
        project_id: Set(project),
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
    let key = badges::enable(database, &fixture.owner, project)
        .await
        .unwrap();

    assert_eq!(
        badges::summary(database, &key, Some("0.9")).await.unwrap(),
        Summary::Findings(OpenSummary {
            counts: SeverityCounts {
                critical: 1,
                ..SeverityCounts::default()
            },
            known_exploited: 0,
        })
    );
    assert!(matches!(
        badges::summary(database, &key, Some("9.9")).await,
        Err(Error::NotFound)
    ));
    for unknown in ["", "nanobom", "0123456789abcdef0123456789abcdef"] {
        assert!(matches!(
            badges::summary(database, unknown, None).await,
            Err(Error::NotFound)
        ));
    }
    // Keys are lowercase: another spelling of the same key is another key.
    assert!(matches!(
        badges::summary(database, &key.to_uppercase(), None).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn deleting_the_project_removes_its_badge() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let key = badges::enable(database, &fixture.owner, fixture.project)
        .await
        .unwrap();
    projects::delete(database, &fixture.owner, fixture.project)
        .await
        .unwrap();
    assert!(matches!(
        badges::summary(database, &key, None).await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        nanobom_entity::project_badges::Entity::find()
            .all(database)
            .await
            .unwrap(),
        Vec::new()
    );
}
