//! License policies: who reads and changes them, and the violations they give.

use nanobom_domain::{
    Error, Problem,
    access::{Actor, Role},
    inventory::{self, UploadSource},
    licenses::{self, Action, Policy, Rule, ViolationCounts},
    memberships, organizations, testing, tokens,
    users::{self, NewUser},
};
use nanobom_entity::upload_tokens;
use sea_orm::DatabaseConnection;
use serde_json::json;

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    admin: Actor,
    member: Actor,
    viewer: Actor,
    outsider: Actor,
    organization: i64,
    other_organization: i64,
}

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

async fn setup() -> Fixture {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let admin = user(&database, "admin").await;
    let member = user(&database, "member").await;
    let viewer = user(&database, "viewer").await;
    let outsider = user(&database, "outsider").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    for (login, role) in [
        ("admin", Role::Admin),
        ("member", Role::Member),
        ("viewer", Role::Viewer),
    ] {
        memberships::add(&database, &owner, organization, login, role)
            .await
            .unwrap();
    }
    let other_organization = organizations::create(&database, &outsider, "other", "Other")
        .await
        .unwrap()
        .id;
    Fixture {
        database,
        owner,
        admin,
        member,
        viewer,
        outsider,
        organization,
        other_organization,
    }
}

fn rule(license: &str, action: Action) -> Rule {
    Rule {
        license: license.to_owned(),
        action,
    }
}

fn policy(unlisted: Action, unknown: Action, rules: &[(&str, Action)]) -> Policy {
    Policy {
        unlisted,
        unknown,
        rules: rules
            .iter()
            .map(|(license, action)| rule(license, *action))
            .collect(),
    }
}

/// A CycloneDX document with one npm component per `(name, licenses)` pair.
fn sbom(components: &[(&str, serde_json::Value)]) -> inventory::ParsedSbom {
    let components: Vec<_> = components
        .iter()
        .map(|(name, licenses)| {
            let mut component = json!({
                "type": "library",
                "name": name,
                "version": "1.0.0",
                "purl": format!("pkg:npm/{name}@1.0.0"),
            });
            if !licenses.is_null() {
                component["licenses"] = licenses.clone();
            }
            component
        })
        .collect();
    let document = json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": components});
    inventory::parse(document.to_string().as_bytes()).unwrap()
}

async fn token(fixture: &Fixture, organization: i64) -> upload_tokens::Model {
    let owner = if organization == fixture.organization {
        &fixture.owner
    } else {
        &fixture.outsider
    };
    let created = tokens::create(&fixture.database, owner, organization, None, "CI")
        .await
        .unwrap();
    tokens::authenticate(&fixture.database, &created.secret)
        .await
        .unwrap()
        .unwrap()
}

async fn upload(fixture: &Fixture, components: &[(&str, serde_json::Value)]) -> i64 {
    let token = token(fixture, fixture.organization).await;
    inventory::ingest(
        &fixture.database,
        &token,
        "acme",
        "web",
        sbom(components),
        UploadSource::default(),
    )
    .await
    .unwrap()
    .project_id
}

fn expression(text: &str) -> serde_json::Value {
    json!([{ "expression": text }])
}

#[tokio::test]
async fn organizations_start_without_a_policy() {
    let fixture = setup().await;
    let policy = licenses::policy(&fixture.database, &fixture.viewer, fixture.organization)
        .await
        .unwrap();
    assert_eq!(policy, Policy::default());
    assert!(!policy.is_active());
    let project = upload(
        &fixture,
        &[("a", expression("GPL-3.0-only")), ("b", json!(null))],
    )
    .await;
    let violations = licenses::violations(&fixture.database, &fixture.viewer, project, 0, 10)
        .await
        .unwrap();
    assert!(!violations.active);
    assert!(violations.items.is_empty());
    assert_eq!(violations.counts, ViolationCounts::default());
    assert_eq!(
        licenses::counts_by_project(&fixture.database, &fixture.viewer, fixture.organization)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn admins_change_the_policy_and_viewers_read_it() {
    let fixture = setup().await;
    let database = &fixture.database;
    let wanted = policy(
        Action::Forbid,
        Action::Warn,
        &[
            ("mit", Action::Allow),
            ("GPL-2.0", Action::Forbid),
            ("LicenseRef-internal", Action::Warn),
            ("MIT", Action::Allow),
        ],
    );
    for refused in [&fixture.member, &fixture.viewer] {
        assert!(matches!(
            licenses::set_policy(database, refused, fixture.organization, &wanted).await,
            Err(Error::Forbidden)
        ));
    }
    let saved = licenses::set_policy(database, &fixture.admin, fixture.organization, &wanted)
        .await
        .unwrap();
    let expected = policy(
        Action::Forbid,
        Action::Warn,
        &[
            ("GPL-2.0-only", Action::Forbid),
            ("LicenseRef-internal", Action::Warn),
            ("MIT", Action::Allow),
        ],
    );
    assert_eq!(saved, expected);
    for reader in [&fixture.viewer, &fixture.member, &fixture.owner] {
        assert_eq!(
            licenses::policy(database, reader, fixture.organization)
                .await
                .unwrap(),
            expected
        );
    }
    let token = token(&fixture, fixture.organization).await;
    assert_eq!(
        licenses::policy(database, &token, fixture.organization)
            .await
            .unwrap(),
        expected
    );

    // A new policy replaces the whole previous one.
    let replaced = licenses::set_policy(
        database,
        &fixture.owner,
        fixture.organization,
        &policy(
            Action::Allow,
            Action::Allow,
            &[("AGPL-3.0-only", Action::Forbid)],
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        replaced,
        policy(
            Action::Allow,
            Action::Allow,
            &[("AGPL-3.0-only", Action::Forbid)]
        )
    );
    assert_eq!(
        licenses::policy(database, &fixture.viewer, fixture.organization)
            .await
            .unwrap(),
        replaced
    );
}

#[tokio::test]
async fn invalid_rules_change_nothing() {
    let fixture = setup().await;
    let database = &fixture.database;
    let before = policy(Action::Allow, Action::Allow, &[("MIT", Action::Warn)]);
    licenses::set_policy(database, &fixture.owner, fixture.organization, &before)
        .await
        .unwrap();
    for (rules, problem) in [
        (
            vec![
                rule("MIT", Action::Allow),
                rule("Apache License", Action::Forbid),
            ],
            Problem::UnknownLicenseId {
                license: "Apache License".to_owned(),
            },
        ),
        (
            vec![rule("MIT", Action::Allow), rule("mit", Action::Forbid)],
            Problem::ConflictingLicenseRule {
                license: "MIT".to_owned(),
            },
        ),
    ] {
        let result = licenses::set_policy(
            database,
            &fixture.owner,
            fixture.organization,
            &Policy {
                unlisted: Action::Forbid,
                unknown: Action::Forbid,
                rules,
            },
        )
        .await;
        match result {
            Err(Error::Invalid(found)) => assert_eq!(found, problem),
            other => panic!("expected {problem:?}, got {other:?}"),
        }
    }
    assert_eq!(
        licenses::policy(database, &fixture.viewer, fixture.organization)
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn other_organizations_are_not_found() {
    let fixture = setup().await;
    let database = &fixture.database;
    let project = upload(&fixture, &[("a", expression("GPL-3.0-only"))]).await;
    let other_token = token(&fixture, fixture.other_organization).await;
    assert!(matches!(
        licenses::policy(database, &fixture.outsider, fixture.organization).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        licenses::policy(database, &other_token, fixture.organization).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        licenses::set_policy(
            database,
            &fixture.outsider,
            fixture.organization,
            &Policy::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        licenses::violations(database, &fixture.outsider, project, 0, 10).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        licenses::violations(database, &other_token, project, 0, 10).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        licenses::counts_by_project(database, &fixture.outsider, fixture.organization).await,
        Err(Error::NotFound)
    ));
    // The other organization's policy does not apply here, and the reverse.
    licenses::set_policy(
        database,
        &fixture.outsider,
        fixture.other_organization,
        &policy(Action::Forbid, Action::Forbid, &[]),
    )
    .await
    .unwrap();
    assert!(
        !licenses::violations(database, &fixture.viewer, project, 0, 10)
            .await
            .unwrap()
            .active
    );
}

#[tokio::test]
async fn violations_are_listed_forbidden_first_then_by_name() {
    let fixture = setup().await;
    let database = &fixture.database;
    let project = upload(
        &fixture,
        &[
            ("f", expression("LGPL-2.1-only")),
            ("a", expression("MIT")),
            ("b", expression("GPL-3.0-only")),
            ("c", json!(null)),
            ("d", expression("MIT OR GPL-3.0-only")),
            ("e", json!([{"license": {"name": "Apache License 2.0"}}])),
            ("g", expression("Apache-2.0 AND gpl-3.0-only")),
        ],
    )
    .await;
    licenses::set_policy(
        database,
        &fixture.admin,
        fixture.organization,
        &policy(
            Action::Allow,
            Action::Warn,
            &[
                ("GPL-3.0-only", Action::Forbid),
                ("LGPL-2.1-only", Action::Warn),
            ],
        ),
    )
    .await
    .unwrap();
    let all = licenses::violations(database, &fixture.viewer, project, 0, 100)
        .await
        .unwrap();
    assert!(all.active);
    assert_eq!(
        all.counts,
        ViolationCounts {
            forbidden: 2,
            warned: 3
        }
    );
    assert_eq!(all.total(), 5);
    let listed: Vec<(&str, Action, Vec<&str>, Option<&str>)> = all
        .items
        .iter()
        .map(|violation| {
            (
                violation.name.as_str(),
                violation.verdict,
                violation.licenses.iter().map(String::as_str).collect(),
                violation.license.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            (
                "b",
                Action::Forbid,
                vec!["GPL-3.0-only"],
                Some("GPL-3.0-only")
            ),
            (
                "g",
                Action::Forbid,
                vec!["GPL-3.0-only"],
                Some("Apache-2.0 AND gpl-3.0-only")
            ),
            ("c", Action::Warn, vec![], None),
            ("e", Action::Warn, vec![], Some("Apache License 2.0")),
            (
                "f",
                Action::Warn,
                vec!["LGPL-2.1-only"],
                Some("LGPL-2.1-only")
            ),
        ]
    );
    assert_eq!(all.items[0].purl, "pkg:npm/b@1.0.0");
    assert_eq!(all.items[0].version.as_deref(), Some("1.0.0"));

    let names = |violations: licenses::Violations| -> Vec<String> {
        violations
            .items
            .into_iter()
            .map(|violation| violation.name)
            .collect()
    };
    for (offset, limit, expected) in [
        (1, 2, vec!["g", "c"]),
        (2, 2, vec!["c", "e"]),
        (4, 10, vec!["f"]),
        (5, 10, vec![]),
        (0, 0, vec![]),
    ] {
        let page = licenses::violations(database, &fixture.viewer, project, offset, limit)
            .await
            .unwrap();
        assert_eq!(page.counts, all.counts);
        assert_eq!(names(page), expected, "offset {offset}, limit {limit}");
    }

    // A project token reads its project's violations.
    let token = token(&fixture, fixture.organization).await;
    assert_eq!(
        licenses::violations(database, &token, project, 0, 1)
            .await
            .unwrap()
            .counts,
        all.counts
    );
    assert_eq!(
        licenses::counts_by_project(database, &fixture.viewer, fixture.organization)
            .await
            .unwrap()
            .unwrap()
            .get(&project),
        Some(&all.counts)
    );

    // Allowing what was warned about takes effect at once, without a run.
    licenses::set_policy(
        database,
        &fixture.admin,
        fixture.organization,
        &policy(
            Action::Allow,
            Action::Allow,
            &[("GPL-3.0-only", Action::Forbid)],
        ),
    )
    .await
    .unwrap();
    let after = licenses::violations(database, &fixture.viewer, project, 0, 100)
        .await
        .unwrap();
    assert_eq!(
        after.counts,
        ViolationCounts {
            forbidden: 2,
            warned: 0
        }
    );
}

#[tokio::test]
async fn pages_are_found_across_many_components() {
    let fixture = setup().await;
    let database = &fixture.database;
    let names: Vec<String> = (0..1200)
        .map(|index| format!("package-{index:04}"))
        .collect();
    let components: Vec<(&str, serde_json::Value)> = names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let license = match index % 3 {
                0 => "GPL-3.0-only",
                1 => "MPL-2.0",
                _ => "MIT",
            };
            (name.as_str(), expression(license))
        })
        .collect();
    let project = upload(&fixture, &components).await;
    licenses::set_policy(
        database,
        &fixture.admin,
        fixture.organization,
        &policy(
            Action::Allow,
            Action::Allow,
            &[("GPL-3.0-only", Action::Forbid), ("MPL-2.0", Action::Warn)],
        ),
    )
    .await
    .unwrap();
    let page = licenses::violations(database, &fixture.viewer, project, 390, 20)
        .await
        .unwrap();
    assert_eq!(
        page.counts,
        ViolationCounts {
            forbidden: 400,
            warned: 400
        }
    );
    let listed: Vec<(&str, Action)> = page
        .items
        .iter()
        .map(|violation| (violation.name.as_str(), violation.verdict))
        .collect();
    let mut expected: Vec<(String, Action)> = (390..400)
        .map(|index| (format!("package-{:04}", index * 3), Action::Forbid))
        .collect();
    expected.extend((0..10).map(|index| (format!("package-{:04}", index * 3 + 1), Action::Warn)));
    assert_eq!(
        listed,
        expected
            .iter()
            .map(|(name, action)| (name.as_str(), *action))
            .collect::<Vec<_>>()
    );
    let last = licenses::violations(database, &fixture.viewer, project, 799, 20)
        .await
        .unwrap();
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].name, "package-1198");
}
