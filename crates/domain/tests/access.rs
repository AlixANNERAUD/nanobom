//! Organization isolation and the permissions of every role.

use std::collections::BTreeMap;

use nanobom_domain::{
    Error,
    access::{Actor, Permission, Role},
    memberships, organizations, projects, testing,
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;

async fn user(database: &DatabaseConnection, username: &str) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: username.to_owned(),
            email: Some(format!("{username}@example.org")),
            ..NewUser::default()
        },
        true,
    )
    .await
    .expect("create the user");
    Actor::from_user(&user)
}

async fn administrator(database: &DatabaseConnection) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: "root".to_owned(),
            is_instance_administrator: true,
            ..NewUser::default()
        },
        false,
    )
    .await
    .expect("create the administrator");
    Actor::from_user(&user)
}

/// An organization owned by `owner` with one member of each other role.
struct Fixture {
    database: DatabaseConnection,
    organization: i64,
    owner: Actor,
    admin: Actor,
    member: Actor,
    viewer: Actor,
    outsider: Actor,
}

async fn fixture() -> Fixture {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let admin = user(&database, "admin").await;
    let member = user(&database, "member").await;
    let viewer = user(&database, "viewer").await;
    let outsider = user(&database, "outsider").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .expect("create the organization")
        .id;
    for (login, role) in [
        ("admin", Role::Admin),
        ("member@example.org", Role::Member),
        ("viewer", Role::Viewer),
    ] {
        memberships::add(&database, &owner, organization, login, role)
            .await
            .expect("add a member");
    }
    Fixture {
        database,
        organization,
        owner,
        admin,
        member,
        viewer,
        outsider,
    }
}

#[test]
fn each_role_has_exactly_its_permissions() {
    use Permission::*;
    let expected: [(Role, &[Permission]); 4] = [
        (Role::Viewer, &[View]),
        (Role::Member, &[View, TriageFindings, TriggerRuns]),
        (
            Role::Admin,
            &[
                View,
                TriageFindings,
                TriggerRuns,
                ManageMembers,
                ManageProjects,
                ManageUploadTokens,
                ManageWebhook,
                ManageOrganization,
            ],
        ),
        (Role::Owner, &Permission::ALL),
    ];
    for (role, allowed) in expected {
        for permission in Permission::ALL {
            assert_eq!(
                role.allows(permission),
                allowed.contains(&permission),
                "{role} and {permission:?}"
            );
        }
    }
}

#[tokio::test]
async fn new_users_get_a_personal_organization_unless_disabled() {
    let database = testing::database().await;
    let alice = user(&database, "alice").await;
    let organizations = organizations::list(&database, &alice).await.unwrap();
    assert_eq!(organizations.len(), 1);
    assert_eq!(organizations[0].slug, "alice");
    assert!(organizations[0].is_personal);
    assert_eq!(organizations[0].role, Role::Owner);

    let bob = users::create(
        &database,
        NewUser {
            username: "bob".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let bob = Actor::from_user(&bob);
    assert!(
        organizations::list(&database, &bob)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn personal_organization_slugs_do_not_collide() {
    let database = testing::database().await;
    let alice = user(&database, "alice").await;
    organizations::create(&database, &alice, "carol", "Taken")
        .await
        .unwrap();
    let carol = user(&database, "carol").await;
    let organizations = organizations::list(&database, &carol).await.unwrap();
    assert_eq!(organizations[0].slug, "carol-2");
}

#[tokio::test]
async fn usernames_and_emails_are_unique() {
    let database = testing::database().await;
    user(&database, "alice").await;
    let same_username = users::create(
        &database,
        NewUser {
            username: "Alice".to_owned(),
            ..NewUser::default()
        },
        true,
    )
    .await;
    assert!(matches!(same_username, Err(Error::Conflict(_))));
    let same_email = users::create(
        &database,
        NewUser {
            username: "other".to_owned(),
            email: Some("ALICE@example.org".to_owned()),
            ..NewUser::default()
        },
        true,
    )
    .await;
    assert!(matches!(same_email, Err(Error::Conflict(_))));
}

#[tokio::test]
async fn outsiders_cannot_see_an_organization() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let outsider = &fixture.outsider;

    let visible = organizations::list(database, outsider).await.unwrap();
    assert!(
        visible
            .iter()
            .all(|organization| organization.slug != "acme")
    );
    assert!(matches!(
        organizations::find(database, outsider, "acme").await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        projects::list(database, outsider, fixture.organization).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        memberships::list(database, outsider, fixture.organization).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        projects::create(database, outsider, fixture.organization, "api", "API").await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        organizations::delete(database, outsider, fixture.organization).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn members_see_the_organization_with_their_role() {
    let fixture = fixture().await;
    for (actor, role) in [
        (&fixture.owner, Role::Owner),
        (&fixture.admin, Role::Admin),
        (&fixture.member, Role::Member),
        (&fixture.viewer, Role::Viewer),
    ] {
        let organization = organizations::find(&fixture.database, actor, "ACME")
            .await
            .unwrap();
        assert_eq!(organization.role, role);
    }
    let members = memberships::list(&fixture.database, &fixture.viewer, fixture.organization)
        .await
        .unwrap();
    let usernames: Vec<_> = members
        .iter()
        .map(|member| member.username.as_str())
        .collect();
    assert_eq!(usernames, ["admin", "member", "owner", "viewer"]);
}

#[tokio::test]
async fn only_admins_and_owners_manage_projects() {
    let fixture = fixture().await;
    let database = &fixture.database;
    for actor in [&fixture.member, &fixture.viewer] {
        assert!(matches!(
            projects::create(database, actor, fixture.organization, "api", "API").await,
            Err(Error::Forbidden)
        ));
    }
    let project = projects::create(database, &fixture.admin, fixture.organization, "API", "Api")
        .await
        .unwrap();
    assert_eq!(project.slug, "api");
    let found = projects::find(database, &fixture.viewer, fixture.organization, "api")
        .await
        .unwrap();
    assert_eq!(found.id, project.id);
    assert!(matches!(
        projects::delete(database, &fixture.member, project.id).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        projects::delete(database, &fixture.outsider, project.id).await,
        Err(Error::NotFound)
    ));
    projects::delete(database, &fixture.owner, project.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn admins_manage_members_but_not_owners() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let organization = fixture.organization;

    assert!(matches!(
        memberships::add(
            database,
            &fixture.member,
            organization,
            "outsider",
            Role::Viewer
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        memberships::add(
            database,
            &fixture.admin,
            organization,
            "outsider",
            Role::Owner
        )
        .await,
        Err(Error::Forbidden)
    ));
    memberships::add(
        database,
        &fixture.admin,
        organization,
        "outsider",
        Role::Viewer,
    )
    .await
    .unwrap();
    assert!(matches!(
        memberships::add(
            database,
            &fixture.admin,
            organization,
            "outsider",
            Role::Viewer
        )
        .await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        memberships::add(
            database,
            &fixture.admin,
            organization,
            "nobody",
            Role::Viewer
        )
        .await,
        Err(Error::Invalid(_))
    ));
    memberships::set_role(
        database,
        &fixture.admin,
        organization,
        fixture.outsider.user_id,
        Role::Member,
    )
    .await
    .unwrap();
    assert!(matches!(
        memberships::set_role(
            database,
            &fixture.admin,
            organization,
            fixture.owner.user_id,
            Role::Viewer
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        memberships::remove(
            database,
            &fixture.admin,
            organization,
            fixture.owner.user_id
        )
        .await,
        Err(Error::Forbidden)
    ));
    memberships::remove(
        database,
        &fixture.admin,
        organization,
        fixture.outsider.user_id,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn owners_manage_owners_but_never_remove_the_last_one() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let organization = fixture.organization;
    assert!(matches!(
        memberships::set_role(
            database,
            &fixture.owner,
            organization,
            fixture.owner.user_id,
            Role::Admin
        )
        .await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(
        memberships::remove(
            database,
            &fixture.owner,
            organization,
            fixture.owner.user_id
        )
        .await,
        Err(Error::Conflict(_))
    ));
    memberships::set_role(
        database,
        &fixture.owner,
        organization,
        fixture.admin.user_id,
        Role::Owner,
    )
    .await
    .unwrap();
    memberships::remove(
        database,
        &fixture.owner,
        organization,
        fixture.owner.user_id,
    )
    .await
    .unwrap();
    assert!(matches!(
        organizations::find(database, &fixture.owner, "acme").await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn members_can_leave() {
    let fixture = fixture().await;
    memberships::remove(
        &fixture.database,
        &fixture.viewer,
        fixture.organization,
        fixture.viewer.user_id,
    )
    .await
    .unwrap();
    assert!(matches!(
        organizations::find(&fixture.database, &fixture.viewer, "acme").await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn only_owners_delete_the_organization() {
    let fixture = fixture().await;
    let database = &fixture.database;
    assert!(matches!(
        organizations::delete(database, &fixture.admin, fixture.organization).await,
        Err(Error::Forbidden)
    ));
    organizations::delete(database, &fixture.owner, fixture.organization)
        .await
        .unwrap();
    assert!(matches!(
        organizations::find(database, &fixture.owner, "acme").await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn instance_administrators_see_and_manage_everything() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let root = administrator(database).await;
    let all = organizations::list(database, &root).await.unwrap();
    assert!(all.iter().any(|organization| organization.slug == "acme"));
    assert!(
        all.iter()
            .any(|organization| organization.slug == "outsider")
    );
    projects::create(database, &root, fixture.organization, "api", "API")
        .await
        .unwrap();
    assert_eq!(users::list(database, &root).await.unwrap().len(), 6);
    assert!(matches!(
        users::list(database, &fixture.owner).await,
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn disabled_users_cannot_act() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let root = administrator(database).await;
    users::set_disabled(database, &root, fixture.viewer.user_id, true)
        .await
        .unwrap();
    assert!(matches!(
        Actor::load(database, fixture.viewer.user_id).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        users::set_disabled(database, &fixture.admin, fixture.viewer.user_id, false).await,
        Err(Error::Forbidden)
    ));
    assert!(
        users::set_disabled(database, &root, root.user_id, true)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn synchronized_memberships_are_kept_apart_from_manual_ones() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let viewer = fixture.viewer.user_id;

    let roles = BTreeMap::from([
        ("acme".to_owned(), Role::Admin),
        ("platform".to_owned(), Role::Member),
    ]);
    memberships::synchronize(database, viewer, &roles)
        .await
        .unwrap();
    let acme = organizations::find(database, &fixture.viewer, "acme")
        .await
        .unwrap();
    assert_eq!(acme.role, Role::Admin);
    let platform = organizations::find(database, &fixture.viewer, "platform")
        .await
        .unwrap();
    assert_eq!(platform.role, Role::Member);
    let member = memberships::list(database, &fixture.owner, fixture.organization)
        .await
        .unwrap()
        .into_iter()
        .find(|member| member.user_id == viewer)
        .unwrap();
    assert_eq!(member.manual_role, Some(Role::Viewer));
    assert_eq!(member.synchronized_role, Some(Role::Admin));

    memberships::synchronize(database, viewer, &BTreeMap::new())
        .await
        .unwrap();
    let acme = organizations::find(database, &fixture.viewer, "acme")
        .await
        .unwrap();
    assert_eq!(acme.role, Role::Viewer, "the manual membership remains");
    assert!(matches!(
        organizations::find(database, &fixture.viewer, "platform").await,
        Err(Error::NotFound)
    ));
}
