//! The upload token each project comes with: created by every path that creates a project,
//! shown again to those who manage tokens, renewed rather than revoked.

use nanobom_domain::{
    Error, Problem,
    access::{Actor, Role},
    database,
    inventory::{self, UploadSource},
    memberships, organizations, projects, testing,
    tokens::{self, Scope, UploadToken},
    users::{self, NewUser},
};
use nanobom_entity::{project_tokens, upload_tokens};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter,
};

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
    .expect("create the user");
    Actor::from_user(&user)
}

fn sbom() -> inventory::ParsedSbom {
    let path = format!(
        "{}/tests/fixtures/sboms/cyclonedx-npm.json",
        env!("CARGO_MANIFEST_DIR")
    );
    inventory::parse(&std::fs::read(path).expect("the fixture")).expect("a valid SBOM")
}

async fn authenticated(database: &DatabaseConnection, secret: &str) -> upload_tokens::Model {
    tokens::authenticate(database, secret)
        .await
        .unwrap()
        .expect("an active token")
}

/// The project tokens listed for an organization, as `(project, revoked)`.
fn project_tokens_of(listed: &[UploadToken]) -> Vec<(String, bool)> {
    let mut found: Vec<(String, bool)> = listed
        .iter()
        .filter(|token| token.project_token)
        .map(|token| {
            (
                token.project_slug.clone().expect("a project token"),
                token.revoked_at.is_some(),
            )
        })
        .collect();
    found.sort();
    found
}

#[tokio::test]
async fn every_way_of_creating_a_project_gives_it_one_upload_token() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let organization_token = tokens::create(&database, &owner, acme.id, None, "CI")
        .await
        .unwrap();
    let organization_token = authenticated(&database, &organization_token.secret).await;

    // The interface, an upload with an organization token, Dependency-Track's autoCreate and
    // the command line.
    let interface = projects::create(&database, &owner, acme.id, "web", "")
        .await
        .unwrap();
    assert_eq!(interface.name, "web", "a blank name defaults to the slug");
    inventory::ingest(
        &database,
        &organization_token,
        "acme",
        "api",
        sbom(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    inventory::ingest_into_token_organization(
        &database,
        &organization_token,
        "worker",
        sbom(),
        UploadSource::default(),
        true,
    )
    .await
    .unwrap();
    projects::create_from_command_line(&database, "acme", "cli", Some("CLI"))
        .await
        .unwrap();

    let listed = tokens::list(&database, &owner, acme.id).await.unwrap();
    assert_eq!(
        project_tokens_of(&listed),
        [
            ("api".to_owned(), false),
            ("cli".to_owned(), false),
            ("web".to_owned(), false),
            ("worker".to_owned(), false),
        ]
    );
    for slug in ["web", "api", "worker", "cli"] {
        let project = projects::find(&database, &owner, acme.id, slug)
            .await
            .unwrap();
        let shown = tokens::project_token(&database, &owner, project.id)
            .await
            .unwrap();
        assert!(shown.token.project_token);
        assert_eq!(shown.token.scope, Scope::Upload);
        assert_eq!(shown.token.project_slug.as_deref(), Some(slug));
        let stored = authenticated(&database, &shown.secret).await;
        assert_eq!(stored.project_id, Some(project.id));
        assert_eq!(stored.id, shown.token.id);
    }
}

#[tokio::test]
async fn the_project_token_uploads_to_its_project_only() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    projects::create(&database, &owner, acme.id, "api", "API")
        .await
        .unwrap();
    let secret = tokens::project_token(&database, &owner, web.id)
        .await
        .unwrap()
        .secret;
    let token = authenticated(&database, &secret).await;

    let outcome = inventory::ingest(
        &database,
        &token,
        "acme",
        "web",
        sbom(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    assert_eq!(outcome.project_id, web.id);
    assert!(matches!(
        inventory::ingest(
            &database,
            &token,
            "acme",
            "api",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        inventory::ingest(
            &database,
            &token,
            "acme",
            "new",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    let used = tokens::project_token(&database, &owner, web.id)
        .await
        .unwrap();
    assert!(used.token.last_used_at.is_some());
}

#[tokio::test]
async fn renewing_replaces_the_value_at_once() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let old = tokens::project_token(&database, &owner, web.id)
        .await
        .unwrap();
    let old_token = authenticated(&database, &old.secret).await;

    let renewed = tokens::renew_project_token(&database, &owner, web.id)
        .await
        .unwrap();
    assert_ne!(renewed.secret, old.secret);
    assert!(
        tokens::authenticate(&database, &old.secret)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!tokens::is_active(&database, old_token.id).await.unwrap());
    let new_token = authenticated(&database, &renewed.secret).await;
    assert_eq!(new_token.project_id, Some(web.id));
    assert_eq!(
        tokens::project_token(&database, &owner, web.id)
            .await
            .unwrap()
            .secret,
        renewed.secret
    );

    // The old token stays listed, revoked, for the record; the project still has one token.
    let listed = tokens::list(&database, &owner, acme.id).await.unwrap();
    assert_eq!(project_tokens_of(&listed), [("web".to_owned(), false)]);
    let old_listed = listed
        .iter()
        .find(|token| token.id == old.token.id)
        .expect("the old token is listed");
    assert!(old_listed.revoked_at.is_some() && !old_listed.project_token);

    // The command line shows the same value, and renews it too.
    let shown = tokens::project_token_from_command_line(&database, "acme", "web", false)
        .await
        .unwrap();
    assert_eq!(shown.secret, renewed.secret);
    let again = tokens::project_token_from_command_line(&database, "acme", "web", true)
        .await
        .unwrap();
    assert_ne!(again.secret, renewed.secret);
    assert!(
        tokens::authenticate(&database, &renewed.secret)
            .await
            .unwrap()
            .is_none()
    );
    authenticated(&database, &again.secret).await;
}

#[tokio::test]
async fn the_project_token_cannot_be_revoked() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let shown = tokens::project_token(&database, &owner, web.id)
        .await
        .unwrap();
    assert!(matches!(
        tokens::revoke(&database, &owner, shown.token.id).await,
        Err(Error::Conflict(Problem::ProjectTokenRevoke))
    ));
    assert!(matches!(
        tokens::revoke_from_command_line(&database, shown.token.id).await,
        Err(Error::Conflict(Problem::ProjectTokenRevoke))
    ));
    authenticated(&database, &shown.secret).await;
}

#[tokio::test]
async fn only_those_who_manage_tokens_see_or_renew_it() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let admin = user(&database, "admin").await;
    let member = user(&database, "member").await;
    let viewer = user(&database, "viewer").await;
    let outsider = user(&database, "outsider").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    organizations::create(&database, &outsider, "globex", "Globex")
        .await
        .unwrap();
    for (username, role) in [
        ("admin", Role::Admin),
        ("member", Role::Member),
        ("viewer", Role::Viewer),
    ] {
        memberships::add(&database, &owner, acme.id, username, role)
            .await
            .unwrap();
    }
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let secret = tokens::project_token(&database, &admin, web.id)
        .await
        .unwrap()
        .secret;

    for actor in [&member, &viewer] {
        assert!(matches!(
            tokens::project_token(&database, actor, web.id).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            tokens::renew_project_token(&database, actor, web.id).await,
            Err(Error::Forbidden)
        ));
        assert!(matches!(
            tokens::list(&database, actor, acme.id).await,
            Err(Error::Forbidden)
        ));
    }
    // Another organization's project is missing, not forbidden.
    assert!(matches!(
        tokens::project_token(&database, &outsider, web.id).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        tokens::renew_project_token(&database, &outsider, web.id).await,
        Err(Error::NotFound)
    ));
    // Nothing was renewed, and listings never carry the value.
    authenticated(&database, &secret).await;
    let listed = tokens::list(&database, &owner, acme.id).await.unwrap();
    let serialized = serde_json::to_string(&listed).unwrap();
    assert!(!serialized.contains(&secret), "{serialized}");
    let from_command_line = tokens::list_from_command_line(&database, "acme")
        .await
        .unwrap();
    assert!(
        !serde_json::to_string(&from_command_line)
            .unwrap()
            .contains(&secret)
    );
}

#[tokio::test]
async fn deleting_the_project_deletes_its_token() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let secret = tokens::project_token(&database, &owner, web.id)
        .await
        .unwrap()
        .secret;
    projects::delete(&database, &owner, web.id).await.unwrap();
    assert!(
        tokens::authenticate(&database, &secret)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        project_tokens::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
    assert!(
        tokens::list(&database, &owner, acme.id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Projects created before project tokens existed get one when the migrations run, once.
#[tokio::test]
async fn migrating_gives_existing_projects_a_token() {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let kept = projects::create(&database, &owner, acme.id, "kept", "Kept")
        .await
        .unwrap();
    let kept_secret = tokens::project_token(&database, &owner, kept.id)
        .await
        .unwrap()
        .secret;
    // A project as an older release created it: a row of its own, with no token.
    let old = nanobom_entity::projects::ActiveModel {
        organization_id: Set(acme.id),
        slug: Set("old".to_owned()),
        name: Set("Old".to_owned()),
        created_at: Set(chrono::Utc::now().fixed_offset()),
        last_upload_at: Set(None),
        ..Default::default()
    }
    .insert(&database)
    .await
    .unwrap();
    assert!(matches!(
        tokens::project_token(&database, &owner, old.id).await,
        Err(Error::NotFound)
    ));

    database::migrate(&database).await.unwrap();
    database::migrate(&database).await.unwrap();

    let shown = tokens::project_token(&database, &owner, old.id)
        .await
        .unwrap();
    assert_eq!(
        authenticated(&database, &shown.secret).await.project_id,
        Some(old.id)
    );
    assert_eq!(
        tokens::project_token(&database, &owner, kept.id)
            .await
            .unwrap()
            .secret,
        kept_secret,
        "a project that has a token keeps it"
    );
    assert_eq!(
        project_tokens::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        upload_tokens::Entity::find()
            .filter(upload_tokens::Column::ProjectId.eq(old.id))
            .count(&database)
            .await
            .unwrap(),
        1
    );
}
