//! Token scopes, and what tokens read through [`Reader`].

use chrono::{Duration, Utc};
use nanobom_domain::{
    Error, Problem,
    access::{Actor, Permission, Reader, Role},
    findings::{self, Filter},
    inventory::{self, UploadSource},
    organizations, projects, testing,
    tokens::{self, Scope},
    users::{self, NewUser},
    vex,
};
use nanobom_entity::upload_tokens;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait, PaginatorTrait,
};

async fn owner(database: &DatabaseConnection) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: "owner".to_owned(),
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

#[test]
fn scopes_have_stable_names() {
    for scope in Scope::ALL {
        assert_eq!(Scope::parse(scope.as_str()).unwrap(), scope);
    }
    assert_eq!(Scope::default(), Scope::Upload);
    assert!(matches!(
        Scope::parse("write"),
        Err(Error::Invalid(Problem::UnknownTokenScope { .. }))
    ));
}

#[tokio::test]
async fn tokens_are_created_with_a_scope() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let upload = tokens::create(&database, &owner, acme.id, None, "CI")
        .await
        .unwrap();
    assert_eq!(upload.token.scope, Scope::Upload);
    let read = tokens::create_from_command_line(&database, "acme", None, "Grafana", Scope::Read)
        .await
        .unwrap();
    assert_eq!(read.token.scope, Scope::Read);
    let stored = authenticated(&database, &read.secret).await;
    assert_eq!(stored.scope, "read");
    let listed = tokens::list(&database, &owner, acme.id).await.unwrap();
    let scopes: Vec<Scope> = listed.iter().map(|token| token.scope).collect();
    assert!(scopes.contains(&Scope::Upload) && scopes.contains(&Scope::Read));
}

/// Authenticating is a read: `last_used_at` is written only when it is a minute old, so a
/// script polling the read API does not contend for the writer lock on every request.
#[tokio::test]
async fn use_is_recorded_at_most_once_a_minute() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let created = tokens::create(&database, &owner, acme.id, None, "CI")
        .await
        .unwrap();

    let first = authenticated(&database, &created.secret).await;
    let first_use = first.last_used_at.expect("the first use is recorded");

    // Within the minute: the stored value stays, and so does the one returned.
    let second = authenticated(&database, &created.secret).await;
    assert_eq!(second.last_used_at, Some(first_use));
    let stored = upload_tokens::Entity::find_by_id(first.id)
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.last_used_at, Some(first_use));

    // Older than a minute: written again.
    let old = (Utc::now() - Duration::minutes(2)).fixed_offset();
    let mut active: upload_tokens::ActiveModel = stored.into();
    active.last_used_at = Set(Some(old));
    active.update(&database).await.unwrap();
    let third = authenticated(&database, &created.secret).await;
    assert!(third.last_used_at.unwrap() > old + Duration::minutes(1));
    let listed = tokens::list(&database, &owner, acme.id).await.unwrap();
    assert_eq!(listed[0].last_used_at, third.last_used_at);
}

/// The domain refuses read tokens on every write path, whatever the server checks first.
#[tokio::test]
async fn read_tokens_cannot_upload_import_or_create_projects() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let read = tokens::create_with_scope(&database, &owner, acme.id, None, "read", Scope::Read)
        .await
        .unwrap();
    let token = authenticated(&database, &read.secret).await;

    for project in ["web", "new"] {
        let result = inventory::ingest(
            &database,
            &token,
            "acme",
            project,
            sbom(),
            UploadSource::default(),
        )
        .await;
        assert!(matches!(result, Err(Error::Forbidden)), "{project}");
        let result = inventory::ingest_into_token_organization(
            &database,
            &token,
            project,
            sbom(),
            UploadSource::default(),
            true,
        )
        .await;
        assert!(matches!(result, Err(Error::Forbidden)), "{project}");
    }
    let statements = vex::parse(
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "vulnerabilities": []}"#,
    )
    .unwrap();
    assert!(matches!(
        vex::import(&database, &token, "acme", "web", None, &statements).await,
        Err(Error::Forbidden)
    ));
    // Another organization stays missing rather than forbidden.
    assert!(matches!(
        inventory::ingest(
            &database,
            &token,
            "globex",
            "web",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    assert_eq!(
        nanobom_entity::projects::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        1,
        "no project was created"
    );
    assert_eq!(
        nanobom_entity::sbom_uploads::Entity::find()
            .count(&database)
            .await
            .unwrap(),
        0
    );
}

/// A token reads as a viewer of its organization, and a project token sees one project.
#[tokio::test]
async fn token_readers_see_their_reach_as_viewers() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let globex = organizations::create(&database, &owner, "globex", "Globex")
        .await
        .unwrap();
    let web = projects::create(&database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let api = projects::create(&database, &owner, acme.id, "api", "API")
        .await
        .unwrap();
    let organization_token = tokens::create(&database, &owner, acme.id, None, "organization")
        .await
        .unwrap();
    let project_token =
        tokens::create_with_scope(&database, &owner, acme.id, Some("web"), "web", Scope::Read)
            .await
            .unwrap();
    let organization_token = authenticated(&database, &organization_token.secret).await;
    let project_token = authenticated(&database, &project_token.secret).await;

    for token in [&organization_token, &project_token] {
        let reader = Reader::from(token);
        let visible = organizations::list(&database, reader).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].slug, "acme");
        assert_eq!(visible[0].role, Role::Viewer);
        assert!(matches!(
            organizations::find(&database, reader, "globex").await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            projects::list(&database, reader, globex.id).await,
            Err(Error::NotFound)
        ));
        // Viewers do not triage.
        assert!(matches!(
            reader
                .authorize(&database, acme.id, Permission::TriageFindings)
                .await,
            Err(Error::Forbidden)
        ));
        findings::list(&database, reader, web.id, &Filter::default())
            .await
            .unwrap();
    }

    let reader = Reader::from(&organization_token);
    let slugs: Vec<String> = projects::list(&database, reader, acme.id)
        .await
        .unwrap()
        .into_iter()
        .map(|project| project.slug)
        .collect();
    assert_eq!(slugs, ["api", "web"]);

    let reader = Reader::from(&project_token);
    let slugs: Vec<String> = projects::list(&database, reader, acme.id)
        .await
        .unwrap()
        .into_iter()
        .map(|project| project.slug)
        .collect();
    assert_eq!(slugs, ["web"]);
    assert!(matches!(
        projects::find(&database, reader, acme.id, "api").await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        findings::list(&database, reader, api.id, &Filter::default()).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        inventory::components(&database, reader, api.id).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        vex::export(&database, reader, "acme", "api", None).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn revoked_and_deleted_tokens_are_no_longer_active() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let revoked = tokens::create(&database, &owner, acme.id, None, "CI")
        .await
        .unwrap();
    let token = authenticated(&database, &revoked.secret).await;
    assert!(tokens::is_active(&database, token.id).await.unwrap());
    tokens::revoke(&database, &owner, token.id).await.unwrap();
    assert!(!tokens::is_active(&database, token.id).await.unwrap());

    let deleted = tokens::create(&database, &owner, acme.id, None, "Release")
        .await
        .unwrap();
    upload_tokens::Entity::delete_by_id(deleted.token.id)
        .exec(&database)
        .await
        .unwrap();
    assert!(
        !tokens::is_active(&database, deleted.token.id)
            .await
            .unwrap()
    );
}
