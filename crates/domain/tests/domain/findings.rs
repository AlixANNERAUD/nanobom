//! Listing findings: the open findings an upload token may read back after an upload.

use chrono::Utc;
use nanobom_domain::{
    Error,
    access::Actor,
    findings, organizations, projects, testing, tokens,
    users::{self, NewUser},
};
use nanobom_entity::{components, findings as findings_entity, upload_tokens, vulnerabilities};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection};

/// An open finding of `vulnerability_id` in a project.
async fn open_finding(database: &DatabaseConnection, project_id: i64, vulnerability_id: &str) {
    vulnerabilities::ActiveModel {
        id: Set(vulnerability_id.to_owned()),
        modified: Set(Utc::now().fixed_offset()),
        aliases: Set("[]".to_owned()),
        severity: Set("high".to_owned()),
        record: Set("{}".to_owned()),
        fetched_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
    findings_entity::ActiveModel {
        project_id: Set(project_id),
        purl: Set("pkg:npm/lodash@4.17.20".to_owned()),
        ecosystem: Set("npm".to_owned()),
        vulnerability_id: Set(vulnerability_id.to_owned()),
        status: Set("open".to_owned()),
        severity: Set("high".to_owned()),
        first_seen_at: Set(Utc::now().fixed_offset()),
        last_seen_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
}

/// The token as authenticated by the upload API.
async fn token_model(
    database: &DatabaseConnection,
    token: &tokens::CreatedToken,
) -> upload_tokens::Model {
    tokens::authenticate(database, &token.secret)
        .await
        .unwrap()
        .expect("a valid token")
}

#[tokio::test]
async fn upload_tokens_read_only_the_open_findings_of_projects_they_cover() {
    let database = testing::database().await;
    let user = users::create(
        &database,
        NewUser {
            username: "owner".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let owner = Actor::from_user(&user);
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    let globex = organizations::create(&database, &owner, "globex", "Globex")
        .await
        .unwrap()
        .id;
    let web = projects::create(&database, &owner, acme, "web", "Web")
        .await
        .unwrap()
        .id;
    let api = projects::create(&database, &owner, acme, "api", "API")
        .await
        .unwrap()
        .id;
    open_finding(&database, web, "GHSA-0000-0000-0001").await;
    open_finding(&database, api, "GHSA-0000-0000-0002").await;

    let acme_token = tokens::create(&database, &owner, acme, None, "CI")
        .await
        .unwrap();
    let acme_token = token_model(&database, &acme_token).await;
    let web_token = tokens::create(&database, &owner, acme, Some("web"), "Web CI")
        .await
        .unwrap();
    let web_token = token_model(&database, &web_token).await;
    let globex_token = tokens::create(&database, &owner, globex, None, "CI")
        .await
        .unwrap();
    let globex_token = token_model(&database, &globex_token).await;

    let identifiers = |findings: Vec<findings::Finding>| {
        findings
            .into_iter()
            .map(|finding| finding.vulnerability_id)
            .collect::<Vec<_>>()
    };
    // The token's own project, whether the token covers the organization or the project.
    assert_eq!(
        identifiers(
            findings::open_for_upload_token(&database, &acme_token, api)
                .await
                .unwrap()
        ),
        ["GHSA-0000-0000-0002"]
    );
    assert_eq!(
        identifiers(
            findings::open_for_upload_token(&database, &web_token, web)
                .await
                .unwrap()
        ),
        ["GHSA-0000-0000-0001"]
    );
    // Another organization's token.
    assert!(matches!(
        findings::open_for_upload_token(&database, &globex_token, web).await,
        Err(Error::NotFound)
    ));
    // A project token used on a sibling project.
    assert!(matches!(
        findings::open_for_upload_token(&database, &web_token, api).await,
        Err(Error::NotFound)
    ));
    // A project that does not exist.
    assert!(matches!(
        findings::open_for_upload_token(&database, &acme_token, api + web + 100).await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn every_finding_of_a_component_carries_its_license() {
    let database = testing::database().await;
    let user = users::create(
        &database,
        NewUser {
            username: "owner".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let owner = Actor::from_user(&user);
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    let web = projects::create(&database, &owner, acme, "web", "Web")
        .await
        .unwrap()
        .id;
    components::ActiveModel {
        project_id: Set(web),
        purl: Set("pkg:npm/lodash@4.17.20".to_owned()),
        query_purl: Set("pkg:npm/lodash@4.17.20".to_owned()),
        ecosystem: Set("npm".to_owned()),
        name: Set("lodash".to_owned()),
        version: Set(Some("4.17.20".to_owned())),
        license: Set(Some("MIT".to_owned())),
        ..Default::default()
    }
    .insert(&database)
    .await
    .unwrap();
    // Two vulnerabilities of the same component.
    open_finding(&database, web, "GHSA-0000-0000-0001").await;
    open_finding(&database, web, "GHSA-0000-0000-0002").await;

    let findings = findings::list(&database, &owner, web, &findings::Filter::default())
        .await
        .unwrap();
    assert_eq!(findings.len(), 2);
    for finding in &findings {
        assert_eq!(
            finding.license.as_deref(),
            Some("MIT"),
            "{}",
            finding.vulnerability_id
        );
    }
}
