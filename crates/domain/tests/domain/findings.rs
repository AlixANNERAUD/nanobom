//! Listing findings: the open findings an upload token may read back after an upload, the
//! licenses they carry and the summary of a version's open findings.

use chrono::Utc;
use nanobom_domain::{
    Error,
    access::Actor,
    findings, organizations, projects, testing, tokens,
    users::{self, NewUser},
};
use nanobom_entity::{
    components, exploitation, findings as findings_entity, upload_tokens, vulnerabilities,
};
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
        version_id: Set(Some(testing::latest_version(database, project_id).await)),
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
            findings::open_for_upload_token(&database, &acme_token, api, "")
                .await
                .unwrap()
        ),
        ["GHSA-0000-0000-0002"]
    );
    assert_eq!(
        identifiers(
            findings::open_for_upload_token(&database, &web_token, web, "")
                .await
                .unwrap()
        ),
        ["GHSA-0000-0000-0001"]
    );
    // Another organization's token.
    assert!(matches!(
        findings::open_for_upload_token(&database, &globex_token, web, "").await,
        Err(Error::NotFound)
    ));
    // A project token used on a sibling project.
    assert!(matches!(
        findings::open_for_upload_token(&database, &web_token, api, "").await,
        Err(Error::NotFound)
    ));
    // A project that does not exist.
    assert!(matches!(
        findings::open_for_upload_token(&database, &acme_token, api + web + 100, "").await,
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
        version_id: Set(Some(testing::latest_version(&database, web).await)),
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

/// A finding of the project's latest version, each on its own component.
async fn finding(
    database: &DatabaseConnection,
    project_id: i64,
    vulnerability_id: &str,
    aliases: &[&str],
    severity: &str,
    status: &str,
) {
    vulnerabilities::ActiveModel {
        id: Set(vulnerability_id.to_owned()),
        modified: Set(Utc::now().fixed_offset()),
        aliases: Set(serde_json::to_string(aliases).unwrap()),
        severity: Set(severity.to_owned()),
        record: Set("{}".to_owned()),
        fetched_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
    findings_entity::ActiveModel {
        project_id: Set(project_id),
        version_id: Set(Some(testing::latest_version(database, project_id).await)),
        purl: Set(format!("pkg:npm/{}@1.0.0", vulnerability_id.to_lowercase())),
        ecosystem: Set("npm".to_owned()),
        vulnerability_id: Set(vulnerability_id.to_owned()),
        status: Set(status.to_owned()),
        severity: Set(severity.to_owned()),
        first_seen_at: Set(Utc::now().fixed_offset()),
        last_seen_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
}

async fn known_exploited(database: &DatabaseConnection, cve: &str) {
    exploitation::ActiveModel {
        cve_id: Set(cve.to_owned()),
        known_exploited: Set(true),
        kev_ransomware: Set(false),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
}

#[tokio::test]
async fn the_open_summary_counts_only_open_findings_of_the_version() {
    let database = testing::database().await;
    let user = |username: &str| {
        users::create(
            &database,
            NewUser {
                username: username.to_owned(),
                ..NewUser::default()
            },
            false,
        )
    };
    let owner = Actor::from_user(&user("owner").await.unwrap());
    let stranger = Actor::from_user(&user("stranger").await.unwrap());
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    let web = projects::create(&database, &owner, acme, "web", "Web")
        .await
        .unwrap()
        .id;
    let empty = projects::create(&database, &owner, acme, "empty", "Empty")
        .await
        .unwrap()
        .id;

    assert_eq!(
        findings::open_summary_in_version(&database, &owner, empty, None)
            .await
            .unwrap(),
        findings::OpenSummary::default()
    );

    finding(
        &database,
        web,
        "GHSA-0000-0000-0001",
        &["CVE-2024-0001"],
        "critical",
        "open",
    )
    .await;
    finding(&database, web, "GHSA-0000-0000-0002", &[], "high", "open").await;
    finding(&database, web, "GHSA-0000-0000-0003", &[], "high", "open").await;
    // A severity the database holds but the code does not know counts as unknown.
    finding(&database, web, "GHSA-0000-0000-0004", &[], "none", "open").await;
    // Neither ignored nor fixed findings are open, known exploited or not.
    finding(
        &database,
        web,
        "GHSA-0000-0000-0005",
        &["CVE-2024-0005"],
        "critical",
        "ignored",
    )
    .await;
    finding(
        &database,
        web,
        "GHSA-0000-0000-0006",
        &["CVE-2024-0006"],
        "low",
        "fixed",
    )
    .await;
    // A vulnerability filed under its CVE identifier.
    finding(&database, web, "CVE-2024-0007", &[], "medium", "open").await;
    for cve in [
        "CVE-2024-0001",
        "CVE-2024-0005",
        "CVE-2024-0006",
        "CVE-2024-0007",
    ] {
        known_exploited(&database, cve).await;
    }

    let summary = findings::open_summary_in_version(&database, &owner, web, None)
        .await
        .unwrap();
    assert_eq!(
        summary.counts,
        findings::SeverityCounts {
            critical: 1,
            high: 2,
            medium: 1,
            low: 0,
            unknown: 1,
        }
    );
    assert_eq!(summary.known_exploited, 2);
    // The latest version by its name (the unnamed version) is the same.
    assert_eq!(
        findings::open_summary_in_version(&database, &owner, web, Some(""))
            .await
            .unwrap(),
        summary
    );

    assert!(matches!(
        findings::open_summary_in_version(&database, &owner, web, Some("9.9")).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        findings::open_summary_in_version(&database, &stranger, web, None).await,
        Err(Error::NotFound)
    ));
}
