//! Stale projects: the threshold, projects that never uploaded and one notification per stale
//! period.

use chrono::{Duration, Utc};
use nanobom_domain::{
    access::Actor,
    notifications, organizations, projects, staleness, testing,
    users::{self, NewUser},
};
use nanobom_entity::projects as project_entity;
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection};

async fn owner(database: &DatabaseConnection) -> Actor {
    Actor::from_user(
        &users::create(
            database,
            NewUser {
                username: "owner".to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap(),
    )
}

/// Sets a project's dates, `days` days ago.
async fn age(
    database: &DatabaseConnection,
    project: project_entity::Model,
    created: i64,
    uploaded: Option<i64>,
) -> project_entity::Model {
    let mut active: project_entity::ActiveModel = project.into();
    active.created_at = Set((Utc::now() - Duration::days(created)).fixed_offset());
    active.last_upload_at =
        Set(uploaded.map(|days| (Utc::now() - Duration::days(days)).fixed_offset()));
    active.update(database).await.unwrap()
}

#[tokio::test]
async fn projects_are_stale_past_the_threshold_and_never_when_disabled() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let fresh = projects::create(&database, &owner, organization.id, "fresh", "Fresh")
        .await
        .unwrap();
    age(&database, fresh, 90, Some(2)).await;
    let old = projects::create(&database, &owner, organization.id, "old", "Old")
        .await
        .unwrap();
    age(&database, old, 90, Some(40)).await;
    let never = projects::create(&database, &owner, organization.id, "never", "Never")
        .await
        .unwrap();
    age(&database, never, 31, None).await;
    let recent = projects::create(&database, &owner, organization.id, "recent", "Recent")
        .await
        .unwrap();
    age(&database, recent, 3, None).await;

    let mut stale: Vec<String> = staleness::stale_projects(&database, 30)
        .await
        .unwrap()
        .into_iter()
        .map(|project| project.slug)
        .collect();
    stale.sort();
    assert_eq!(stale, ["never", "old"]);
    assert_eq!(staleness::stale_count(&database, 30).await.unwrap(), 2);
    assert_eq!(staleness::stale_count(&database, 100).await.unwrap(), 0);
    assert_eq!(staleness::stale_count(&database, 0).await.unwrap(), 0);
}

#[tokio::test]
async fn stale_projects_come_in_creation_order() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let first = projects::create(&database, &owner, organization.id, "first", "First")
        .await
        .unwrap();
    let first = age(&database, first, 90, None).await;
    let second = projects::create(&database, &owner, organization.id, "second", "Second")
        .await
        .unwrap();
    age(&database, second, 90, None).await;
    // Updated last: PostgreSQL now holds its row after the second one.
    age(&database, first, 80, None).await;

    let stale: Vec<String> = staleness::stale_projects(&database, 30)
        .await
        .unwrap()
        .into_iter()
        .map(|project| project.slug)
        .collect();
    assert_eq!(stale, ["first", "second"]);
}

#[tokio::test]
async fn a_stale_period_is_notified_once_and_again_after_a_new_upload() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let silent = organizations::create(&database, &owner, "silent", "Silent")
        .await
        .unwrap();
    notifications::set(
        &database,
        &owner,
        organization.id,
        "http://127.0.0.1:9/hook",
        Severity::Critical,
        true,
        true,
    )
    .await
    .unwrap();
    let web = projects::create(&database, &owner, organization.id, "web", "Web")
        .await
        .unwrap();
    let web = age(&database, web, 90, Some(40)).await;
    let other = projects::create(&database, &owner, silent.id, "other", "Other")
        .await
        .unwrap();
    age(&database, other, 90, Some(40)).await;
    let public_url = "https://nanobom.example.org/".parse().unwrap();

    // The organization without a webhook is left out, and its project stays unnotified.
    let deliveries = notifications::stale_deliveries(&database, 30, &public_url)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    let payload = &deliveries[0].payload;
    assert_eq!(payload.event, "projects.stale");
    assert_eq!(payload.organization.slug, "acme");
    assert_eq!(payload.projects.len(), 1);
    assert_eq!(payload.projects[0].project, "web");
    assert!(payload.projects[0].last_upload_at.is_some());
    assert_eq!(
        payload.projects[0].url,
        "https://nanobom.example.org/organizations/acme/projects/web"
    );

    // Once per stale period.
    assert!(
        notifications::stale_deliveries(&database, 30, &public_url)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        staleness::newly_stale(&database, 0)
            .await
            .unwrap()
            .is_empty()
    );

    // A new upload ends the period; going stale again notifies again.
    let mut active: project_entity::ActiveModel = web.into();
    active.last_upload_at = Set(Some(Utc::now().fixed_offset()));
    let web = active.update(&database).await.unwrap();
    assert!(
        notifications::stale_deliveries(&database, 30, &public_url)
            .await
            .unwrap()
            .is_empty()
    );
    let mut active: project_entity::ActiveModel = web.into();
    active.last_upload_at = Set(Some((Utc::now() - Duration::days(35)).fixed_offset()));
    active.stale_notified_at = Set(Some((Utc::now() - Duration::days(36)).fixed_offset()));
    active.update(&database).await.unwrap();
    assert_eq!(
        notifications::stale_deliveries(&database, 30, &public_url)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn projects_that_never_uploaded_are_notified_once() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &database,
        &owner,
        organization.id,
        "http://127.0.0.1:9/hook",
        Severity::Low,
        true,
        false,
    )
    .await
    .unwrap();
    let project = projects::create(&database, &owner, organization.id, "web", "Web")
        .await
        .unwrap();
    age(&database, project, 45, None).await;
    let public_url = "https://nanobom.example.org/".parse().unwrap();
    let first = notifications::stale_deliveries(&database, 30, &public_url)
        .await
        .unwrap();
    assert_eq!(first[0].payload.projects[0].last_upload_at, None);
    assert!(
        notifications::stale_deliveries(&database, 30, &public_url)
            .await
            .unwrap()
            .is_empty()
    );
}
