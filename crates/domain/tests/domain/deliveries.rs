//! The webhook delivery queue: backoff, permanent failures, claims, pruning and listing.

use std::time::Duration;

use chrono::{DateTime, FixedOffset, SubsecRound, TimeDelta, Utc};
use nanobom_domain::{
    Error,
    access::{Actor, Role},
    deliveries::{self, ATTEMPT_LEASE, Attempt, Outcome, RETENTION, RETRY_DELAYS, State},
    memberships,
    notifications::{self, Delivery, Notifier, Payload},
    organizations, testing,
    users::{self, NewUser},
};
use nanobom_entity::webhook_deliveries;
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};
use serde::Serialize;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn actor(database: &DatabaseConnection, username: &str) -> Actor {
    Actor::from_user(
        &users::create(
            database,
            NewUser {
                username: username.to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap(),
    )
}

#[derive(Serialize)]
struct Ping {
    event: String,
}

impl Payload for Ping {
    fn event(&self) -> &str {
        &self.event
    }
}

fn ping() -> Ping {
    Ping {
        event: "ping".to_owned(),
    }
}

/// The current time to the microsecond, as PostgreSQL stores it, so that timestamps read back
/// compare equal.
fn now() -> DateTime<FixedOffset> {
    Utc::now().fixed_offset().trunc_subsecs(6)
}

fn answered(status: u16) -> Attempt {
    Attempt::Answered {
        status,
        description: status.to_string(),
    }
}

async fn enqueue(database: &DatabaseConnection, now: DateTime<FixedOffset>) -> i64 {
    deliveries::enqueue(database, None, "http://127.0.0.1:9/", "ping", &ping(), now)
        .await
        .unwrap()
        .id
}

/// Claims a delivery and records an attempt, as the notifier does.
async fn attempt(
    database: &DatabaseConnection,
    id: i64,
    result: &Attempt,
    now: DateTime<FixedOffset>,
) -> Outcome {
    let claimed = deliveries::claim(database, id, now)
        .await
        .unwrap()
        .expect("the delivery is due");
    deliveries::record(database, claimed, result, now)
        .await
        .unwrap()
        .expect("the claim still holds")
}

async fn row(database: &DatabaseConnection, id: i64) -> webhook_deliveries::Model {
    webhook_deliveries::Entity::find_by_id(id)
        .one(database)
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn answers_are_classified() {
    for status in [200, 202, 204] {
        assert!(answered(status).succeeded(), "{status}");
    }
    for status in [400, 401, 404, 410, 422] {
        assert!(answered(status).is_permanent_failure(), "{status}");
    }
    for status in [301, 408, 429, 500, 502, 503] {
        let attempt = answered(status);
        assert!(
            !attempt.succeeded() && !attempt.is_permanent_failure(),
            "{status}"
        );
    }
    let unreachable = Attempt::Unreachable("connection refused".to_owned());
    assert!(!unreachable.succeeded() && !unreachable.is_permanent_failure());
}

#[test]
fn retries_back_off_then_stop() {
    let now = now();
    assert_eq!(deliveries::next_attempt(0, now), None);
    assert_eq!(
        deliveries::next_attempt(1, now),
        Some(now + TimeDelta::minutes(1))
    );
    assert_eq!(
        deliveries::next_attempt(2, now),
        Some(now + TimeDelta::minutes(10))
    );
    assert_eq!(
        deliveries::next_attempt(3, now),
        Some(now + TimeDelta::hours(1))
    );
    assert_eq!(deliveries::next_attempt(4, now), None);
}

#[tokio::test]
async fn failed_deliveries_are_retried_three_times_then_abandoned() {
    let database = testing::database().await;
    let mut now = now();
    let id = enqueue(&database, now).await;
    assert_eq!(deliveries::due(&database, now, 10).await.unwrap().len(), 1);

    for delay in RETRY_DELAYS {
        assert_eq!(
            attempt(&database, id, &answered(503), now).await,
            Outcome::Retried
        );
        let pending = row(&database, id).await;
        assert_eq!(pending.next_attempt_at, Some(now + delay));
        assert_eq!(pending.last_status.as_deref(), Some("503"));
        assert!(
            deliveries::due(&database, now + delay - TimeDelta::seconds(1), 10)
                .await
                .unwrap()
                .is_empty(),
            "not due before its backoff expires"
        );
        now += delay;
        assert_eq!(deliveries::due(&database, now, 10).await.unwrap().len(), 1);
    }

    let unreachable = Attempt::Unreachable("connection refused".to_owned());
    assert_eq!(
        attempt(&database, id, &unreachable, now).await,
        Outcome::Abandoned
    );
    let abandoned = row(&database, id).await;
    assert_eq!(abandoned.attempts, 4);
    assert_eq!(abandoned.next_attempt_at, None);
    assert_eq!(abandoned.delivered_at, None);
    assert_eq!(abandoned.last_status.as_deref(), Some("connection refused"));
    assert!(
        deliveries::due(&database, now + TimeDelta::days(1), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn deliveries_refused_by_the_receiver_are_not_retried() {
    let database = testing::database().await;
    let now = now();
    let refused = enqueue(&database, now).await;
    assert_eq!(
        attempt(&database, refused, &answered(404), now).await,
        Outcome::Abandoned
    );
    assert_eq!(row(&database, refused).await.attempts, 1);

    for status in [408, 429] {
        let id = enqueue(&database, now).await;
        assert_eq!(
            attempt(&database, id, &answered(status), now).await,
            Outcome::Retried,
            "{status}"
        );
    }

    let delivered = enqueue(&database, now).await;
    assert_eq!(
        attempt(&database, delivered, &answered(200), now).await,
        Outcome::Delivered
    );
    let delivered = row(&database, delivered).await;
    assert_eq!(delivered.delivered_at, Some(now));
    assert_eq!(delivered.next_attempt_at, None);
}

#[tokio::test]
async fn a_claimed_delivery_is_not_attempted_twice() {
    let database = testing::database().await;
    let now = now();
    let id = enqueue(&database, now).await;
    assert!(
        deliveries::claim(&database, id, now)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        deliveries::claim(&database, id, now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        deliveries::due(&database, now, 10)
            .await
            .unwrap()
            .is_empty()
    );
    // An attempt cut short (a restart) leaves the row to be retried once its lease expires.
    assert!(
        deliveries::claim(&database, id, now + ATTEMPT_LEASE)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn old_finished_deliveries_are_pruned() {
    let database = testing::database().await;
    let now = now();
    let old = now - RETENTION - TimeDelta::days(1);
    let old_delivered = enqueue(&database, old).await;
    attempt(&database, old_delivered, &answered(200), old).await;
    let old_refused = enqueue(&database, old).await;
    attempt(&database, old_refused, &answered(410), old).await;
    // Still pending, however old: never pruned.
    let old_pending = enqueue(&database, old).await;
    let recent = enqueue(&database, now).await;
    attempt(&database, recent, &answered(200), now).await;

    assert_eq!(deliveries::prune(&database, now).await.unwrap(), 2);
    let left: Vec<i64> = webhook_deliveries::Entity::find()
        .all(&database)
        .await
        .unwrap()
        .into_iter()
        .map(|delivery| delivery.id)
        .collect();
    assert_eq!(left, [old_pending, recent]);
}

#[tokio::test]
async fn only_webhook_managers_see_their_organization_deliveries() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let member = actor(&database, "member").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let other = organizations::create(&database, &owner, "other", "Other")
        .await
        .unwrap();
    memberships::add(&database, &owner, acme.id, "member", Role::Member)
        .await
        .unwrap();
    let now = now();
    let url = "http://127.0.0.1:9/";
    let first = deliveries::enqueue(&database, Some(acme.id), url, "ping", &ping(), now)
        .await
        .unwrap();
    deliveries::enqueue(&database, Some(other.id), url, "ping", &ping(), now)
        .await
        .unwrap();
    // The instance's failure webhook belongs to no organization.
    deliveries::enqueue(&database, None, url, "run.failed", &ping(), now)
        .await
        .unwrap();
    let second = deliveries::enqueue(
        &database,
        Some(acme.id),
        url,
        "ping",
        &ping(),
        now + TimeDelta::seconds(1),
    )
    .await
    .unwrap();
    attempt(
        &database,
        second.id,
        &answered(429),
        now + TimeDelta::seconds(1),
    )
    .await;

    assert!(matches!(
        deliveries::recent(&database, &member, acme.id, 10).await,
        Err(Error::Forbidden)
    ));
    let recent = deliveries::recent(&database, &owner, acme.id, 10)
        .await
        .unwrap();
    let ids: Vec<i64> = recent.iter().map(|delivery| delivery.id).collect();
    assert_eq!(ids, [second.id, first.id], "the newest first");
    assert_eq!(recent[0].state, State::Pending);
    assert_eq!(recent[0].attempts, 1);
    assert_eq!(recent[1].attempts, 0);
}

#[tokio::test]
async fn removing_a_webhook_abandons_its_pending_deliveries() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let other = organizations::create(&database, &owner, "other", "Other")
        .await
        .unwrap();
    for organization in [acme.id, other.id] {
        notifications::set(
            &database,
            &owner,
            organization,
            "https://example.org/hook",
            Severity::High,
            true,
            false,
        )
        .await
        .unwrap();
    }
    let now = now();
    let url = "https://example.org/hook";
    let pending = deliveries::enqueue(&database, Some(acme.id), url, "ping", &ping(), now)
        .await
        .unwrap();
    let delivered = deliveries::enqueue(&database, Some(acme.id), url, "ping", &ping(), now)
        .await
        .unwrap();
    attempt(&database, delivered.id, &answered(200), now).await;
    let elsewhere = deliveries::enqueue(&database, Some(other.id), url, "ping", &ping(), now)
        .await
        .unwrap();

    notifications::delete(&database, &owner, acme.id)
        .await
        .unwrap();
    assert_eq!(row(&database, pending.id).await.next_attempt_at, None);
    assert!(row(&database, delivered.id).await.delivered_at.is_some());
    let due: Vec<i64> = deliveries::due(&database, now, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|delivery| delivery.id)
        .collect();
    assert_eq!(due, [elsewhere.id]);
}

#[tokio::test]
async fn the_notifier_retries_a_delivery_once_its_backoff_expires() {
    let database = testing::database().await;
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&receiver)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;
    let notifier = Notifier::new().unwrap();
    let outcomes = notifier
        .deliver(
            &database,
            vec![Delivery {
                organization_id: None,
                url: format!("{}/hook", receiver.uri()),
                payload: ping(),
            }],
        )
        .await
        .unwrap();
    assert_eq!(outcomes, [Outcome::Retried]);
    assert!(
        notifier.retry_due(&database, 10).await.unwrap().is_empty(),
        "not due yet"
    );

    let pending = webhook_deliveries::Entity::find()
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    let mut active: webhook_deliveries::ActiveModel = pending.into();
    active.next_attempt_at = Set(Some((Utc::now() - TimeDelta::seconds(1)).fixed_offset()));
    let pending = active.update(&database).await.unwrap();

    assert_eq!(
        notifier.retry_due(&database, 10).await.unwrap(),
        [Outcome::Delivered]
    );
    let delivered = row(&database, pending.id).await;
    assert_eq!(delivered.attempts, 2);
    assert!(delivered.delivered_at.is_some());
    let requests = receiver.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body, "the same document");
    assert_eq!(
        requests[1].headers.get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn an_attempt_does_not_overwrite_a_cancellation_or_a_newer_claim() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let acme = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let now = now();
    let url = "https://example.org/hook";

    // The webhook is removed while an attempt is in progress.
    let cancelled = deliveries::enqueue(&database, Some(acme.id), url, "ping", &ping(), now)
        .await
        .unwrap();
    let claimed = deliveries::claim(&database, cancelled.id, now)
        .await
        .unwrap()
        .unwrap();
    deliveries::cancel_pending(&database, acme.id)
        .await
        .unwrap();
    assert_eq!(
        deliveries::record(&database, claimed, &answered(503), now)
            .await
            .unwrap(),
        None
    );
    let cancelled = row(&database, cancelled.id).await;
    assert_eq!(cancelled.next_attempt_at, None, "no retry is scheduled");
    assert_eq!(cancelled.attempts, 0);

    // An attempt outlives its lease and another one takes over.
    let id = enqueue(&database, now).await;
    let late = deliveries::claim(&database, id, now)
        .await
        .unwrap()
        .unwrap();
    let later = now + ATTEMPT_LEASE;
    let current = deliveries::claim(&database, id, later)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        deliveries::record(&database, late, &answered(503), later)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        deliveries::record(&database, current, &answered(200), later)
            .await
            .unwrap(),
        Some(Outcome::Delivered)
    );
    let delivered = row(&database, id).await;
    assert_eq!(delivered.attempts, 1);
    assert_eq!(delivered.delivered_at, Some(later));
}

#[tokio::test]
async fn every_delivery_is_recorded_before_the_first_attempt() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let mut organizations_ids = Vec::new();
    for slug in ["acme", "other", "third"] {
        organizations_ids.push(
            organizations::create(&database, &owner, slug, slug)
                .await
                .unwrap()
                .id,
        );
    }
    let receiver = MockServer::start().await;
    // The first receiver never answers in time.
    Mock::given(method("POST"))
        .and(path("/hangs"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
        .mount(&receiver)
        .await;
    Mock::given(method("POST"))
        .and(path("/answers"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&receiver)
        .await;
    let deliveries: Vec<Delivery<Ping>> = organizations_ids
        .iter()
        .enumerate()
        .map(|(index, &organization)| Delivery {
            organization_id: Some(organization),
            url: format!(
                "{}/{}",
                receiver.uri(),
                if index == 0 { "hangs" } else { "answers" }
            ),
            payload: ping(),
        })
        .collect();
    let sending = tokio::spawn({
        let database = database.clone();
        async move {
            Notifier::new()
                .unwrap()
                .deliver(&database, deliveries)
                .await
        }
    });

    // Wait for the first post to reach the receiver that hangs.
    tokio::time::timeout(Duration::from_secs(10), async {
        while receiver.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first delivery is attempted");
    // A restart now would lose nothing: every organization's document is recorded.
    let rows = webhook_deliveries::Entity::find()
        .all(&database)
        .await
        .unwrap();
    let recorded: Vec<Option<i64>> = rows.iter().map(|row| row.organization_id).collect();
    let expected: Vec<Option<i64>> = organizations_ids.iter().copied().map(Some).collect();
    assert_eq!(recorded, expected);
    assert_eq!(
        receiver.received_requests().await.unwrap().len(),
        1,
        "the others wait for the first attempt"
    );
    assert!(
        rows[1..]
            .iter()
            .all(|row| row.attempts == 0 && row.next_attempt_at.is_some()),
        "the others are pending"
    );
    sending.abort();
}
