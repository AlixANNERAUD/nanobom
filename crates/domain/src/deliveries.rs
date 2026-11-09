//! The delivery queue of notifications: webhooks and emails.
//!
//! Every document is recorded in `webhook_deliveries` before its first attempt, so that a
//! receiver that is down misses nothing: failed attempts are retried with backoff
//! ([`RETRY_DELAYS`]) and the organization's settings show the latest deliveries. Findings and
//! projects are marked notified when deliveries are prepared; from then on the row is the
//! durable record of what is owed to the receiver, so nothing is notified twice.
//!
//! A row is in one of three states:
//!
//! - pending: `next_attempt_at` is set, the time of its next attempt;
//! - delivered: `delivered_at` is set;
//! - abandoned: neither, after a permanent failure, once the retries are exhausted, or when it
//!   is cancelled ([`State`] tells a cancellation before any recorded attempt apart).
//!
//! An attempt first claims its row by moving `next_attempt_at` [`ATTEMPT_LEASE`] ahead, so the
//! attempt made right after a run and the retry loop never post the same row at once, and a
//! row whose attempt was cut short (a restart) is retried once the lease expires. Its result is
//! recorded only if the row still holds that lease: a delivery cancelled meanwhile (its webhook
//! removed, disabled or moved) stays cancelled, and an attempt whose lease expired does not
//! overwrite the one that took over.
//!
//! A retry posts the very document recorded at enqueue time, so a receiver sees the same body
//! each time, and may see it twice if an attempt succeeded but its result could not be
//! recorded. Only [`recent`] takes an actor; the rest serves the run worker and the server's
//! retry loop.
//!
//! Each row has a [`Channel`]. Emails share the table and its lease, claim and backoff logic
//! rather than having a queue of their own, which would duplicate every query of this module:
//! an email row holds its one recipient in `url` (an email to several recipients is a row per
//! recipient) and the rendered message in `payload` (see [`crate::email::Message`]).

use chrono::{DateTime, FixedOffset, TimeDelta};
use nanobom_entity::webhook_deliveries;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, sea_query::Expr,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::Result,
};

/// Waits before each retry of a failed attempt: the first retry comes one minute after the
/// first attempt, and so on. A delivery whose last retry fails is abandoned.
pub const RETRY_DELAYS: [TimeDelta; 3] = [
    TimeDelta::minutes(1),
    TimeDelta::minutes(10),
    TimeDelta::hours(1),
];

/// How long a claimed attempt holds its row. Longer than the request timeout of the
/// notifier (15 seconds), so that a claim never expires while its attempt is still running.
pub const ATTEMPT_LEASE: TimeDelta = TimeDelta::minutes(2);

/// Delivered and failed rows older than this are deleted.
pub const RETENTION: TimeDelta = TimeDelta::days(30);

/// How a delivery reaches its receiver, stored in its row's `channel` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// An HTTP post to a webhook.
    Webhook,
    /// An email sent through the instance's SMTP server.
    Email,
}

impl Channel {
    /// The stored name, also the value of the `channel` label of the delivery metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Webhook => "webhook",
            Channel::Email => "email",
        }
    }

    /// The channel of a stored name; anything else is a webhook, the only channel of the rows
    /// that predate the column.
    pub fn parse(value: &str) -> Self {
        if value == "email" {
            Channel::Email
        } else {
            Channel::Webhook
        }
    }
}

/// Where a delivery stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Not attempted yet: the first attempt is about to be made or in progress.
    Sending,
    /// Not delivered yet; another attempt is scheduled.
    Pending,
    Delivered,
    /// Abandoned: the receiver refused it, every retry failed, or it was cancelled after a failed
    /// attempt.
    Failed,
    /// Cancelled (its webhook removed, disabled or moved) before any attempt was recorded. An
    /// attempt in progress at that moment may still have reached the receiver: its result is
    /// not recorded.
    Cancelled,
}

fn state(model: &webhook_deliveries::Model) -> State {
    if model.delivered_at.is_some() {
        State::Delivered
    } else if model.next_attempt_at.is_some() {
        if model.attempts == 0 {
            State::Sending
        } else {
            State::Pending
        }
    } else if model.attempts == 0 {
        // Every recorded attempt counts, so an unfinished row without one was cancelled.
        State::Cancelled
    } else {
        State::Failed
    }
}

/// What an attempt led to, for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    /// The attempt failed and a retry is scheduled.
    Retried,
    /// The attempt failed and no retry follows.
    Abandoned,
}

impl Outcome {
    /// The value of the `outcome` label of the delivery metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Delivered => "delivered",
            Outcome::Retried => "retried",
            Outcome::Abandoned => "abandoned",
        }
    }
}

/// How the receiver answered one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// An HTTP answer, with its status code and a description such as `503 Service Unavailable`.
    Answered { status: u16, description: String },
    /// The last reply of an SMTP server, with its code and a description such as
    /// `550 mailbox unavailable`.
    Replied { code: u16, description: String },
    /// No answer: the connection failed or timed out.
    Unreachable(String),
    /// Not attempted, and never will be: the delivery cannot be made by this server, such as an
    /// email while no SMTP server is configured.
    Impossible(String),
}

impl Attempt {
    /// The status line of the answer, or why there was none.
    pub fn description(&self) -> &str {
        match self {
            Attempt::Answered { description, .. }
            | Attempt::Replied { description, .. }
            | Attempt::Unreachable(description)
            | Attempt::Impossible(description) => description,
        }
    }

    /// Any 2xx answer or reply.
    pub fn succeeded(&self) -> bool {
        matches!(
            self,
            Attempt::Answered { status: code, .. } | Attempt::Replied { code, .. }
                if (200..300).contains(code)
        )
    }

    /// An answer that would come again: an HTTP 4xx other than 408 (Request Timeout) and 429
    /// (Too Many Requests), or an SMTP 5xx (permanent negative completion, such as an unknown
    /// mailbox). SMTP 4xx replies are transient by definition and retried.
    pub fn is_permanent_failure(&self) -> bool {
        match self {
            Attempt::Answered { status, .. } => {
                (400..500).contains(status) && !matches!(status, 408 | 429)
            }
            Attempt::Replied { code, .. } => (500..600).contains(code),
            Attempt::Unreachable(_) => false,
            Attempt::Impossible(_) => true,
        }
    }
}

/// When to try again after `attempts` failed attempts, or `None` to give up.
pub fn next_attempt(attempts: i64, now: DateTime<FixedOffset>) -> Option<DateTime<FixedOffset>> {
    let retry = usize::try_from(attempts).ok()?.checked_sub(1)?;
    RETRY_DELAYS.get(retry).map(|delay| now + *delay)
}

/// Records a webhook delivery to attempt now. `organization_id` is `None` for the instance's
/// failure webhook.
pub async fn enqueue(
    database: &impl ConnectionTrait,
    organization_id: Option<i64>,
    url: &str,
    event: &str,
    payload: &impl Serialize,
    now: DateTime<FixedOffset>,
) -> Result<webhook_deliveries::Model> {
    let payload = serde_json::to_string(payload).expect("payloads serialize to JSON");
    enqueue_body(
        database,
        organization_id,
        Channel::Webhook,
        url,
        event,
        payload,
        now,
    )
    .await
}

/// Like [`enqueue`], for a body rendered by the caller: the chat formats of
/// [`crate::notifications::Format`] are not the serialization of the payload, and an email
/// carries a rendered message. The body is stored as is and sent as is by every attempt. For an
/// email, `url` holds its recipient.
pub async fn enqueue_body(
    database: &impl ConnectionTrait,
    organization_id: Option<i64>,
    channel: Channel,
    url: &str,
    event: &str,
    payload: String,
    now: DateTime<FixedOffset>,
) -> Result<webhook_deliveries::Model> {
    Ok(webhook_deliveries::ActiveModel {
        organization_id: Set(organization_id),
        channel: Set(channel.as_str().to_owned()),
        url: Set(url.to_owned()),
        event: Set(event.to_owned()),
        payload: Set(payload),
        attempts: Set(0),
        next_attempt_at: Set(Some(now)),
        last_attempt_at: Set(None),
        last_status: Set(None),
        delivered_at: Set(None),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(database)
    .await?)
}

/// Pending deliveries due at `now`, the oldest first.
pub async fn due(
    database: &impl ConnectionTrait,
    now: DateTime<FixedOffset>,
    limit: u64,
) -> Result<Vec<webhook_deliveries::Model>> {
    Ok(webhook_deliveries::Entity::find()
        .filter(webhook_deliveries::Column::NextAttemptAt.lte(now))
        .order_by_asc(webhook_deliveries::Column::NextAttemptAt)
        .order_by_asc(webhook_deliveries::Column::Id)
        .limit(limit)
        .all(database)
        .await?)
}

/// Claims a due delivery for an attempt; `None` when it is not due any more (another attempt
/// claimed it, or it is finished).
pub async fn claim(
    database: &impl ConnectionTrait,
    id: i64,
    now: DateTime<FixedOffset>,
) -> Result<Option<webhook_deliveries::Model>> {
    let claimed = webhook_deliveries::Entity::update_many()
        .col_expr(
            webhook_deliveries::Column::NextAttemptAt,
            Expr::value(now + ATTEMPT_LEASE),
        )
        .filter(webhook_deliveries::Column::Id.eq(id))
        .filter(webhook_deliveries::Column::NextAttemptAt.lte(now))
        .exec(database)
        .await?;
    if claimed.rows_affected == 0 {
        return Ok(None);
    }
    Ok(webhook_deliveries::Entity::find_by_id(id)
        .one(database)
        .await?)
}

/// Records the result of an attempt on a delivery returned by [`claim`] and schedules the next
/// one. `None` when the row no longer holds that claim: the delivery was cancelled during the
/// attempt, or the lease expired and another attempt took over; the row is then left as is.
pub async fn record(
    database: &impl ConnectionTrait,
    delivery: webhook_deliveries::Model,
    attempt: &Attempt,
    now: DateTime<FixedOffset>,
) -> Result<Option<Outcome>> {
    let Some(lease) = delivery.next_attempt_at else {
        return Ok(None);
    };
    let attempts = delivery.attempts + 1;
    let (outcome, next, delivered) = if attempt.succeeded() {
        (Outcome::Delivered, None, Some(now))
    } else if attempt.is_permanent_failure() {
        (Outcome::Abandoned, None, None)
    } else {
        match next_attempt(attempts, now) {
            Some(next) => (Outcome::Retried, Some(next), None),
            None => (Outcome::Abandoned, None, None),
        }
    };
    // The lease read back by `claim` is compared with itself as stored, so the equality holds
    // whatever precision the database keeps.
    let recorded = webhook_deliveries::Entity::update_many()
        .col_expr(webhook_deliveries::Column::Attempts, Expr::value(attempts))
        .col_expr(
            webhook_deliveries::Column::LastAttemptAt,
            Expr::value(Some(now)),
        )
        .col_expr(
            webhook_deliveries::Column::LastStatus,
            Expr::value(Some(attempt.description().to_owned())),
        )
        .col_expr(webhook_deliveries::Column::NextAttemptAt, Expr::value(next))
        .col_expr(
            webhook_deliveries::Column::DeliveredAt,
            Expr::value(delivered),
        )
        .filter(webhook_deliveries::Column::Id.eq(delivery.id))
        .filter(webhook_deliveries::Column::Attempts.eq(delivery.attempts))
        .filter(webhook_deliveries::Column::NextAttemptAt.eq(lease))
        .exec(database)
        .await?;
    Ok((recorded.rows_affected > 0).then_some(outcome))
}

/// Abandons the pending deliveries of an organization on one channel, when its webhook is
/// removed, disabled or moved to another URL, or its email recipients change: they would
/// otherwise go on reaching a receiver its admins took away.
pub async fn cancel_pending(
    database: &impl ConnectionTrait,
    organization_id: i64,
    channel: Channel,
) -> Result<()> {
    webhook_deliveries::Entity::update_many()
        .col_expr(
            webhook_deliveries::Column::NextAttemptAt,
            Expr::value(Option::<DateTime<FixedOffset>>::None),
        )
        .filter(webhook_deliveries::Column::OrganizationId.eq(organization_id))
        .filter(webhook_deliveries::Column::Channel.eq(channel.as_str()))
        .filter(webhook_deliveries::Column::NextAttemptAt.is_not_null())
        .exec(database)
        .await?;
    Ok(())
}

/// Abandons every pending email delivery; returns how many. Called at startup when no SMTP
/// server is configured any more: they could never be sent.
pub async fn cancel_pending_emails(database: &impl ConnectionTrait) -> Result<u64> {
    Ok(webhook_deliveries::Entity::update_many()
        .col_expr(
            webhook_deliveries::Column::NextAttemptAt,
            Expr::value(Option::<DateTime<FixedOffset>>::None),
        )
        .filter(webhook_deliveries::Column::Channel.eq(Channel::Email.as_str()))
        .filter(webhook_deliveries::Column::NextAttemptAt.is_not_null())
        .exec(database)
        .await?
        .rows_affected)
}

/// Abandons the pending deliveries to the instance's failure webhook that do not go to `url`,
/// its current address (`None`: it is not configured any more); returns how many. Called at
/// startup, since the address comes from the configuration.
pub async fn cancel_pending_failures(
    database: &impl ConnectionTrait,
    url: Option<&str>,
) -> Result<u64> {
    let mut query = webhook_deliveries::Entity::update_many()
        .col_expr(
            webhook_deliveries::Column::NextAttemptAt,
            Expr::value(Option::<DateTime<FixedOffset>>::None),
        )
        .filter(webhook_deliveries::Column::OrganizationId.is_null())
        .filter(webhook_deliveries::Column::Channel.eq(Channel::Webhook.as_str()))
        .filter(webhook_deliveries::Column::NextAttemptAt.is_not_null());
    if let Some(url) = url {
        query = query.filter(webhook_deliveries::Column::Url.ne(url));
    }
    Ok(query.exec(database).await?.rows_affected)
}

/// Deletes delivered and failed deliveries created before `now - RETENTION`; returns how many.
pub async fn prune(database: &impl ConnectionTrait, now: DateTime<FixedOffset>) -> Result<u64> {
    Ok(webhook_deliveries::Entity::delete_many()
        .filter(webhook_deliveries::Column::NextAttemptAt.is_null())
        .filter(webhook_deliveries::Column::CreatedAt.lt(now - RETENTION))
        .exec(database)
        .await?
        .rows_affected)
}

/// A delivery as shown in the organization's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverySummary {
    pub id: i64,
    pub channel: Channel,
    /// The address of an email; `None` for a webhook, whose URL may hold a secret.
    pub recipient: Option<String>,
    pub event: String,
    pub state: State,
    pub attempts: i64,
    pub created_at: DateTime<FixedOffset>,
    pub last_attempt_at: Option<DateTime<FixedOffset>>,
    /// The HTTP status or SMTP reply of the last attempt, or why it got no answer.
    pub last_status: Option<String>,
    pub next_attempt_at: Option<DateTime<FixedOffset>>,
}

/// The latest deliveries of an organization, webhooks and emails, the newest first. Requires
/// [`Permission::ManageWebhook`], like the webhook and the email settings themselves.
pub async fn recent(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    limit: u64,
) -> Result<Vec<DeliverySummary>> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let models = webhook_deliveries::Entity::find()
        .filter(webhook_deliveries::Column::OrganizationId.eq(organization_id))
        .order_by_desc(webhook_deliveries::Column::CreatedAt)
        .order_by_desc(webhook_deliveries::Column::Id)
        .limit(limit)
        .all(database)
        .await?;
    Ok(models
        .into_iter()
        .map(|model| DeliverySummary {
            state: state(&model),
            id: model.id,
            recipient: (Channel::parse(&model.channel) == Channel::Email).then_some(model.url),
            channel: Channel::parse(&model.channel),
            event: model.event,
            attempts: model.attempts,
            created_at: model.created_at,
            last_attempt_at: model.last_attempt_at,
            last_status: model.last_status,
            next_attempt_at: model.next_attempt_at,
        })
        .collect())
}
