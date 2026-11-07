//! Webhooks: each organization can send its new findings to a URL as JSON, grouped per run,
//! and the instance can report failed runs to another URL.
//!
//! Payloads (documented in the README):
//!
//! - `findings.new`: new and reopened findings of one organization, at or above the webhook's
//!   minimum severity;
//! - `run.failed`: a run that could not complete, sent to the instance's failure webhook.

use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use nanobom_entity::{organization_webhooks, organizations};
use nanobom_osv::Severity;
use reqwest::Url;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, EntityTrait, ModelTrait};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    evaluation::{NewFinding, RunOutcome},
};

/// An organization's webhook settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    pub minimum_severity: Severity,
    pub enabled: bool,
    pub last_delivery_at: Option<DateTime<FixedOffset>>,
    pub last_delivery_status: Option<String>,
}

fn view(model: organization_webhooks::Model) -> Webhook {
    Webhook {
        url: model.url,
        minimum_severity: model.minimum_severity.parse().unwrap_or(Severity::Unknown),
        enabled: model.enabled,
        last_delivery_at: model.last_delivery_at,
        last_delivery_status: model.last_delivery_status,
    }
}

/// Validates a webhook address: an absolute `http` or `https` URL.
pub fn validate_url(value: &str) -> Result<Url> {
    let url: Url = value
        .trim()
        .parse()
        .map_err(|_| Error::invalid("the webhook URL is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(Error::invalid(
            "the webhook URL must be an http or https URL",
        ));
    }
    Ok(url)
}

/// The webhook of an organization, if configured.
pub async fn get(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Option<Webhook>> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    Ok(organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .map(view))
}

/// Creates or replaces the webhook of an organization.
pub async fn set(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    url: &str,
    minimum_severity: Severity,
    enabled: bool,
) -> Result<Webhook> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let url = validate_url(url)?;
    let existing = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?;
    let model = match existing {
        Some(model) => {
            let mut active: organization_webhooks::ActiveModel = model.into();
            active.url = Set(url.to_string());
            active.minimum_severity = Set(minimum_severity.as_str().to_owned());
            active.enabled = Set(enabled);
            active.update(database).await?
        }
        None => {
            organization_webhooks::ActiveModel {
                organization_id: Set(organization_id),
                url: Set(url.to_string()),
                minimum_severity: Set(minimum_severity.as_str().to_owned()),
                enabled: Set(enabled),
                last_delivery_at: Set(None),
                last_delivery_status: Set(None),
            }
            .insert(database)
            .await?
        }
    };
    Ok(view(model))
}

/// Removes the webhook of an organization.
pub async fn delete(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    if let Some(model) = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?
    {
        model.delete(database).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadOrganization {
    pub slug: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadRun {
    pub id: i64,
    pub trigger: String,
    pub started_at: DateTime<FixedOffset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadFinding {
    pub project: String,
    pub component: String,
    pub vulnerability: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub summary: Option<String>,
    /// True when the finding was fixed before and came back.
    pub reopened: bool,
    pub url: String,
}

/// `findings.new`: new findings of one organization in one run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewFindingsPayload {
    pub event: String,
    pub organization: PayloadOrganization,
    pub run: PayloadRun,
    pub count: usize,
    pub highest_severity: Severity,
    pub findings: Vec<PayloadFinding>,
}

/// `run.failed`: a run that could not complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunFailedPayload {
    pub event: String,
    pub instance_url: String,
    pub run: PayloadRun,
    pub scope: String,
    pub error: String,
}

fn run(outcome: &RunOutcome) -> PayloadRun {
    PayloadRun {
        id: outcome.run_id,
        trigger: outcome.trigger.as_str().to_owned(),
        started_at: outcome.started_at,
    }
}

fn link(public_url: &Url, path: &str) -> String {
    public_url
        .join(path)
        .map_or_else(|_| public_url.to_string(), |url| url.to_string())
}

/// A webhook delivery to make.
#[derive(Debug, Clone)]
pub struct Delivery<T> {
    pub organization_id: i64,
    pub url: String,
    pub payload: T,
}

/// The `findings.new` deliveries a successful run calls for: one per organization with an
/// enabled webhook and new findings at or above its minimum severity.
pub async fn new_findings_deliveries(
    database: &impl ConnectionTrait,
    outcome: &RunOutcome,
    public_url: &Url,
) -> Result<Vec<Delivery<NewFindingsPayload>>> {
    let mut by_organization: std::collections::BTreeMap<i64, Vec<&NewFinding>> =
        std::collections::BTreeMap::new();
    for finding in &outcome.new_findings {
        by_organization
            .entry(finding.organization_id)
            .or_default()
            .push(finding);
    }
    let mut deliveries = Vec::new();
    for (organization_id, findings) in by_organization {
        let Some(webhook) = organization_webhooks::Entity::find_by_id(organization_id)
            .one(database)
            .await?
            .filter(|webhook| webhook.enabled)
        else {
            continue;
        };
        let minimum: Severity = webhook
            .minimum_severity
            .parse()
            .unwrap_or(Severity::Unknown);
        let findings: Vec<&NewFinding> = findings
            .into_iter()
            .filter(|finding| finding.severity >= minimum)
            .collect();
        if findings.is_empty() {
            continue;
        }
        let Some(organization) = organizations::Entity::find_by_id(organization_id)
            .one(database)
            .await?
        else {
            continue;
        };
        let payload = NewFindingsPayload {
            event: "findings.new".to_owned(),
            organization: PayloadOrganization {
                url: link(public_url, &format!("organizations/{}", organization.slug)),
                slug: organization.slug,
                name: organization.name,
            },
            run: run(outcome),
            count: findings.len(),
            highest_severity: findings
                .iter()
                .map(|finding| finding.severity)
                .max()
                .unwrap_or(Severity::Unknown),
            findings: findings
                .into_iter()
                .map(|finding| PayloadFinding {
                    project: finding.project_slug.clone(),
                    component: finding.purl.clone(),
                    vulnerability: finding.vulnerability_id.clone(),
                    aliases: finding.aliases.clone(),
                    severity: finding.severity,
                    cvss_score: finding.cvss_score,
                    summary: finding.summary.clone(),
                    reopened: finding.reopened,
                    url: link(public_url, &format!("findings/{}", finding.finding_id)),
                })
                .collect(),
        };
        deliveries.push(Delivery {
            organization_id,
            url: webhook.url,
            payload,
        });
    }
    Ok(deliveries)
}

/// The `run.failed` payload for a failed run.
pub fn run_failed_payload(outcome: &RunOutcome, public_url: &Url) -> Option<RunFailedPayload> {
    let error = outcome.error.clone()?;
    Some(RunFailedPayload {
        event: "run.failed".to_owned(),
        instance_url: public_url.to_string(),
        run: run(outcome),
        scope: outcome.scope.as_str().to_owned(),
        error,
    })
}

/// Sends webhook payloads.
#[derive(Debug, Clone)]
pub struct Notifier {
    http: reqwest::Client,
}

impl Notifier {
    pub fn new() -> std::result::Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("nanobom/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }

    /// Posts a payload; returns a short description of the outcome.
    pub async fn post<T: Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> std::result::Result<String, String> {
        match self.http.post(url).json(payload).send().await {
            Ok(response) if response.status().is_success() => Ok(response.status().to_string()),
            Ok(response) => Err(response.status().to_string()),
            Err(error) => Err(error.without_url().to_string()),
        }
    }

    /// Delivers `findings.new` payloads and records the outcome on each webhook.
    pub async fn deliver(
        &self,
        database: &impl ConnectionTrait,
        deliveries: Vec<Delivery<NewFindingsPayload>>,
    ) -> Result<()> {
        for delivery in deliveries {
            let result = self.post(&delivery.url, &delivery.payload).await;
            let status = match &result {
                Ok(status) => status.clone(),
                Err(error) => format!("failed: {error}"),
            };
            match &result {
                Ok(_) => tracing::info!(
                    organization = delivery.organization_id,
                    findings = delivery.payload.count,
                    "webhook delivered"
                ),
                Err(error) => tracing::warn!(
                    organization = delivery.organization_id,
                    %error,
                    "webhook delivery failed"
                ),
            }
            if let Some(model) = organization_webhooks::Entity::find_by_id(delivery.organization_id)
                .one(database)
                .await?
            {
                let mut active: organization_webhooks::ActiveModel = model.into();
                active.last_delivery_at = Set(Some(Utc::now().fixed_offset()));
                active.last_delivery_status = Set(Some(status));
                active.update(database).await?;
            }
        }
        Ok(())
    }
}
