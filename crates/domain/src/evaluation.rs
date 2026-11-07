//! Runs: matching the current components against OSV and updating findings.
//!
//! A run queries every distinct package URL in its scope once, fetches the details of
//! vulnerabilities it has not cached (or that OSV modified since), merges aliases (GHSA, CVE,
//! RUSTSEC… of the same issue) and updates the lifecycle of each finding:
//!
//! - a vulnerability newly affecting a component opens a finding;
//! - a finding whose component is gone, or that OSV no longer reports, is fixed;
//! - a fixed finding that comes back is reopened;
//! - ignored findings stay ignored while they are reported, and return to open when their
//!   ignore expires.
//!
//! A run that cannot complete (OSV unreachable, for example) changes no finding and is recorded
//! as failed, so a failure never reads as "no vulnerabilities".

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};

use chrono::{DateTime, FixedOffset, Utc};
use nanobom_entity::{
    components, finding_events, findings, organizations, projects, runs, vulnerabilities,
};
use nanobom_osv::{Severity, Vulnerability, VulnerabilityReference, VulnerabilitySource, assess};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, QueryFilter, TransactionTrait, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    findings::{EventKind, Status},
};

/// Vulnerability details fetched concurrently.
const CONCURRENT_DETAIL_REQUESTS: usize = 8;

/// What a run covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Every project of every organization: the scheduled run.
    All,
    Organization(i64),
    Project(i64),
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::All => "all",
            Scope::Organization(_) => "organization",
            Scope::Project(_) => "project",
        }
    }
}

/// Why a run started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trigger {
    Scheduled,
    Manual,
    Upload,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::Scheduled => "scheduled",
            Trigger::Manual => "manual",
            Trigger::Upload => "upload",
        }
    }
}

/// A finding opened or reopened by a run, for notifications.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewFinding {
    pub finding_id: i64,
    pub organization_id: i64,
    pub organization_slug: String,
    pub project_slug: String,
    pub purl: String,
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub reopened: bool,
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunOutcome {
    pub run_id: i64,
    pub scope: Scope,
    pub trigger: Trigger,
    pub started_at: DateTime<FixedOffset>,
    pub duration_seconds: f64,
    /// Why the run failed; findings were left untouched.
    pub error: Option<String>,
    pub component_count: usize,
    pub vulnerability_count: usize,
    pub new_findings: Vec<NewFinding>,
    pub fixed_findings: usize,
}

impl RunOutcome {
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
    }
}

/// Checks that the actor may start a run on a scope.
pub async fn authorize(database: &impl ConnectionTrait, actor: &Actor, scope: Scope) -> Result<()> {
    match scope {
        Scope::All => actor.require_instance_administrator(),
        Scope::Organization(organization_id) => actor
            .authorize(database, organization_id, Permission::TriggerRuns)
            .await
            .map(drop),
        Scope::Project(project_id) => {
            crate::projects::authorize(database, actor, project_id, Permission::TriggerRuns)
                .await
                .map(drop)
        }
    }
}

/// Runs evaluations one at a time against a vulnerability source.
pub struct Evaluator<S> {
    database: DatabaseConnection,
    source: Arc<S>,
    running: Mutex<()>,
}

/// A component to evaluate.
struct Target {
    project_id: i64,
    purl: String,
    query_purl: String,
    ecosystem: String,
}

impl<S: VulnerabilitySource + 'static> Evaluator<S> {
    pub fn new(database: DatabaseConnection, source: Arc<S>) -> Self {
        Self {
            database,
            source,
            running: Mutex::new(()),
        }
    }

    /// Runs an evaluation; concurrent calls wait for the current run to finish. Errors are
    /// database errors; a failure to reach the vulnerability source is a failed run, reported
    /// in the outcome.
    pub async fn run(
        &self,
        trigger: Trigger,
        scope: Scope,
        triggered_by: Option<i64>,
    ) -> Result<RunOutcome> {
        let _running = self.running.lock().await;
        let clock = Instant::now();
        let started_at = Utc::now().fixed_offset();
        let (organization_id, project_id) = match scope {
            Scope::All => (None, None),
            Scope::Organization(id) => (Some(id), None),
            Scope::Project(id) => {
                let project = projects::Entity::find_by_id(id)
                    .one(&self.database)
                    .await?
                    .ok_or(Error::NotFound)?;
                (Some(project.organization_id), Some(id))
            }
        };
        let run = runs::ActiveModel {
            trigger: Set(trigger.as_str().to_owned()),
            scope: Set(scope.as_str().to_owned()),
            organization_id: Set(organization_id),
            project_id: Set(project_id),
            triggered_by_user_id: Set(triggered_by),
            started_at: Set(started_at),
            finished_at: Set(None),
            status: Set("running".to_owned()),
            error: Set(None),
            ..Default::default()
        }
        .insert(&self.database)
        .await?;

        let mut outcome = RunOutcome {
            run_id: run.id,
            scope,
            trigger,
            started_at,
            duration_seconds: 0.0,
            error: None,
            component_count: 0,
            vulnerability_count: 0,
            new_findings: Vec::new(),
            fixed_findings: 0,
        };
        let result = self.evaluate(run.id, scope, &mut outcome).await;
        outcome.duration_seconds = clock.elapsed().as_secs_f64();
        let status = match &result {
            Ok(()) => "succeeded",
            Err(error) => {
                outcome.error = Some(error.clone());
                "failed"
            }
        };
        let mut finished: runs::ActiveModel = run.into();
        finished.finished_at = Set(Some(Utc::now().fixed_offset()));
        finished.status = Set(status.to_owned());
        finished.error = Set(outcome.error.clone());
        finished.component_count = Set(count(outcome.component_count));
        finished.vulnerability_count = Set(count(outcome.vulnerability_count));
        finished.new_findings = Set(count(outcome.new_findings.len()));
        finished.fixed_findings = Set(count(outcome.fixed_findings));
        finished.update(&self.database).await?;

        match &outcome.error {
            None => tracing::info!(
                run = outcome.run_id,
                scope = scope.as_str(),
                components = outcome.component_count,
                vulnerabilities = outcome.vulnerability_count,
                new = outcome.new_findings.len(),
                fixed = outcome.fixed_findings,
                seconds = outcome.duration_seconds,
                "run succeeded"
            ),
            Some(error) => tracing::error!(
                run = outcome.run_id,
                scope = scope.as_str(),
                %error,
                "run failed; findings left unchanged"
            ),
        }
        Ok(outcome)
    }

    /// The body of a run. Any error leaves findings as they were.
    async fn evaluate(
        &self,
        run_id: i64,
        scope: Scope,
        outcome: &mut RunOutcome,
    ) -> std::result::Result<(), String> {
        let database_error = |error: sea_orm::DbErr| format!("database error: {error}");
        expire_ignores(&self.database, scope, run_id)
            .await
            .map_err(database_error)?;

        let targets = targets(&self.database, scope)
            .await
            .map_err(database_error)?;
        outcome.component_count = targets.len();
        let query_purls: Vec<String> = targets
            .iter()
            .map(|target| target.query_purl.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let answers = self
            .source
            .query(&query_purls)
            .await
            .map_err(|error| format!("querying vulnerabilities failed: {error}"))?;
        let references: HashMap<&str, Vec<VulnerabilityReference>> = query_purls
            .iter()
            .map(String::as_str)
            .zip(answers)
            .collect();

        let records = self.refresh_records(references.values().flatten()).await?;
        outcome.vulnerability_count = records.len();

        let projects = scope_projects(&self.database, scope)
            .await
            .map_err(database_error)?;
        for project in projects {
            let project_targets: Vec<&Target> = targets
                .iter()
                .filter(|target| target.project_id == project.id)
                .collect();
            let changes = update_project(
                &self.database,
                run_id,
                &project,
                &project_targets,
                &references,
                &records,
            )
            .await
            .map_err(database_error)?;
            outcome.fixed_findings += changes.fixed;
            outcome.new_findings.extend(changes.new_findings);
        }
        Ok(())
    }

    /// Makes sure every referenced vulnerability is cached and up to date, and returns the
    /// records by identifier, withdrawn ones excluded.
    async fn refresh_records<'a>(
        &self,
        references: impl Iterator<Item = &'a VulnerabilityReference>,
    ) -> std::result::Result<HashMap<String, Vulnerability>, String> {
        let mut latest: BTreeMap<&str, DateTime<Utc>> = BTreeMap::new();
        for reference in references {
            let entry = latest.entry(&reference.id).or_insert(reference.modified);
            *entry = (*entry).max(reference.modified);
        }
        let identifiers: Vec<String> = latest.keys().map(|id| (*id).to_owned()).collect();
        let mut cached: HashMap<String, vulnerabilities::Model> = HashMap::new();
        for chunk in identifiers.chunks(500) {
            for model in vulnerabilities::Entity::find()
                .filter(vulnerabilities::Column::Id.is_in(chunk.iter().cloned()))
                .all(&self.database)
                .await
                .map_err(|error| format!("database error: {error}"))?
            {
                cached.insert(model.id.clone(), model);
            }
        }

        let mut records = HashMap::new();
        let mut stale = Vec::new();
        for (id, modified) in latest {
            match cached
                .get(id)
                .and_then(|model| serde_json::from_str::<Vulnerability>(&model.record).ok())
            {
                Some(record) if record.modified >= modified => {
                    records.insert(id.to_owned(), record);
                }
                _ => stale.push(id.to_owned()),
            }
        }

        let mut fetches = JoinSet::new();
        let mut queue = stale.into_iter();
        let mut fetched = Vec::new();
        loop {
            while fetches.len() < CONCURRENT_DETAIL_REQUESTS {
                let Some(id) = queue.next() else { break };
                let source = Arc::clone(&self.source);
                fetches.spawn(async move { source.vulnerability(&id).await });
            }
            let Some(result) = fetches.join_next().await else {
                break;
            };
            let record = result
                .map_err(|error| format!("fetching a vulnerability failed: {error}"))?
                .map_err(|error| format!("fetching a vulnerability failed: {error}"))?;
            fetched.push(record);
        }
        for record in fetched {
            store_record(&self.database, &record)
                .await
                .map_err(|error| format!("database error: {error}"))?;
            records.insert(record.id.clone(), record);
        }
        records.retain(|_, record| record.withdrawn.is_none());
        Ok(records)
    }
}

fn count(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Caches a vulnerability record with its derived severity.
async fn store_record(
    database: &impl ConnectionTrait,
    record: &Vulnerability,
) -> std::result::Result<(), sea_orm::DbErr> {
    let assessment = assess(record);
    let model = vulnerabilities::ActiveModel {
        id: Set(record.id.clone()),
        modified: Set(record.modified.fixed_offset()),
        published: Set(record.published.map(|date| date.fixed_offset())),
        withdrawn: Set(record.withdrawn.map(|date| date.fixed_offset())),
        summary: Set(record.summary.clone()),
        details: Set(record.details.clone()),
        aliases: Set(serde_json::to_string(&record.aliases).expect("strings serialize")),
        severity: Set(assessment.severity.as_str().to_owned()),
        cvss_score: Set(assessment.cvss.as_ref().map(|cvss| cvss.score)),
        cvss_version: Set(assessment.cvss.as_ref().map(|cvss| cvss.version.to_owned())),
        cvss_vector: Set(assessment.cvss.as_ref().map(|cvss| cvss.vector.clone())),
        record: Set(serde_json::to_string(record).expect("records serialize")),
        fetched_at: Set(Utc::now().fixed_offset()),
    };
    vulnerabilities::Entity::insert(model)
        .on_conflict(
            OnConflict::column(vulnerabilities::Column::Id)
                .update_columns([
                    vulnerabilities::Column::Modified,
                    vulnerabilities::Column::Published,
                    vulnerabilities::Column::Withdrawn,
                    vulnerabilities::Column::Summary,
                    vulnerabilities::Column::Details,
                    vulnerabilities::Column::Aliases,
                    vulnerabilities::Column::Severity,
                    vulnerabilities::Column::CvssScore,
                    vulnerabilities::Column::CvssVersion,
                    vulnerabilities::Column::CvssVector,
                    vulnerabilities::Column::Record,
                    vulnerabilities::Column::FetchedAt,
                ])
                .to_owned(),
        )
        .exec(database)
        .await?;
    Ok(())
}

async fn scope_projects(
    database: &impl ConnectionTrait,
    scope: Scope,
) -> std::result::Result<Vec<projects::Model>, sea_orm::DbErr> {
    let query = projects::Entity::find();
    match scope {
        Scope::All => query.all(database).await,
        Scope::Organization(id) => {
            query
                .filter(projects::Column::OrganizationId.eq(id))
                .all(database)
                .await
        }
        Scope::Project(id) => {
            query
                .filter(projects::Column::Id.eq(id))
                .all(database)
                .await
        }
    }
}

/// The versioned components in scope; components without a version cannot be matched.
async fn targets(
    database: &impl ConnectionTrait,
    scope: Scope,
) -> std::result::Result<Vec<Target>, sea_orm::DbErr> {
    let project_ids: Vec<i64> = scope_projects(database, scope)
        .await?
        .into_iter()
        .map(|project| project.id)
        .collect();
    let mut targets = Vec::new();
    for chunk in project_ids.chunks(500) {
        let models = components::Entity::find()
            .filter(components::Column::ProjectId.is_in(chunk.iter().copied()))
            .filter(components::Column::Version.is_not_null())
            .all(database)
            .await?;
        targets.extend(models.into_iter().map(|component| Target {
            project_id: component.project_id,
            purl: component.purl,
            query_purl: component.query_purl,
            ecosystem: component.ecosystem,
        }));
    }
    Ok(targets)
}

/// Returns findings whose ignore expired to open.
async fn expire_ignores(
    database: &DatabaseConnection,
    scope: Scope,
    run_id: i64,
) -> std::result::Result<(), sea_orm::DbErr> {
    let now = Utc::now().fixed_offset();
    let project_ids: Vec<i64> = scope_projects(database, scope)
        .await?
        .into_iter()
        .map(|project| project.id)
        .collect();
    for chunk in project_ids.chunks(500) {
        let expired = findings::Entity::find()
            .filter(findings::Column::ProjectId.is_in(chunk.iter().copied()))
            .filter(findings::Column::Status.eq(Status::Ignored.as_str()))
            .filter(findings::Column::IgnoreExpiresAt.lte(now))
            .all(database)
            .await?;
        for finding in expired {
            let transaction = database.begin().await?;
            let id = finding.id;
            let mut finding: findings::ActiveModel = finding.into();
            finding.status = Set(Status::Open.as_str().to_owned());
            finding.update(&transaction).await?;
            record_event(
                &transaction,
                id,
                EventKind::IgnoreExpired,
                None,
                None,
                Some(run_id),
            )
            .await?;
            transaction.commit().await?;
        }
    }
    Ok(())
}

pub(crate) async fn record_event(
    database: &impl ConnectionTrait,
    finding_id: i64,
    kind: EventKind,
    actor_user_id: Option<i64>,
    reason: Option<String>,
    run_id: Option<i64>,
) -> std::result::Result<(), sea_orm::DbErr> {
    finding_events::ActiveModel {
        finding_id: Set(finding_id),
        created_at: Set(Utc::now().fixed_offset()),
        kind: Set(kind.as_str().to_owned()),
        actor_user_id: Set(actor_user_id),
        reason: Set(reason),
        run_id: Set(run_id),
        ..Default::default()
    }
    .insert(database)
    .await?;
    Ok(())
}

/// Vulnerability identifiers reported for one component, merged when they are aliases of each
/// other. Each group lists the reported identifiers first (sorted), then every alias.
fn alias_groups(
    reported: &[&VulnerabilityReference],
    records: &HashMap<String, Vulnerability>,
) -> Vec<(Vec<String>, BTreeSet<String>)> {
    let identifiers: Vec<&str> = reported
        .iter()
        .map(|reference| reference.id.as_str())
        .filter(|id| records.contains_key(*id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let names = |id: &str| -> BTreeSet<String> {
        let mut names: BTreeSet<String> = records[id].aliases.iter().cloned().collect();
        names.insert(id.to_owned());
        names
    };
    let mut parent: Vec<usize> = (0..identifiers.len()).collect();
    fn root(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }
    for left in 0..identifiers.len() {
        for right in left + 1..identifiers.len() {
            if !names(identifiers[left]).is_disjoint(&names(identifiers[right])) {
                let (left_root, right_root) = (root(&mut parent, left), root(&mut parent, right));
                parent[right_root] = left_root;
            }
        }
    }
    let mut groups: BTreeMap<usize, (Vec<String>, BTreeSet<String>)> = BTreeMap::new();
    for (index, id) in identifiers.iter().enumerate() {
        let group = groups.entry(root(&mut parent, index)).or_default();
        group.0.push((*id).to_owned());
        group.1.extend(names(id));
    }
    groups.into_values().collect()
}

struct ProjectChanges {
    fixed: usize,
    new_findings: Vec<NewFinding>,
}

async fn update_project(
    database: &DatabaseConnection,
    run_id: i64,
    project: &projects::Model,
    targets: &[&Target],
    references: &HashMap<&str, Vec<VulnerabilityReference>>,
    records: &HashMap<String, Vulnerability>,
) -> std::result::Result<ProjectChanges, sea_orm::DbErr> {
    let organization = organizations::Entity::find_by_id(project.organization_id)
        .one(database)
        .await?
        .ok_or_else(|| sea_orm::DbErr::RecordNotFound("organization".to_owned()))?;
    let transaction = database.begin().await?;
    let now = Utc::now().fixed_offset();
    let existing = findings::Entity::find()
        .filter(findings::Column::ProjectId.eq(project.id))
        .all(&transaction)
        .await?;
    let mut by_purl: HashMap<&str, Vec<&findings::Model>> = HashMap::new();
    for finding in &existing {
        by_purl
            .entry(finding.purl.as_str())
            .or_default()
            .push(finding);
    }
    let mut seen: BTreeSet<i64> = BTreeSet::new();
    let mut changes = ProjectChanges {
        fixed: 0,
        new_findings: Vec::new(),
    };

    for target in targets {
        let reported: Vec<&VulnerabilityReference> = references
            .get(target.query_purl.as_str())
            .map(|references| references.iter().collect())
            .unwrap_or_default();
        for (identifiers, names) in alias_groups(&reported, records) {
            let severity = identifiers
                .iter()
                .map(|id| assess(&records[id]))
                .max_by(|left, right| {
                    left.severity.cmp(&right.severity).then(
                        left.cvss
                            .as_ref()
                            .map(|cvss| cvss.score)
                            .partial_cmp(&right.cvss.as_ref().map(|cvss| cvss.score))
                            .unwrap_or(std::cmp::Ordering::Equal),
                    )
                })
                .expect("groups are never empty");
            let matching = by_purl.get(target.purl.as_str()).and_then(|candidates| {
                candidates
                    .iter()
                    .find(|finding| names.contains(&finding.vulnerability_id))
                    .copied()
            });
            let (finding_id, vulnerability_id, reopened) = match matching {
                Some(finding) if seen.contains(&finding.id) => continue,
                Some(finding) => {
                    let status = Status::parse(&finding.status);
                    let mut active: findings::ActiveModel = finding.clone().into();
                    active.last_seen_at = Set(now);
                    active.severity = Set(severity.severity.as_str().to_owned());
                    let reopened = status == Status::Fixed;
                    if reopened {
                        active.status = Set(Status::Open.as_str().to_owned());
                        active.fixed_at = Set(None);
                    }
                    active.update(&transaction).await?;
                    seen.insert(finding.id);
                    if !reopened {
                        continue;
                    }
                    record_event(
                        &transaction,
                        finding.id,
                        EventKind::Reopened,
                        None,
                        None,
                        Some(run_id),
                    )
                    .await?;
                    (finding.id, finding.vulnerability_id.clone(), true)
                }
                None => {
                    let vulnerability_id = identifiers[0].clone();
                    let created = findings::ActiveModel {
                        project_id: Set(project.id),
                        purl: Set(target.purl.clone()),
                        ecosystem: Set(target.ecosystem.clone()),
                        vulnerability_id: Set(vulnerability_id.clone()),
                        status: Set(Status::Open.as_str().to_owned()),
                        severity: Set(severity.severity.as_str().to_owned()),
                        first_seen_at: Set(now),
                        last_seen_at: Set(now),
                        ..Default::default()
                    }
                    .insert(&transaction)
                    .await?;
                    seen.insert(created.id);
                    record_event(
                        &transaction,
                        created.id,
                        EventKind::Opened,
                        None,
                        None,
                        Some(run_id),
                    )
                    .await?;
                    (created.id, vulnerability_id, false)
                }
            };
            let record = records
                .get(&vulnerability_id)
                .unwrap_or(&records[&identifiers[0]]);
            changes.new_findings.push(NewFinding {
                finding_id,
                organization_id: organization.id,
                organization_slug: organization.slug.clone(),
                project_slug: project.slug.clone(),
                purl: target.purl.clone(),
                vulnerability_id: vulnerability_id.clone(),
                aliases: names
                    .iter()
                    .filter(|name| **name != vulnerability_id)
                    .cloned()
                    .collect(),
                summary: record.summary.clone(),
                severity: severity.severity,
                cvss_score: severity.cvss.as_ref().map(|cvss| cvss.score),
                reopened,
            });
        }
    }

    for finding in &existing {
        let status = Status::parse(&finding.status);
        if seen.contains(&finding.id) || status == Status::Fixed {
            continue;
        }
        let mut active: findings::ActiveModel = finding.clone().into();
        active.status = Set(Status::Fixed.as_str().to_owned());
        active.fixed_at = Set(Some(now));
        active.update(&transaction).await?;
        record_event(
            &transaction,
            finding.id,
            EventKind::Fixed,
            None,
            None,
            Some(run_id),
        )
        .await?;
        changes.fixed += 1;
    }
    transaction.commit().await?;
    Ok(changes)
}
