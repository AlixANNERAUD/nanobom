//! License policy: what an organization allows, warns about or forbids among the licenses of
//! its components, and the components of a project that break it.
//!
//! A policy has rules, each an SPDX license identifier (or a `LicenseRef-…`) with an
//! [`Action`], and two defaults: the action for a license no rule lists, and the action for a
//! component whose license is unknown. Both defaults start at [`Action::Allow`], so an
//! organization that never set a policy sees no violations ([`Policy::is_active`]).
//!
//! # Evaluation
//!
//! A component's license is an SPDX expression ([`crate::inventory`] stores it as read from the
//! SBOM). [`Policy::evaluate`] gives each license identifier of the expression its action (its
//! rule, else the default for unlisted licenses; `WITH` exceptions are ignored, the license
//! decides), then combines them: `OR` takes the least severe side, since the user may pick that
//! license, and `AND` the most severe, since every license applies. Identifiers and operators
//! match case-insensitively. A license that is missing, or is not a valid SPDX expression (a
//! free-text name, an identifier outside the SPDX list), is unknown and gets the default for
//! unknown licenses as a whole.
//!
//! Evaluation is pure, and nothing is stored: violations are computed when read, so changing
//! the policy applies to every project at once, without a run.

use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use nanobom_entity::{components, license_rules, organizations};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionSession, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use spdx::{
    LicenseId, LicenseItem, ParseMode,
    expression::{ExprNode, Expression, Operator},
};

use crate::{
    access::{Actor, Permission, Reader},
    error::{Error, Result},
    exploitation::QUERY_CHUNK,
    problem::Problem,
};

/// What a policy does with a license, from the least to the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    /// Reported, without failing the upload gate.
    Warn,
    /// Reported, and fails the upload gate with `fail_on=license`.
    Forbid,
}

impl Action {
    /// Every action, from the least to the most severe.
    pub const ALL: [Action; 3] = [Action::Allow, Action::Warn, Action::Forbid];

    /// The name stored in the database and sent by forms and the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Warn => "warn",
            Action::Forbid => "forbid",
        }
    }

    /// Parses a name produced by [`Action::as_str`]; anything else is
    /// [`Problem::UnknownLicenseAction`].
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == value.trim())
            .ok_or_else(|| {
                Error::invalid(Problem::UnknownLicenseAction {
                    action: value.to_owned(),
                })
            })
    }

    /// A stored action; a value no version wrote reads as [`Action::Allow`].
    fn stored(value: &str) -> Self {
        Self::parse(value).unwrap_or(Action::Allow)
    }
}

/// One rule of a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// An SPDX license identifier in its canonical spelling (`GPL-3.0-only`), or a
    /// `LicenseRef-…`.
    pub license: String,
    pub action: Action,
}

/// An organization's license policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The action for licenses no rule lists: [`Action::Forbid`] makes the rules an allowlist.
    pub unlisted: Action,
    /// The action for components whose license is missing or is not an SPDX expression.
    pub unknown: Action,
    /// Sorted by license identifier, case-insensitively.
    pub rules: Vec<Rule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            unlisted: Action::Allow,
            unknown: Action::Allow,
            rules: Vec::new(),
        }
    }
}

/// The outcome of evaluating one component's license.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    /// The license identifiers that lead to the action, sorted; empty when the action is
    /// [`Action::Allow`] or the license is unknown.
    pub licenses: Vec<String>,
}

impl Policy {
    /// Whether the policy can report anything: a default or a rule other than
    /// [`Action::Allow`]. The interface shows licenses only for active policies.
    pub fn is_active(&self) -> bool {
        self.unlisted != Action::Allow
            || self.unknown != Action::Allow
            || self.rules.iter().any(|rule| rule.action != Action::Allow)
    }

    /// The verdict on a component's license (see the [module documentation](self)).
    pub fn evaluate(&self, license: Option<&str>) -> Verdict {
        Matcher::new(self).evaluate(license)
    }
}

/// A policy with its rules indexed, to evaluate many licenses.
struct Matcher<'a> {
    policy: &'a Policy,
    /// Rules by lower-case identifier.
    actions: HashMap<String, Action>,
}

impl<'a> Matcher<'a> {
    fn new(policy: &'a Policy) -> Self {
        Self {
            policy,
            actions: policy
                .rules
                .iter()
                .map(|rule| (rule.license.to_ascii_lowercase(), rule.action))
                .collect(),
        }
    }

    fn unknown(&self) -> Verdict {
        Verdict {
            action: self.policy.unknown,
            licenses: Vec::new(),
        }
    }

    fn evaluate(&self, license: Option<&str>) -> Verdict {
        let Some(expression) = license.and_then(parse_expression) else {
            return self.unknown();
        };
        // The expression is in postfix order: each operator combines the two entries above it.
        let mut stack: Vec<(Action, BTreeSet<String>)> = Vec::new();
        for node in expression.iter() {
            match node {
                ExprNode::Req(requirement) => {
                    let license = license_name(&requirement.req.license);
                    let action = self
                        .actions
                        .get(&license.to_ascii_lowercase())
                        .copied()
                        .unwrap_or(self.policy.unlisted);
                    stack.push((action, BTreeSet::from([license])));
                }
                ExprNode::Op(operator) => {
                    let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
                        return self.unknown();
                    };
                    stack.push(combine(*operator, left, right));
                }
            }
        }
        match (stack.pop(), stack.is_empty()) {
            (Some((Action::Allow, _)), true) => Verdict {
                action: Action::Allow,
                licenses: Vec::new(),
            },
            (Some((action, licenses)), true) => Verdict {
                action,
                licenses: licenses.into_iter().collect(),
            },
            _ => self.unknown(),
        }
    }
}

/// `OR` keeps the least severe side and `AND` the most severe; the identifiers of both sides
/// are kept when they tie, since either one gives the action.
fn combine(
    operator: Operator,
    left: (Action, BTreeSet<String>),
    right: (Action, BTreeSet<String>),
) -> (Action, BTreeSet<String>) {
    let left_wins = match operator {
        Operator::And => left.0 > right.0,
        Operator::Or => left.0 < right.0,
    };
    let right_wins = match operator {
        Operator::And => right.0 > left.0,
        Operator::Or => right.0 < left.0,
    };
    if left_wins {
        left
    } else if right_wins {
        right
    } else {
        let (action, mut licenses) = left;
        licenses.extend(right.1);
        (action, licenses)
    }
}

/// Lenient parsing: deprecated identifiers, `/` for `OR` and `GPL-2.0+` are accepted, as SBOM
/// generators write them; imprecise names (`Apache`) are not, since guessing a license is not
/// what a policy should do.
const PARSE_MODE: ParseMode = ParseMode {
    allow_slash_as_or_operator: true,
    allow_imprecise_license_names: false,
    allow_postfix_plus_on_gpl: true,
    allow_deprecated: true,
    allow_unknown: false,
};

/// Parses an expression case-insensitively; `None` when it is not a valid SPDX expression.
fn parse_expression(text: &str) -> Option<Expression> {
    Expression::parse_mode(&canonical_case(text), PARSE_MODE).ok()
}

/// SPDX identifiers and operators are case-insensitive, but the `spdx` crate compares them
/// exactly: every word is rewritten in its canonical spelling before parsing. A word is what
/// the crate's lexer reads as one (`[-A-Za-z0-9.:]+`), so `+`, `/` and parentheses stay as
/// they are.
fn canonical_case(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut word = String::new();
    let flush = |word: &mut String, output: &mut String| {
        if !word.is_empty() {
            output.push_str(&canonical_word(word));
            word.clear();
        }
    };
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | ':') {
            word.push(character);
        } else {
            flush(&mut word, &mut output);
            output.push(character);
        }
    }
    flush(&mut word, &mut output);
    output
}

fn canonical_word(word: &str) -> String {
    for operator in ["AND", "OR", "WITH"] {
        if word.eq_ignore_ascii_case(operator) {
            return operator.to_owned();
        }
    }
    let lower = word.to_ascii_lowercase();
    if let Some(name) = names().licenses.get(&lower) {
        return (*name).to_owned();
    }
    if let Some(name) = names().exceptions.get(&lower) {
        return (*name).to_owned();
    }
    // `DocumentRef-a:LicenseRef-b`: each part keeps its text, with its prefix spelled as the
    // lexer expects.
    word.split(':')
        .map(|part| {
            ["DocumentRef-", "LicenseRef-", "AdditionRef-"]
                .into_iter()
                .find_map(|prefix| {
                    part.get(..prefix.len())
                        .filter(|start| start.eq_ignore_ascii_case(prefix))
                        .map(|_| format!("{prefix}{}", &part[prefix.len()..]))
                })
                .unwrap_or_else(|| part.to_owned())
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// The SPDX license and exception identifiers by lower-case spelling.
struct Names {
    licenses: HashMap<String, &'static str>,
    exceptions: HashMap<String, &'static str>,
}

fn names() -> &'static Names {
    static NAMES: OnceLock<Names> = OnceLock::new();
    NAMES.get_or_init(|| Names {
        licenses: spdx::identifiers::LICENSES
            .iter()
            .map(|license| (license.name.to_ascii_lowercase(), license.name))
            .collect(),
        exceptions: spdx::identifiers::EXCEPTIONS
            .iter()
            .map(|exception| (exception.name.to_ascii_lowercase(), exception.name))
            .collect(),
    })
}

/// The identifier a rule matches for one license of an expression. The bare GNU identifiers,
/// deprecated (`GPL-2.0`), mean the `-only` variant, so a rule on `GPL-2.0-only` covers both;
/// `+` on other licenses (`Apache-1.0+`) is ignored.
fn license_name(license: &LicenseItem) -> String {
    match license {
        LicenseItem::Spdx { id, .. } => gnu_only(*id).name.to_owned(),
        LicenseItem::Other(reference) => reference.to_string(),
    }
}

fn gnu_only(id: LicenseId) -> LicenseId {
    if id.is_gnu() && !id.name.ends_with("-only") && !id.name.ends_with("-or-later") {
        spdx::gnu_license_id(id.name, false).unwrap_or(id)
    } else {
        id
    }
}

/// The longest identifier a rule accepts. SPDX identifiers are far shorter; the bound is for
/// `LicenseRef-…`.
pub const MAXIMUM_IDENTIFIER_LENGTH: usize = 200;

/// The most rules a policy holds.
pub const MAXIMUM_RULES: usize = 1000;

/// The canonical spelling of a rule's identifier: an SPDX license identifier, in any case, or
/// `LicenseRef-` followed by letters, digits, `.` and `-`. Anything else, an exception
/// identifier or `GPL-2.0+` included, is [`Problem::UnknownLicenseId`].
pub fn canonical_identifier(text: &str) -> Result<String> {
    let text = text.trim();
    let unknown = || {
        Error::invalid(Problem::UnknownLicenseId {
            license: text.chars().take(MAXIMUM_IDENTIFIER_LENGTH).collect(),
        })
    };
    // `+` (or later) belongs to expressions: `GPL-2.0+`, a deprecated identifier, is
    // `GPL-2.0-or-later`, which a rule names directly.
    if text.is_empty() || text.len() > MAXIMUM_IDENTIFIER_LENGTH || text.contains('+') {
        return Err(unknown());
    }
    const REFERENCE: &str = "LicenseRef-";
    if let Some(start) = text.get(..REFERENCE.len())
        && start.eq_ignore_ascii_case(REFERENCE)
    {
        let reference = &text[REFERENCE.len()..];
        if !reference.is_empty()
            && reference.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
            })
        {
            return Ok(format!("{REFERENCE}{reference}"));
        }
        return Err(unknown());
    }
    let name = names()
        .licenses
        .get(&text.to_ascii_lowercase())
        .copied()
        .ok_or_else(unknown)?;
    let id = spdx::license_id(name).ok_or_else(unknown)?;
    Ok(gnu_only(id).name.to_owned())
}

/// The identifiers of a list typed in a form: separated by whitespace or commas.
pub fn split_identifiers(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| character.is_whitespace() || character == ',')
        .filter(|identifier| !identifier.is_empty())
}

/// Checks and normalizes the rules of a new policy: identifiers in their canonical spelling
/// (see [`canonical_identifier`]), sorted, an identifier listed twice with the same action kept
/// once. The same identifier with two actions is [`Problem::ConflictingLicenseRule`].
pub fn normalize_rules(rules: &[Rule]) -> Result<Vec<Rule>> {
    let mut normalized: HashMap<String, Rule> = HashMap::new();
    for rule in rules {
        let license = canonical_identifier(&rule.license)?;
        let key = license.to_ascii_lowercase();
        match normalized.get(&key) {
            Some(existing) if existing.action != rule.action => {
                return Err(Error::invalid(Problem::ConflictingLicenseRule { license }));
            }
            Some(_) => {}
            None => {
                normalized.insert(
                    key,
                    Rule {
                        license,
                        action: rule.action,
                    },
                );
            }
        }
    }
    if normalized.len() > MAXIMUM_RULES {
        return Err(Error::invalid(Problem::TooManyLicenseRules {
            maximum: MAXIMUM_RULES,
        }));
    }
    let mut rules: Vec<Rule> = normalized.into_values().collect();
    sort_rules(&mut rules);
    Ok(rules)
}

fn sort_rules(rules: &mut [Rule]) {
    rules.sort_by(|left, right| {
        left.license
            .to_ascii_lowercase()
            .cmp(&right.license.to_ascii_lowercase())
            .then_with(|| left.license.cmp(&right.license))
    });
}

/// The policy of an organization, without checking access.
async fn load(database: &impl ConnectionTrait, organization_id: i64) -> Result<Policy> {
    let organization = organizations::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let mut rules: Vec<Rule> = license_rules::Entity::find()
        .filter(license_rules::Column::OrganizationId.eq(organization_id))
        .order_by_asc(license_rules::Column::License)
        .all(database)
        .await?
        .into_iter()
        .map(|rule| Rule {
            license: rule.license,
            action: Action::stored(&rule.action),
        })
        .collect();
    sort_rules(&mut rules);
    Ok(Policy {
        unlisted: Action::stored(&organization.license_unlisted_action),
        unknown: Action::stored(&organization.license_unknown_action),
        rules,
    })
}

/// The license policy of an organization. Requires [`Permission::View`].
pub async fn policy(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_id: i64,
) -> Result<Policy> {
    reader
        .into()
        .authorize(database, organization_id, Permission::View)
        .await?;
    load(database, organization_id).await
}

/// Replaces the license policy of an organization, rules and defaults at once, after
/// [`normalize_rules`]. Requires [`Permission::ManageOrganization`].
pub async fn set_policy(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    organization_id: i64,
    policy: &Policy,
) -> Result<Policy> {
    actor
        .authorize(database, organization_id, Permission::ManageOrganization)
        .await?;
    let rules = normalize_rules(&policy.rules)?;
    let transaction = crate::database::begin_write(database).await?;
    let organization = organizations::Entity::find_by_id(organization_id)
        .one(&transaction)
        .await?
        .ok_or(Error::NotFound)?;
    let mut organization: organizations::ActiveModel = organization.into();
    organization.license_unlisted_action = Set(policy.unlisted.as_str().to_owned());
    organization.license_unknown_action = Set(policy.unknown.as_str().to_owned());
    organization.update(&transaction).await?;
    license_rules::Entity::delete_many()
        .filter(license_rules::Column::OrganizationId.eq(organization_id))
        .exec(&transaction)
        .await?;
    for chunk in rules.chunks(QUERY_CHUNK) {
        license_rules::Entity::insert_many(chunk.iter().map(|rule| license_rules::ActiveModel {
            organization_id: Set(organization_id),
            license: Set(rule.license.clone()),
            action: Set(rule.action.as_str().to_owned()),
            ..Default::default()
        }))
        .exec(&transaction)
        .await?;
    }
    transaction.commit().await?;
    tracing::info!(
        organization = organization_id,
        user = actor.user_id,
        rules = rules.len(),
        "license policy changed"
    );
    Ok(Policy {
        unlisted: policy.unlisted,
        unknown: policy.unknown,
        rules,
    })
}

/// A component whose license the policy warns about or forbids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub purl: String,
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
    /// The license as read from the SBOM; `None` when it gave none.
    pub license: Option<String>,
    /// [`Action::Warn`] or [`Action::Forbid`].
    pub verdict: Action,
    /// The identifiers that lead to the verdict; empty when the license is unknown.
    pub licenses: Vec<String>,
}

/// Components breaking a policy, by verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationCounts {
    pub forbidden: u64,
    pub warned: u64,
}

/// One page of a project's violations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violations {
    /// Whether the organization's policy is active ([`Policy::is_active`]); when it is not,
    /// there is nothing else.
    pub active: bool,
    /// Across the whole project, not only this page.
    pub counts: ViolationCounts,
    /// Forbidden components first, then warned ones, each sorted by name then package URL.
    pub items: Vec<Violation>,
}

impl Violations {
    /// Violations across pages.
    pub fn total(&self) -> u64 {
        self.counts.forbidden + self.counts.warned
    }
}

/// Components read at a time while looking for a page of violations.
const SCAN_BATCH: u64 = 500;

/// The verdict on each distinct license of the components of these projects, with how many
/// components have it, by project. Each distinct license is evaluated once.
async fn verdicts_by_project(
    database: &impl ConnectionTrait,
    matcher: &Matcher<'_>,
    project_ids: &[i64],
) -> Result<HashMap<i64, Vec<(Option<String>, u64, Verdict)>>> {
    let mut verdicts: HashMap<Option<String>, Verdict> = HashMap::new();
    let mut grouped: HashMap<i64, Vec<(Option<String>, u64, Verdict)>> = HashMap::new();
    for chunk in project_ids.chunks(QUERY_CHUNK) {
        let rows: Vec<(i64, Option<String>, i64)> = components::Entity::find()
            .select_only()
            .column(components::Column::ProjectId)
            .column(components::Column::License)
            .column_as(components::Column::Id.count(), "count")
            .filter(components::Column::ProjectId.is_in(chunk.iter().copied()))
            .group_by(components::Column::ProjectId)
            .group_by(components::Column::License)
            .order_by_asc(components::Column::ProjectId)
            .order_by_asc(components::Column::License)
            .into_tuple()
            .all(database)
            .await?;
        for (project_id, license, count) in rows {
            let verdict = verdicts
                .entry(license.clone())
                .or_insert_with(|| matcher.evaluate(license.as_deref()))
                .clone();
            grouped.entry(project_id).or_default().push((
                license,
                u64::try_from(count).unwrap_or_default(),
                verdict,
            ));
        }
    }
    Ok(grouped)
}

fn count(verdicts: &[(Option<String>, u64, Verdict)]) -> ViolationCounts {
    let mut counts = ViolationCounts::default();
    for (_, count, verdict) in verdicts {
        match verdict.action {
            Action::Allow => {}
            Action::Warn => counts.warned += count,
            Action::Forbid => counts.forbidden += count,
        }
    }
    counts
}

/// The components of a project that the organization's policy warns about or forbids:
/// `limit` of them from `offset`, forbidden first (see [`Violations::items`]), with the counts
/// of the whole project. Requires [`Permission::View`].
///
/// Licenses are evaluated once per distinct value, counted by the database, and components are
/// read in batches until the page is full, so memory stays bounded by the page and the
/// distinct licenses, however many components the project has.
pub async fn violations(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    offset: usize,
    limit: usize,
) -> Result<Violations> {
    let project =
        crate::projects::authorize(database, reader, project_id, Permission::View).await?;
    let policy = load(database, project.organization_id).await?;
    if !policy.is_active() {
        return Ok(Violations::default());
    }
    let matcher = Matcher::new(&policy);
    let grouped = verdicts_by_project(database, &matcher, &[project_id])
        .await?
        .remove(&project_id)
        .unwrap_or_default();
    let counts = count(&grouped);
    let verdicts: HashMap<Option<String>, Verdict> = grouped
        .into_iter()
        .map(|(license, _, verdict)| (license, verdict))
        .collect();
    let mut items = Vec::new();
    let mut skip = u64::try_from(offset).unwrap_or(u64::MAX);
    for (verdict, total) in [
        (Action::Forbid, counts.forbidden),
        (Action::Warn, counts.warned),
    ] {
        if items.len() >= limit {
            break;
        }
        // The whole section is before the page: no need to read it.
        if skip >= total {
            skip -= total;
            continue;
        }
        let mut position = 0;
        'scan: loop {
            let batch = components::Entity::find()
                .filter(components::Column::ProjectId.eq(project_id))
                .order_by_asc(components::Column::Name)
                .order_by_asc(components::Column::Purl)
                .offset(position)
                .limit(SCAN_BATCH)
                .all(database)
                .await?;
            let read = batch.len() as u64;
            for component in batch {
                let Some(found) = verdicts
                    .get(&component.license)
                    .filter(|found| found.action == verdict)
                else {
                    continue;
                };
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                items.push(Violation {
                    licenses: found.licenses.clone(),
                    purl: component.purl,
                    name: component.name,
                    version: component.version,
                    ecosystem: component.ecosystem,
                    license: component.license,
                    verdict,
                });
                if items.len() >= limit {
                    break 'scan;
                }
            }
            if read < SCAN_BATCH {
                break;
            }
            position += read;
        }
    }
    Ok(Violations {
        active: true,
        counts,
        items,
    })
}

/// The violation counts of each project of an organization the reader sees, for the project
/// list; `None` when the organization's policy is not active. Projects without violations are
/// left out. Requires [`Permission::View`].
pub async fn counts_by_project(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_id: i64,
) -> Result<Option<HashMap<i64, ViolationCounts>>> {
    let projects = crate::projects::list(database, reader, organization_id).await?;
    let policy = load(database, organization_id).await?;
    if !policy.is_active() {
        return Ok(None);
    }
    let identifiers: Vec<i64> = projects.iter().map(|project| project.id).collect();
    let matcher = Matcher::new(&policy);
    Ok(Some(
        verdicts_by_project(database, &matcher, &identifiers)
            .await?
            .into_iter()
            .map(|(project_id, verdicts)| (project_id, count(&verdicts)))
            .filter(|(_, counts)| counts.forbidden + counts.warned > 0)
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(unlisted: Action, unknown: Action, rules: &[(&str, Action)]) -> Policy {
        Policy {
            unlisted,
            unknown,
            rules: normalize_rules(
                &rules
                    .iter()
                    .map(|(license, action)| Rule {
                        license: (*license).to_owned(),
                        action: *action,
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("valid rules"),
        }
    }

    /// The action and the identifiers behind it, joined (leaked: tests compare it with
    /// literals).
    fn verdict(policy: &Policy, license: &str) -> (Action, &'static str) {
        let verdict = policy.evaluate(Some(license));
        (verdict.action, verdict.licenses.join(", ").leak())
    }

    fn problem<T: std::fmt::Debug>(result: Result<T>) -> Problem {
        match result {
            Err(Error::Invalid(problem)) => problem,
            other => panic!("expected a problem, got {other:?}"),
        }
    }

    use Action::{Allow, Forbid, Warn};

    #[test]
    fn without_rules_everything_is_allowed() {
        let policy = Policy::default();
        assert!(!policy.is_active());
        assert_eq!(verdict(&policy, "GPL-3.0-only"), (Allow, ""));
        assert_eq!(policy.evaluate(None).action, Allow);
        assert!(!self::policy(Allow, Allow, &[("MIT", Allow)]).is_active());
        assert!(self::policy(Allow, Allow, &[("MIT", Warn)]).is_active());
        assert!(self::policy(Allow, Warn, &[]).is_active());
        assert!(self::policy(Forbid, Allow, &[]).is_active());
    }

    #[test]
    fn a_single_license_gets_its_rule_or_the_unlisted_default() {
        let policy = policy(Warn, Allow, &[("GPL-3.0-only", Forbid), ("MIT", Allow)]);
        assert_eq!(verdict(&policy, "GPL-3.0-only"), (Forbid, "GPL-3.0-only"));
        assert_eq!(verdict(&policy, "MIT"), (Allow, ""));
        assert_eq!(verdict(&policy, "Apache-2.0"), (Warn, "Apache-2.0"));
    }

    #[test]
    fn or_takes_the_least_severe_side_and_and_the_most_severe() {
        let policy = policy(
            Allow,
            Allow,
            &[("GPL-3.0-only", Forbid), ("LGPL-2.1-only", Warn)],
        );
        assert_eq!(verdict(&policy, "MIT OR GPL-3.0-only"), (Allow, ""));
        assert_eq!(
            verdict(&policy, "MIT AND GPL-3.0-only"),
            (Forbid, "GPL-3.0-only")
        );
        assert_eq!(
            verdict(&policy, "GPL-3.0-only OR LGPL-2.1-only"),
            (Warn, "LGPL-2.1-only")
        );
        assert_eq!(
            verdict(&policy, "GPL-3.0-only AND LGPL-2.1-only"),
            (Forbid, "GPL-3.0-only")
        );
    }

    #[test]
    fn and_binds_tighter_than_or_and_parentheses_override_it() {
        let policy = policy(Allow, Allow, &[("GPL-3.0-only", Forbid), ("MIT", Warn)]);
        // MIT OR (GPL-3.0-only AND Apache-2.0): warned MIT is better than a forbidden pair.
        assert_eq!(
            verdict(&policy, "MIT OR GPL-3.0-only AND Apache-2.0"),
            (Warn, "MIT")
        );
        // (MIT OR GPL-3.0-only) AND Apache-2.0: the choice gives MIT, warned.
        assert_eq!(
            verdict(&policy, "(MIT OR GPL-3.0-only) AND Apache-2.0"),
            (Warn, "MIT")
        );
        // MIT AND (GPL-3.0-only OR Apache-2.0): Apache-2.0 is chosen, MIT still applies.
        assert_eq!(
            verdict(&policy, "MIT AND (GPL-3.0-only OR Apache-2.0)"),
            (Warn, "MIT")
        );
        // GPL-3.0-only AND (MIT OR Apache-2.0): forbidden whatever the choice.
        assert_eq!(
            verdict(&policy, "GPL-3.0-only AND (MIT OR Apache-2.0)"),
            (Forbid, "GPL-3.0-only")
        );
        assert_eq!(
            verdict(&policy, "((GPL-3.0-only))"),
            (Forbid, "GPL-3.0-only")
        );
    }

    #[test]
    fn ties_name_every_license_that_gives_the_verdict() {
        let policy = policy(Allow, Allow, &[("GPL-3.0-only", Warn), ("MPL-2.0", Warn)]);
        assert_eq!(
            verdict(&policy, "GPL-3.0-only AND MPL-2.0 AND MIT"),
            (Warn, "GPL-3.0-only, MPL-2.0")
        );
        assert_eq!(
            verdict(&policy, "GPL-3.0-only OR MPL-2.0"),
            (Warn, "GPL-3.0-only, MPL-2.0")
        );
    }

    #[test]
    fn identifiers_and_operators_match_case_insensitively() {
        let policy = policy(Allow, Allow, &[("gpl-3.0-ONLY", Forbid)]);
        assert_eq!(policy.rules[0].license, "GPL-3.0-only");
        assert_eq!(
            verdict(&policy, "mit and gpl-3.0-only"),
            (Forbid, "GPL-3.0-only")
        );
        assert_eq!(verdict(&policy, "Mit Or GPL-3.0-Only"), (Allow, ""));
    }

    #[test]
    fn exceptions_are_judged_by_their_license() {
        let policy = policy(Allow, Allow, &[("GPL-2.0-only", Forbid)]);
        assert_eq!(
            verdict(&policy, "GPL-2.0-only WITH Classpath-exception-2.0"),
            (Forbid, "GPL-2.0-only")
        );
        assert_eq!(
            verdict(&policy, "gpl-2.0-only with classpath-exception-2.0 OR MIT"),
            (Allow, "")
        );
    }

    #[test]
    fn deprecated_gnu_identifiers_mean_their_current_ones() {
        let policy = policy(
            Allow,
            Allow,
            &[("GPL-2.0", Forbid), ("GPL-2.0-or-later", Warn)],
        );
        assert_eq!(policy.rules[0].license, "GPL-2.0-only");
        assert_eq!(verdict(&policy, "GPL-2.0"), (Forbid, "GPL-2.0-only"));
        assert_eq!(verdict(&policy, "GPL-2.0+"), (Warn, "GPL-2.0-or-later"));
        assert_eq!(verdict(&policy, "MIT/GPL-2.0"), (Allow, ""));
    }

    #[test]
    fn an_allowlist_forbids_unlisted_licenses() {
        let policy = policy(Forbid, Allow, &[("MIT", Allow), ("Apache-2.0", Allow)]);
        assert_eq!(verdict(&policy, "MIT"), (Allow, ""));
        assert_eq!(verdict(&policy, "BSD-3-Clause"), (Forbid, "BSD-3-Clause"));
        assert_eq!(verdict(&policy, "MIT OR BSD-3-Clause"), (Allow, ""));
        assert_eq!(
            verdict(&policy, "MIT AND BSD-3-Clause"),
            (Forbid, "BSD-3-Clause")
        );
    }

    #[test]
    fn missing_and_invalid_licenses_are_unknown() {
        let policy = policy(Forbid, Warn, &[("MIT", Allow)]);
        assert_eq!(policy.evaluate(None).action, Warn);
        for license in [
            "",
            "Apache License 2.0",
            "Apache",
            "MIT AND Unknown-License",
            "MIT AND",
            "(MIT",
            "MIT WITH Some-exception",
        ] {
            assert_eq!(verdict(&policy, license), (Warn, ""), "{license}");
        }
    }

    #[test]
    fn license_references_match_their_rule() {
        let policy = policy(Allow, Allow, &[("licenseref-Proprietary", Forbid)]);
        assert_eq!(policy.rules[0].license, "LicenseRef-Proprietary");
        assert_eq!(
            verdict(&policy, "LicenseRef-proprietary OR LicenseRef-other"),
            (Allow, "")
        );
        assert_eq!(
            verdict(&policy, "MIT AND LicenseRef-Proprietary"),
            (Forbid, "LicenseRef-Proprietary")
        );
        // A reference to another document is another license.
        assert_eq!(
            verdict(&policy, "DocumentRef-x:LicenseRef-Proprietary"),
            (Allow, "")
        );
    }

    #[test]
    fn rule_identifiers_are_checked_and_normalized() {
        assert_eq!(canonical_identifier(" mit ").unwrap(), "MIT");
        assert_eq!(canonical_identifier("lgpl-2.1").unwrap(), "LGPL-2.1-only");
        assert_eq!(
            canonical_identifier("LICENSEREF-my.license-1").unwrap(),
            "LicenseRef-my.license-1"
        );
        for invalid in [
            "",
            "Apache",
            "GPL-2.0+",
            "LLVM-exception",
            "LicenseRef-",
            "LicenseRef-a b",
            "MIT OR Apache-2.0",
        ] {
            assert_eq!(
                problem(canonical_identifier(invalid)),
                Problem::UnknownLicenseId {
                    license: invalid.trim().to_owned()
                },
                "{invalid}"
            );
        }
        let long = format!("LicenseRef-{}", "a".repeat(MAXIMUM_IDENTIFIER_LENGTH));
        assert!(canonical_identifier(&long).is_err());
    }

    #[test]
    fn rules_are_deduplicated_sorted_and_conflicts_refused() {
        let rule = |license: &str, action| Rule {
            license: license.to_owned(),
            action,
        };
        assert_eq!(
            normalize_rules(&[
                rule("MIT", Allow),
                rule("apache-2.0", Warn),
                rule("mit", Allow),
            ])
            .unwrap(),
            vec![rule("Apache-2.0", Warn), rule("MIT", Allow)]
        );
        assert_eq!(
            problem(normalize_rules(&[rule("MIT", Allow), rule("mit", Forbid)])),
            Problem::ConflictingLicenseRule {
                license: "MIT".to_owned()
            }
        );
        let many: Vec<Rule> = (0..=MAXIMUM_RULES)
            .map(|index| rule(&format!("LicenseRef-{index}"), Forbid))
            .collect();
        assert_eq!(
            problem(normalize_rules(&many)),
            Problem::TooManyLicenseRules {
                maximum: MAXIMUM_RULES
            }
        );
    }

    #[test]
    fn lists_split_on_whitespace_and_commas() {
        assert_eq!(
            split_identifiers(" MIT,Apache-2.0\n\nGPL-3.0-only ,, ").collect::<Vec<_>>(),
            vec!["MIT", "Apache-2.0", "GPL-3.0-only"]
        );
    }

    #[test]
    fn actions_parse_their_names() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()).unwrap(), action);
        }
        assert!(Action::parse("deny").is_err());
        assert!(Allow < Warn && Warn < Forbid);
    }
}
