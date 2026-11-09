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
//! match case-insensitively. A missing license, or `NOASSERTION` within an expression, is
//! unknown and gets the default for unknown licenses.
//!
//! A license that is not a valid SPDX expression (a free-text name, an identifier outside the
//! SPDX list, CycloneDX entries of both kinds joined with `AND`) is unknown too, but its words
//! are still read: it gets the most severe of the default for unknown licenses and the actions
//! of the SPDX identifiers and `LicenseRef-…` it names, as if they were joined with `AND`. A
//! forbidden identifier can then not pass because something else in the text is not SPDX. An
//! identifier that is an ordinary word (`Intel`, `MIT`) only counts when it stands alone
//! between separators (parentheses, operators, `,`, `;`, `/`), so that prose does not name
//! licenses by accident.
//!
//! Evaluation is pure, and nothing is stored: violations are computed when read, so changing
//! the policy applies to every project at once, without a run.

use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use nanobom_entity::{components, license_rules, organizations};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, TransactionSession, TransactionTrait,
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
    /// [`Action::Allow`] or comes from the default for unknown licenses alone.
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

    /// The action of one identifier: its rule, else the default for unlisted licenses.
    fn action(&self, license: &str) -> Action {
        self.actions
            .get(&license.to_ascii_lowercase())
            .copied()
            .unwrap_or(self.policy.unlisted)
    }

    fn evaluate(&self, license: Option<&str>) -> Verdict {
        let Some(text) = license else {
            return verdict(self.policy.unknown, BTreeSet::new());
        };
        let Some(expression) = parse_expression(text) else {
            return self.scan(text);
        };
        // The expression is in postfix order: each operator combines the two entries above it.
        let mut stack: Vec<(Action, BTreeSet<String>)> = Vec::new();
        for node in expression.iter() {
            match node {
                ExprNode::Req(requirement) => {
                    stack.push(match license_name(&requirement.req.license) {
                        Some(license) => (self.action(&license), BTreeSet::from([license])),
                        None => (self.policy.unknown, BTreeSet::new()),
                    });
                }
                ExprNode::Op(operator) => {
                    let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
                        return self.scan(text);
                    };
                    stack.push(combine(*operator, left, right));
                }
            }
        }
        match (stack.pop(), stack.is_empty()) {
            (Some((action, licenses)), true) => verdict(action, licenses),
            _ => self.scan(text),
        }
    }

    /// The verdict on a license that is not a valid expression (see the
    /// [module documentation](self)): the identifiers it names are joined with `AND`, along with
    /// the default for unknown licenses, which is therefore the least it gets.
    fn scan(&self, text: &str) -> Verdict {
        let mut found = (self.policy.unknown, BTreeSet::new());
        for license in named_licenses(text) {
            let action = self.action(&license);
            found = combine(Operator::And, found, (action, BTreeSet::from([license])));
        }
        verdict(found.0, found.1)
    }
}

/// A verdict names no license when it allows: nothing needs explaining.
fn verdict(action: Action, licenses: BTreeSet<String>) -> Verdict {
    Verdict {
        action,
        licenses: if action == Action::Allow {
            Vec::new()
        } else {
            licenses.into_iter().collect()
        },
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

/// The text split into words, as the `spdx` crate's lexer reads them (`[-A-Za-z0-9.:]+`), and
/// the characters between them, one at a time; `true` marks a word.
fn tokens(text: &str) -> impl Iterator<Item = (bool, &str)> {
    let is_word = |character: char| character.is_ascii_alphanumeric() || "-.:".contains(character);
    let mut rest = text;
    std::iter::from_fn(move || {
        let first = rest.chars().next()?;
        let end = if is_word(first) {
            rest.find(|character| !is_word(character))
                .unwrap_or(rest.len())
        } else {
            first.len_utf8()
        };
        let (token, after) = rest.split_at(end);
        rest = after;
        Some((is_word(first), token))
    })
}

/// SPDX identifiers and operators are case-insensitive, but the `spdx` crate compares them
/// exactly: every word is rewritten in its canonical spelling before parsing, while `+`, `/`
/// and parentheses stay as they are.
fn canonical_case(text: &str) -> String {
    tokens(text)
        .map(|(word, token)| {
            if word {
                canonical_word(token)
            } else {
                token.to_owned()
            }
        })
        .collect()
}

/// The identifiers a rule matches among the words of a text that is not a valid expression,
/// read as [`license_name`] reads those of an expression: an SPDX license identifier, `+`
/// right after a GNU one meaning its `-or-later` variant, or a license reference.
///
/// Free text is not an expression, so a word is matched in steps: as it is; then without the
/// `.`, `:` and `-` around it, which the lexer keeps in words (`AGPL-3.0-only.`); then, for a
/// word with `:` that is not a `DocumentRef-…:LicenseRef-…`, each of its parts
/// (`License:AGPL-3.0-only`). An identifier shaped like one (with a digit, `-`, `.` or `+`, or
/// a license reference) is taken wherever it appears. Close to 200 SPDX identifiers are letters
/// only, many of them ordinary words (`Intel`, `Ruby`, `DOC`, `MIT`, the German "mit"): one of
/// those is taken only when it is the only word of a part of the text, as it is or without what
/// surrounds it, parts being separated by parentheses, `AND`, `OR`, `WITH`, `,`, `;` and `/`.
/// `Intel Simplified Software License` names no license, and `MIT, Some proprietary thing`
/// names `MIT`.
fn named_licenses(text: &str) -> impl Iterator<Item = String> {
    let tokens: Vec<(bool, &str)> = tokens(text).collect();
    let separates = |(word, token): (bool, &str)| {
        if word {
            ["AND", "OR", "WITH"]
                .iter()
                .any(|operator| token.eq_ignore_ascii_case(operator))
        } else {
            "(),;/".contains(token)
        }
    };
    // Whether each token is the only word of its part, ignoring white space and a `+`.
    let mut alone = vec![false; tokens.len()];
    let mut start = 0;
    for end in 0..=tokens.len() {
        if end < tokens.len() && !separates(tokens[end]) {
            continue;
        }
        let part = &tokens[start..end];
        let words: Vec<usize> = (start..end).filter(|&index| tokens[index].0).collect();
        let only_space = part
            .iter()
            .all(|&(word, token)| word || token == "+" || token.trim().is_empty());
        if let [index] = words[..]
            && only_space
        {
            alone[index] = true;
        }
        start = end + 1;
    }
    (0..tokens.len()).flat_map(move |index| {
        let (true, word) = tokens[index] else {
            return Vec::new();
        };
        let plus = tokens.get(index + 1) == Some(&(false, "+"));
        let trimmed = word.trim_matches(['.', ':', '-']);
        // Each candidate with whether it is the whole word, without what surrounds it.
        let candidates: Vec<(&str, bool)> = match [word, trimmed]
            .into_iter()
            .find(|candidate| identify(candidate).is_some())
        {
            Some(candidate) => vec![(candidate, true)],
            None if trimmed.contains(':') => trimmed
                .split(':')
                .map(|part| (part.trim_matches(['.', '-']), false))
                .collect(),
            None => Vec::new(),
        };
        let last = candidates.len().saturating_sub(1);
        candidates
            .into_iter()
            .enumerate()
            .filter_map(|(position, (candidate, whole))| {
                match identify(candidate)? {
                    Named::Reference(reference) => Some(reference),
                    Named::Spdx(id) => {
                        let plain = id
                            .name
                            .chars()
                            .all(|character| character.is_ascii_alphabetic());
                        if plain && !(whole && alone[index]) {
                            return None;
                        }
                        let mut id = current_id(id);
                        // `+` follows the end of the word only.
                        if plus && position == last && id.is_gnu() {
                            id = or_later(id).unwrap_or(id);
                        }
                        license_name(&LicenseItem::Spdx {
                            id,
                            or_later: false,
                        })
                    }
                }
            })
            .collect()
    })
}

/// What a word of free text names.
enum Named {
    Spdx(LicenseId),
    /// A `LicenseRef-…` or `DocumentRef-…:LicenseRef-…`, spelled as in an expression.
    Reference(String),
}

fn identify(word: &str) -> Option<Named> {
    let word = canonical_word(word);
    if let Some(id) = spdx::license_id(&word) {
        return Some(Named::Spdx(id));
    }
    // `canonical_word` spelled the prefixes as an expression does.
    let reference = |part: &str, prefix: &str| {
        part.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains(':'))
    };
    let is_reference = match word.split_once(':') {
        Some((document, license)) => {
            reference(document, "DocumentRef-") && reference(license, "LicenseRef-")
        }
        None => reference(&word, "LicenseRef-"),
    };
    is_reference.then_some(Named::Reference(word))
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

/// The identifier a rule matches for one license of an expression (see [`current_id`]); `+`
/// on licenses other than GNU ones (`Apache-1.0+`) is ignored. `None` for `NOASSERTION`, which
/// the `spdx` crate lists as a license but which says the license is unknown.
fn license_name(license: &LicenseItem) -> Option<String> {
    match license {
        LicenseItem::Spdx { id, .. } if id.name == "NOASSERTION" => None,
        LicenseItem::Spdx { id, .. } => Some(current_id(*id).name.to_owned()),
        LicenseItem::Other(reference) => Some(reference.to_string()),
    }
}

/// The identifier that replaces a deprecated one carrying a GNU license, so that a rule on the
/// current identifier covers both. A bare identifier (`GPL-2.0`) means the `-only` variant, and
/// an identifier with an exception means its license, since exceptions are ignored (the current
/// form of `GPL-2.0-with-classpath-exception`, `GPL-2.0-only WITH Classpath-exception-2.0`, is
/// judged by `GPL-2.0-only`). The deprecated identifiers with an exception are the GNU
/// `…-with-…-exception` ones, `eCos-2.0` (now `GPL-2.0-or-later WITH eCos-exception-2.0`) and
/// `wxWindows` (now `LGPL-2.0-or-later WITH WxWindows-exception-3.1`).
fn current_id(id: LicenseId) -> LicenseId {
    let license = match id.name {
        "eCos-2.0" => Some("GPL-2.0-or-later"),
        "wxWindows" => Some("LGPL-2.0-or-later"),
        name => name
            .split_once("-with-")
            .filter(|(_, exception)| exception.ends_with("-exception"))
            .map(|(license, _)| license),
    };
    let id = license.and_then(spdx::license_id).unwrap_or(id);
    if id.is_gnu() && !id.name.ends_with("-only") && !id.name.ends_with("-or-later") {
        spdx::gnu_license_id(id.name, false).unwrap_or(id)
    } else {
        id
    }
}

/// The `-or-later` variant of a GNU license, which `+` asks for.
fn or_later(id: LicenseId) -> Option<LicenseId> {
    if id.name.ends_with("-or-later") {
        return Some(id);
    }
    spdx::gnu_license_id(id.name.strip_suffix("-only").unwrap_or(id.name), true)
}

/// The longest identifier a rule accepts. SPDX identifiers are far shorter; the bound is for
/// `LicenseRef-…`.
pub const MAXIMUM_IDENTIFIER_LENGTH: usize = 200;

/// The most rules a policy holds.
pub const MAXIMUM_RULES: usize = 1000;

/// The canonical spelling of a rule's identifier: an SPDX license identifier, in any case, or
/// `LicenseRef-` followed by letters, digits, `.` and `-`. Deprecated identifiers carrying a
/// GNU license are replaced by the current ones they mean: `GPL-3.0` and
/// `GPL-3.0-with-GCC-exception` are stored as `GPL-3.0-only`, `wxWindows` as
/// `LGPL-2.0-or-later`. Anything else, an exception identifier, `NOASSERTION` or `GPL-2.0+`
/// included, is [`Problem::UnknownLicenseId`].
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
    license_name(&LicenseItem::Spdx {
        id,
        or_later: false,
    })
    .ok_or_else(unknown)
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
    /// The identifiers that lead to the verdict; empty when the action for unknown licenses
    /// alone gives it.
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

/// Components read at a time by [`section`] when it scans a project.
const SCAN_BATCH: u64 = 500;

/// The components of a project whose license gets `verdict` (`verdicts` has the verdict on
/// each of its distinct licenses): `limit` of them from `skip`, by name, package URL, then
/// identifier, so pages neither overlap nor miss a component.
///
/// The database selects them by license. Past [`QUERY_CHUNK`] licenses, too many for one
/// query, the components of the project are read in batches and filtered here instead:
/// splitting the list would mean merging the sorted results of each part, each as long as the
/// offset, and that many distinct licenses with one verdict in one project is rare.
async fn section(
    database: &impl ConnectionTrait,
    version_id: i64,
    verdicts: &HashMap<Option<String>, Verdict>,
    verdict: Action,
    skip: u64,
    limit: u64,
) -> Result<Vec<components::Model>> {
    let licenses: Vec<&str> = verdicts
        .iter()
        .filter(|(_, found)| found.action == verdict)
        .filter_map(|(license, _)| license.as_deref())
        .collect();
    let ordered = components::Entity::find()
        .filter(components::Column::VersionId.eq(version_id))
        .order_by_asc(components::Column::Name)
        .order_by_asc(components::Column::Purl)
        .order_by_asc(components::Column::Id);
    if licenses.len() <= QUERY_CHUNK {
        let mut matching = Condition::any().add(components::Column::License.is_in(licenses));
        if verdicts
            .get(&None)
            .is_some_and(|found| found.action == verdict)
        {
            matching = matching.add(components::Column::License.is_null());
        }
        return Ok(ordered
            .filter(matching)
            .offset(skip)
            .limit(limit)
            .all(database)
            .await?);
    }
    let mut found = Vec::new();
    let mut skip = skip;
    let mut position = 0;
    loop {
        let batch = ordered
            .clone()
            .offset(position)
            .limit(SCAN_BATCH)
            .all(database)
            .await?;
        let read = batch.len() as u64;
        for component in batch {
            if verdicts
                .get(&component.license)
                .is_none_or(|found| found.action != verdict)
            {
                continue;
            }
            if skip > 0 {
                skip -= 1;
                continue;
            }
            found.push(component);
            if found.len() as u64 >= limit {
                return Ok(found);
            }
        }
        if read < SCAN_BATCH {
            return Ok(found);
        }
        position += read;
    }
}

/// The verdict on each distinct license of the components of these versions, with how many
/// components have it, by version. Each distinct license is evaluated once.
async fn verdicts_by_version(
    database: &impl ConnectionTrait,
    matcher: &Matcher<'_>,
    version_ids: &[i64],
) -> Result<HashMap<i64, Vec<(Option<String>, u64, Verdict)>>> {
    let mut verdicts: HashMap<Option<String>, Verdict> = HashMap::new();
    let mut grouped: HashMap<i64, Vec<(Option<String>, u64, Verdict)>> = HashMap::new();
    for chunk in version_ids.chunks(QUERY_CHUNK) {
        let rows: Vec<(Option<i64>, Option<String>, i64)> = components::Entity::find()
            .select_only()
            .column(components::Column::VersionId)
            .column(components::Column::License)
            .column_as(components::Column::Id.count(), "count")
            .filter(components::Column::VersionId.is_in(chunk.iter().copied()))
            .group_by(components::Column::VersionId)
            .group_by(components::Column::License)
            .order_by_asc(components::Column::VersionId)
            .order_by_asc(components::Column::License)
            .into_tuple()
            .all(database)
            .await?;
        for (version_id, license, count) in rows {
            // Never `None`: the filter above names the versions.
            let Some(version_id) = version_id else {
                continue;
            };
            let verdict = verdicts
                .entry(license.clone())
                .or_insert_with(|| matcher.evaluate(license.as_deref()))
                .clone();
            grouped.entry(version_id).or_default().push((
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

/// The components of a project's latest version that the organization's policy warns about or
/// forbids: `limit` of them from `offset`, forbidden first (see [`Violations::items`]), with
/// the counts of the whole version. Requires [`Permission::View`].
///
/// Licenses are evaluated once per distinct value and counted by the database, which then
/// selects the page of each verdict by its licenses, so memory stays bounded by the page and
/// the distinct licenses, however many components the project has.
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
    let version_id = crate::versions::select(database, project_id, None)
        .await?
        .id;
    let matcher = Matcher::new(&policy);
    let grouped = verdicts_by_version(database, &matcher, &[version_id])
        .await?
        .remove(&version_id)
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
        let remaining = u64::try_from(limit - items.len()).unwrap_or(u64::MAX);
        let found = section(database, version_id, &verdicts, verdict, skip, remaining).await?;
        skip = 0;
        items.extend(found.into_iter().map(|component| {
            Violation {
                licenses: verdicts
                    .get(&component.license)
                    .map(|found| found.licenses.clone())
                    .unwrap_or_default(),
                purl: component.purl,
                name: component.name,
                version: component.version,
                ecosystem: component.ecosystem,
                license: component.license,
                verdict,
            }
        }));
    }
    Ok(Violations {
        active: true,
        counts,
        items,
    })
}

/// The violation counts of the latest version of each project of an organization the reader
/// sees, for the project list; `None` when the organization's policy is not active. Projects
/// without violations are left out. Requires [`Permission::View`].
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
    let project_of: HashMap<i64, i64> = crate::versions::latest_of(database, &identifiers)
        .await?
        .into_iter()
        .map(|version| (version.id, version.project_id))
        .collect();
    let version_ids: Vec<i64> = project_of.keys().copied().collect();
    let matcher = Matcher::new(&policy);
    Ok(Some(
        verdicts_by_version(database, &matcher, &version_ids)
            .await?
            .into_iter()
            .map(|(version_id, verdicts)| (project_of[&version_id], count(&verdicts)))
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
    fn deprecated_gnu_identifiers_with_an_exception_mean_their_license() {
        let policy = policy(
            Allow,
            Allow,
            &[("GPL-2.0-only", Forbid), ("GPL-3.0-only", Warn)],
        );
        for license in [
            "GPL-2.0-with-classpath-exception",
            "gpl-2.0-with-gcc-exception",
            "GPL-2.0-with-autoconf-exception",
            "GPL-2.0-with-bison-exception",
            "GPL-2.0-with-font-exception",
        ] {
            assert_eq!(
                verdict(&policy, license),
                (Forbid, "GPL-2.0-only"),
                "{license}"
            );
        }
        assert_eq!(
            verdict(
                &policy,
                "GPL-3.0-with-GCC-exception OR GPL-3.0-with-autoconf-exception"
            ),
            (Warn, "GPL-3.0-only")
        );
        assert_eq!(
            canonical_identifier("GPL-2.0-with-classpath-exception").unwrap(),
            "GPL-2.0-only"
        );
        assert_eq!(
            canonical_identifier("gpl-3.0-with-gcc-exception").unwrap(),
            "GPL-3.0-only"
        );
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
            "NOASSERTION",
            "MIT AND noassertion",
            "MIT AND NONE",
        ] {
            assert_eq!(verdict(&policy, license), (Warn, ""), "{license}");
        }
        assert_eq!(verdict(&policy, "MIT OR NOASSERTION"), (Allow, ""));
    }

    #[test]
    fn invalid_licenses_get_the_most_severe_identifier_they_name() {
        let policy = policy(
            Allow,
            Warn,
            &[
                ("AGPL-3.0-only", Forbid),
                ("GPL-3.0-only", Forbid),
                ("GPL-2.0-or-later", Forbid),
                ("LicenseRef-Proprietary", Forbid),
                ("MIT", Forbid),
                ("MPL-2.0", Warn),
            ],
        );
        for (license, expected) in [
            // CycloneDX entries of both kinds, joined by the inventory.
            (
                "(GNU Affero General Public License v3) AND AGPL-3.0-only",
                "AGPL-3.0-only",
            ),
            ("GPL-3.0-only WITH Some-Custom-exception", "GPL-3.0-only"),
            ("MIT AND NOASSERTION", "MIT"),
            ("mit and NONE", "MIT"),
            // `+` and deprecated identifiers read as in an expression.
            ("GPL-2.0+ AND Custom", "GPL-2.0-or-later"),
            ("Custom AND gpl-2.0-only+", "GPL-2.0-or-later"),
            (
                "licenseref-proprietary AND Custom",
                "LicenseRef-proprietary",
            ),
            ("GPL-3.0 OR Custom", "GPL-3.0-only"),
        ] {
            assert_eq!(verdict(&policy, license), (Forbid, expected), "{license}");
        }
        // Without an expression, `OR` gives no choice.
        assert_eq!(verdict(&policy, "Apache-2.0 OR GPL-3.0-only"), (Allow, ""));
        assert_eq!(
            verdict(&policy, "Apache-2.0 OR GPL-3.0-only OR Custom"),
            (Forbid, "GPL-3.0-only")
        );
        // The default for unknown licenses is the least: an allowed identifier does not lower
        // it, an identifier with the same action is named.
        assert_eq!(verdict(&policy, "Apache-2.0 AND Custom"), (Warn, ""));
        assert_eq!(verdict(&policy, "GPL-2.0 AND Custom"), (Warn, ""));
        assert_eq!(verdict(&policy, "MPL-2.0 AND Custom"), (Warn, "MPL-2.0"));
        // A reference to another document is another license; exceptions are not licenses.
        assert_eq!(
            verdict(&policy, "DocumentRef-x:LicenseRef-Proprietary AND Custom"),
            (Warn, "")
        );
        assert_eq!(
            verdict(&policy, "Classpath-exception-2.0 Custom"),
            (Warn, "")
        );
    }

    #[test]
    fn identifiers_glued_to_punctuation_are_read() {
        let policy = policy(
            Allow,
            Warn,
            &[
                ("AGPL-3.0-only", Forbid),
                ("GPL-3.0-only", Forbid),
                ("GPL-2.0-or-later", Forbid),
                ("LicenseRef-Proprietary", Forbid),
            ],
        );
        for (license, expected) in [
            ("Licensed under AGPL-3.0-only", "AGPL-3.0-only"),
            ("Licensed under AGPL-3.0-only.", "AGPL-3.0-only"),
            ("License:AGPL-3.0-only", "AGPL-3.0-only"),
            ("GPL-3.0-only: see COPYING", "GPL-3.0-only"),
            ("-GPL-3.0-only- and more", "GPL-3.0-only"),
            ("License:GPL-2.0+", "GPL-2.0-or-later"),
            ("Terms:LicenseRef-Proprietary.", "LicenseRef-Proprietary"),
        ] {
            assert_eq!(verdict(&policy, license), (Forbid, expected), "{license}");
        }
        // A reference to another document stays whole, and stays another license.
        assert_eq!(
            verdict(&policy, "See DocumentRef-x:LicenseRef-Proprietary."),
            (Warn, "")
        );
    }

    #[test]
    fn identifiers_that_are_ordinary_words_count_only_alone() {
        // An allowlist: every SPDX identifier read in prose would be forbidden.
        let policy = policy(Forbid, Warn, &[("Apache-2.0", Allow)]);
        for license in [
            "Intel Simplified Software License",
            "SEE LICENSE IN doc/LICENSE",
            "Lizenz mit Ausnahmen",
            "Fair use of the JSON data, see curl and Vim docs",
            "Licensed under MIT.",
            "License: MIT",
            "License:MIT",
            "Apache-2.0, Some proprietary thing",
        ] {
            assert_eq!(verdict(&policy, license), (Warn, ""), "{license}");
        }
        for (license, expected) in [
            ("(Ruby) AND Foo bar", "Ruby"),
            ("MIT, Some proprietary thing", "MIT"),
            ("mit; Custom", "MIT"),
            ("Custom / Intel", "Intel"),
            ("Custom OR MIT+", "MIT"),
            ("Some text WITH Unlicense", "Unlicense"),
            // Identifiers shaped like one count anywhere.
            ("Licensed under BSD-3-Clause", "BSD-3-Clause"),
            (
                "(GNU Affero General Public License v3) AND AGPL-3.0-only",
                "AGPL-3.0-only",
            ),
        ] {
            assert_eq!(verdict(&policy, license), (Forbid, expected), "{license}");
        }
    }

    #[test]
    fn deprecated_identifiers_with_an_exception_on_a_gnu_license_mean_it() {
        let policy = policy(
            Allow,
            Allow,
            &[("GPL-2.0-or-later", Forbid), ("LGPL-2.0-or-later", Warn)],
        );
        assert_eq!(verdict(&policy, "eCos-2.0"), (Forbid, "GPL-2.0-or-later"));
        assert_eq!(verdict(&policy, "wxWindows"), (Warn, "LGPL-2.0-or-later"));
        assert_eq!(
            verdict(&policy, "ecos-2.0 OR wxwindows"),
            (Warn, "LGPL-2.0-or-later")
        );
        assert_eq!(
            verdict(&policy, "wxWindows AND Custom"),
            (Warn, "LGPL-2.0-or-later")
        );
        assert_eq!(
            canonical_identifier("eCos-2.0").unwrap(),
            "GPL-2.0-or-later"
        );
        assert_eq!(
            canonical_identifier("wxwindows").unwrap(),
            "LGPL-2.0-or-later"
        );
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
            "NOASSERTION",
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
