//! Reading identity provider claims: instance administrator rights and organization memberships
//! from groups or roles.
//!
//! A claim path names a claim of the ID token or user information. It is first looked up as a
//! whole (`urn:zitadel:iam:org:project:roles` is one claim), then as a dot-separated path into
//! nested objects (`realm_access.roles` for Keycloak).
//!
//! Group names are read from a claim that is a list of strings (`["admins", "dev"]`), an object
//! whose keys are the names (Zitadel's roles claim), or a single string.

use std::collections::BTreeMap;

use nanobom_domain::access::Role;
use serde_json::{Map, Value};

/// Finds the value at a claim path.
pub fn lookup<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    if let Some(value) = claims.get(path) {
        return Some(value);
    }
    let mut segments = path.split('.');
    let mut value = claims.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

/// The names in a group or role claim.
pub fn names(value: &Value) -> Vec<String> {
    match value {
        Value::String(name) => vec![name.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Value::Object(map) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

/// Whether the claims grant instance administration: the claim at `path` contains `value`
/// (as a name, see [`names`]), or, without a value, is `true`.
pub fn is_administrator(claims: &Map<String, Value>, path: &str, value: Option<&str>) -> bool {
    let Some(claim) = lookup(claims, path) else {
        return false;
    };
    match value {
        Some(expected) => names(claim).iter().any(|name| name == expected),
        None => claim.as_bool().unwrap_or(false),
    }
}

/// A mapping from identity provider groups to organization roles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMapping {
    entries: Vec<(String, String, Role)>,
}

impl GroupMapping {
    /// Parses `group=organization:role` entries separated by `;` or new lines. Group names may
    /// contain `:` but not `=`; organization slugs contain neither.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for entry in value
            .split([';', '\n'])
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (group, target) = entry
                .rsplit_once('=')
                .ok_or_else(|| format!("{entry:?} is not group=organization:role"))?;
            let (organization, role) = target
                .rsplit_once(':')
                .ok_or_else(|| format!("{entry:?} is not group=organization:role"))?;
            let role = Role::parse(role.trim()).map_err(|error| format!("{entry:?}: {error}"))?;
            let organization =
                nanobom_domain::names::slug(nanobom_domain::Field::OrganizationSlug, organization)
                    .map_err(|error| format!("{entry:?}: {error}"))?;
            entries.push((group.trim().to_owned(), organization, role));
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The role in each organization the groups grant; the highest wins.
    pub fn roles(&self, groups: &[String]) -> BTreeMap<String, Role> {
        let mut roles: BTreeMap<String, Role> = BTreeMap::new();
        for (group, organization, role) in &self.entries {
            if groups.iter().any(|name| name == group) {
                let entry = roles.entry(organization.clone()).or_insert(*role);
                *entry = (*entry).max(*role);
            }
        }
        roles
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn whole_claim_names_win_over_paths() {
        let claims = claims(json!({
            "urn:zitadel:iam:org:project:roles": {"admin": {"123": "example.org"}},
            "realm_access": {"roles": ["offline_access", "nanobom-admin"]}
        }));
        assert!(lookup(&claims, "urn:zitadel:iam:org:project:roles").is_some());
        assert_eq!(
            names(lookup(&claims, "realm_access.roles").unwrap()),
            ["offline_access", "nanobom-admin"]
        );
        assert!(lookup(&claims, "realm_access.missing").is_none());
    }

    #[test]
    fn administrators_are_recognized_in_lists_objects_and_flags() {
        let claims = claims(json!({
            "groups": ["/nanobom/admins", "/dev"],
            "urn:zitadel:iam:org:project:roles": {"nanobom-admin": {"1": "acme"}},
            "nanobom_admin": true
        }));
        assert!(is_administrator(&claims, "groups", Some("/nanobom/admins")));
        assert!(!is_administrator(&claims, "groups", Some("admins")));
        assert!(is_administrator(
            &claims,
            "urn:zitadel:iam:org:project:roles",
            Some("nanobom-admin")
        ));
        assert!(is_administrator(&claims, "nanobom_admin", None));
        assert!(!is_administrator(&claims, "missing", None));
    }

    #[test]
    fn group_mappings_grant_the_highest_role() {
        let mapping = GroupMapping::parse(
            "platform-team=platform:admin; /acme/dev=acme:member\nacme-readers = Acme : viewer;;",
        )
        .unwrap();
        let roles = mapping.roles(&["/acme/dev".to_owned(), "acme-readers".to_owned()]);
        assert_eq!(roles, BTreeMap::from([("acme".to_owned(), Role::Member)]));
        assert!(mapping.roles(&["unrelated".to_owned()]).is_empty());
        assert!(GroupMapping::parse("").unwrap().is_empty());
    }

    #[test]
    fn invalid_group_mappings_are_rejected() {
        for value in [
            "no-equals",
            "group=organization",
            "group=acme:superuser",
            "group=bad slug:admin",
        ] {
            assert!(GroupMapping::parse(value).is_err(), "{value:?}");
        }
    }
}
