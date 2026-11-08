//! Validation of the identifiers that appear in URLs: usernames and organization and project
//! slugs. They are lower case, so `MyProject` and `myproject` name the same project.

use crate::{
    error::{Error, Result},
    problem::{Field, Problem},
};

pub const MAXIMUM_LENGTH: usize = 64;

/// Normalizes and validates a slug or username: 1 to 64 characters among lower-case ASCII
/// letters, digits, `.`, `_` and `-`, starting with a letter or a digit. Upper-case letters are
/// folded to lower case.
pub fn slug(field: Field, value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    let valid_characters = value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character));
    let valid_start = value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphanumeric());
    if value.len() > MAXIMUM_LENGTH || !valid_characters || !valid_start {
        return Err(Error::invalid(Problem::InvalidSlug(field)));
    }
    Ok(value)
}

/// Validates a display name: not blank, at most 200 characters.
pub fn display_name(field: Field, value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 200 {
        return Err(Error::invalid(Problem::InvalidName(field)));
    }
    Ok(value.to_owned())
}

/// Normalizes and loosely validates an email address; the address is not verified.
pub fn email(value: &str) -> Result<String> {
    let value = value.trim().to_lowercase();
    let mut parts = value.split('@');
    let valid = matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && domain.contains('.')
    ) && value.len() <= 254
        && !value.chars().any(char::is_whitespace);
    if valid {
        Ok(value)
    } else {
        Err(Error::invalid(Problem::InvalidEmail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_folded_to_lower_case() {
        assert_eq!(
            slug(Field::ProjectSlug, " MyProject ").unwrap(),
            "myproject"
        );
        assert_eq!(
            slug(Field::ProjectSlug, "api.v2_beta-1").unwrap(),
            "api.v2_beta-1"
        );
    }

    #[test]
    fn invalid_slugs_are_rejected() {
        for value in [
            "",
            "-leading",
            ".hidden",
            "with space",
            "slash/name",
            "é",
            &"a".repeat(65),
        ] {
            assert!(
                slug(Field::ProjectSlug, value).is_err(),
                "{value:?} should be rejected"
            );
        }
    }

    #[test]
    fn emails_are_normalized() {
        assert_eq!(email(" Alice@Example.org ").unwrap(), "alice@example.org");
        for value in [
            "alice",
            "alice@localhost",
            "a@b@c.d",
            "@example.org",
            "a b@c.d",
        ] {
            assert!(email(value).is_err(), "{value:?} should be rejected");
        }
    }
}
