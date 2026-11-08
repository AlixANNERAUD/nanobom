//! Local account passwords, hashed with Argon2id.
//!
//! Hashing is deliberately slow, so [`hash`] and [`verify`] run on the blocking thread pool
//! instead of stalling the asynchronous runtime. Accounts created through OpenID Connect may
//! have no password at all.

use crate::{
    error::{Error, Result},
    problem::Problem,
};

/// Upper bound on password length, so hashing cannot be used to exhaust the server.
const MAXIMUM_LENGTH: usize = 1024;

/// The rules a new password must follow, set by the operator.
#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    /// Minimum length in characters (Unicode scalar values, not bytes).
    pub minimum_length: usize,
}

impl PasswordPolicy {
    /// Checks a new password's length against the policy and against a fixed upper bound of
    /// 1024 characters; the error is a [`Problem`] to show to the user.
    pub fn validate(&self, password: &str) -> Result<()> {
        let length = password.chars().count();
        if length < self.minimum_length {
            return Err(Error::invalid(Problem::PasswordTooShort {
                minimum: self.minimum_length,
            }));
        }
        if length > MAXIMUM_LENGTH {
            return Err(Error::invalid(Problem::PasswordTooLong {
                maximum: MAXIMUM_LENGTH,
            }));
        }
        Ok(())
    }
}

/// Hashes a password with Argon2id, off the asynchronous runtime.
pub async fn hash(password: String) -> String {
    tokio::task::spawn_blocking(move || password_auth::generate_hash(password))
        .await
        .expect("password hashing does not panic")
}

/// Checks a password against a stored hash, off the asynchronous runtime. A malformed hash, or
/// a panic of the hashing task, counts as a mismatch.
pub async fn verify(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || password_auth::verify_password(password, &hash).is_ok())
        .await
        .unwrap_or(false)
}
