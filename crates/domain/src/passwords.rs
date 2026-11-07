//! Local account passwords, hashed with Argon2id.

use crate::error::{Error, Result};

/// Upper bound on password length, so hashing cannot be used to exhaust the server.
const MAXIMUM_LENGTH: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub minimum_length: usize,
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<()> {
        let length = password.chars().count();
        if length < self.minimum_length {
            return Err(Error::invalid(format!(
                "the password must be at least {} characters long",
                self.minimum_length
            )));
        }
        if length > MAXIMUM_LENGTH {
            return Err(Error::invalid(format!(
                "the password must be at most {MAXIMUM_LENGTH} characters long"
            )));
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

/// Checks a password against a stored hash, off the asynchronous runtime.
pub async fn verify(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || password_auth::verify_password(password, &hash).is_ok())
        .await
        .unwrap_or(false)
}
