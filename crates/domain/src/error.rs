//! The error type of every domain operation.
//!
//! The variants are what callers branch on: the upload API and the interface map each one to an
//! HTTP status (404, 403, 422 or 409, 500) without inspecting messages. Only the [`Problem`] of
//! [`Error::Invalid`] and [`Error::Conflict`] is shown to users; database errors are logged and
//! replaced by a generic message.

use sea_orm::DbErr;

use crate::problem::Problem;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The resource does not exist, or the actor may not see it. The two cases are
    /// indistinguishable on purpose, so nothing leaks across organizations.
    #[error("not found")]
    NotFound,
    /// The actor can see the resource but may not perform this action on it.
    #[error("permission denied")]
    Forbidden,
    /// The input is invalid; the problem is safe to show to the user.
    #[error("{0}")]
    Invalid(Problem),
    /// The action conflicts with existing data; the problem is safe to show to the user.
    #[error("{0}")]
    Conflict(Problem),
    /// The database failed. The message may reveal schema details, so it is logged and never
    /// shown to the user.
    #[error("database error: {0}")]
    Database(#[from] DbErr),
}

impl Error {
    pub fn invalid(problem: Problem) -> Self {
        Self::Invalid(problem)
    }

    pub fn conflict(problem: Problem) -> Self {
        Self::Conflict(problem)
    }
}

/// The result of a domain operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;
