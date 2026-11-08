//! The error type of every domain operation.

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

pub type Result<T, E = Error> = std::result::Result<T, E>;
