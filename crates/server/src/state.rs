//! State shared by every request handler.

use std::sync::Arc;

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use sea_orm::DatabaseConnection;
use tokio::sync::Semaphore;

use crate::command_line::ServeOptions;

#[derive(Clone)]
pub struct AppState {
    pub database: DatabaseConnection,
    pub options: Arc<ServeOptions>,
    pub leptos_options: LeptosOptions,
    /// Bounds how many SBOMs are parsed at once, which bounds memory use.
    pub sbom_parsing: Arc<Semaphore>,
}

/// SBOMs parsed concurrently; others wait their turn.
const CONCURRENT_SBOM_PARSING: usize = 2;

impl AppState {
    pub fn new(
        database: DatabaseConnection,
        options: ServeOptions,
        leptos_options: LeptosOptions,
    ) -> Self {
        Self {
            database,
            options: Arc::new(options),
            leptos_options,
            sbom_parsing: Arc::new(Semaphore::new(CONCURRENT_SBOM_PARSING)),
        }
    }
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
