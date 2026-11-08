//! State shared by every request handler.
//!
//! Cloned for every request, so every field is cheap to clone (handles and `Arc`s). Interface
//! pages do not see it: [`crate::serve`] gives them a narrower `InterfaceContext` from the app
//! crate.

use std::sync::Arc;

use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use nanobom_authentication::OpenId;
use sea_orm::DatabaseConnection;
use tokio::sync::Semaphore;

use crate::{command_line::ServeOptions, runner::Runner};

/// Handles to the database, the configuration and the background services.
#[derive(Clone)]
pub struct AppState {
    pub database: DatabaseConnection,
    /// The `serve` options, with the public URL normalized by [`crate::serve::run`].
    pub options: Arc<ServeOptions>,
    pub leptos_options: LeptosOptions,
    /// Bounds how many SBOMs are parsed at once, which bounds memory use.
    pub sbom_parsing: Arc<Semaphore>,
    /// Queues runs; see [`crate::runner`].
    pub runner: Runner,
    /// The OpenID Connect provider, when configured.
    pub openid: Option<Arc<OpenId>>,
}

/// SBOMs parsed concurrently; others wait their turn.
const CONCURRENT_SBOM_PARSING: usize = 2;

impl AppState {
    pub fn new(
        database: DatabaseConnection,
        options: ServeOptions,
        leptos_options: LeptosOptions,
        runner: Runner,
        openid: Option<OpenId>,
    ) -> Self {
        Self {
            database,
            options: Arc::new(options),
            leptos_options,
            sbom_parsing: Arc::new(Semaphore::new(CONCURRENT_SBOM_PARSING)),
            runner,
            openid: openid.map(Arc::new),
        }
    }
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}
