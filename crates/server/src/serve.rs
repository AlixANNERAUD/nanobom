//! The HTTP server.

use std::sync::Arc;

use axum::Router;
use leptos::config::LeptosOptions;
use leptos_axum::{LeptosRoutes, generate_route_list};
use nanobom_app::{App, shell};
use nanobom_domain::{evaluation::Evaluator, notifications::Notifier};
use nanobom_osv::OsvClient;
use sea_orm::DatabaseConnection;

use crate::{
    api,
    command_line::ServeOptions,
    metrics, operations,
    runner::{self, NotificationSettings, Runner},
    state::AppState,
};

/// The options of the web interface: where its assets are and how they are named.
pub fn leptos_options(options: &ServeOptions) -> LeptosOptions {
    LeptosOptions::builder()
        .output_name("nanobom")
        .site_root(options.site_root.to_string_lossy().into_owned())
        .site_pkg_dir("pkg")
        .site_addr(options.listen_address)
        .build()
}

/// Every route of the server.
pub fn router(state: AppState) -> Router {
    let routes = generate_route_list(App);
    let leptos_options = state.leptos_options.clone();
    Router::new()
        .merge(api::router(&state))
        .merge(operations::router())
        .leptos_routes(&state, routes, move || shell(leptos_options.clone()))
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell))
        .with_state(state)
}

pub async fn run(
    database: DatabaseConnection,
    mut options: ServeOptions,
) -> Result<(), crate::Failure> {
    // Links are built relative to the public URL, which must end with a slash.
    if !options.public_url.path().ends_with('/') {
        let path = format!("{}/", options.public_url.path());
        options.public_url.set_path(&path);
    }
    let schedule = runner::parse_schedule(&options.schedule)?;
    let address = options.listen_address;
    metrics::initialize(&database).await;

    let source = Arc::new(OsvClient::new(options.osv_url.clone())?);
    let evaluator = Arc::new(Evaluator::new(database.clone(), source));
    let runner = Runner::start(
        database.clone(),
        evaluator,
        Notifier::new()?,
        NotificationSettings {
            public_url: options.public_url.clone(),
            failure_webhook: options.failure_webhook_url.clone(),
        },
    );
    match schedule {
        Some(schedule) => runner::start_schedule(runner.clone(), schedule),
        None => tracing::info!("scheduled runs are off"),
    }

    let leptos_options = leptos_options(&options);
    let state = AppState::new(database, options, leptos_options, runner);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");
    axum::serve(listener, router(state).into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
    tracing::info!("shutting down");
}
