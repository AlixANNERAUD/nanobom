//! The HTTP server: checks the configuration, starts the background services and serves every
//! route until `SIGINT` or `SIGTERM`.

use std::sync::Arc;

use axum::Router;
use leptos::config::LeptosOptions;
use leptos::prelude::provide_context;
use leptos_axum::{LeptosRoutes, generate_route_list};
use nanobom_app::{
    App,
    server::{InterfaceContext, InterfaceSettings},
    shell,
};
use nanobom_domain::{
    evaluation::Evaluator,
    exploitation::{FeedSettings, Feeds},
    notifications::Notifier,
};
use nanobom_osv::OsvClient;
use sea_orm::DatabaseConnection;

use crate::{
    api, authentication,
    command_line::ServeOptions,
    deliveries, dependency_track, http, metrics, operations,
    runner::{self, NotificationSettings, RunRequest, Runner},
    state::AppState,
    vex,
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

/// What the interface's pages and server functions need from the server.
fn interface_context(state: &AppState) -> InterfaceContext {
    let runner = state.runner.clone();
    InterfaceContext {
        database: state.database.clone(),
        settings: InterfaceSettings {
            local_accounts: state.options.local_accounts,
            openid_button: state
                .openid
                .as_ref()
                .map(|_| state.options.openid.oidc_button_label.clone()),
            password_minimum_length: state.options.accounts.password_minimum_length,
            personal_organizations: state.options.accounts.personal_organizations,
            stale_after_days: state.options.stale_after_days,
        },
        request_run: Arc::new(move |trigger, scope, triggered_by| {
            runner.request(RunRequest {
                trigger,
                scope,
                triggered_by,
            })
        }),
    }
}

/// Every route of the server.
pub fn router(state: AppState) -> Router {
    let routes = generate_route_list(App);
    let leptos_options = state.leptos_options.clone();
    let context = interface_context(&state);
    let fallback_context = context.clone();
    let interface = Router::new()
        .leptos_routes_with_context(
            &state,
            routes,
            move || provide_context(context.clone()),
            move || shell(leptos_options.clone()),
        )
        .fallback(leptos_axum::file_and_error_handler_with_context::<
            AppState,
            _,
        >(
            move || provide_context(fallback_context.clone()), shell
        ));
    // The VEX export reads the session, so it sits behind the session layer.
    let interface = authentication::layer(interface.merge(vex::router(&state)), &state);
    http::layers(
        Router::new()
            .merge(api::router(&state))
            .merge(dependency_track::router(&state))
            .merge(operations::router())
            .merge(interface)
            .with_state(state),
    )
}

/// Starts the server on a migrated database and returns once it has shut down.
///
/// Fails before listening when the configuration cannot work: an invalid schedule or group
/// mapping, half an OpenID Connect configuration, or no sign-in method at all. The identity
/// provider itself is only contacted at the first sign-in. On shutdown, requests in flight
/// finish; a run in progress is abandoned, and the next start records it as failed
/// ([`runner::close_interrupted_runs`]).
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
    let openid = authentication::openid(&options)?;
    if !options.local_accounts && openid.is_none() {
        return Err(
            "no sign-in method: enable local accounts (NANOBOM_LOCAL_ACCOUNTS) or \
             configure OpenID Connect (NANOBOM_OIDC_ISSUER and NANOBOM_OIDC_CLIENT_ID)"
                .into(),
        );
    }
    let address = options.listen_address;
    metrics::initialize(&database, options.stale_after_days).await;

    let source = Arc::new(OsvClient::new(options.osv_url.clone())?);
    let evaluator = Arc::new(Evaluator::new(database.clone(), source));
    let feeds = if options.exploitation_data {
        Some(Arc::new(Feeds::new(FeedSettings {
            kev_url: options.kev_url.clone(),
            epss_url: options.epss_url.clone(),
        })?))
    } else {
        tracing::info!("exploitation data is off");
        None
    };
    let notifier = Notifier::new()?;
    let settings = NotificationSettings {
        public_url: options.public_url.clone(),
        failure_webhook: options.failure_webhook_url.clone(),
        stale_after_days: options.stale_after_days,
        exploitation_refresh_timeout: runner::EXPLOITATION_REFRESH_TIMEOUT,
    };
    deliveries::cancel_outdated_failures(&database, settings.failure_webhook.as_ref()).await;
    runner::close_interrupted_runs(&database, &settings).await;
    deliveries::start(
        database.clone(),
        notifier.clone(),
        deliveries::RETRY_INTERVAL,
    );
    let runner = Runner::start(database.clone(), evaluator, notifier, settings, feeds);
    match schedule {
        Some(schedule) => runner::start_schedule(runner.clone(), schedule),
        None => tracing::info!("scheduled runs are off"),
    }

    let leptos_options = leptos_options(&options);
    let state = AppState::new(database, options, leptos_options, runner, openid);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
