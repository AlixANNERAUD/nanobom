//! Helpers shared by the server's tests.

#![allow(dead_code)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::extract::ConnectInfo;

use clap::Parser;
use nanobom::{
    command_line::ServeOptions,
    runner::{self, NotificationSettings, Runner},
    serve,
    state::AppState,
};
use nanobom_domain::{
    access::Actor,
    evaluation::Evaluator,
    exploitation::{FeedSettings, Feeds},
    notifications::Notifier,
    testing::{self, FakeSource},
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;
use tower::ServiceExt;

#[derive(Parser)]
struct Options {
    #[command(flatten)]
    serve: ServeOptions,
}

/// Default serve options, adjusted by `adjust`.
pub fn options(arguments: &[&str]) -> ServeOptions {
    Options::parse_from(std::iter::once("nanobom").chain(arguments.iter().copied())).serve
}

pub struct TestServer {
    pub database: DatabaseConnection,
    pub router: Router,
    pub source: Arc<FakeSource>,
    pub runner: Runner,
}

/// A server on a fresh database, with an in-memory vulnerability source.
pub async fn server(arguments: &[&str]) -> TestServer {
    build(arguments, false, runner::EXPLOITATION_REFRESH_TIMEOUT).await
}

/// Like `server`, downloading exploitation data from the `--kev-url` and `--epss-url` given.
pub async fn server_with_exploitation(arguments: &[&str]) -> TestServer {
    build(arguments, true, runner::EXPLOITATION_REFRESH_TIMEOUT).await
}

/// Like `server_with_exploitation`, abandoning refreshes of exploitation data after `timeout`.
pub async fn server_with_exploitation_timeout(arguments: &[&str], timeout: Duration) -> TestServer {
    build(arguments, true, timeout).await
}

async fn build(
    arguments: &[&str],
    exploitation: bool,
    exploitation_refresh_timeout: Duration,
) -> TestServer {
    let database = testing::database().await;
    let options = options(arguments);
    let source = Arc::new(FakeSource::default());
    let feeds = exploitation.then(|| {
        Arc::new(
            Feeds::new(FeedSettings {
                kev_url: options.kev_url.clone(),
                epss_url: options.epss_url.clone(),
            })
            .expect("an HTTP client")
            .with_retry_delay(Duration::ZERO),
        )
    });
    let runner = Runner::start(
        database.clone(),
        Arc::new(Evaluator::new(database.clone(), Arc::clone(&source))),
        Notifier::new().expect("an HTTP client"),
        NotificationSettings {
            public_url: options.public_url.clone(),
            failure_webhook: options.failure_webhook_url.clone(),
            stale_after_days: options.stale_after_days,
            exploitation_refresh_timeout,
        },
        feeds,
    );
    let leptos_options = serve::leptos_options(&options);
    let openid = nanobom::authentication::openid(&options).expect("valid OpenID Connect options");
    let state = AppState::new(
        database.clone(),
        options,
        leptos_options,
        runner.clone(),
        openid,
    );
    TestServer {
        database,
        router: serve::router(state),
        source,
        runner,
    }
}

impl TestServer {
    /// Sends a request as if it came from one client address.
    pub async fn send(&self, mut request: Request<Body>) -> Response<Body> {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 40000))));
        self.router
            .clone()
            .oneshot(request)
            .await
            .expect("the router never fails")
    }
}

pub async fn body_text(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read the body");
    String::from_utf8(bytes.to_vec()).expect("UTF-8 body")
}

pub async fn body_json(response: Response<Body>) -> serde_json::Value {
    serde_json::from_str(&body_text(response).await).expect("JSON body")
}

pub async fn user(database: &DatabaseConnection, username: &str) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: username.to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .expect("create the user");
    Actor::from_user(&user)
}

pub fn sbom_document(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../domain/tests/fixtures/sboms/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

/// Creates a local account with a password.
pub async fn local_user(database: &DatabaseConnection, username: &str, password: &str) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: username.to_owned(),
            password_hash: Some(nanobom_domain::passwords::hash(password.to_owned()).await),
            ..NewUser::default()
        },
        true,
    )
    .await
    .expect("create the user");
    Actor::from_user(&user)
}
