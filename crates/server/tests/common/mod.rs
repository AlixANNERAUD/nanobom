//! Helpers shared by the server's tests.

#![allow(dead_code)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response},
};
use clap::Parser;
use nanobom::{command_line::ServeOptions, serve, state::AppState};
use nanobom_domain::{
    access::Actor,
    testing,
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
}

pub async fn server(arguments: &[&str]) -> TestServer {
    let database = testing::database().await;
    let options = options(arguments);
    let leptos_options = serve::leptos_options(&options);
    let state = AppState::new(database.clone(), options, leptos_options);
    TestServer {
        database,
        router: serve::router(state),
    }
}

impl TestServer {
    pub async fn send(&self, request: Request<Body>) -> Response<Body> {
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
