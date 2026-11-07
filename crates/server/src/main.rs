//! The nanobom server and its command line.

use axum::Router;
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};
use nanobom_app::{App, shell};

#[tokio::main]
async fn main() {
    let configuration = get_configuration(None).expect("Leptos configuration");
    let options = configuration.leptos_options;
    let address = options.site_addr;
    let routes = generate_route_list(App);
    let application = Router::new()
        .leptos_routes(&options, routes, {
            let options = options.clone();
            move || shell(options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(options);
    let listener = tokio::net::TcpListener::bind(&address).await.expect("bind");
    axum::serve(listener, application.into_make_service())
        .await
        .expect("serve");
}
