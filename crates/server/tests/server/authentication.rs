//! Local sign-in, sessions, rate limiting and cross-site request checks.

use crate::common::{local_user, server};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const PASSWORD: &str = "correct horse battery staple";

fn sign_in(login: &str, password: &str, origin: Option<&str>) -> Request<Body> {
    let body = format!(
        "login={}&password={}&next=%2Forganizations",
        login,
        password.replace(' ', "+")
    );
    let mut request = Request::post("/auth/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    request.body(Body::from(body)).unwrap()
}

fn location(response: &axum::http::Response<Body>) -> &str {
    response.headers()[header::LOCATION].to_str().unwrap()
}

fn session_cookie(response: &axum::http::Response<Body>) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("nanobom_session="))
        .map(str::to_owned)
}

#[tokio::test]
async fn local_accounts_sign_in_with_a_session_cookie() {
    let server = server(&["--public-url", "https://nanobom.example.org"]).await;
    local_user(&server.database, "alice", PASSWORD).await;

    let response = server
        .send(sign_in(
            "alice",
            PASSWORD,
            Some("https://nanobom.example.org"),
        ))
        .await;
    if response.status() != StatusCode::SEE_OTHER {
        panic!(
            "{:?} {}",
            response.status(),
            crate::common::body_text(response).await
        );
    }
    assert_eq!(location(&response), "/organizations");
    let cookie = session_cookie(&response).expect("a session cookie");
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Secure"));

    let cookie_pair = cookie.split(';').next().unwrap().to_owned();
    let response = server
        .send(
            Request::post("/auth/logout")
                .header(header::COOKIE, &cookie_pair)
                .header(header::ORIGIN, "https://nanobom.example.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login");
}

#[tokio::test]
async fn wrong_passwords_and_unknown_users_are_refused_alike() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    for (login, password) in [("alice", "wrong password"), ("nobody", PASSWORD)] {
        let response = server.send(sign_in(login, password, None)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(location(&response).starts_with("/login?error=invalid"));
        assert!(session_cookie(&response).is_none());
    }
}

#[tokio::test]
async fn sign_in_attempts_are_rate_limited() {
    let server = server(&[]).await;
    // Sent together: after a burst of 5, the limiter lets one attempt through every 4 seconds,
    // and one password check can take that long under coverage instrumentation, so attempts
    // sent one after the other may each find the limiter refilled.
    let attempt = || server.send(sign_in("alice", "guess", None));
    let responses = tokio::join!(
        attempt(),
        attempt(),
        attempt(),
        attempt(),
        attempt(),
        attempt(),
        attempt()
    );
    let statuses = [
        responses.0.status(),
        responses.1.status(),
        responses.2.status(),
        responses.3.status(),
        responses.4.status(),
        responses.5.status(),
        responses.6.status(),
    ];
    let count = |expected| {
        statuses
            .iter()
            .filter(|status| **status == expected)
            .count()
    };
    assert_eq!(count(StatusCode::SEE_OTHER), 5, "{statuses:?}");
    assert_eq!(count(StatusCode::TOO_MANY_REQUESTS), 2, "{statuses:?}");
}

#[tokio::test]
async fn cross_site_requests_are_refused() {
    let server = server(&["--public-url", "https://nanobom.example.org"]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let response = server
        .send(sign_in("alice", PASSWORD, Some("https://evil.example")))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn local_sign_in_can_be_disabled() {
    let server = server(&["--local-accounts", "false"]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let response = server.send(sign_in("alice", PASSWORD, None)).await;
    assert!(session_cookie(&response).is_none());
    assert_ne!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn openid_sign_in_without_a_provider_returns_to_the_sign_in_page() {
    let server = server(&[]).await;
    let response = server
        .send(
            Request::get("/auth/oidc/login?next=//evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login?error=unavailable&next=%2F");
}

/// Serves the discovery document of a provider whose issuer is `issuer` (announced verbatim)
/// and whose endpoints are under `root`.
async fn provider(root: &str, issuer: impl FnOnce(String) -> String) -> (MockServer, String) {
    let server = MockServer::start().await;
    let issuer = issuer(server.uri());
    let base = format!("{}{root}", server.uri());
    Mock::given(method("GET"))
        .and(path(format!("{root}/.well-known/openid-configuration")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{root}/jwks")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": []})))
        .mount(&server)
        .await;
    (server, issuer)
}

/// Starts a sign-in with `NANOBOM_OIDC_ISSUER` set to `configured`, and returns where the
/// browser is sent.
async fn start_openid(configured: &str) -> String {
    let server = server(&[
        "--oidc-issuer",
        configured,
        "--oidc-client-id",
        "nanobom",
        "--oidc-client-secret",
        "secret",
    ])
    .await;
    let response = server
        .send(
            Request::get("/auth/oidc/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    location(&response).to_owned()
}

#[tokio::test]
async fn openid_discovery_works_with_an_issuer_ending_with_a_slash() {
    let (provider, issuer) = provider("/application/o/nanobom", |origin| {
        format!("{origin}/application/o/nanobom/")
    })
    .await;
    assert!(issuer.ends_with('/'));
    let location = start_openid(&issuer).await;
    assert!(
        location.starts_with(&format!(
            "{}/application/o/nanobom/authorize?",
            provider.uri()
        )),
        "redirected to the provider, not back to the sign-in page: {location}"
    );
}

#[tokio::test]
async fn openid_discovery_works_with_an_issuer_without_a_slash() {
    let (provider, issuer) = provider("", |origin| origin).await;
    assert!(!issuer.ends_with('/'));
    let location = start_openid(&issuer).await;
    assert!(
        location.starts_with(&format!("{}/authorize?", provider.uri())),
        "redirected to the provider, not back to the sign-in page: {location}"
    );
}
