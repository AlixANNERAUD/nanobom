//! Local sign-in, sessions, rate limiting and cross-site request checks.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{local_user, server};

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
            common::body_text(response).await
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
    let mut statuses = Vec::new();
    for _ in 0..7 {
        statuses.push(server.send(sign_in("alice", "guess", None)).await.status());
    }
    assert!(
        statuses[..5]
            .iter()
            .all(|status| *status == StatusCode::SEE_OTHER)
    );
    assert_eq!(statuses[6], StatusCode::TOO_MANY_REQUESTS);
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
