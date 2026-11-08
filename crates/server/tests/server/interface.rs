//! The web interface over HTTP: pages, sign-in redirects, isolation and forms.

use crate::common::{TestServer, body_text, local_user, sbom_document, server};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use nanobom_domain::{
    findings::{self, Filter, Status},
    organizations, projects, tokens,
};
use serde_json::json;

const PASSWORD: &str = "correct horse battery staple";
const ORIGIN: &str = "http://localhost:8080";

/// A browser: keeps the session cookie and sends forms like a page of the interface would.
struct Browser<'a> {
    server: &'a TestServer,
    cookie: String,
}

impl<'a> Browser<'a> {
    async fn sign_in(server: &'a TestServer, username: &str) -> Self {
        let response = server
            .send(
                Request::post("/auth/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::ORIGIN, ORIGIN)
                    .body(Body::from(format!(
                        "login={username}&password={}",
                        PASSWORD.replace(' ', "+")
                    )))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("nanobom_session="))
            .expect("a session cookie")
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        Self { server, cookie }
    }

    async fn get(&self, path: &str) -> Response<Body> {
        self.server
            .send(
                Request::get(path)
                    .header(header::COOKIE, &self.cookie)
                    .header(header::ACCEPT, "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
    }

    async fn page(&self, path: &str) -> String {
        let response = self.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        body_text(response).await
    }

    /// Submits a form from `page` to a server function.
    async fn submit(&self, page: &str, function: &str, form: &str) -> Response<Body> {
        self.server
            .send(
                Request::post(format!("/api/{function}"))
                    .header(header::COOKIE, &self.cookie)
                    .header(header::ACCEPT, "text/html")
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::HOST, "localhost:8080")
                    .header(header::REFERER, format!("{ORIGIN}{page}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_owned()))
                    .unwrap(),
            )
            .await
    }
}

fn location(response: &Response<Body>) -> String {
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn the_sign_in_page_offers_local_accounts() {
    let server = server(&[]).await;
    let response = server
        .send(Request::get("/login").body(Body::empty()).unwrap())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("action=\"/auth/login\""));
    assert!(html.contains("autocomplete=\"current-password\""));
    assert!(
        !html.contains("single sign-on"),
        "OpenID Connect is not configured"
    );
}

#[tokio::test]
async fn pages_redirect_to_sign_in_without_a_session() {
    let server = server(&[]).await;
    let response = server
        .send(
            Request::get("/organizations")
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), "/login?next=/organizations");
}

#[tokio::test]
async fn organizations_are_listed_created_and_isolated() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    local_user(&server.database, "mallory", PASSWORD).await;
    let alice = Browser::sign_in(&server, "alice").await;

    let html = alice.page("/organizations").await;
    assert!(
        html.contains("href=\"/organizations/alice\""),
        "the personal organization"
    );

    let response = alice
        .submit(
            "/organizations",
            "create_organization",
            "name=Acme+Corp&slug=acme",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).starts_with("/organizations/acme?notice="));
    let html = alice.page("/organizations/acme").await;
    assert!(html.contains("Acme Corp"));
    assert!(html.contains("No project yet"));

    let mallory = Browser::sign_in(&server, "mallory").await;
    let response = mallory.get("/organizations/acme").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let html = body_text(response).await;
    assert!(!html.contains("Acme Corp"));
    let response = mallory
        .submit(
            "/organizations/acme/settings",
            "add_member",
            "organization=acme&login=mallory&role=owner",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).contains("error=Not%20found."));
}

#[tokio::test]
async fn findings_are_shown_and_ignored_from_the_interface() {
    let server = server(&[]).await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
        }),
        &["pkg:npm/lodash@4.17.20"],
    );
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let secret = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom")
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    server.runner.wait_until_idle().await;
    let alice = Browser::sign_in(&server, "alice").await;

    let html = alice.page("/organizations/acme").await;
    assert!(html.contains("/organizations/acme/projects/web"));
    let html = alice.page("/organizations/acme/projects/web").await;
    assert!(html.contains("GHSA-35jh-r3h4-6jhm"));
    assert!(html.contains("lodash"));
    let html = alice
        .page("/organizations/acme/projects/web?severity=critical")
        .await;
    assert!(html.contains("No finding matches"));

    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let finding = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap()[0]
        .id;
    let page = format!("/findings/{finding}");
    let html = alice.page(&page).await;
    assert!(html.contains("CVE-2021-23337"));
    assert!(html.contains("4.17.21"), "the fixed version");
    assert!(html.contains("Ignore finding"));

    let response = alice
        .submit(
            &page,
            "ignore_finding",
            &format!("finding={finding}&reason=Not+reachable&expires_on="),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        location(&response),
        format!("{page}?notice=Finding%20ignored.")
    );
    let listed = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap();
    assert_eq!(listed[0].status, Status::Ignored);
    let html = alice.page(&page).await;
    assert!(html.contains("Not reachable"));
    assert!(html.contains("Restore finding"));

    let html = alice.page("/search?query=lodash+4.17").await;
    assert!(html.contains("pkg:npm/lodash@4.17.20"));
}

#[tokio::test]
async fn new_tokens_are_shown_once() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    let response = alice
        .submit(
            page,
            "create_token",
            "organization=acme&name=GitHub+Actions&project=",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let html = alice.page(page).await;
    assert!(html.contains("Your new token"));
    let secret_start = html.find("value=\"nanobom_").expect("the token is shown") + 7;
    let secret = &html[secret_start..secret_start + 8 + 64];
    assert!(
        tokens::authenticate(&server.database, secret)
            .await
            .unwrap()
            .is_some()
    );
    let html = alice.page(page).await;
    assert!(!html.contains("Your new token"), "shown only once");
    assert!(html.contains("GitHub Actions"));
}

#[tokio::test]
async fn administration_is_for_instance_administrators() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let alice = Browser::sign_in(&server, "alice").await;
    let response = alice.get("/administration").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pages_follow_the_chosen_language() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let alice = Browser::sign_in(&server, "alice").await;

    let html = alice.page("/organizations").await;
    assert!(html.contains("<html lang=\"en\""));
    assert!(html.contains("The organizations you belong to."));

    let response = server
        .send(
            Request::get("/organizations")
                .header(header::COOKIE, &alice.cookie)
                .header(header::ACCEPT, "text/html")
                .header(header::ACCEPT_LANGUAGE, "fr-FR,fr;q=0.9,en;q=0.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("<html lang=\"fr\""));
    assert!(html.contains("Les organisations dont vous faites partie."));

    let response = alice
        .submit("/organizations", "set_language", "locale=fr")
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(location(&response), "/organizations");
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("nanobom_locale="))
        .expect("a language cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(cookie, "nanobom_locale=fr");

    let french = Browser {
        server: &server,
        cookie: format!("{}; {cookie}", alice.cookie),
    };
    let html = french.page("/organizations").await;
    assert!(html.contains("<html lang=\"fr\""));
    assert!(html.contains("Nouvelle organisation"));
}
