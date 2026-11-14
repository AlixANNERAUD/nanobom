//! Public pages: served to anyone holding the key, as HTML and as a VEX document, with public
//! caching headers, without the members' notes, and the same whoever is signed in.

use crate::common::{TestServer, body_json, body_text, local_user, sbom_document, server};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use nanobom_domain::{
    access::Actor,
    findings::{self, Filter, Justification},
    organizations, projects, public_pages,
    tokens::{self, Scope},
};
use serde_json::json;

const PASSWORD: &str = "correct horse battery staple";
const ORIGIN: &str = "http://localhost:8080";
const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";
/// The reason the owner gives when ignoring minimist: a note for members only.
const REASON: &str = "Only used by the build, see ticket SEC-4242";
const PAGE_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; \
                           base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// `acme/web` version 1.0 evaluated from the npm fixture: lodash open, minimist ignored by
/// `alice` as not reachable. Its public page is on.
struct Setup {
    server: TestServer,
    owner: Actor,
    project: i64,
    token: String,
    key: String,
}

async fn setup() -> Setup {
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
        &[LODASH],
    );
    server.source.publish(
        json!({
            "id": "GHSA-xvch-5gv4-984h",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-44906"],
            "summary": "Prototype Pollution in minimist",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }),
        &[MINIMIST],
    );
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme Corp")
        .await
        .unwrap();
    let token = tokens::create_with_scope(
        &server.database,
        &owner,
        organization.id,
        None,
        "ci",
        Scope::Upload,
    )
    .await
    .unwrap()
    .secret;
    upload(&server, &token, "1.0").await;
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap()
        .id;
    let minimist = findings::list(&server.database, &owner, project, &Filter::default())
        .await
        .unwrap()
        .into_iter()
        .find(|finding| finding.purl == MINIMIST)
        .expect("the minimist finding")
        .id;
    findings::ignore(
        &server.database,
        &owner,
        minimist,
        REASON,
        Some(Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();
    let key = public_pages::enable(&server.database, &owner, project)
        .await
        .unwrap();
    Setup {
        server,
        owner,
        project,
        token,
        key,
    }
}

async fn upload(server: &TestServer, token: &str, version: &str) {
    let response = server
        .send(
            Request::put(format!(
                "/api/organizations/acme/projects/web/sbom?version={version}&wait=true"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(sbom_document("cyclonedx-npm.json")))
            .unwrap(),
        )
        .await;
    assert!(response.status().is_success(), "{}", response.status());
}

/// A `GET` with optional `Accept-Language` and `Cookie` headers.
async fn get(
    server: &TestServer,
    path: &str,
    language: Option<&str>,
    cookie: Option<&str>,
) -> Response<Body> {
    let mut request = Request::get(path);
    if let Some(language) = language {
        request = request.header(header::ACCEPT_LANGUAGE, language);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

fn header_value(response: &Response<Body>, name: &str) -> String {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("a {name} header"))
        .to_str()
        .unwrap()
        .to_owned()
}

/// `GET` expecting an empty `404` that caches do not keep.
async fn missing(server: &TestServer, path: &str) {
    let response = get(server, path, None, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "GET {path}");
    assert_eq!(
        header_value(&response, "cache-control"),
        "no-store",
        "GET {path}"
    );
    assert_eq!(body_text(response).await, "", "GET {path}");
}

async fn sign_in(server: &TestServer, username: &str) -> String {
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
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("nanobom_session="))
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn anyone_with_the_key_reads_the_page_with_public_headers() {
    let setup = setup().await;
    let server = &setup.server;
    let path = format!("/public/{}", setup.key);

    let response = get(server, &path, None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&response, "content-type"),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        header_value(&response, "cache-control"),
        "public, max-age=300"
    );
    assert_eq!(header_value(&response, "vary"), "Accept-Language");
    assert_eq!(header_value(&response, "referrer-policy"), "no-referrer");
    assert_eq!(header_value(&response, "x-robots-tag"), "noindex");
    assert_eq!(
        header_value(&response, "content-security-policy"),
        PAGE_POLICY
    );
    assert_eq!(header_value(&response, "x-content-type-options"), "nosniff");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let html = body_text(response).await;
    for expected in [
        "<html lang=\"en\"",
        ">web<",
        "version 1.0",
        "GHSA-35jh-r3h4-6jhm",
        "CVE-2021-23337",
        "Command Injection in lodash",
        LODASH,
        "4.17.21",
        "GHSA-xvch-5gv4-984h",
        "Vulnerable code not reachable",
        &format!("http://localhost:8080/public/{}/vex.json", setup.key),
    ] {
        assert!(html.contains(expected), "{expected} missing from {html}");
    }
    for absent in [
        REASON,
        "alice",
        "acme",
        "Acme Corp",
        "/organizations",
        "<script",
        // No footer and no release: the page is anonymous.
        "<footer",
        concat!("nanobom ", env!("CARGO_PKG_VERSION")),
    ] {
        assert!(!html.contains(absent), "{absent} in {html}");
    }

    let response = get(server, &path, Some("fr-FR,fr;q=0.9"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("<html lang=\"fr\""), "{html}");
    assert!(html.contains("Évaluées par les mainteneurs"), "{html}");
}

#[tokio::test]
async fn a_session_changes_nothing() {
    let setup = setup().await;
    let server = &setup.server;
    let cookie = sign_in(server, "alice").await;
    let path = format!("/public/{}", setup.key);

    let anonymous = get(server, &path, None, None).await;
    let signed_in = get(server, &path, None, Some(&cookie)).await;
    assert_eq!(signed_in.status(), StatusCode::OK);
    assert!(signed_in.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        header_value(&signed_in, "cache-control"),
        "public, max-age=300"
    );
    assert_eq!(body_text(anonymous).await, body_text(signed_in).await);

    // A signed-in member does not reach a page that is off either.
    public_pages::disable(&server.database, &setup.owner, setup.project)
        .await
        .unwrap();
    let response = get(server, &path, None, Some(&cookie)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_vex_document_has_no_reason_and_no_organization() {
    let setup = setup().await;
    let server = &setup.server;

    let response = get(
        server,
        &format!("/public/{}/vex.json", setup.key),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&response, "content-type"),
        "application/vnd.cyclonedx+json"
    );
    assert_eq!(
        header_value(&response, "cache-control"),
        "public, max-age=300"
    );
    assert_eq!(header_value(&response, "referrer-policy"), "no-referrer");
    assert_eq!(header_value(&response, "x-robots-tag"), "noindex");
    let document = body_json(response).await;
    let text = document.to_string();
    for absent in ["\"detail\"", REASON, "alice", "acme"] {
        assert!(!text.contains(absent), "{absent} in {text}");
    }
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["metadata"]["component"]["name"], "web");
    assert_eq!(document["metadata"]["component"]["version"], "1.0");
    assert!(document["metadata"]["component"].get("bom-ref").is_none());
    let minimist = document["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vulnerability| vulnerability["id"] == "GHSA-xvch-5gv4-984h")
        .expect("the minimist statement");
    assert_eq!(minimist["analysis"]["state"], "not_affected");
    assert_eq!(minimist["analysis"]["justification"], "code_not_reachable");
}

#[tokio::test]
async fn a_version_is_chosen_by_name() {
    let setup = setup().await;
    let server = &setup.server;
    // A new version becomes the latest; 1.0 stays readable by name.
    upload(server, &setup.token, "2.0").await;
    let key = &setup.key;

    let html = body_text(get(server, &format!("/public/{key}"), None, None).await).await;
    assert!(html.contains("version 2.0"), "{html}");
    let response = get(server, &format!("/public/{key}?version=1.0"), None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(html.contains("version 1.0"), "{html}");
    assert!(
        html.contains(&format!("/public/{key}/vex.json?version=1.0")),
        "{html}"
    );
    let document = body_json(
        get(
            server,
            &format!("/public/{key}/vex.json?version=1.0"),
            None,
            None,
        )
        .await,
    )
    .await;
    assert_eq!(document["metadata"]["component"]["version"], "1.0");

    missing(server, &format!("/public/{key}?version=9.9")).await;
    missing(server, &format!("/public/{key}/vex.json?version=9.9")).await;
    missing(server, &format!("/public/{key}?version=1.0&version=2.0")).await;
}

#[tokio::test]
async fn anything_that_does_not_resolve_is_an_empty_not_found() {
    let setup = setup().await;
    let server = &setup.server;
    let key = &setup.key;

    missing(server, "/public/0123456789abcdef0123456789abcdef").await;
    missing(server, "/public/0123456789abcdef0123456789abcdef/vex.json").await;
    missing(server, "/public/nanobom").await;
    missing(server, &format!("/public/{}", key.to_uppercase())).await;

    let replaced = public_pages::regenerate(&server.database, &setup.owner, setup.project)
        .await
        .unwrap();
    missing(server, &format!("/public/{key}")).await;
    missing(server, &format!("/public/{key}/vex.json")).await;
    let response = get(server, &format!("/public/{replaced}"), None, None).await;
    assert_eq!(response.status(), StatusCode::OK);

    public_pages::disable(&server.database, &setup.owner, setup.project)
        .await
        .unwrap();
    missing(server, &format!("/public/{replaced}")).await;
    missing(server, &format!("/public/{replaced}/vex.json")).await;
}
