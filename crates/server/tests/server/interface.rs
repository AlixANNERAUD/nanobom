//! The web interface over HTTP: pages, sign-in redirects, isolation and forms.

use crate::common::{TestServer, body_text, local_user, sbom_document, server};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use nanobom_domain::{
    deliveries::{self, Attempt},
    email::{self, Language},
    findings::{self, Filter, Status},
    notifications, organizations, passwords, projects,
    testing::SmtpSink,
    tokens,
    users::{self, NewUser},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait};
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
    let heading = element(&html, "<h1", "</h1>");
    assert_mark_before_wordmark(heading);
}

/// The first element of `html` opened by `open`, up to `close`.
fn element<'a>(html: &'a str, open: &str, close: &str) -> &'a str {
    let start = html.find(open).unwrap_or_else(|| panic!("no {open}"));
    let end = html[start..]
        .find(close)
        .unwrap_or_else(|| panic!("{open} is not closed"));
    &html[start..start + end]
}

/// The mark is decorative (hidden from assistive technology) and sits before the name.
fn assert_mark_before_wordmark(html: &str) {
    let mark = html.find("<svg").expect("the mark");
    let name = html.find("nanobom").expect("the wordmark");
    assert!(mark < name, "the mark comes first: {html}");
    let svg = element(html, "<svg", ">");
    assert!(
        svg.contains("aria-hidden=\"true\""),
        "the mark is decorative: {html}"
    );
    // Without its view box, the drawing is clipped to the element's size instead of scaled.
    assert!(svg.contains("viewBox=\"0 0 18 18\""), "{html}");
}

#[tokio::test]
async fn the_header_shows_the_mark_before_the_wordmark() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let alice = Browser::sign_in(&server, "alice").await;
    let html = alice.page("/organizations").await;
    let header = element(&html, "<header", "</header>");
    assert_mark_before_wordmark(element(header, "<a href=\"/organizations\"", "</a>"));
}

/// The `<details>` of `html` whose `<summary>` has `label` as its accessible name.
fn menu<'a>(html: &'a str, label: &str) -> &'a str {
    let name = format!("aria-label=\"{label}\"");
    html.split("<details")
        .skip(1)
        .map(|rest| rest.split("</details>").next().unwrap_or(rest))
        .find(|details| {
            details
                .split("</summary>")
                .next()
                .is_some_and(|summary| summary.contains(&name))
        })
        .unwrap_or_else(|| panic!("no menu labelled {label}"))
}

/// The opening tags of the language buttons of a menu.
fn language_buttons(menu: &str) -> Vec<&str> {
    menu.split("<button")
        .skip(1)
        .map(|button| button.split('>').next().unwrap_or(button))
        .filter(|button| button.contains("name=\"locale\""))
        .collect()
}

#[tokio::test]
async fn the_user_menu_holds_language_theme_and_sign_out() {
    let server = server(&[]).await;
    users::create(
        &server.database,
        NewUser {
            username: "alice".to_owned(),
            display_name: Some("Émilie Dupont".to_owned()),
            password_hash: Some(passwords::hash(PASSWORD.to_owned()).await),
            is_instance_administrator: true,
            ..NewUser::default()
        },
        true,
    )
    .await
    .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let html = alice.page("/organizations").await;
    assert!(
        !html.contains("<select id=\"language\""),
        "no language list"
    );
    let header = element(&html, "<header", "</header>");
    let account = menu(header, "Account");

    // The button shows the initial; the name is spelled out inside.
    let summary = element(account, "<summary", "</summary>");
    assert!(summary.contains("title=\"Account\""), "{summary}");
    assert!(summary.contains(">É<"), "{summary}");
    assert!(account.contains("Émilie Dupont"), "{account}");
    assert!(account.contains("alice"), "the username, since it differs");
    assert!(account.contains("href=\"/administration\""));

    // One submit button per language, in one form, so the choice works without JavaScript.
    assert_eq!(account.matches("action=\"/api/set_language\"").count(), 1);
    let buttons = language_buttons(account);
    assert_eq!(buttons.len(), 2, "{account}");
    for button in &buttons {
        assert!(button.contains("type=\"submit\""), "{button}");
    }
    let english = buttons
        .iter()
        .find(|button| button.contains("value=\"en\""))
        .expect("an English button");
    assert!(english.contains("lang=\"en\""), "{english}");
    assert!(english.contains("aria-current=\"true\""), "{english}");
    let french = buttons
        .iter()
        .find(|button| button.contains("value=\"fr\""))
        .expect("a French button");
    assert!(french.contains("lang=\"fr\""), "{french}");
    assert!(!french.contains("aria-current"), "{french}");
    assert!(account.contains(">English<") && account.contains(">Français<"));

    // The theme switch is named by its visible label, which voice control relies on; the full
    // sentence is its tooltip.
    let theme = account
        .split("<button")
        .find(|button| button.contains("Switch theme"))
        .expect("the theme switch");
    let theme = theme.split("</button>").next().unwrap();
    assert!(!theme.contains("aria-label"), "{theme}");
    assert!(
        theme.contains("title=\"Switch between the light and dark themes\""),
        "{theme}"
    );

    let sign_out = element(
        account,
        "<form method=\"post\" action=\"/auth/logout\"",
        "</form>",
    );
    assert!(sign_out.contains("Sign out"), "{sign_out}");
    assert_eq!(
        html.matches("action=\"/auth/logout\"").count(),
        1,
        "signing out is offered in the menu only"
    );

    // The same menu in French.
    let french = Browser {
        server: &server,
        cookie: format!("{}; nanobom_locale=fr", alice.cookie),
    };
    let html = french.page("/organizations").await;
    let account = menu(element(&html, "<header", "</header>"), "Compte");
    let buttons = language_buttons(account);
    assert_eq!(buttons.len(), 2, "{account}");
    for button in buttons {
        assert_eq!(
            button.contains("aria-current=\"true\""),
            button.contains("value=\"fr\""),
            "{button}"
        );
    }
    assert!(account.contains("Se déconnecter"));
    assert!(account.contains("Changer de thème"));
}

/// A user without a display name of their own is named once, and a user who is not an instance
/// administrator gets no link to the administration.
#[tokio::test]
async fn the_user_menu_names_the_user_once_without_a_display_name() {
    let server = server(&[]).await;
    local_user(&server.database, "bob", PASSWORD).await;
    let bob = Browser::sign_in(&server, "bob").await;
    let html = bob.page("/organizations").await;
    let account = menu(element(&html, "<header", "</header>"), "Account");
    let summary = element(account, "<summary", "</summary>");
    assert!(summary.contains(">B<"), "{summary}");
    // Shown once; the tooltip of the line, for names cut short, repeats it.
    assert_eq!(account.matches(">bob<").count(), 1, "{account}");
    assert!(!account.contains("/administration"));
}

/// The stylesheet loads its fonts from the site root, where the build copies `public/`: the
/// sign-in page needs them before any session exists.
#[tokio::test]
async fn fonts_are_served() {
    let public = concat!(env!("CARGO_MANIFEST_DIR"), "/../../public");
    let server = server(&["--site-root", public]).await;
    for font in [
        "inter-latin-wght-normal.woff2",
        "ibm-plex-mono-latin-400-normal.woff2",
        "ibm-plex-mono-latin-500-normal.woff2",
    ] {
        let response = server
            .send(
                Request::get(format!("/fonts/{font}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{font}");
        assert_eq!(response.headers()[header::CONTENT_TYPE], "font/woff2");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.starts_with(b"wOF2"), "{font} is a WOFF2 file");
    }
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
async fn findings_show_the_direct_dependency_that_introduces_them() {
    let server = server(&[]).await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "summary": "Command Injection in lodash",
            "database_specific": {"severity": "HIGH"}
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
    let mut document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "shop"}},
        "components": [
            {"type": "library", "name": "web-framework", "version": "2.1.0", "bom-ref": "framework",
                "purl": "pkg:npm/web-framework@2.1.0"},
            {"type": "library", "name": "template-engine", "version": "0.9.0", "bom-ref": "engine",
                "purl": "pkg:npm/template-engine@0.9.0"},
            {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash",
                "purl": "pkg:npm/lodash@4.17.20"}
        ],
        "dependencies": [
            {"ref": "shop", "dependsOn": ["framework"]},
            {"ref": "framework", "dependsOn": ["engine"]},
            {"ref": "engine", "dependsOn": ["lodash"]}
        ]
    });
    let upload = |document: &serde_json::Value| {
        Request::put("/api/organizations/acme/projects/shop/sbom")
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .body(Body::from(document.to_string()))
            .unwrap()
    };
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let alice = Browser::sign_in(&server, "alice").await;

    let html = alice.page("/organizations/acme/projects/shop").await;
    assert!(html.contains("Introduced via"));
    assert!(html.contains("web-framework"));
    let project = projects::find(&server.database, &owner, organization.id, "shop")
        .await
        .unwrap();
    let finding = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap()[0]
        .id;
    let page = format!("/findings/{finding}");
    let html = alice.page(&page).await;
    assert!(
        html.contains("web-framework 2.1.0 → template-engine 0.9.0 → lodash 4.17.20"),
        "{html}"
    );

    document.as_object_mut().unwrap().remove("dependencies");
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let html = alice.page(&page).await;
    assert!(html.contains("does not say which components the project depends on directly"));

    // A link through a component without a package URL is lost, and the page says so.
    document["components"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type": "library", "name": "vendored", "bom-ref": "vendored"}));
    document["dependencies"] = json!([
        {"ref": "shop", "dependsOn": ["framework"]},
        {"ref": "framework", "dependsOn": ["engine", "vendored"]},
        {"ref": "engine", "dependsOn": ["lodash"]},
        {"ref": "vendored", "dependsOn": ["lodash"]}
    ]);
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let html = alice.page(&page).await;
    assert!(html.contains("web-framework 2.1.0 → template-engine 0.9.0 → lodash 4.17.20"));
    assert!(html.contains("Some links of the dependency graph could not be followed"));

    // Once the component is gone the finding is fixed: there is no path to show.
    document["components"]
        .as_array_mut()
        .unwrap()
        .retain(|component| component["name"] != "lodash");
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let html = alice.page(&page).await;
    assert!(html.contains("Fixed"), "{html}");
    assert!(!html.contains("Introduced via"));
}

#[tokio::test]
async fn spdx_findings_say_when_links_of_the_graph_were_lost() {
    let server = server(&[]).await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "summary": "Command Injection in lodash",
            "database_specific": {"severity": "HIGH"}
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
    let package = |id: &str, name: &str, version: &str, purl: Option<&str>| {
        let mut package = json!({"SPDXID": id, "name": name, "versionInfo": version});
        if let Some(purl) = purl {
            package["externalRefs"] = json!([{"referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl", "referenceLocator": purl}]);
        }
        package
    };
    let depends = |from: &str, to: &str| json!({"spdxElementId": from, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": to});
    let mut document = json!({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "shop",
        "documentDescribes": ["SPDXRef-shop"],
        "packages": [
            package("SPDXRef-shop", "shop", "1.0.0", Some("pkg:npm/shop@1.0.0")),
            package("SPDXRef-framework", "web-framework", "2.1.0", Some("pkg:npm/web-framework@2.1.0")),
            package("SPDXRef-engine", "template-engine", "0.9.0", Some("pkg:npm/template-engine@0.9.0")),
            package("SPDXRef-lodash", "lodash", "4.17.20", Some("pkg:npm/lodash@4.17.20")),
        ],
        "relationships": [
            depends("SPDXRef-shop", "SPDXRef-framework"),
            depends("SPDXRef-framework", "SPDXRef-engine"),
            depends("SPDXRef-engine", "SPDXRef-lodash"),
        ]
    });
    let upload = |document: &serde_json::Value| {
        Request::put("/api/organizations/acme/projects/shop/sbom")
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .body(Body::from(document.to_string()))
            .unwrap()
    };
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let alice = Browser::sign_in(&server, "alice").await;
    let project = projects::find(&server.database, &owner, organization.id, "shop")
        .await
        .unwrap();
    let finding = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap()[0]
        .id;
    let page = format!("/findings/{finding}");
    let html = alice.page(&page).await;
    assert!(
        html.contains("web-framework 2.1.0 → template-engine 0.9.0 → lodash 4.17.20"),
        "{html}"
    );
    assert!(!html.contains("Some links of the dependency graph could not be followed"));

    // A package without a package URL that the graph reaches and leaves loses links.
    document["packages"].as_array_mut().unwrap().push(package(
        "SPDXRef-vendored",
        "vendored",
        "1.0",
        None,
    ));
    let relationships = document["relationships"].as_array_mut().unwrap();
    relationships.push(depends("SPDXRef-framework", "SPDXRef-vendored"));
    relationships.push(depends("SPDXRef-vendored", "SPDXRef-lodash"));
    server.send(upload(&document)).await;
    server.runner.wait_until_idle().await;
    let html = alice.page(&page).await;
    assert!(html.contains("web-framework 2.1.0 → template-engine 0.9.0 → lodash 4.17.20"));
    assert!(html.contains("Some links of the dependency graph could not be followed"));
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
    // The VEX export is a link that works with the session.
    assert!(html.contains("href=\"/api/organizations/acme/projects/web/vex\""));
    let response = alice.get("/api/organizations/acme/projects/web/vex").await;
    assert_eq!(response.status(), StatusCode::OK);
    let document = crate::common::body_json(response).await;
    assert_eq!(
        document["vulnerabilities"][0]["analysis"]["state"],
        "in_triage"
    );
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
    assert!(
        html.contains("License") && html.contains("MIT"),
        "the license"
    );
    assert!(html.contains("Ignore finding"));
    assert!(
        html.contains("name=\"justification\""),
        "the justification select"
    );

    let response = alice
        .submit(
            &page,
            "ignore_finding",
            &format!(
                "finding={finding}&reason=Not+reachable&justification=code_not_reachable&expires_on="
            ),
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
    assert_eq!(
        listed[0].ignore_justification,
        Some(nanobom_domain::findings::Justification::CodeNotReachable)
    );
    let html = alice.page(&page).await;
    assert!(html.contains("Not reachable"));
    assert!(html.contains("Vulnerable code not reachable"));
    assert!(html.contains("Restore finding"));

    let html = alice.page("/search?query=lodash+4.17").await;
    assert!(html.contains("pkg:npm/lodash@4.17.20"));
    assert!(html.contains("MIT"), "the license column");
    let html = alice.page("/search?query=&license=mit").await;
    assert!(html.contains("pkg:npm/lodash@4.17.20"));
    assert!(html.contains("pkg:npm/minimist@1.2.5"));
    let html = alice.page("/search?query=lodash&license=GPL").await;
    assert!(html.contains("No component found"));
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
async fn read_tokens_are_created_from_the_settings() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    let html = alice.page(page).await;
    assert!(html.contains("name=\"scope\""), "the form offers a scope");
    let response = alice
        .submit(
            page,
            "create_token",
            "organization=acme&name=Dashboard&project=&scope=read",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let html = alice.page(page).await;
    let secret_start = html.find("value=\"nanobom_").expect("the token is shown") + 7;
    let secret = &html[secret_start..secret_start + 8 + 64];
    let token = tokens::authenticate(&server.database, secret)
        .await
        .unwrap()
        .expect("an active token");
    assert_eq!(tokens::Scope::of(&token), tokens::Scope::Read);
    assert!(html.contains("Read only"));

    // An unknown scope creates nothing.
    alice
        .submit(
            page,
            "create_token",
            "organization=acme&name=Other&project=&scope=admin",
        )
        .await;
    let listed = tokens::list(&server.database, &owner, token.organization_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
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

/// The table row (`<tr>` to `</tr>`) of a page that mentions `text`.
fn table_row<'a>(html: &'a str, text: &str) -> &'a str {
    html.split("<tr")
        .map(|row| row.split("</tr>").next().unwrap_or(row))
        .find(|row| row.contains(text))
        .unwrap_or_else(|| panic!("no row mentions {text}"))
}

#[tokio::test]
async fn exploitation_signals_are_shown_and_filtered() {
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
    // A sibling finding with a CVE scored by EPSS but not in the KEV catalog.
    server.source.publish(
        json!({
            "id": "GHSA-xvch-5gv4-984h",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-44906"],
            "summary": "Prototype Pollution in minimist",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]}]
        }),
        &["pkg:npm/minimist@1.2.5"],
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
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let finding = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap()
        .into_iter()
        .find(|finding| finding.vulnerability_id == "GHSA-35jh-r3h4-6jhm")
        .expect("the lodash finding")
        .id;
    let project_page = "/organizations/acme/projects/web";
    let finding_page = format!("/findings/{finding}");

    let html = alice.page(project_page).await;
    assert!(!html.contains("Known exploited"));
    let html = alice.page(&finding_page).await;
    assert!(html.contains("No exploitation is known"));

    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_date_added: Set(Some("2022-03-01".to_owned())),
        kev_due_date: Set(Some("2022-03-22".to_owned())),
        kev_ransomware: Set(true),
        epss_score: Set(Some(0.5)),
        epss_percentile: Set(Some(0.97)),
        epss_date: Set(Some("2026-11-02".to_owned())),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();
    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-44906".to_owned()),
        known_exploited: Set(false),
        kev_ransomware: Set(false),
        epss_score: Set(Some(0.02)),
        epss_percentile: Set(Some(0.61)),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();

    let html = alice.page(project_page).await;
    let exploited = table_row(&html, "GHSA-35jh-r3h4-6jhm");
    assert!(exploited.contains("Known exploited"));
    assert!(exploited.contains("CISA due date: 2022-03-22"));
    assert!(exploited.contains("97%"));
    let sibling = table_row(&html, "GHSA-xvch-5gv4-984h");
    assert!(!sibling.contains("Known exploited"), "{sibling}");
    assert!(sibling.contains("61%"));
    let html = alice.page(&format!("{project_page}?exploited=1")).await;
    assert!(html.contains("GHSA-35jh-r3h4-6jhm"));
    assert!(
        !html.contains("GHSA-xvch-5gv4-984h"),
        "the filter hides the sibling"
    );
    let html = alice.page("/organizations/acme").await;
    assert!(html.contains("Known exploited"), "the organization column");

    let html = alice.page(&finding_page).await;
    assert!(html.contains("Exploitation"));
    assert!(html.contains("2022-03-01"));
    assert!(html.contains("2022-03-22"));
    assert!(html.contains("0.500"));
    assert!(html.contains("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"));
    assert!(html.contains("https://www.first.org/epss/"));
    assert!(html.contains("Ransomware campaigns"));
    assert!(!html.contains("Unknown"));

    // A KEV entry without a due date: the badge has no tooltip rather than an empty one.
    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        kev_due_date: Set(None),
        kev_ransomware: Set(false),
        ..Default::default()
    }
    .update(&server.database)
    .await
    .unwrap();
    let html = alice.page(project_page).await;
    assert!(html.contains("Known exploited"));
    assert!(!html.contains("CISA due date"));
    assert!(
        !html.contains("title=\"\""),
        "an empty title attribute in:\n{html}"
    );
    let html = alice.page(&finding_page).await;
    assert!(html.contains("Unknown"));

    // Without the exploitation row, the filter hides the finding.
    nanobom_entity::exploitation::Entity::delete_by_id("CVE-2021-23337")
        .exec(&server.database)
        .await
        .unwrap();
    let html = alice.page(&format!("{project_page}?exploited=1")).await;
    assert!(html.contains("No finding matches"));
}

#[tokio::test]
async fn the_webhook_form_saves_the_exploited_only_option() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    let html = alice.page(page).await;
    assert!(html.contains("Only known exploited vulnerabilities"));

    let response = alice
        .submit(
            page,
            "save_webhook",
            "organization=acme&url=https%3A%2F%2Fexample.org%2Fhook&minimum_severity=high&enabled=on&exploited_only=on",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let webhook = notifications::get(&server.database, &owner, organization.id)
        .await
        .unwrap()
        .expect("a webhook");
    assert!(webhook.exploited_only);

    alice
        .submit(
            page,
            "save_webhook",
            "organization=acme&url=https%3A%2F%2Fexample.org%2Fhook&minimum_severity=high&enabled=on",
        )
        .await;
    let webhook = notifications::get(&server.database, &owner, organization.id)
        .await
        .unwrap()
        .expect("a webhook");
    assert!(!webhook.exploited_only);
}

#[tokio::test]
async fn the_webhook_form_saves_the_format() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    let html = alice.page(page).await;
    assert!(html.contains("name=\"format\""));
    assert!(html.contains("Slack message"));
    assert!(html.contains("Microsoft Teams message (Workflows)"));

    let save = |format: &'static str| {
        let alice = &alice;
        async move {
            let form = format!(
                "organization=acme&url=https%3A%2F%2Fexample.org%2Fhook&minimum_severity=high&enabled=on{format}"
            );
            let response = alice.submit(page, "save_webhook", &form).await;
            assert_eq!(response.status(), StatusCode::FOUND);
            location(&response)
        }
    };
    let format = || async {
        notifications::get(&server.database, &owner, organization.id)
            .await
            .unwrap()
            .expect("a webhook")
            .format
    };

    // A form without the field keeps the JSON documents.
    save("").await;
    assert_eq!(format().await, notifications::Format::Json);
    save("&format=teams").await;
    assert_eq!(format().await, notifications::Format::Teams);
    let html = alice.page(page).await;
    assert!(html.contains("<option value=\"teams\" selected"), "{html}");
    save("&format=slack").await;
    assert_eq!(format().await, notifications::Format::Slack);

    // An unknown format is refused and the webhook is left as it was.
    let location = save("&format=email").await;
    assert!(
        location.contains("error=Unknown%20webhook%20format"),
        "{location}"
    );
    assert_eq!(format().await, notifications::Format::Slack);
}

#[tokio::test]
async fn the_webhook_settings_list_recent_deliveries() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    assert!(!alice.page(page).await.contains("Recent deliveries"));

    let now = chrono::Utc::now().fixed_offset();
    let delivery = deliveries::enqueue(
        &server.database,
        Some(organization.id),
        "https://example.org/hook",
        "findings.new",
        &json!({"event": "findings.new"}),
        now,
    )
    .await
    .unwrap();
    let claimed = deliveries::claim(&server.database, delivery.id, now)
        .await
        .unwrap()
        .unwrap();
    let attempt = Attempt::Answered {
        status: 502,
        description: "502 Bad Gateway".to_owned(),
    };
    deliveries::record(&server.database, claimed, &attempt, now)
        .await
        .unwrap()
        .expect("the claim still holds");
    // A first attempt in progress: its lease is not a scheduled retry.
    let in_flight = deliveries::enqueue(
        &server.database,
        Some(organization.id),
        "https://example.org/hook",
        "projects.stale",
        &json!({"event": "projects.stale"}),
        now,
    )
    .await
    .unwrap();
    deliveries::claim(&server.database, in_flight.id, now)
        .await
        .unwrap()
        .unwrap();
    let html = alice.page(page).await;
    assert!(html.contains("Recent deliveries"), "{html}");
    assert!(html.contains("findings.new"));
    assert!(html.contains("Retrying"));
    assert!(html.contains("502 Bad Gateway"));
    assert!(html.contains("Sending"), "{html}");
    assert_eq!(
        html.matches("Next attempt").count(),
        1,
        "only the retried delivery has a next attempt: {html}"
    );
}

#[tokio::test]
async fn stale_projects_are_flagged() {
    let server = server(&["--stale-after-days", "30"]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let project = projects::create(&server.database, &owner, organization.id, "web", "Web")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/projects/web";
    let html = alice.page("/organizations/acme").await;
    assert!(!html.contains("Stale"));
    assert!(!alice.page(page).await.contains("No SBOM received since"));

    let mut active: nanobom_entity::projects::ActiveModel = project.into();
    active.last_upload_at = Set(Some(
        (chrono::Utc::now() - chrono::Duration::days(40)).fixed_offset(),
    ));
    active.update(&server.database).await.unwrap();
    let html = alice.page("/organizations/acme").await;
    assert!(html.contains("Stale"));
    assert!(html.contains("Last upload: "));
    let html = alice.page(page).await;
    assert!(html.contains("No SBOM received since"));
    assert!(html.contains("check the CI job uploading it"));

    // A project that never received an SBOM is stale from its creation.
    let never = projects::create(&server.database, &owner, organization.id, "fresh", "Fresh")
        .await
        .unwrap();
    let mut active: nanobom_entity::projects::ActiveModel = never.into();
    active.created_at = Set((chrono::Utc::now() - chrono::Duration::days(45)).fixed_offset());
    active.update(&server.database).await.unwrap();
    let html = alice.page("/organizations/acme/projects/fresh").await;
    assert!(html.contains("No SBOM received since this project was created on "));
    assert!(!html.contains("since never"));
    let html = alice.page("/organizations/acme").await;
    assert!(html.contains("No SBOM received yet"));
    assert!(!html.contains("Last upload: never"));
}

#[tokio::test]
async fn license_policies_are_edited_and_violations_shown() {
    let server = server(&[]).await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let secret = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    // Every component of the npm fixture is MIT.
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

    // Without a policy, licenses are not mentioned.
    let html = alice.page("/organizations/acme/projects/web").await;
    assert!(!html.contains("Components breaking the license policy"));
    assert!(!alice.page("/organizations/acme").await.contains("license"));

    let page = "/organizations/acme/settings";
    let html = alice.page(page).await;
    assert!(html.contains("License policy"));
    assert!(html.contains("name=\"forbidden\""));
    assert!(html.contains("action=\"/api/save_license_policy\""));

    let save = |form: &'static str| {
        let alice = &alice;
        async move {
            let response = alice.submit(page, "save_license_policy", form).await;
            assert_eq!(response.status(), StatusCode::FOUND);
            location(&response)
        }
    };
    let location = save(
        "organization=acme&unlisted=allow&unknown=warn&allowed=Apache-2.0&warned=MPL-2.0%2C+BSD-3-Clause&forbidden=mit%0D%0AGPL-3.0-only",
    )
    .await;
    assert!(
        location.contains("notice=License%20policy%20saved."),
        "{location}"
    );
    let policy = nanobom_domain::licenses::policy(&server.database, &owner, organization.id)
        .await
        .unwrap();
    assert_eq!(policy.unknown, nanobom_domain::licenses::Action::Warn);
    assert_eq!(policy.rules.len(), 5);

    let html = alice.page(page).await;
    assert!(html.contains("GPL-3.0-only\nMIT</textarea>"), "{html}");
    assert!(html.contains("BSD-3-Clause\nMPL-2.0</textarea>"));
    assert!(html.contains("<option value=\"warn\" selected"));

    let html = alice.page("/organizations/acme/projects/web").await;
    assert!(html.contains("Components breaking the license policy"));
    let row = table_row(&html, "@babel/helper-string-parser");
    assert!(row.contains("Forbidden"), "{row}");
    assert!(row.contains(">MIT<"), "{row}");
    assert!(html.contains("3 forbidden"));
    let html = alice.page("/organizations/acme").await;
    assert!(table_row(&html, "/organizations/acme/projects/web").contains("3 forbidden licenses"));

    // Pages follow the language.
    let french = Browser {
        server: &server,
        cookie: format!("{}; nanobom_locale=fr", alice.cookie),
    };
    let html = french.page("/organizations/acme/projects/web").await;
    assert!(html.contains("Interdite"));
    assert!(french.page(page).await.contains("Politique de licences"));

    // An invalid identifier is refused, and the policy is left as it was.
    let location = save(
        "organization=acme&unlisted=forbid&unknown=allow&allowed=&warned=&forbidden=Apache+License",
    )
    .await;
    assert!(location.contains("error="), "{location}");
    assert!(
        location.contains("is%20not%20an%20SPDX%20license%20identifier"),
        "{location}"
    );
    assert_eq!(
        nanobom_domain::licenses::policy(&server.database, &owner, organization.id)
            .await
            .unwrap(),
        policy
    );

    // Emptying every list and allowing everything turns the policy off.
    save("organization=acme&unlisted=allow&unknown=allow&allowed=&warned=&forbidden=").await;
    let html = alice.page("/organizations/acme/projects/web").await;
    assert!(!html.contains("Components breaking the license policy"));
}

#[tokio::test]
async fn email_settings_say_why_they_are_off_without_smtp() {
    let server = server(&[]).await;
    local_user(&server.database, "alice", PASSWORD).await;
    let owner = local_user(&server.database, "bob", PASSWORD).await;
    organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let bob = Browser::sign_in(&server, "bob").await;
    let page = "/organizations/acme/settings";
    let html = bob.page(page).await;
    assert!(html.contains("Email is off on this server"), "{html}");
    assert!(!html.contains("name=\"recipients\""));

    let response = bob
        .submit(page, "send_test_email", "organization=acme")
        .await;
    assert!(
        location(&response).contains("error=Email%20is%20not%20configured"),
        "{}",
        location(&response)
    );
}

#[tokio::test]
async fn the_email_form_saves_recipients_and_sends_a_test_email() {
    let sink = SmtpSink::start().await;
    let server = server(&[
        "--smtp-url",
        &sink.url(),
        "--smtp-from",
        "nanobom@example.org",
    ])
    .await;
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let alice = Browser::sign_in(&server, "alice").await;
    let page = "/organizations/acme/settings";
    let html = alice.page(page).await;
    assert!(html.contains("name=\"recipients\""), "{html}");
    assert!(!html.contains("Send a test email"), "nothing to test yet");

    let response = alice
        .submit(
            page,
            "save_email",
            "organization=acme&recipients=not-an-address&language=en&minimum_severity=high",
        )
        .await;
    assert!(
        location(&response)
            .contains("error=%22not-an-address%22%20is%20not%20an%20email%20address"),
        "{}",
        location(&response)
    );
    let response = alice
        .submit(
            page,
            "save_email",
            "organization=acme&recipients=alice%40example.org%0D%0Abob%40example.org&language=fr&minimum_severity=critical&exploited_only=on",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).contains("notice=Email%20settings%20saved"));
    let saved = email::get(&server.database, &owner, organization.id)
        .await
        .unwrap()
        .expect("email settings");
    assert_eq!(saved.recipients, ["alice@example.org", "bob@example.org"]);
    assert_eq!(saved.language, Language::French);
    assert!(saved.exploited_only);
    let html = alice.page(page).await;
    assert!(
        html.contains("alice@example.org\nbob@example.org"),
        "{html}"
    );
    assert!(html.contains("<option value=\"fr\" selected"), "{html}");

    let response = alice
        .submit(page, "send_test_email", "organization=acme")
        .await;
    assert!(
        location(&response).contains("notice=Test%20email%20sent"),
        "{}",
        location(&response)
    );
    // One message per recipient, each listing both in `To`.
    let received = sink.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].recipients, ["alice@example.org"]);
    assert_eq!(received[1].recipients, ["bob@example.org"]);
    assert!(
        received[1]
            .data
            .contains("To: alice@example.org, bob@example.org"),
        "{}",
        received[1].data
    );
    let response = alice
        .submit(page, "send_test_email", "organization=acme")
        .await;
    assert!(
        location(&response).contains("error=Too%20many%20test%20emails%20were%20sent%20recently"),
        "{}",
        location(&response)
    );
    assert_eq!(sink.received().len(), 2);

    alice
        .submit(page, "delete_email", "organization=acme")
        .await;
    assert_eq!(
        email::get(&server.database, &owner, organization.id)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn new_findings_of_an_upload_are_emailed() {
    let sink = SmtpSink::start().await;
    let server = server(&[
        "--smtp-url",
        &sink.url(),
        "--smtp-from",
        "nanobom@example.org",
    ])
    .await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
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
    email::set(
        &server.database,
        &owner,
        organization.id,
        &email::EmailSettings {
            recipients: vec!["security@example.org".to_owned()],
            language: Language::English,
            minimum_severity: nanobom_osv::Severity::Low,
            exploited_only: false,
        },
    )
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

    let received = sink.received();
    assert_eq!(received.len(), 1, "one email for the run");
    assert_eq!(received[0].recipients, ["security@example.org"]);
    assert!(
        received[0]
            .data
            .contains("Subject: nanobom: 1 new vulnerability in acme/web"),
        "{}",
        received[0].data
    );
    let alice = Browser::sign_in(&server, "alice").await;
    let html = alice.page("/organizations/acme/settings").await;
    assert!(html.contains("Recent deliveries"), "{html}");
    assert!(html.contains("Email to security@example.org"), "{html}");
}

#[tokio::test]
async fn smtp_settings_are_checked_at_startup_without_revealing_the_password() {
    let options = crate::common::options(&["--smtp-url", "smtps://user:hunter2@smtp.example.org"]);
    assert!(!format!("{options:?}").contains("hunter2"));
    let error = nanobom::serve::mailer(&options).unwrap_err().to_string();
    assert!(error.contains("NANOBOM_SMTP_FROM"), "{error}");
    let options = crate::common::options(&[
        "--smtp-url",
        "smtps://user:hunter2@smtp.example.org",
        "--smtp-from",
        "not a mailbox",
    ]);
    let error = nanobom::serve::mailer(&options).unwrap_err().to_string();
    assert!(error.contains("NANOBOM_SMTP_FROM"), "{error}");
    assert!(!error.contains("hunter2"), "{error}");
    let options = crate::common::options(&[
        "--smtp-url",
        "imap://user:hunter2@smtp.example.org",
        "--smtp-from",
        "nanobom@example.org",
    ]);
    let error = nanobom::serve::mailer(&options).unwrap_err().to_string();
    assert!(error.contains("NANOBOM_SMTP_URL"), "{error}");
    assert!(!error.contains("hunter2"), "{error}");
    // Credentials over plain SMTP would be sent in clear text.
    let options = crate::common::options(&[
        "--smtp-url",
        "smtp://user:hunter2@smtp.example.org:587",
        "--smtp-from",
        "nanobom@example.org",
    ]);
    let error = nanobom::serve::mailer(&options).unwrap_err().to_string();
    assert!(error.contains("tls=required"), "{error}");
    assert!(!error.contains("hunter2"), "{error}");
    assert!(
        nanobom::serve::mailer(&crate::common::options(&[]))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_project_page_shows_one_version_at_a_time() {
    let server = server(&[]).await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "summary": "Command Injection in lodash",
            "database_specific": {"severity": "HIGH"}
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
    let upload = |project: &str, query: &str, document: &str| {
        Request::put(format!(
            "/api/organizations/acme/projects/{project}/sbom{query}"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {secret}"))
        .body(Body::from(sbom_document(document)))
        .unwrap()
    };
    server.send(upload("web", "", "cyclonedx-npm.json")).await;
    server.runner.wait_until_idle().await;
    server
        .send(upload("web", "?version=2.0", "cyclonedx-py.json"))
        .await;
    server.send(upload("api", "", "cyclonedx-npm.json")).await;
    server.runner.wait_until_idle().await;
    let alice = Browser::sign_in(&server, "alice").await;

    // A project that never named a version has no selector.
    let html = alice.page("/organizations/acme/projects/api").await;
    assert!(!html.contains("name=\"version\""));

    // The latest version by default: 2.0 has no lodash.
    let html = alice.page("/organizations/acme/projects/web").await;
    assert!(
        html.contains("<select id=\"version\" name=\"version\""),
        "{html}"
    );
    assert!(html.contains("2.0 (latest)"));
    assert!(html.contains("Unnamed version"));
    assert!(!html.contains("GHSA-35jh-r3h4-6jhm"));
    assert!(html.contains("href=\"/api/organizations/acme/projects/web/vex\""));
    // The upload history covers every version and says which.
    assert!(html.contains("version 2.0"));
    assert!(html.contains("· unnamed version"));

    // `version=` (empty) names the unnamed version, whose findings and links follow.
    let html = alice
        .page("/organizations/acme/projects/web?version=")
        .await;
    assert!(html.contains("GHSA-35jh-r3h4-6jhm"));
    assert!(html.contains("href=\"/api/organizations/acme/projects/web/vex?version=\""));
    assert!(html.contains("<input type=\"hidden\" name=\"version\" value=\"\""));
    let response = alice
        .get("/organizations/acme/projects/web?version=9.9")
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // A finding's page names its version, and what 2.0 inherited says where it comes from.
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let inherited = findings::list_in_version(
        &server.database,
        &owner,
        project.id,
        Some("2.0"),
        &Filter::default(),
    )
    .await
    .unwrap();
    assert_eq!(inherited.len(), 1, "fixed by the run, still listed");
    let html = alice.page(&format!("/findings/{}", inherited[0].id)).await;
    assert!(html.contains("href=\"/organizations/acme/projects/web?version=2.0\""));
    assert!(html.contains("Inherited from the unnamed version"));
}

#[tokio::test]
async fn versions_are_managed_from_the_project_page() {
    use nanobom_domain::{access::Role, memberships, versions};
    let server = server(&[]).await;
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "summary": "Command Injection in lodash",
            "database_specific": {"severity": "HIGH"}
        }),
        &["pkg:npm/lodash@4.17.20"],
    );
    let owner = local_user(&server.database, "alice", PASSWORD).await;
    local_user(&server.database, "bob", PASSWORD).await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    memberships::add(
        &server.database,
        &owner,
        organization.id,
        "bob",
        Role::Viewer,
    )
    .await
    .unwrap();
    let secret = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let upload = |query: &str, document: &str| {
        Request::put(format!("/api/organizations/acme/projects/web/sbom{query}"))
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .body(Body::from(sbom_document(document)))
            .unwrap()
    };
    // 1.0 has lodash; 2.0 inherits it and its run fixes it; 3.0 is created after, without it.
    server
        .send(upload("?version=1.0", "cyclonedx-npm.json"))
        .await;
    server.runner.wait_until_idle().await;
    server
        .send(upload("?version=2.0", "cyclonedx-py.json"))
        .await;
    server.runner.wait_until_idle().await;
    server
        .send(upload("?version=3.0&latest=false", "cyclonedx-py.json"))
        .await;
    server.runner.wait_until_idle().await;
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let state = || async {
        let mut listed: Vec<(String, bool, bool)> =
            versions::list(&server.database, &owner, project.id)
                .await
                .unwrap()
                .into_iter()
                .map(|version| (version.name, version.latest, version.active))
                .collect();
        listed.sort();
        listed
    };
    let alice = Browser::sign_in(&server, "alice").await;
    let bob = Browser::sign_in(&server, "bob").await;
    let page = "/organizations/acme/projects/web";

    let html = alice.page(page).await;
    assert!(html.contains(">Versions<"), "{html}");
    assert!(html.contains("action=\"/api/set_version_active\""));
    assert!(html.contains("action=\"/api/set_latest_version\""));
    assert!(html.contains("action=\"/api/delete_version\""));
    // Viewers see the versions, not the actions.
    let html = bob.page(page).await;
    assert!(html.contains(">Versions<"));
    assert!(!html.contains("action=\"/api/set_version_active\""));
    assert!(!html.contains("action=\"/api/delete_version\""));
    let response = bob
        .submit(
            page,
            "set_version_active",
            "organization=acme&project=web&version=1.0&active=false",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).contains("error="));

    // Made inactive, a version is marked in the selector and on its page.
    let response = alice
        .submit(
            page,
            "set_version_active",
            "organization=acme&project=web&version=1.0&active=false",
        )
        .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).contains("notice="));
    assert_eq!(
        state().await,
        [
            ("1.0".to_owned(), false, false),
            ("2.0".to_owned(), true, true),
            ("3.0".to_owned(), false, true)
        ]
    );
    let html = alice.page(&format!("{page}?version=1.0")).await;
    assert!(html.contains("1.0 (inactive)"));
    assert!(html.contains("This version is inactive"));
    assert!(html.contains("Make active"));
    // Searches leave it out unless asked.
    let html = alice.page("/search?query=lodash").await;
    assert!(!html.contains("/organizations/acme/projects/web?version=1.0"));
    let html = alice.page("/search?query=lodash&inactive=1").await;
    assert!(html.contains("href=\"/organizations/acme/projects/web?version=1.0\""));
    assert!(html.contains("version 1.0"));
    assert!(html.contains(" · inactive"));

    // The finding page compares the versions.
    let lodash = findings::list_in_version(
        &server.database,
        &owner,
        project.id,
        Some("1.0"),
        &Filter::default(),
    )
    .await
    .unwrap();
    let html = alice.page(&format!("/findings/{}", lodash[0].id)).await;
    assert!(html.contains("Versions of this project"));
    assert!(html.contains("Not affected"), "3.0 never had lodash");
    assert!(html.contains("this finding"));

    // The latest moves; it can be neither made inactive nor deleted.
    let response = alice
        .submit(
            page,
            "set_latest_version",
            "organization=acme&project=web&version=3.0",
        )
        .await;
    assert!(location(&response).contains("notice="));
    let response = alice
        .submit(
            page,
            "delete_version",
            "organization=acme&project=web&version=3.0&confirm=1",
        )
        .await;
    assert!(location(&response).contains("error="));
    // Deletion needs the confirmation box.
    let response = alice
        .submit(
            page,
            "delete_version",
            "organization=acme&project=web&version=2.0",
        )
        .await;
    assert!(location(&response).contains("error="));
    assert_eq!(state().await.len(), 3);
    let response = alice
        .submit(
            page,
            "delete_version",
            "organization=acme&project=web&version=2.0&confirm=1",
        )
        .await;
    let target = location(&response);
    assert!(
        target.starts_with(&format!("{page}?notice=")),
        "back to the latest version: {target}"
    );
    assert_eq!(
        state().await,
        [
            ("1.0".to_owned(), false, false),
            ("3.0".to_owned(), true, true)
        ]
    );
}
