//! The SBOM upload endpoint.

use std::time::{Duration, Instant};

use crate::common::{
    TestServer, body_json, sbom_document, server, server_with_exploitation_timeout, user,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use nanobom_domain::{inventory, notifications, organizations, projects, tokens};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn upload(path: &str, token: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::put(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn organization_tokens_upload_and_create_projects() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;

    let response = server
        .send(upload(
            "/api/organizations/acme/projects/web/sbom?source_commit=abc123&image_tag=web:1.2",
            Some(&token),
            sbom_document("cyclonedx-npm.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let outcome = body_json(response).await;
    assert_eq!(outcome["project"], "web");
    assert_eq!(outcome["project_created"], true);
    assert_eq!(outcome["component_count"], 3);
    assert_eq!(outcome["components_without_purl"], 0);

    let response = server
        .send(upload(
            "/api/organizations/acme/projects/web/sbom",
            Some(&token),
            sbom_document("syft.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    assert!(project.last_upload_at.is_some());
}

#[tokio::test]
async fn uploads_without_a_valid_token_are_refused() {
    let server = server(&[]).await;
    for token in [None, Some("nanobom_unknown"), Some("garbage")] {
        let response = server
            .send(upload(
                "/api/organizations/acme/projects/web/sbom",
                token,
                sbom_document("cyclonedx-py.json"),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
}

#[tokio::test]
async fn project_tokens_cannot_reach_other_projects_or_organizations() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let acme = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    for slug in ["api", "web"] {
        projects::create(&server.database, &owner, acme.id, slug, slug)
            .await
            .unwrap();
    }
    organizations::create(&server.database, &owner, "other", "Other")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, acme.id, Some("api"), "API")
        .await
        .unwrap()
        .secret;
    let attempt = |path: &str| upload(path, Some(&token), sbom_document("cargo-cyclonedx.json"));

    let response = server
        .send(attempt("/api/organizations/acme/projects/api/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = server
        .send(attempt("/api/organizations/acme/projects/web/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = server
        .send(attempt("/api/organizations/acme/projects/new/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server
        .send(attempt("/api/organizations/other/projects/api/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_and_oversized_documents_are_rejected() {
    let server = server(&["--maximum-sbom-size", "1"]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let path = "/api/organizations/acme/projects/web/sbom";

    let refused = [
        (&b"{\"name\": \"sbom\"}"[..], "or an SPDX JSON document"),
        (
            b"SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n",
            "SPDX tag-value documents are not supported",
        ),
        (
            b"<rdf:RDF xmlns:spdx=\"http://spdx.org/rdf/terms#\"/>",
            "SPDX RDF documents are not supported",
        ),
        (
            b"{\"@context\": \"https://spdx.org/rdf/3.0.1/spdx-context.jsonld\"}",
            "unsupported SPDX version \"SPDX-3.0.1\"",
        ),
    ];
    for (document, message) in refused {
        let response = server
            .send(upload(path, Some(&token), document.to_vec()))
            .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(response).await;
        let error = body["error"].as_str().unwrap();
        assert!(error.contains(message), "{error}");
    }

    let response = server
        .send(upload(path, Some(&token), vec![b' '; 1024 * 1024 + 1]))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // The limit is the same for SPDX.
    let mut document = sbom_document("syft-spdx.json");
    document.extend(std::iter::repeat_n(b' ', 1024 * 1024));
    let response = server.send(upload(path, Some(&token), document)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn spdx_documents_are_uploaded_like_cyclonedx() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;

    let response = server
        .send(upload(
            "/api/organizations/acme/projects/web/sbom",
            Some(&token),
            sbom_document("trivy-npm-spdx.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let outcome = body_json(response).await;
    assert_eq!(outcome["component_count"], 5);
    assert_eq!(outcome["components_without_purl"], 1);
    assert_eq!(outcome["skipped"][0]["name"], "package-lock.json");
    assert_eq!(outcome["skipped"][0]["reason"], "no package URL");

    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let uploads = inventory::uploads(&server.database, &owner, project.id)
        .await
        .unwrap();
    assert_eq!(uploads[0].specification_version, "SPDX-2.3");
}

/// A high severity advisory affecting the lodash of `cyclonedx-npm.json`.
fn lodash_advisory() -> serde_json::Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

/// An organization `acme` with an organization-wide upload token, returned.
async fn acme_token(server: &TestServer) -> String {
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret
}

/// Uploads the lodash SBOM to `acme/web` with a query string.
async fn upload_web(
    server: &TestServer,
    token: &str,
    query: &str,
) -> (StatusCode, serde_json::Value) {
    let response = server
        .send(upload(
            &format!("/api/organizations/acme/projects/web/sbom{query}"),
            Some(token),
            sbom_document("cyclonedx-npm.json"),
        ))
        .await;
    let status = response.status();
    (status, body_json(response).await)
}

#[tokio::test]
async fn waiting_uploads_return_the_evaluation() {
    // Waiting runs the project even when runs after uploads are disabled.
    let server = server(&[
        "--run-after-upload",
        "false",
        "--public-url",
        "https://nanobom.example.org/",
    ])
    .await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let token = acme_token(&server).await;

    let (status, body) = upload_web(&server, &token, "").await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body.get("evaluation").is_none(), "{body}");
    assert!(body.get("error").is_none(), "{body}");
    server.runner.wait_until_idle().await;
    assert_eq!(
        nanobom_entity::runs::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        0,
        "no run without wait when runs after uploads are disabled"
    );

    let (status, body) = upload_web(&server, &token, "?wait=true").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["project"], "web");
    assert_eq!(body["component_count"], 3);
    let evaluation = &body["evaluation"];
    assert_eq!(evaluation["status"], "succeeded", "{body}");
    assert!(evaluation["run_id"].as_i64().is_some());
    assert_eq!(
        evaluation["open"],
        json!({"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0})
    );
    assert_eq!(evaluation["known_exploited"], 0);
    let findings = evaluation["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["vulnerability"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(findings[0]["component"], "pkg:npm/lodash@4.17.20");
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(findings[0]["known_exploited"], false);
    assert_eq!(
        findings[0]["introduced_via"],
        json!(["lodash"]),
        "a direct dependency introduces itself"
    );
    let id = nanobom_entity::findings::Entity::find()
        .one(&server.database)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(
        findings[0]["url"],
        format!("https://nanobom.example.org/findings/{id}")
    );
}

#[tokio::test]
async fn fail_on_a_severity_fails_uploads_with_findings_at_or_above_it() {
    let server = server(&[]).await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let token = acme_token(&server).await;

    let (status, body) = upload_web(&server, &token, "?fail_on=critical").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["evaluation"]["open"]["high"], 1);

    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "1 open finding at or above high");
    assert_eq!(body["project"], "web");
    assert_eq!(body["evaluation"]["status"], "succeeded");

    let (status, body) = upload_web(&server, &token, "?fail_on=low&wait=false").await;
    assert_eq!(status, StatusCode::CONFLICT, "fail_on implies wait");
    assert_eq!(body["error"], "1 open finding at or above low");
}

#[tokio::test]
async fn fail_on_high_passes_without_a_high_finding() {
    let server = server(&[]).await;
    let token = acme_token(&server).await;
    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["evaluation"]["status"], "succeeded");
    assert_eq!(body["evaluation"]["findings"], json!([]));
}

#[tokio::test]
async fn fail_on_exploited_fails_uploads_with_known_exploited_findings() {
    let server = server(&[]).await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let token = acme_token(&server).await;

    let (status, body) = upload_web(&server, &token, "?fail_on=exploited").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["evaluation"]["known_exploited"], 0);

    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_date_added: Set(Some("2022-03-01".to_owned())),
        kev_due_date: Set(Some("2022-03-22".to_owned())),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();
    let (status, body) = upload_web(&server, &token, "?fail_on=exploited").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "1 open finding is known exploited");
    assert_eq!(body["evaluation"]["known_exploited"], 1);
    assert_eq!(body["evaluation"]["findings"][0]["known_exploited"], true);
}

#[tokio::test]
async fn invalid_wait_parameters_are_refused_before_storing_anything() {
    let server = server(&[]).await;
    let token = acme_token(&server).await;
    let (status, body) = upload_web(&server, &token, "?fail_on=severe").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        json!({"error": "fail_on must be critical, high, medium, low or exploited"})
    );
    let (status, body) = upload_web(&server, &token, "?wait=yes").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "wait must be true or false"}));
    assert_eq!(
        nanobom_entity::projects::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        nanobom_entity::sbom_uploads::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn fail_on_exploited_is_refused_without_exploitation_data() {
    let server = server(&["--exploitation-data", "false"]).await;
    let token = acme_token(&server).await;
    let (status, body) = upload_web(&server, &token, "?fail_on=Exploited").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        json!({"error": "fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)"})
    );
    assert_eq!(
        nanobom_entity::sbom_uploads::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        0
    );
    // Severity thresholds do not need it.
    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn failed_evaluations_fail_only_uploads_with_fail_on() {
    let server = server(&[]).await;
    server.source.set_failing(true);
    let token = acme_token(&server).await;

    let (status, body) = upload_web(&server, &token, "?wait=true").await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["evaluation"]["status"], "failed");
    assert!(body["evaluation"]["run_id"].as_i64().is_some());

    let (status, body) = upload_web(&server, &token, "?fail_on=critical").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "the evaluation did not complete");
    assert_eq!(body["evaluation"]["status"], "failed");
}

#[tokio::test]
async fn evaluations_that_panic_are_reported_as_failed() {
    let server = server(&[]).await;
    let token = acme_token(&server).await;

    // The run's row exists when it panics: it is recorded as failed, and reported.
    server.source.panic_once();
    let (status, body) = upload_web(&server, &token, "?wait=true").await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["evaluation"]["status"], "failed");
    assert!(body["evaluation"]["run_id"].as_i64().is_some(), "{body}");

    server.source.panic_once();
    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "the evaluation did not complete");
    assert_eq!(body["evaluation"]["status"], "failed");
    assert!(body["evaluation"]["run_id"].as_i64().is_some(), "{body}");

    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["evaluation"]["status"], "succeeded");
}

#[tokio::test]
async fn evaluations_that_take_too_long_time_out() {
    let server = server(&["--upload-wait-seconds", "0"]).await;
    server.source.pause();
    let token = acme_token(&server).await;

    let (status, body) = upload_web(&server, &token, "?wait=true").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["evaluation"]["status"], "timed_out");
    assert_eq!(body["evaluation"]["run_id"], serde_json::Value::Null);

    let (status, body) = upload_web(&server, &token, "?fail_on=high").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "the evaluation did not complete");
    assert_eq!(body["evaluation"]["status"], "timed_out");

    server.source.resume();
    server.runner.wait_until_idle().await;
}

#[tokio::test]
async fn waiting_uploads_are_answered_before_webhook_deliveries() {
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(8)))
        .mount(&receiver)
        .await;
    let server = server(&["--upload-wait-seconds", "4"]).await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    notifications::set(
        &server.database,
        &owner,
        organization.id,
        &notifications::Webhook {
            url: format!("{}/hook", receiver.uri()),
            minimum_severity: Severity::Low,
            enabled: true,
            exploited_only: false,
            format: notifications::Format::Json,
        },
    )
    .await
    .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;

    // The run opens a finding, so its `findings.new` delivery takes 8 seconds.
    let started = Instant::now();
    let (status, body) = upload_web(&server, &token, "?wait=true").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["evaluation"]["status"], "succeeded", "{body}");
    assert_eq!(body["evaluation"]["open"]["high"], 1);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn a_hanging_exploitation_feed_holds_waiting_uploads_only_up_to_the_bound() {
    let feeds = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"vulnerabilities": []}))
                .set_delay(Duration::from_secs(20)),
        )
        .mount(&feeds)
        .await;
    let kev_url = format!("{}/kev.json", feeds.uri());
    let epss_url = format!("{}/epss", feeds.uri());
    let server = server_with_exploitation_timeout(
        &[
            "--kev-url",
            &kev_url,
            "--epss-url",
            &epss_url,
            "--upload-wait-seconds",
            "10",
        ],
        Duration::from_secs(1),
    )
    .await;
    server
        .source
        .publish(lodash_advisory(), &["pkg:npm/lodash@4.17.20"]);
    let token = acme_token(&server).await;

    let started = Instant::now();
    let (status, body) = upload_web(&server, &token, "?fail_on=exploited").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["evaluation"]["status"], "succeeded", "{body}");
    assert_eq!(body["evaluation"]["known_exploited"], 0);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(10),
        "{elapsed:?}"
    );
    assert!(
        nanobom_entity::exploitation::Entity::find()
            .all(&server.database)
            .await
            .unwrap()
            .is_empty(),
        "an abandoned refresh stores nothing"
    );
}
