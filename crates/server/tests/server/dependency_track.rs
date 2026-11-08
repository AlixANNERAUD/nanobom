//! The Dependency-Track upload API, with requests shaped like those of its clients.

use std::time::{Duration, Instant};

use crate::common::{TestServer, body_json, body_text, sbom_document, server, user};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use nanobom_domain::{access::Actor, inventory, organizations, projects, tokens};
use serde_json::json;

/// The boundary undici (Node's `fetch`) uses, which gh-upload-sbom sends with.
const BOUNDARY: &str = "----formdata-undici-0.5827195467216513";

/// A multipart body as gh-upload-sbom's `fetch` serializes its `FormData`: the SBOM first, as a
/// `Blob` named `bom` without a type, then text fields in the order the action appends them.
fn gh_upload_sbom_form(bom: &[u8], fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"bom\"; filename=\"bom\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bom);
    body.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn post_form(api_key: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::post("/api/v1/bom").header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={BOUNDARY}"),
    );
    if let Some(api_key) = api_key {
        // gh-upload-sbom spells it `X-API-Key`; header names are case-insensitive.
        request = request.header("X-API-Key", api_key);
    }
    request.body(Body::from(body)).unwrap()
}

fn put_json(api_key: Option<&str>, body: &serde_json::Value) -> Request<Body> {
    let mut request = Request::put("/api/v1/bom").header(header::CONTENT_TYPE, "application/json");
    if let Some(api_key) = api_key {
        request = request.header("X-Api-Key", api_key);
    }
    request.body(Body::from(body.to_string())).unwrap()
}

fn status_request(path: &str, api_key: &str) -> Request<Body> {
    Request::get(path)
        .header("X-Api-Key", api_key)
        .body(Body::empty())
        .unwrap()
}

fn encoded(document: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(document)
}

struct Setup {
    server: TestServer,
    owner: Actor,
    organization_id: i64,
    token: String,
}

async fn setup(arguments: &[&str]) -> Setup {
    let server = server(arguments).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    Setup {
        server,
        owner,
        organization_id: organization.id,
        token,
    }
}

async fn processing(server: &TestServer, path: &str, api_key: &str) -> bool {
    let response = server.send(status_request(path, api_key)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let status = body_json(response).await;
    status["processing"]
        .as_bool()
        .expect("processing is a boolean")
}

#[tokio::test]
async fn gh_upload_sbom_requests_create_the_project() {
    let Setup {
        server,
        owner,
        organization_id,
        token,
    } = setup(&[]).await;
    let body = gh_upload_sbom_form(
        &sbom_document("cyclonedx-npm.json"),
        &[
            ("projectName", "Web-App"),
            ("projectVersion", "1.4.0"),
            ("autoCreate", "true"),
            ("projectTags", "frontend,team-a"),
            ("isLatest", "true"),
            ("parentName", "platform"),
            ("parentVersion", "1"),
        ],
    );

    let response = server.send(post_form(Some(&token), body)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let answer = body_json(response).await;
    let upload_token = answer["token"].as_str().expect("a token");
    assert_eq!(upload_token.len(), 36, "a UUID: {upload_token}");

    let project = projects::find(&server.database, &owner, organization_id, "web-app")
        .await
        .unwrap();
    let uploads = inventory::uploads(&server.database, &owner, project.id)
        .await
        .unwrap();
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].image_tag.as_deref(), Some("1.4.0"));
    assert_eq!(uploads[0].component_count, 3);
}

#[tokio::test]
async fn base64_json_uploads_are_accepted() {
    let Setup {
        server,
        owner,
        organization_id,
        token,
    } = setup(&[]).await;
    // As the Maven plugin sends it, with the fields nanobom ignores.
    let request = json!({
        "projectName": "MyService",
        "projectVersion": "2.0.0-SNAPSHOT",
        "autoCreate": true,
        "isLatestProjectVersion": false,
        "projectTags": [{"name": "backend"}],
        "parentUUID": null,
        "bom": encoded(&sbom_document("cyclonedx-py.json")),
    });

    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_json(response).await["token"].is_string());
    let project = projects::find(&server.database, &owner, organization_id, "myservice")
        .await
        .unwrap();
    let uploads = inventory::uploads(&server.database, &owner, project.id)
        .await
        .unwrap();
    assert_eq!(uploads[0].image_tag.as_deref(), Some("2.0.0-SNAPSHOT"));

    // A wrapped encoding, a byte order mark and a string `autoCreate` are tolerated.
    let mut document = b"\xEF\xBB\xBF".to_vec();
    document.extend(sbom_document("syft.json"));
    let wrapped = encoded(&document)
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let request = json!({"projectName": "other", "autoCreate": "true", "bom": wrapped});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn uploads_without_a_valid_key_are_refused() {
    let Setup { server, .. } = setup(&[]).await;
    let request = json!({"projectName": "web", "autoCreate": true,
        "bom": encoded(&sbom_document("cyclonedx-py.json"))});
    for api_key in [None, Some("nanobom_unknown"), Some("garbage")] {
        let response = server.send(put_json(api_key, &request)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let form = gh_upload_sbom_form(
            &sbom_document("cyclonedx-py.json"),
            &[("projectName", "web"), ("autoCreate", "true")],
        );
        let response = server.send(post_form(api_key, form)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = server
        .send(status_request(
            "/api/v1/event/token/7f6b3a9e-0f4e-4a43-9a51-3c2b8f0c1d2e",
            "nanobom_unknown",
        ))
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_tokens_are_accepted_too() {
    let Setup { server, token, .. } = setup(&[]).await;
    let request = Request::put("/api/v1/bom")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            json!({"projectName": "web", "autoCreate": true,
                "bom": encoded(&sbom_document("cyclonedx-py.json"))})
            .to_string(),
        ))
        .unwrap();
    assert_eq!(server.send(request).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn without_auto_create_only_existing_projects_are_accepted() {
    let Setup {
        server,
        owner,
        organization_id,
        token,
    } = setup(&[]).await;
    let document = encoded(&sbom_document("cyclonedx-py.json"));

    let request = json!({"projectName": "web", "projectVersion": "1", "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(body_text(response).await, "The project could not be found.");
    let request = json!({"projectName": "web", "autoCreate": false, "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let form = gh_upload_sbom_form(
        &sbom_document("cyclonedx-py.json"),
        &[("projectName", "web"), ("autoCreate", "false")],
    );
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    projects::create(&server.database, &owner, organization_id, "web", "Web")
        .await
        .unwrap();
    let request = json!({"projectName": "WEB", "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn project_tokens_reach_their_project_only() {
    let Setup {
        server,
        owner,
        organization_id,
        ..
    } = setup(&[]).await;
    for slug in ["api", "web"] {
        projects::create(&server.database, &owner, organization_id, slug, slug)
            .await
            .unwrap();
    }
    let token = tokens::create(
        &server.database,
        &owner,
        organization_id,
        Some("api"),
        "API",
    )
    .await
    .unwrap()
    .secret;
    let document = encoded(&sbom_document("cyclonedx-py.json"));
    let attempt = |name: &str| json!({"projectName": name, "autoCreate": true, "bom": document});

    let response = server.send(put_json(Some(&token), &attempt("api"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = server.send(put_json(Some(&token), &attempt("web"))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = server.send(put_json(Some(&token), &attempt("new"))).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn projects_must_be_named_with_a_valid_slug() {
    let Setup { server, token, .. } = setup(&[]).await;
    let document = encoded(&sbom_document("cyclonedx-py.json"));

    // gh-upload-sbom sends only the UUID unless `auto-create` is set.
    let form = gh_upload_sbom_form(
        &sbom_document("cyclonedx-py.json"),
        &[("project", "38640b33-4ba9-4733-bdab-cbfc40c6f8aa")],
    );
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(response).await.contains("send projectName"));
    let request = json!({"project": "38640b33-4ba9-4733-bdab-cbfc40c6f8aa", "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let request = json!({"projectName": "Example Application", "autoCreate": true,
        "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = body_text(response).await;
    assert!(
        message.contains("\"Example Application\" cannot be a nanobom project slug"),
        "{message}"
    );

    let request = json!({"autoCreate": true, "bom": document});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_text(response).await, "projectName is required");
}

#[tokio::test]
async fn invalid_sboms_are_problems() {
    let Setup { server, token, .. } = setup(&[]).await;

    let xml = br#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>"#;
    let form = gh_upload_sbom_form(xml, &[("projectName", "web"), ("autoCreate", "true")]);
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let problem = body_json(response).await;
    assert_eq!(problem["status"], 400);
    assert_eq!(problem["title"], "The uploaded BOM is invalid");
    assert!(problem["detail"].as_str().unwrap().contains("JSON only"));

    let request = json!({"projectName": "web", "autoCreate": true,
        "bom": encoded(br#"{"bomFormat": "SPDX"}"#)});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await["title"],
        "The uploaded BOM is invalid"
    );

    let request = json!({"projectName": "web", "autoCreate": true, "bom": "not base64!"});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let form = gh_upload_sbom_form(b"", &[("projectName", "web")]);
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sboms_over_the_size_limit_are_refused() {
    let Setup { server, token, .. } = setup(&["--maximum-sbom-size", "1"]).await;
    let mut document = sbom_document("cyclonedx-py.json");
    // Padding after the document keeps it valid JSON while making it larger than 1 MiB.
    document.extend(std::iter::repeat_n(b' ', 1024 * 1024));

    let form = gh_upload_sbom_form(&document, &[("projectName", "web"), ("autoCreate", "true")]);
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let request = json!({"projectName": "web", "autoCreate": true, "bom": encoded(&document)});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Base64 makes an SBOM under the limit larger than it: still accepted.
    let mut document = sbom_document("cyclonedx-py.json");
    document.extend(std::iter::repeat_n(b' ', 900 * 1024));
    let request = json!({"projectName": "web", "autoCreate": true, "bom": encoded(&document)});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tokens_are_processing_until_the_run_finishes() {
    let Setup {
        server,
        owner,
        organization_id,
        token,
    } = setup(&[]).await;
    server.source.pause();
    let form = gh_upload_sbom_form(
        &sbom_document("cyclonedx-npm.json"),
        &[("projectName", "web"), ("autoCreate", "true")],
    );
    let response = server.send(post_form(Some(&token), form)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let upload_token = body_json(response).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    server.source.query_started().await;

    let event = format!("/api/v1/event/token/{upload_token}");
    let bom = format!("/api/v1/bom/token/{upload_token}");
    assert!(processing(&server, &event, &token).await);
    assert!(processing(&server, &bom, &token).await);
    // Another organization's token does not see it.
    let other = organizations::create(&server.database, &owner, "other", "Other")
        .await
        .unwrap();
    let other_token = tokens::create(&server.database, &owner, other.id, None, "CI")
        .await
        .unwrap()
        .secret;
    assert!(!processing(&server, &event, &other_token).await);

    server.source.resume();
    let started = Instant::now();
    while processing(&server, &event, &token).await {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "still processing"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!processing(&server, &bom, &token).await);
    let project = projects::find(&server.database, &owner, organization_id, "web")
        .await
        .unwrap();
    assert!(project.last_upload_at.is_some());

    // Unknown tokens are not processing, as in Dependency-Track; malformed ones are refused.
    assert!(
        !processing(
            &server,
            "/api/v1/event/token/7f6b3a9e-0f4e-4a43-9a51-3c2b8f0c1d2e",
            &token
        )
        .await
    );
    let response = server
        .send(status_request("/api/v1/event/token/not-a-uuid", &token))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn tokens_are_done_at_once_without_runs_after_uploads() {
    let Setup { server, token, .. } = setup(&["--run-after-upload", "false"]).await;
    let request = json!({"projectName": "web", "autoCreate": true,
        "bom": encoded(&sbom_document("cyclonedx-py.json"))});
    let response = server.send(put_json(Some(&token), &request)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let upload_token = body_json(response).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        !processing(
            &server,
            &format!("/api/v1/bom/token/{upload_token}"),
            &token
        )
        .await
    );
}
