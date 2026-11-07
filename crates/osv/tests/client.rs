//! The OSV client against a mocked API: batching, pagination and failure handling.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use nanobom_osv::{OsvClient, SourceError, VulnerabilitySource};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

fn client(server: &MockServer) -> OsvClient {
    OsvClient::new(server.uri().parse().unwrap())
        .unwrap()
        .with_retry_delay(Duration::from_millis(1))
}

/// Answers batch queries from a table of package URL to pages of vulnerability identifiers, and
/// records the size of every batch it receives.
#[derive(Clone)]
struct Osv {
    pages: BTreeMap<String, Vec<Vec<&'static str>>>,
    batch_sizes: Arc<Mutex<Vec<usize>>>,
}

impl Osv {
    fn new(pages: &[(&str, Vec<Vec<&'static str>>)]) -> Self {
        Self {
            pages: pages
                .iter()
                .map(|(purl, pages)| ((*purl).to_owned(), pages.clone()))
                .collect(),
            batch_sizes: Arc::default(),
        }
    }
}

impl Respond for Osv {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let queries = body["queries"].as_array().unwrap();
        self.batch_sizes.lock().unwrap().push(queries.len());
        let results: Vec<Value> = queries
            .iter()
            .map(|query| {
                let purl = query["package"]["purl"].as_str().unwrap();
                let page: usize = query["page_token"]
                    .as_str()
                    .map_or(0, |token| token.parse().unwrap());
                let pages = self.pages.get(purl).cloned().unwrap_or_default();
                let vulnerabilities: Vec<Value> = pages
                    .get(page)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|id| json!({"id": id, "modified": "2024-01-02T03:04:05Z"}))
                    .collect();
                let mut result = json!({"vulns": vulnerabilities});
                if page + 1 < pages.len() {
                    result["next_page_token"] = json!((page + 1).to_string());
                }
                result
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({"results": results}))
    }
}

fn ids(references: &[nanobom_osv::VulnerabilityReference]) -> Vec<&str> {
    references
        .iter()
        .map(|reference| reference.id.as_str())
        .collect()
}

#[tokio::test]
async fn queries_are_sent_in_batches_and_answers_kept_in_order() {
    let server = MockServer::start().await;
    let osv = Osv::new(&[
        ("pkg:npm/a@1", vec![vec!["GHSA-a"]]),
        ("pkg:npm/c@1", vec![vec!["GHSA-c1", "GHSA-c2"]]),
        ("pkg:npm/e@1", vec![vec!["GHSA-e"]]),
    ]);
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(osv.clone())
        .mount(&server)
        .await;

    let purls: Vec<String> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|name| format!("pkg:npm/{name}@1"))
        .collect();
    let results = client(&server)
        .with_batch_size(2)
        .query(&purls)
        .await
        .unwrap();
    assert_eq!(*osv.batch_sizes.lock().unwrap(), [2, 2, 1]);
    assert_eq!(results.len(), 5);
    assert_eq!(ids(&results[0]), ["GHSA-a"]);
    assert!(results[1].is_empty());
    assert_eq!(ids(&results[2]), ["GHSA-c1", "GHSA-c2"]);
    assert!(results[3].is_empty());
    assert_eq!(ids(&results[4]), ["GHSA-e"]);
}

#[tokio::test]
async fn batches_hold_at_most_a_thousand_queries() {
    let server = MockServer::start().await;
    let osv = Osv::new(&[]);
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(osv.clone())
        .mount(&server)
        .await;
    let purls: Vec<String> = (0..2500)
        .map(|number| format!("pkg:npm/p{number}@1"))
        .collect();
    let results = client(&server).query(&purls).await.unwrap();
    assert_eq!(results.len(), 2500);
    assert_eq!(*osv.batch_sizes.lock().unwrap(), [1000, 1000, 500]);
}

#[tokio::test]
async fn paginated_answers_are_followed() {
    let server = MockServer::start().await;
    let osv = Osv::new(&[
        (
            "pkg:pypi/django@1.0",
            vec![vec!["PYSEC-1", "PYSEC-2"], vec!["PYSEC-3"], vec!["PYSEC-4"]],
        ),
        ("pkg:pypi/flask@0.1", vec![vec!["PYSEC-9"]]),
    ]);
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(osv.clone())
        .mount(&server)
        .await;
    let purls = vec![
        "pkg:pypi/django@1.0".to_owned(),
        "pkg:pypi/flask@0.1".to_owned(),
    ];
    let results = client(&server).query(&purls).await.unwrap();
    assert_eq!(
        ids(&results[0]),
        ["PYSEC-1", "PYSEC-2", "PYSEC-3", "PYSEC-4"]
    );
    assert_eq!(ids(&results[1]), ["PYSEC-9"]);
    assert_eq!(
        *osv.batch_sizes.lock().unwrap(),
        [2, 1, 1],
        "only the paginated query is sent again"
    );
}

#[tokio::test]
async fn transient_failures_are_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(Osv::new(&[("pkg:npm/a@1", vec![vec!["GHSA-a"]])]))
        .mount(&server)
        .await;
    let results = client(&server)
        .query(&["pkg:npm/a@1".to_owned()])
        .await
        .unwrap();
    assert_eq!(ids(&results[0]), ["GHSA-a"]);
}

#[tokio::test]
async fn persistent_failures_fail_the_whole_query() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .expect(3)
        .mount(&server)
        .await;
    let error = client(&server)
        .query(&["pkg:npm/a@1".to_owned()])
        .await
        .unwrap_err();
    assert!(matches!(error, SourceError::Status { status, .. } if status == 500));
}

#[tokio::test]
async fn client_errors_are_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid query"))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server)
        .query(&["pkg:npm/a@1?bad".to_owned()])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Invalid query"));
}

#[tokio::test]
async fn mismatched_and_malformed_answers_are_errors() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": []})))
        .mount(&server)
        .await;
    let error = client(&server)
        .query(&["pkg:npm/a@1".to_owned()])
        .await
        .unwrap_err();
    assert!(matches!(error, SourceError::InvalidResponse { .. }));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&server)
        .await;
    let error = client(&server)
        .query(&["pkg:npm/a@1".to_owned()])
        .await
        .unwrap_err();
    assert!(matches!(error, SourceError::InvalidResponse { .. }));
}

#[tokio::test]
async fn unreachable_servers_are_errors() {
    let client = OsvClient::new("http://127.0.0.1:9/".parse().unwrap())
        .unwrap()
        .with_retry_delay(Duration::from_millis(1));
    let error = client.query(&["pkg:npm/a@1".to_owned()]).await.unwrap_err();
    assert!(matches!(error, SourceError::Request { .. }));
}

#[tokio::test]
async fn vulnerability_details_are_fetched() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vulns/GHSA-29mw-wpgm-hmr9"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "GHSA-29mw-wpgm-hmr9",
            "modified": "2024-06-01T00:00:00Z",
            "aliases": ["CVE-2020-28500"],
            "summary": "Regular Expression Denial of Service in lodash",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]
            }],
            "schema_version": "1.6.0",
            "a_field_from_the_future": {"nested": true}
        })))
        .mount(&server)
        .await;
    let record = client(&server)
        .vulnerability("GHSA-29mw-wpgm-hmr9")
        .await
        .unwrap();
    assert_eq!(record.aliases, ["CVE-2020-28500"]);
    assert_eq!(record.fixed_versions(Some("lodash")), ["4.17.21"]);
    assert!(record.fixed_versions(Some("other")).is_empty());

    let error = client(&server)
        .vulnerability("GHSA-missing")
        .await
        .unwrap_err();
    assert!(matches!(error, SourceError::Status { status, .. } if status == 404));
}
