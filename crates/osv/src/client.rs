//! Where vulnerabilities come from, and the client for OSV.dev's API.

use std::{collections::BTreeMap, future::Future, time::Duration};

use chrono::{DateTime, Utc};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::schema::Vulnerability;

/// A vulnerability affecting a package, as returned by a batch query: details are fetched
/// separately and cached, refreshed when `modified` changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityReference {
    pub id: String,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("request to {url} failed: {source}")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{url} answered {status}: {body}")]
    Status {
        url: String,
        status: StatusCode,
        body: String,
    },
    #[error("unexpected response from {url}: {message}")]
    InvalidResponse { url: String, message: String },
}

/// A source of vulnerability data. OSV.dev's API is the only one today; an offline source built
/// from OSV's bulk exports can implement the same trait.
pub trait VulnerabilitySource: Send + Sync {
    /// Returns, for each package URL (with a version), the vulnerabilities affecting it, in the
    /// same order. Fails as a whole if any part fails, so a partial answer is never mistaken
    /// for "no vulnerabilities".
    fn query(
        &self,
        purls: &[String],
    ) -> impl Future<Output = Result<Vec<Vec<VulnerabilityReference>>, SourceError>> + Send;

    /// Returns the full record of a vulnerability.
    fn vulnerability(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<Vulnerability, SourceError>> + Send;
}

/// The default address of OSV.dev's API.
pub const DEFAULT_URL: &str = "https://api.osv.dev/";
/// OSV accepts at most this many queries per batch.
pub const MAXIMUM_BATCH_SIZE: usize = 1000;
/// A guard against a server that would paginate forever.
const MAXIMUM_PAGES: usize = 100;
const ATTEMPTS: u32 = 3;

/// Client for OSV.dev's API (`/v1/querybatch` and `/v1/vulns/{id}`).
#[derive(Debug, Clone)]
pub struct OsvClient {
    http: reqwest::Client,
    base_url: Url,
    batch_size: usize,
    retry_delay: Duration,
}

#[derive(Serialize)]
struct BatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Serialize)]
struct Query<'a> {
    package: PackageQuery<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Serialize)]
struct PackageQuery<'a> {
    purl: &'a str,
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<VulnerabilityReference>,
    #[serde(default)]
    next_page_token: Option<String>,
}

impl OsvClient {
    /// A client for the API at `base_url` (normally [`DEFAULT_URL`]).
    pub fn new(base_url: Url) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .user_agent(concat!(
                "nanobom/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/AlixANNERAUD/nanobom)"
            ))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self {
            http,
            base_url,
            batch_size: MAXIMUM_BATCH_SIZE,
            retry_delay: Duration::from_secs(2),
        })
    }

    /// Uses smaller batches, for tests.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size.clamp(1, MAXIMUM_BATCH_SIZE);
        self
    }

    /// Changes the delay before retrying a failed request, for tests.
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay = delay;
        self
    }

    fn url(&self, path: &str) -> Result<Url, SourceError> {
        self.base_url
            .join(path)
            .map_err(|error| SourceError::InvalidResponse {
                url: self.base_url.to_string(),
                message: error.to_string(),
            })
    }

    /// Sends a request, retrying network errors, rate limiting and server errors.
    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        body: Option<&BatchRequest<'_>>,
    ) -> Result<T, SourceError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let request = match body {
                Some(body) => self.http.post(url.clone()).json(body),
                None => self.http.get(url.clone()),
            };
            let error = match request.send().await {
                Ok(response) if response.status().is_success() => {
                    let bytes = response
                        .bytes()
                        .await
                        .map_err(|source| SourceError::Request {
                            url: url.to_string(),
                            source,
                        })?;
                    return serde_json::from_slice(&bytes).map_err(|error| {
                        record_error("invalid_response");
                        SourceError::InvalidResponse {
                            url: url.to_string(),
                            message: error.to_string(),
                        }
                    });
                }
                Ok(response) => {
                    let status = response.status();
                    let body: String = response
                        .text()
                        .await
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect();
                    SourceError::Status {
                        url: url.to_string(),
                        status,
                        body,
                    }
                }
                Err(source) => SourceError::Request {
                    url: url.to_string(),
                    source,
                },
            };
            let retryable = match &error {
                SourceError::Status { status, .. } => {
                    status.is_server_error() || *status == StatusCode::TOO_MANY_REQUESTS
                }
                SourceError::Request { .. } => true,
                SourceError::InvalidResponse { .. } => false,
            };
            record_error(match &error {
                SourceError::Status { .. } => "status",
                _ => "request",
            });
            if !retryable || attempt >= ATTEMPTS {
                return Err(error);
            }
            tracing::warn!(%error, attempt, "OSV request failed, retrying");
            tokio::time::sleep(self.retry_delay * attempt).await;
        }
    }

    /// Sends one batch of at most `batch_size` queries.
    async fn batch(&self, queries: Vec<Query<'_>>) -> Result<Vec<BatchResult>, SourceError> {
        let url = self.url("v1/querybatch")?;
        let expected = queries.len();
        let response: BatchResponse = self
            .send(url.clone(), Some(&BatchRequest { queries }))
            .await?;
        if response.results.len() != expected {
            record_error("invalid_response");
            return Err(SourceError::InvalidResponse {
                url: url.to_string(),
                message: format!("{} results for {expected} queries", response.results.len()),
            });
        }
        Ok(response.results)
    }
}

fn record_error(kind: &'static str) {
    metrics::counter!("nanobom_osv_request_errors_total", "kind" => kind).increment(1);
}

impl VulnerabilitySource for OsvClient {
    async fn query(
        &self,
        purls: &[String],
    ) -> Result<Vec<Vec<VulnerabilityReference>>, SourceError> {
        let mut found: Vec<Vec<VulnerabilityReference>> = vec![Vec::new(); purls.len()];
        // Queries still to send: the index of the package URL and its page token.
        let mut pending: Vec<(usize, Option<String>)> =
            (0..purls.len()).map(|index| (index, None)).collect();
        let mut pages: BTreeMap<usize, usize> = BTreeMap::new();
        while !pending.is_empty() {
            let mut next = Vec::new();
            for chunk in pending.chunks(self.batch_size) {
                let queries = chunk
                    .iter()
                    .map(|(index, token)| Query {
                        package: PackageQuery {
                            purl: &purls[*index],
                        },
                        page_token: token.as_deref(),
                    })
                    .collect();
                let results = self.batch(queries).await?;
                for ((index, _), result) in chunk.iter().zip(results) {
                    found[*index].extend(result.vulns);
                    if let Some(token) = result.next_page_token.filter(|token| !token.is_empty()) {
                        let count = pages.entry(*index).or_default();
                        *count += 1;
                        if *count >= MAXIMUM_PAGES {
                            return Err(SourceError::InvalidResponse {
                                url: self.base_url.to_string(),
                                message: format!(
                                    "more than {MAXIMUM_PAGES} pages for {}",
                                    purls[*index]
                                ),
                            });
                        }
                        next.push((*index, Some(token)));
                    }
                }
            }
            pending = next;
        }
        for references in &mut found {
            references.sort_by(|left, right| left.id.cmp(&right.id));
            references.dedup_by(|left, right| left.id == right.id);
        }
        Ok(found)
    }

    async fn vulnerability(&self, id: &str) -> Result<Vulnerability, SourceError> {
        let mut url = self.url("v1/vulns/")?;
        url.path_segments_mut()
            .map_err(|()| SourceError::InvalidResponse {
                url: self.base_url.to_string(),
                message: "the base URL cannot have a path".to_owned(),
            })?
            .pop_if_empty()
            .push(id);
        self.send(url, None).await
    }
}
