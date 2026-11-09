//! Helpers for tests: a fresh, migrated database per test, a fake vulnerability source and an
//! SMTP sink.
//!
//! Tests use a private in-memory SQLite database by default. Set `NANOBOM_TEST_DATABASE_URL` to
//! run them against another database such as PostgreSQL; the schema is then dropped and recreated
//! for each test, so run them one at a time (`--test-threads 1`).
//!
//! The module is compiled for this crate's tests and, through the `testing` feature, for the
//! server's; it is not part of the production build.

use std::sync::atomic::{AtomicU64, Ordering};

use nanobom_migration::{Migrator, MigratorTrait};
use sea_orm::DatabaseConnection;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

/// Returns a connection to an empty database with every migration applied. Each call gets its
/// own SQLite in-memory database, named after the process and a counter, which lives as long as
/// a connection to it stays open.
pub async fn database() -> DatabaseConnection {
    match std::env::var("NANOBOM_TEST_DATABASE_URL") {
        Ok(url) => {
            let database = crate::database::connect(&url)
                .await
                .expect("connect to the test database");
            Migrator::fresh(&database)
                .await
                .expect("recreate the test schema");
            database
        }
        Err(_) => {
            let number = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let url = format!(
                "sqlite:file:nanobom-test-{}-{number}?mode=memory&cache=shared",
                std::process::id()
            );
            let database = crate::database::connect(&url)
                .await
                .expect("open the in-memory test database");
            crate::database::migrate(&database)
                .await
                .expect("migrate the test database");
            database
        }
    }
}

/// An in-memory vulnerability source: records are attached to package URLs and can change
/// between runs, and the source can be told to fail, to panic once or to hold queries until
/// resumed.
///
/// Package URLs are matched exactly, so attach records to the query form the evaluator sends
/// (without qualifiers or subpath).
#[derive(Default)]
pub struct FakeSource {
    state: std::sync::Mutex<FakeState>,
    resumed: tokio::sync::Notify,
    query_started: tokio::sync::Notify,
}

#[derive(Default)]
struct FakeState {
    affected: std::collections::BTreeMap<String, Vec<String>>,
    records: std::collections::BTreeMap<String, nanobom_osv::Vulnerability>,
    failing: bool,
    panicking: bool,
    paused: bool,
    fetches: Vec<String>,
}

impl FakeSource {
    /// Adds or replaces a record, affecting the given package URLs.
    pub fn publish(&self, record: serde_json::Value, purls: &[&str]) {
        let record: nanobom_osv::Vulnerability =
            serde_json::from_value(record).expect("a valid OSV record");
        let mut state = self.state.lock().expect("not poisoned");
        for purl in purls {
            let identifiers = state.affected.entry((*purl).to_owned()).or_default();
            if !identifiers.contains(&record.id) {
                identifiers.push(record.id.clone());
            }
        }
        state.records.insert(record.id.clone(), record);
    }

    /// Stops reporting a vulnerability for a package URL, as when OSV narrows a range.
    pub fn retract(&self, id: &str, purl: &str) {
        let mut state = self.state.lock().expect("not poisoned");
        if let Some(identifiers) = state.affected.get_mut(purl) {
            identifiers.retain(|identifier| identifier != id);
        }
    }

    /// Makes every later query fail, as an unreachable OSV would; fetching details still works.
    pub fn set_failing(&self, failing: bool) {
        self.state.lock().expect("not poisoned").failing = failing;
    }

    /// Makes the next query panic, as a bug in a run would.
    pub fn panic_once(&self) {
        self.state.lock().expect("not poisoned").panicking = true;
    }

    /// Holds queries until `resume`, keeping runs in progress.
    pub fn pause(&self) {
        self.state.lock().expect("not poisoned").paused = true;
    }

    /// Releases held queries.
    pub fn resume(&self) {
        self.state.lock().expect("not poisoned").paused = false;
        self.resumed.notify_waiters();
    }

    /// Waits until a query has started (since the previous call).
    pub async fn query_started(&self) {
        self.query_started.notified().await;
    }

    /// The identifiers whose details were fetched, in order.
    pub fn fetches(&self) -> Vec<String> {
        self.state.lock().expect("not poisoned").fetches.clone()
    }
}

impl nanobom_osv::VulnerabilitySource for FakeSource {
    async fn query(
        &self,
        purls: &[String],
    ) -> Result<Vec<Vec<nanobom_osv::VulnerabilityReference>>, nanobom_osv::SourceError> {
        self.query_started.notify_one();
        loop {
            let resumed = self.resumed.notified();
            if !self.state.lock().expect("not poisoned").paused {
                break;
            }
            resumed.await;
        }
        let mut state = self.state.lock().expect("not poisoned");
        if std::mem::take(&mut state.panicking) {
            // Released first, so that the panic does not poison the state.
            drop(state);
            panic!("the fake source panics");
        }
        if state.failing {
            return Err(nanobom_osv::SourceError::InvalidResponse {
                url: "fake".to_owned(),
                message: "the source is unreachable".to_owned(),
            });
        }
        Ok(purls
            .iter()
            .map(|purl| {
                state
                    .affected
                    .get(purl)
                    .into_iter()
                    .flatten()
                    .map(|id| nanobom_osv::VulnerabilityReference {
                        id: id.clone(),
                        modified: state.records[id].modified,
                    })
                    .collect()
            })
            .collect())
    }

    async fn vulnerability(
        &self,
        id: &str,
    ) -> Result<nanobom_osv::Vulnerability, nanobom_osv::SourceError> {
        let mut state = self.state.lock().expect("not poisoned");
        state.fetches.push(id.to_owned());
        state
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| nanobom_osv::SourceError::InvalidResponse {
                url: "fake".to_owned(),
                message: format!("{id} is unknown"),
            })
    }
}

/// A message accepted by an [`SmtpSink`].
#[derive(Debug, Clone)]
pub struct ReceivedEmail {
    /// The envelope sender (`MAIL FROM`).
    pub from: String,
    /// The envelope recipients (`RCPT TO`).
    pub recipients: Vec<String>,
    /// The message as sent, headers and MIME parts, with dot-stuffing undone.
    pub data: String,
}

#[derive(Default)]
struct SinkState {
    received: Vec<ReceivedEmail>,
    /// Replies to the next `RCPT TO` commands, instead of accepting them.
    rejections: std::collections::VecDeque<String>,
}

/// An SMTP server on the loopback interface that speaks just enough SMTP for lettre (no TLS,
/// no authentication) and records the messages it accepts, so that tests exercise the real
/// SMTP client without reaching the network. It can be told to refuse the next recipients with
/// a given reply, transient (4xx) or permanent (5xx).
pub struct SmtpSink {
    address: std::net::SocketAddr,
    state: std::sync::Arc<std::sync::Mutex<SinkState>>,
}

impl SmtpSink {
    /// Starts the sink on a free port; it serves until the test's runtime ends.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the SMTP sink");
        let address = listener.local_addr().expect("the sink's address");
        let state = std::sync::Arc::new(std::sync::Mutex::new(SinkState::default()));
        let shared = std::sync::Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_smtp(stream, std::sync::Arc::clone(&shared)));
            }
        });
        Self { address, state }
    }

    /// The URL of the sink for `NANOBOM_SMTP_URL`.
    pub fn url(&self) -> String {
        format!("smtp://{}", self.address)
    }

    /// Answers the next `RCPT TO` with this reply, such as `450 4.2.1 mailbox busy`.
    pub fn reject_next(&self, reply: &str) {
        self.state
            .lock()
            .expect("not poisoned")
            .rejections
            .push_back(reply.to_owned());
    }

    /// The messages accepted so far, in order.
    pub fn received(&self) -> Vec<ReceivedEmail> {
        self.state.lock().expect("not poisoned").received.clone()
    }
}

async fn serve_smtp(
    stream: tokio::net::TcpStream,
    state: std::sync::Arc<std::sync::Mutex<SinkState>>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut from = String::new();
    let mut recipients = Vec::new();
    if writer.write_all(b"220 sink ESMTP\r\n").await.is_err() {
        return;
    }
    while let Ok(Some(line)) = lines.next_line().await {
        let command = line.to_ascii_uppercase();
        let reply = if command.starts_with("EHLO") || command.starts_with("HELO") {
            "250 sink".to_owned()
        } else if command.starts_with("MAIL FROM:") {
            from = line["MAIL FROM:".len()..].trim().to_owned();
            recipients.clear();
            "250 2.1.0 ok".to_owned()
        } else if command.starts_with("RCPT TO:") {
            let rejection = state.lock().expect("not poisoned").rejections.pop_front();
            match rejection {
                Some(reply) => reply,
                None => {
                    recipients.push(
                        line["RCPT TO:".len()..]
                            .trim()
                            .trim_matches(['<', '>'])
                            .to_owned(),
                    );
                    "250 2.1.5 ok".to_owned()
                }
            }
        } else if command == "DATA" {
            if writer.write_all(b"354 go ahead\r\n").await.is_err() {
                return;
            }
            let mut data = String::new();
            while let Ok(Some(line)) = lines.next_line().await {
                if line == "." {
                    break;
                }
                data.push_str(line.strip_prefix('.').unwrap_or(&line));
                data.push('\n');
            }
            state
                .lock()
                .expect("not poisoned")
                .received
                .push(ReceivedEmail {
                    from: from.trim_matches(['<', '>']).to_owned(),
                    recipients: std::mem::take(&mut recipients),
                    data,
                });
            "250 2.0.0 queued".to_owned()
        } else if command == "QUIT" {
            let _ = writer.write_all(b"221 2.0.0 bye\r\n").await;
            return;
        } else {
            // RSET, NOOP and anything else.
            "250 ok".to_owned()
        };
        if writer
            .write_all(format!("{reply}\r\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}
