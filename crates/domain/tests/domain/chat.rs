//! Slack and Microsoft Teams webhooks: the messages rendered for each event, their limits and
//! escaping, the format setting and deliveries to a receiver of each kind.

use chrono::{Duration, Utc};
use nanobom_domain::{
    access::Actor,
    chat::MAX_ITEMS,
    deliveries::{self, Outcome, State},
    evaluation::{NewFinding, RunOutcome, Scope, Trigger},
    notifications::{
        self, Format, NewFindingsPayload, Payload, PayloadFinding, PayloadOrganization, PayloadRun,
        PayloadStaleProject, StaleProjectsPayload, Webhook,
    },
    organizations, projects, testing,
    users::{self, NewUser},
};
use nanobom_entity::{projects as project_entity, webhook_deliveries};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn finding(id: &str) -> PayloadFinding {
    PayloadFinding {
        project: "web".to_owned(),
        component: "pkg:npm/lodash@4.17.20".to_owned(),
        vulnerability: id.to_owned(),
        aliases: vec!["CVE-2021-23337".to_owned()],
        severity: Severity::High,
        cvss_score: Some(7.2),
        summary: Some("Command Injection in lodash".to_owned()),
        reopened: false,
        reason: "new".to_owned(),
        known_exploited: false,
        kev_due_date: None,
        epss: None,
        epss_percentile: None,
        introduced_via: Vec::new(),
        url: "https://nanobom.example.org/findings/7".to_owned(),
    }
}

fn payload(findings: Vec<PayloadFinding>) -> NewFindingsPayload {
    NewFindingsPayload {
        event: "findings.new".to_owned(),
        organization: PayloadOrganization {
            slug: "acme".to_owned(),
            name: "Acme".to_owned(),
            url: "https://nanobom.example.org/organizations/acme".to_owned(),
        },
        run: PayloadRun {
            id: 42,
            trigger: "scheduled".to_owned(),
            started_at: Utc::now().fixed_offset(),
        },
        count: findings.len(),
        highest_severity: findings
            .iter()
            .map(|finding| finding.severity)
            .max()
            .unwrap_or(Severity::Unknown),
        known_exploited_count: findings
            .iter()
            .filter(|finding| finding.known_exploited)
            .count(),
        findings,
    }
}

fn stale(count: usize) -> StaleProjectsPayload {
    StaleProjectsPayload {
        event: "projects.stale".to_owned(),
        organization: PayloadOrganization {
            slug: "acme".to_owned(),
            name: "Acme".to_owned(),
            url: "https://nanobom.example.org/organizations/acme".to_owned(),
        },
        projects: (0..count)
            .map(|index| PayloadStaleProject {
                project: format!("web-{index}"),
                last_upload_at: (index % 2 == 0)
                    .then(|| (Utc::now() - Duration::days(40)).fixed_offset()),
                url: format!("https://nanobom.example.org/organizations/acme/projects/web-{index}"),
            })
            .collect(),
    }
}

fn rendered(payload: &impl Payload, format: Format) -> Value {
    serde_json::from_str(&payload.render(format)).expect("a JSON body")
}

/// The text of a Slack block, or of its first element for a context block.
fn block_text(block: &Value) -> &str {
    block["text"]["text"]
        .as_str()
        .or_else(|| block["elements"][0]["text"].as_str())
        .expect("a block with text")
}

/// The texts of the text blocks of an Adaptive Card body, containers included.
fn card_texts(items: &Value) -> Vec<String> {
    let mut texts = Vec::new();
    for item in items.as_array().expect("a list of items") {
        if let Some(text) = item["text"].as_str() {
            texts.push(text.to_owned());
        }
        if item["items"].is_array() {
            texts.extend(card_texts(&item["items"]));
        }
    }
    texts
}

#[test]
fn the_json_format_is_the_document_itself() {
    let payload = payload(vec![finding("GHSA-1")]);
    assert_eq!(
        payload.render(Format::Json),
        serde_json::to_string(&payload).unwrap()
    );
}

#[test]
fn a_slack_message_has_a_fallback_text_and_blocks() {
    let mut exploited = finding("CVE-2021-23337");
    exploited.severity = Severity::Critical;
    exploited.known_exploited = true;
    exploited.reopened = true;
    exploited.introduced_via = vec!["express".to_owned(), "body-parser".to_owned()];
    let message = rendered(&payload(vec![exploited, finding("GHSA-2")]), Format::Slack);

    assert_eq!(
        message["text"],
        "Acme: 2 new findings (highest severity: critical, 1 known exploited)"
    );
    let blocks = message["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 4, "header, two findings and a footer");
    assert_eq!(blocks[0]["type"], "header");
    assert_eq!(blocks[0]["text"]["type"], "plain_text");
    assert_eq!(blocks[0]["text"]["text"], message["text"]);

    assert_eq!(blocks[1]["type"], "section");
    assert_eq!(blocks[1]["text"]["type"], "mrkdwn");
    assert_eq!(
        block_text(&blocks[1]),
        "*<https://nanobom.example.org/findings/7|CVE-2021-23337>* - critical - reopened - known exploited\n\
         `pkg:npm/lodash@4.17.20` in web\n\
         Command Injection in lodash\n\
         Introduced via `express`, `body-parser`"
    );
    assert_eq!(
        block_text(&blocks[2]),
        "*<https://nanobom.example.org/findings/7|GHSA-2>* - high\n\
         `pkg:npm/lodash@4.17.20` in web\n\
         Command Injection in lodash"
    );
    assert_eq!(blocks[3]["type"], "context");
    assert_eq!(
        block_text(&blocks[3]),
        "<https://nanobom.example.org/organizations/acme|Open Acme in nanobom>"
    );
}

#[test]
fn a_slack_message_lists_a_few_findings_and_counts_the_others() {
    let long = "x".repeat(10_000);
    let findings: Vec<PayloadFinding> = (0..60)
        .map(|index| {
            let mut finding = finding(&format!("GHSA-{index}"));
            finding.component = long.clone();
            finding.summary = Some(long.clone());
            finding.project = long.clone();
            finding.introduced_via = vec![long.clone(); 20];
            finding
        })
        .collect();
    let mut payload = payload(findings);
    payload.organization.name = long.clone();
    let message = rendered(&payload, Format::Slack);

    let blocks = message["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), MAX_ITEMS + 2, "far below Slack's 50 blocks");
    assert!(blocks[0]["text"]["text"].as_str().unwrap().chars().count() <= 150);
    for block in &blocks[1..=MAX_ITEMS] {
        assert!(block_text(block).chars().count() <= 3000);
    }
    assert!(block_text(&blocks[MAX_ITEMS + 1]).starts_with("50 more findings not shown. <"));
    assert!(
        message["text"].as_str().unwrap().chars().count() <= 3000,
        "a fallback text well below the 4000 characters Slack recommends"
    );
}

#[test]
fn slack_special_characters_are_escaped() {
    let mut hostile = finding("A&B<c>");
    hostile.component = "pkg:npm/<@channel>&`x`".to_owned();
    hostile.summary = Some("<!here> &amp; <https://evil.example|click>\nnew line".to_owned());
    hostile.project = "<web>".to_owned();
    hostile.introduced_via = vec!["a>b".to_owned()];
    hostile.url = "https://nanobom.example.org/findings/7?a=1|2>3".to_owned();
    let mut payload = payload(vec![hostile]);
    payload.organization.name = "R&D <Team>".to_owned();
    let message = rendered(&payload, Format::Slack);

    assert_eq!(
        message["text"],
        "R&amp;D &lt;Team&gt;: 1 new finding (highest severity: high)"
    );
    let text = block_text(&message["blocks"][1]);
    assert_eq!(
        text,
        "*<https://nanobom.example.org/findings/7?a=1%7C2%3E3|A&amp;B&lt;c&gt;>* - high\n\
         `pkg:npm/&lt;@channel&gt;&amp;'x'` in &lt;web&gt;\n\
         &lt;!here&gt; &amp;amp; &lt;https://evil.example|click&gt; new line\n\
         Introduced via `a&gt;b`"
    );
    // The header is plain text: Slack does not interpret entities there.
    assert_eq!(
        message["blocks"][0]["text"]["text"],
        "R&D <Team>: 1 new finding (highest severity: high)"
    );
}

#[test]
fn a_slack_message_for_stale_projects() {
    let message = rendered(&stale(12), Format::Slack);
    assert_eq!(message["text"], "Acme: 12 projects stopped sending SBOMs");
    let blocks = message["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), MAX_ITEMS + 2);
    assert!(block_text(&blocks[1]).starts_with(
        "*<https://nanobom.example.org/organizations/acme/projects/web-0|web-0>* - last SBOM "
    ));
    assert_eq!(
        block_text(&blocks[2]),
        "*<https://nanobom.example.org/organizations/acme/projects/web-1|web-1>* - never received an SBOM"
    );
    assert_eq!(
        block_text(&blocks[MAX_ITEMS + 1]),
        "2 more projects not shown. <https://nanobom.example.org/organizations/acme|Open Acme in nanobom>"
    );
    assert_eq!(
        rendered(&stale(1), Format::Slack)["text"],
        "Acme: 1 project stopped sending SBOMs"
    );
}

#[test]
fn a_teams_message_carries_one_adaptive_card() {
    let mut exploited = finding("CVE-2021-23337");
    exploited.severity = Severity::Critical;
    exploited.known_exploited = true;
    exploited.introduced_via = vec!["express".to_owned()];
    let message = rendered(&payload(vec![exploited, finding("GHSA-2")]), Format::Teams);

    assert_eq!(message["type"], "message");
    let attachments = message["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(
        attachments[0]["contentType"],
        "application/vnd.microsoft.card.adaptive"
    );
    let card = &attachments[0]["content"];
    assert_eq!(card["type"], "AdaptiveCard");
    assert_eq!(card["version"], "1.2");
    assert_eq!(
        card["$schema"],
        "http://adaptivecards.io/schemas/adaptive-card.json"
    );
    assert_eq!(card["msteams"]["width"], "Full");
    assert_eq!(card["actions"][0]["type"], "Action.OpenUrl");
    assert_eq!(
        card["actions"][0]["url"],
        "https://nanobom.example.org/organizations/acme"
    );
    assert_eq!(card["actions"][0]["title"], "Open Acme in nanobom");

    assert_eq!(
        card_texts(&card["body"]),
        [
            "Acme: 2 new findings (highest severity: critical, 1 known exploited)",
            "**[CVE-2021-23337](https://nanobom.example.org/findings/7)** - critical - known exploited",
            "pkg:npm/lodash@4.17.20 in web",
            "Command Injection in lodash",
            "Introduced via express",
            "**[GHSA-2](https://nanobom.example.org/findings/7)** - high",
            "pkg:npm/lodash@4.17.20 in web",
            "Command Injection in lodash",
        ]
    );
    assert_eq!(card["body"][1]["items"][0]["color"], "Attention");
}

#[test]
fn a_teams_message_stays_under_the_size_limit_with_many_findings() {
    // Four bytes a character: the worst case for a limit counted in bytes.
    let long = "\u{1F4A5}".repeat(10_000);
    let findings: Vec<PayloadFinding> = (0..60)
        .map(|index| {
            let mut finding = finding(&format!("GHSA-{index}"));
            finding.component = long.clone();
            finding.summary = Some(long.clone());
            finding.project = long.clone();
            finding.introduced_via = vec![long.clone(); 20];
            finding
        })
        .collect();
    let body = payload(findings).render(Format::Teams);
    assert!(body.len() <= 28 * 1024, "{} bytes", body.len());
    let message: Value = serde_json::from_str(&body).unwrap();
    let texts = card_texts(&message["attachments"][0]["content"]["body"]);
    assert!(
        texts.last().unwrap().ends_with("more findings not shown."),
        "{:?}",
        texts.last()
    );

    // An ordinary message lists the first ten.
    let message = rendered(
        &payload(
            (0..60)
                .map(|index| finding(&format!("GHSA-{index}")))
                .collect(),
        ),
        Format::Teams,
    );
    let body = &message["attachments"][0]["content"]["body"];
    assert_eq!(body.as_array().unwrap().len(), MAX_ITEMS + 2);
    assert_eq!(
        card_texts(body).last().unwrap(),
        "50 more findings not shown."
    );
}

#[test]
fn teams_markdown_is_escaped() {
    let mut hostile = finding("GHSA-1");
    hostile.summary = Some("*bold* [click](https://evil.example) <b>x</b> _y_ `z`".to_owned());
    hostile.component = "pkg:npm/a_b*c".to_owned();
    hostile.url = "https://nanobom.example.org/findings/7?a=(1)".to_owned();
    let message = rendered(&payload(vec![hostile]), Format::Teams);
    let texts = card_texts(&message["attachments"][0]["content"]["body"]);
    assert!(
        texts[1].contains("(https://nanobom.example.org/findings/7?a=%281%29)"),
        "{}",
        texts[1]
    );
    assert_eq!(texts[2], "pkg:npm/a\\_b\\*c in web");
    assert_eq!(
        texts[3],
        "\\*bold\\* \\[click\\](https://evil.example) \\<b\\>x\\</b\\> \\_y\\_ \\`z\\`"
    );
}

#[test]
fn a_teams_message_for_stale_projects() {
    let message = rendered(&stale(12), Format::Teams);
    let card = &message["attachments"][0]["content"];
    let texts = card_texts(&card["body"]);
    assert_eq!(texts[0], "Acme: 12 projects stopped sending SBOMs");
    assert!(texts[1].starts_with(
        "**[web-0](https://nanobom.example.org/organizations/acme/projects/web-0)** - last SBOM "
    ));
    assert!(texts[2].ends_with("- never received an SBOM"));
    assert_eq!(texts.last().unwrap(), "2 more projects not shown.");
    assert_eq!(texts.len(), MAX_ITEMS + 2);
}

#[test]
fn documents_without_a_chat_rendering_stay_json() {
    let failed = notifications::RunFailedPayload {
        event: "run.failed".to_owned(),
        instance_url: "https://nanobom.example.org/".to_owned(),
        run: PayloadRun {
            id: 1,
            trigger: "manual".to_owned(),
            started_at: Utc::now().fixed_offset(),
        },
        scope: "all".to_owned(),
        error: "timeout".to_owned(),
    };
    for format in Format::ALL {
        assert_eq!(rendered(&failed, format)["event"], "run.failed");
    }
}

async fn owner(database: &DatabaseConnection) -> Actor {
    Actor::from_user(
        &users::create(
            database,
            NewUser {
                username: "owner".to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap(),
    )
}

fn webhook(url: String, format: Format) -> Webhook {
    Webhook {
        url,
        minimum_severity: Severity::Unknown,
        enabled: true,
        exploited_only: false,
        format,
    }
}

fn run_with(organization: i64) -> RunOutcome {
    RunOutcome {
        run_id: 42,
        scope: Scope::All,
        trigger: Trigger::Scheduled,
        started_at: Utc::now().fixed_offset(),
        duration_seconds: 1.5,
        error: None,
        component_count: 3,
        vulnerability_count: 2,
        new_findings: vec![NewFinding {
            finding_id: 7,
            organization_id: organization,
            organization_slug: "acme".to_owned(),
            project_id: 0,
            project_slug: "web".to_owned(),
            purl: "pkg:npm/lodash@4.17.20".to_owned(),
            vulnerability_id: "GHSA-35jh-r3h4-6jhm".to_owned(),
            aliases: vec!["CVE-2021-23337".to_owned()],
            summary: Some("Command Injection in lodash".to_owned()),
            severity: Severity::High,
            cvss_score: Some(7.2),
            reopened: false,
        }],
        fixed_findings: 0,
    }
}

#[tokio::test]
async fn the_format_is_a_setting_and_defaults_to_json() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    assert_eq!(Format::default(), Format::Json);
    for format in Format::ALL {
        assert_eq!(Format::parse(format.as_str()), Some(format));
    }
    assert_eq!(Format::parse("email"), None);

    let saved = notifications::set(
        &database,
        &owner,
        organization.id,
        &webhook(
            "https://hooks.slack.com/services/T0/B0/x".to_owned(),
            Format::Slack,
        ),
    )
    .await
    .unwrap();
    assert_eq!(saved.format, Format::Slack);
    let read = notifications::get(&database, &owner, organization.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.format, Format::Slack);
}

#[tokio::test]
async fn deliveries_are_rendered_and_posted_in_the_webhooks_format() {
    for (format, success, expected) in [
        (Format::Json, ResponseTemplate::new(204), "event"),
        (
            Format::Slack,
            ResponseTemplate::new(200).set_body_string("ok"),
            "blocks",
        ),
        (Format::Teams, ResponseTemplate::new(202), "attachments"),
    ] {
        let database = testing::database().await;
        let owner = owner(&database).await;
        let organization = organizations::create(&database, &owner, "acme", "Acme")
            .await
            .unwrap();
        let receiver = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("content-type", "application/json"))
            .respond_with(success)
            .expect(1)
            .mount(&receiver)
            .await;
        notifications::set(
            &database,
            &owner,
            organization.id,
            &webhook(format!("{}/hook", receiver.uri()), format),
        )
        .await
        .unwrap();

        let deliveries = notifications::new_findings_deliveries(
            &database,
            &run_with(organization.id),
            &"https://nanobom.example.org/".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(deliveries[0].format, format);
        let outcomes = notifications::Notifier::new()
            .unwrap()
            .deliver(&database, deliveries)
            .await
            .unwrap();
        assert_eq!(outcomes, [Outcome::Delivered], "{format:?}");

        let requests = receiver.received_requests().await.unwrap();
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert!(body.get(expected).is_some(), "{format:?}: {body}");
        let recent = deliveries::recent(&database, &owner, organization.id, 10)
            .await
            .unwrap();
        assert_eq!(recent[0].state, State::Delivered);

        // The queue holds the body that was posted, which every retry sends again.
        let stored = webhook_deliveries::Entity::find_by_id(recent[0].id)
            .one(&database)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.payload.as_bytes(), requests[0].body.as_slice());
        match format {
            Format::Json => {}
            Format::Slack => {
                assert_eq!(
                    body["blocks"][1]["text"]["text"]
                        .as_str()
                        .unwrap()
                        .lines()
                        .next(),
                    Some("*<https://nanobom.example.org/findings/7|GHSA-35jh-r3h4-6jhm>* - high")
                );
                assert_eq!(recent[0].last_status.as_deref(), Some("200 OK"));
            }
            Format::Teams => {
                assert_eq!(body["type"], "message");
                assert_eq!(recent[0].last_status.as_deref(), Some("202 Accepted"));
            }
        }
    }
}

#[tokio::test]
async fn a_stale_projects_delivery_follows_the_format() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let receiver = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&receiver)
        .await;
    notifications::set(
        &database,
        &owner,
        organization.id,
        &webhook(format!("{}/hook", receiver.uri()), Format::Slack),
    )
    .await
    .unwrap();
    let project = projects::create(&database, &owner, organization.id, "web", "Web")
        .await
        .unwrap();
    let mut active: project_entity::ActiveModel = project.into();
    active.created_at = Set((Utc::now() - Duration::days(90)).fixed_offset());
    active.last_upload_at = Set(Some((Utc::now() - Duration::days(40)).fixed_offset()));
    active.update(&database).await.unwrap();

    let deliveries = notifications::stale_deliveries(
        &database,
        30,
        &"https://nanobom.example.org/".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(deliveries[0].format, Format::Slack);
    notifications::Notifier::new()
        .unwrap()
        .deliver(&database, deliveries)
        .await
        .unwrap();
    let requests = receiver.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["text"], "Acme: 1 project stopped sending SBOMs");
}

#[tokio::test]
async fn changing_the_format_abandons_the_pending_deliveries() {
    let database = testing::database().await;
    let owner = owner(&database).await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let url = "http://127.0.0.1:9/hook".to_owned();
    notifications::set(
        &database,
        &owner,
        organization.id,
        &webhook(url.clone(), Format::Json),
    )
    .await
    .unwrap();
    let now = Utc::now().fixed_offset();
    deliveries::enqueue(&database, Some(organization.id), &url, "ping", &"{}", now)
        .await
        .unwrap();

    // Saving the same settings again keeps it.
    notifications::set(
        &database,
        &owner,
        organization.id,
        &webhook(url.clone(), Format::Json),
    )
    .await
    .unwrap();
    let recent = deliveries::recent(&database, &owner, organization.id, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].state, State::Sending);

    // A body rendered for one format is not retried to a receiver that expects another.
    notifications::set(
        &database,
        &owner,
        organization.id,
        &webhook(url, Format::Teams),
    )
    .await
    .unwrap();
    let recent = deliveries::recent(&database, &owner, organization.id, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].state, State::Cancelled);
}
