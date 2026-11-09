//! Email notifications: settings, permissions, queueing, the SMTP client against a local sink,
//! retries, cancellation, rendering and the test email.

use chrono::{Duration, Utc};
use nanobom_domain::{
    Error, Problem,
    access::{Actor, Role},
    deliveries::{self, Channel, Outcome, State},
    email::{self, EmailSettings, Language, Mailer},
    evaluation::{NewFinding, RunOutcome, Scope, Trigger},
    memberships,
    notifications::{
        self, Notifier, PayloadFinding, PayloadOrganization, PayloadRun, PayloadStaleProject,
        StaleProjectsPayload, Target,
    },
    organizations, projects,
    testing::{self, SmtpSink},
    users::{self, NewUser},
};
use nanobom_entity::{projects as project_entity, webhook_deliveries};
use nanobom_osv::Severity;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};

async fn actor(database: &DatabaseConnection, username: &str) -> Actor {
    Actor::from_user(
        &users::create(
            database,
            NewUser {
                username: username.to_owned(),
                ..NewUser::default()
            },
            false,
        )
        .await
        .unwrap(),
    )
}

fn settings(recipients: &[&str], language: Language) -> EmailSettings {
    EmailSettings {
        recipients: recipients
            .iter()
            .map(|&address| address.to_owned())
            .collect(),
        language,
        minimum_severity: Severity::High,
        exploited_only: false,
    }
}

fn finding(organization: i64, severity: Severity, id: &str) -> NewFinding {
    NewFinding {
        finding_id: 7,
        organization_id: organization,
        organization_slug: "acme".to_owned(),
        project_id: 0,
        project_slug: "web".to_owned(),
        purl: "pkg:npm/lodash@4.17.20".to_owned(),
        vulnerability_id: id.to_owned(),
        aliases: vec![],
        summary: Some("Command Injection in lodash".to_owned()),
        severity,
        cvss_score: Some(7.2),
        reopened: false,
    }
}

fn outcome(new_findings: Vec<NewFinding>) -> RunOutcome {
    RunOutcome {
        run_id: 42,
        scope: Scope::All,
        trigger: Trigger::Scheduled,
        started_at: Utc::now().fixed_offset(),
        duration_seconds: 1.5,
        error: None,
        component_count: 3,
        vulnerability_count: 2,
        new_findings,
        fixed_findings: 0,
    }
}

fn public_url() -> reqwest::Url {
    "https://nanobom.example.org/".parse().unwrap()
}

fn mailer(sink: &SmtpSink) -> Mailer {
    Mailer::new(&sink.url(), "nanobom <nanobom@example.org>").unwrap()
}

/// An organization with email recipients, owned by `owner`.
async fn organization(database: &DatabaseConnection, owner: &Actor, language: Language) -> i64 {
    let organization = organizations::create(database, owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    email::set(
        database,
        owner,
        organization,
        &settings(&["alice@example.org", "bob@example.org"], language),
    )
    .await
    .unwrap();
    organization
}

/// Makes a pending delivery due now.
async fn make_due(database: &DatabaseConnection, id: i64) {
    let row = webhook_deliveries::Entity::find_by_id(id)
        .one(database)
        .await
        .unwrap()
        .unwrap();
    let mut active: webhook_deliveries::ActiveModel = row.into();
    active.next_attempt_at = Set(Some((Utc::now() - Duration::seconds(1)).fixed_offset()));
    active.update(database).await.unwrap();
}

#[tokio::test]
async fn admins_manage_recipients_and_other_organizations_see_nothing() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let member = actor(&database, "member").await;
    let outsider = actor(&database, "outsider").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    memberships::add(&database, &owner, organization, "member", Role::Member)
        .await
        .unwrap();
    let wanted = settings(&["alice@example.org"], Language::French);

    assert!(matches!(
        email::set(&database, &member, organization, &wanted).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        email::get(&database, &outsider, organization).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        email::set(&database, &outsider, organization, &wanted).await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        email::delete(&database, &outsider, organization).await,
        Err(Error::NotFound)
    ));
    let sink = SmtpSink::start().await;
    assert!(matches!(
        email::send_test(
            &database,
            &outsider,
            organization,
            Some(&mailer(&sink)),
            &public_url()
        )
        .await,
        Err(Error::NotFound)
    ));

    for (recipients, problem) in [
        (vec!["not an address"], "invalid_recipient"),
        (vec![], "no_recipients"),
    ] {
        let result = email::set(
            &database,
            &owner,
            organization,
            &settings(&recipients, Language::English),
        )
        .await;
        match (result, problem) {
            (Err(Error::Invalid(Problem::InvalidRecipient { address })), "invalid_recipient") => {
                assert_eq!(address, "not an address");
            }
            (Err(Error::Invalid(Problem::NoRecipients)), "no_recipients") => {}
            (other, _) => panic!("{problem}: {other:?}"),
        }
    }
    let too_many: Vec<String> = (0..=email::MAX_RECIPIENTS)
        .map(|index| format!("user{index}@example.org"))
        .collect();
    assert!(matches!(
        email::set(
            &database,
            &owner,
            organization,
            &EmailSettings {
                recipients: too_many,
                ..wanted.clone()
            }
        )
        .await,
        Err(Error::Invalid(Problem::TooManyRecipients { maximum: 20 }))
    ));

    let saved = email::set(&database, &owner, organization, &wanted)
        .await
        .unwrap();
    assert_eq!(saved, wanted);
    assert_eq!(
        email::get(&database, &owner, organization).await.unwrap(),
        Some(wanted)
    );
    email::delete(&database, &owner, organization)
        .await
        .unwrap();
    assert_eq!(
        email::get(&database, &owner, organization).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn new_findings_are_mailed_to_every_recipient_in_one_message() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::English).await;
    let sink = SmtpSink::start().await;
    let notifier = Notifier::new().unwrap().with_mailer(mailer(&sink));
    let run = outcome(vec![
        finding(organization, Severity::Critical, "GHSA-1"),
        finding(organization, Severity::Low, "GHSA-2"),
    ]);

    // Email off: nothing is prepared for the recipients.
    assert!(
        notifications::new_findings_deliveries(&database, &run, &public_url(), false)
            .await
            .unwrap()
            .is_empty()
    );

    let ids = notifications::queue_new_findings(&database, &run, &public_url(), true)
        .await
        .unwrap();
    assert_eq!(ids.len(), 1);
    let row = webhook_deliveries::Entity::find_by_id(ids[0])
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.channel, "email");
    assert_eq!(row.url, "alice@example.org, bob@example.org");
    let message: email::Message = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(message.subject, "nanobom: 1 new vulnerability in acme/web");
    assert!(message.text.contains("GHSA-1"), "{}", message.text);
    assert!(
        !message.text.contains("GHSA-2"),
        "below the minimum severity"
    );

    assert_eq!(
        notifier.attempt_all(&database, &ids).await.unwrap(),
        [(Channel::Email, Outcome::Delivered)]
    );
    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].from, "nanobom@example.org");
    assert_eq!(
        received[0].recipients,
        ["alice@example.org", "bob@example.org"]
    );
    let data = &received[0].data;
    assert!(
        data.contains("Subject: nanobom: 1 new vulnerability in acme/web"),
        "{data}"
    );
    assert!(data.contains("multipart/alternative"), "{data}");
    assert!(
        data.contains("text/plain") && data.contains("text/html"),
        "{data}"
    );

    let recent = deliveries::recent(&database, &owner, organization, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].channel, Channel::Email);
    assert_eq!(recent[0].state, State::Delivered);
    assert!(
        recent[0]
            .last_status
            .as_deref()
            .is_some_and(|status| status.starts_with("250")),
        "{:?}",
        recent[0].last_status
    );
}

#[tokio::test]
async fn stale_projects_are_mailed_in_the_organization_language() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::French).await;
    let project = projects::create(&database, &owner, organization, "web", "Web")
        .await
        .unwrap();
    let mut active: project_entity::ActiveModel = project.into();
    active.created_at = Set((Utc::now() - Duration::days(90)).fixed_offset());
    active.last_upload_at = Set(Some((Utc::now() - Duration::days(40)).fixed_offset()));
    active.update(&database).await.unwrap();

    let deliveries = notifications::stale_deliveries(&database, 30, &public_url(), true)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        deliveries[0].target,
        Target::Email {
            recipients: vec!["alice@example.org".into(), "bob@example.org".into()],
            language: Language::French,
        }
    );
    let sink = SmtpSink::start().await;
    let outcomes = Notifier::new()
        .unwrap()
        .with_mailer(mailer(&sink))
        .deliver(&database, deliveries)
        .await
        .unwrap();
    assert_eq!(outcomes, [(Channel::Email, Outcome::Delivered)]);
    assert_eq!(sink.received().len(), 1);
    let row = webhook_deliveries::Entity::find()
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    let message: email::Message = serde_json::from_str(&row.payload).unwrap();
    assert_eq!(message.subject, "nanobom : 1 projet n’envoie plus de SBOM");
    assert!(
        message.text.contains("web (dernier SBOM le "),
        "{}",
        message.text
    );
}

fn stale_payload() -> StaleProjectsPayload {
    StaleProjectsPayload {
        event: "projects.stale".to_owned(),
        organization: PayloadOrganization {
            slug: "acme".to_owned(),
            name: "Acme".to_owned(),
            url: "https://nanobom.example.org/organizations/acme".to_owned(),
        },
        projects: vec![PayloadStaleProject {
            project: "web".to_owned(),
            last_upload_at: None,
            url: "https://nanobom.example.org/organizations/acme/projects/web".to_owned(),
        }],
    }
}

#[tokio::test]
async fn a_transient_rejection_is_retried_and_a_permanent_one_is_not() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::English).await;
    let sink = SmtpSink::start().await;
    let notifier = Notifier::new().unwrap().with_mailer(mailer(&sink));
    let run = outcome(vec![finding(organization, Severity::Critical, "GHSA-1")]);

    sink.reject_next("450 4.2.1 mailbox busy");
    let ids = notifications::queue_new_findings(&database, &run, &public_url(), true)
        .await
        .unwrap();
    assert_eq!(
        notifier.attempt_all(&database, &ids).await.unwrap(),
        [(Channel::Email, Outcome::Retried)]
    );
    let recent = deliveries::recent(&database, &owner, organization, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].state, State::Pending);
    assert!(
        recent[0].last_status.as_deref().unwrap().contains("450"),
        "{:?}",
        recent[0].last_status
    );
    assert!(sink.received().is_empty());
    make_due(&database, ids[0]).await;
    assert_eq!(
        notifier.retry_due(&database, 10).await.unwrap(),
        [(Channel::Email, Outcome::Delivered)]
    );
    assert_eq!(sink.received().len(), 1);

    sink.reject_next("550 5.1.1 no such user");
    let ids = notifications::queue_new_findings(
        &database,
        &outcome(vec![finding(organization, Severity::Critical, "GHSA-3")]),
        &public_url(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        notifier.attempt_all(&database, &ids).await.unwrap(),
        [(Channel::Email, Outcome::Abandoned)]
    );
    let recent = deliveries::recent(&database, &owner, organization, 10)
        .await
        .unwrap();
    assert_eq!(recent[0].state, State::Failed);
    assert!(
        recent[0].last_status.as_deref().unwrap().contains("550"),
        "{:?}",
        recent[0].last_status
    );
    assert_eq!(recent[0].next_attempt_at, None);
}

#[tokio::test]
async fn changing_recipients_or_language_cancels_pending_emails_only() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::English).await;
    let now = Utc::now().fixed_offset();
    let queue = || async {
        let mail = deliveries::enqueue_body(
            &database,
            Some(organization),
            Channel::Email,
            "alice@example.org",
            "findings.new",
            "{}".to_owned(),
            now,
        )
        .await
        .unwrap()
        .id;
        let hook = deliveries::enqueue(
            &database,
            Some(organization),
            "https://hooks.example.org/",
            "findings.new",
            &"{}",
            now,
        )
        .await
        .unwrap()
        .id;
        (mail, hook)
    };
    let state = |id: i64| {
        let database = &database;
        let owner = &owner;
        async move {
            deliveries::recent(database, owner, organization, 50)
                .await
                .unwrap()
                .into_iter()
                .find(|delivery| delivery.id == id)
                .unwrap()
                .state
        }
    };

    // The filters change: pending emails stay.
    let (mail, hook) = queue().await;
    let mut changed = settings(&["alice@example.org", "bob@example.org"], Language::English);
    changed.minimum_severity = Severity::Critical;
    email::set(&database, &owner, organization, &changed)
        .await
        .unwrap();
    assert_eq!(state(mail).await, State::Sending);

    // The recipients change.
    changed.recipients = vec!["carol@example.org".to_owned()];
    email::set(&database, &owner, organization, &changed)
        .await
        .unwrap();
    assert_eq!(state(mail).await, State::Cancelled);
    assert_eq!(state(hook).await, State::Sending, "webhooks are untouched");

    // The language changes.
    let (mail, _) = queue().await;
    changed.language = Language::French;
    email::set(&database, &owner, organization, &changed)
        .await
        .unwrap();
    assert_eq!(state(mail).await, State::Cancelled);

    // The settings are removed.
    let (mail, _) = queue().await;
    email::delete(&database, &owner, organization)
        .await
        .unwrap();
    assert_eq!(state(mail).await, State::Cancelled);
    assert_eq!(state(hook).await, State::Sending);
}

fn findings_payload(project: &str, summary: &str) -> notifications::NewFindingsPayload {
    notifications::NewFindingsPayload {
        event: "findings.new".to_owned(),
        organization: PayloadOrganization {
            slug: "acme".to_owned(),
            name: "Acme <Corp> & \"Co\"".to_owned(),
            url: "https://nanobom.example.org/organizations/acme".to_owned(),
        },
        run: PayloadRun {
            id: 1,
            trigger: "scheduled".to_owned(),
            started_at: Utc::now().fixed_offset(),
        },
        count: 2,
        highest_severity: Severity::Critical,
        known_exploited_count: 1,
        findings: vec![
            PayloadFinding {
                project: project.to_owned(),
                component: "pkg:npm/<img src=x onerror=alert(1)>@1.0.0".to_owned(),
                vulnerability: "GHSA-1".to_owned(),
                aliases: vec![],
                severity: Severity::Critical,
                cvss_score: Some(9.8),
                summary: Some(summary.to_owned()),
                reopened: true,
                reason: "reopened".to_owned(),
                known_exploited: true,
                kev_due_date: None,
                epss: None,
                epss_percentile: None,
                introduced_via: vec!["express".to_owned()],
                url: "https://nanobom.example.org/findings/1".to_owned(),
            },
            PayloadFinding {
                project: "api".to_owned(),
                component: "pkg:npm/lodash@4.17.20".to_owned(),
                vulnerability: "GHSA-2".to_owned(),
                aliases: vec![],
                severity: Severity::High,
                cvss_score: None,
                summary: None,
                reopened: false,
                reason: "new".to_owned(),
                known_exploited: false,
                kev_due_date: None,
                epss: None,
                epss_percentile: None,
                introduced_via: vec![],
                url: "https://nanobom.example.org/findings/2".to_owned(),
            },
        ],
    }
}

#[tokio::test]
async fn emails_render_in_both_languages_and_escape_the_data() {
    let payload = findings_payload("<script>alert(1)</script>", "a & b <b>bold</b>");

    let english = email::new_findings(&payload, Language::English);
    assert_eq!(
        english.subject,
        "nanobom: 2 new vulnerabilities in Acme <Corp> & \"Co\""
    );
    assert!(
        english
            .text
            .contains("Highest severity: critical, 1 known exploited")
    );
    assert!(
        english
            .text
            .contains("GHSA-1 (critical, reopened, known exploited)")
    );
    assert!(
        english.text.contains("<script>alert(1)</script>"),
        "plain text is not escaped"
    );
    assert!(english.text.contains("Introduced via express"));
    assert!(
        english
            .text
            .contains("https://nanobom.example.org/findings/1")
    );
    assert!(
        english
            .text
            .contains("https://nanobom.example.org/organizations/acme/settings")
    );
    for raw in ["<script>", "<img", "<b>bold", "<Corp>", "\"Co\""] {
        assert!(!english.html.contains(raw), "{raw} in {}", english.html);
    }
    assert!(
        english
            .html
            .contains("&lt;script&gt;alert(1)&lt;/script&gt;")
    );
    assert!(english.html.contains("a &amp; b &lt;b&gt;bold&lt;/b&gt;"));
    assert!(
        english
            .html
            .contains("Acme &lt;Corp&gt; &amp; &quot;Co&quot;")
    );
    assert!(
        english
            .html
            .contains("<a href=\"https://nanobom.example.org/findings/1\">")
    );
    assert!(english.html.contains("<html lang=\"en\">"));

    let french = email::new_findings(&payload, Language::French);
    assert_eq!(
        french.subject,
        "nanobom : 2 nouvelles vulnérabilités dans Acme <Corp> & \"Co\""
    );
    assert!(
        french
            .text
            .contains("Sévérité maximale : critique, 1 exploitée connue")
    );
    assert!(
        french
            .text
            .contains("GHSA-1 (critique, rouverte, exploitée connue)")
    );
    assert!(french.text.contains("Introduit par express"));
    assert!(french.html.contains("<html lang=\"fr\">"));
    assert!(!french.html.contains("<script>"));

    // One project: the subject names it.
    let mut single = findings_payload("web", "summary");
    single.findings.truncate(1);
    single.count = 1;
    assert_eq!(
        email::new_findings(&single, Language::English).subject,
        "nanobom: 1 new vulnerability in acme/web"
    );

    let stale = email::stale_projects(&stale_payload(), Language::English);
    assert_eq!(stale.subject, "nanobom: 1 project stopped sending SBOMs");
    assert!(stale.text.contains("web (never received an SBOM)"));
    let stale = email::stale_projects(&stale_payload(), Language::French);
    assert!(stale.text.contains("web (aucun SBOM reçu)"));
}

#[tokio::test]
async fn the_test_email_is_sent_at_once_and_rate_limited() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::English).await;
    let other = organizations::create(&database, &owner, "other", "Other")
        .await
        .unwrap()
        .id;
    let sink = SmtpSink::start().await;
    let mailer = mailer(&sink);

    assert!(matches!(
        email::send_test(&database, &owner, organization, None, &public_url()).await,
        Err(Error::Invalid(Problem::EmailNotConfigured))
    ));
    assert!(matches!(
        email::send_test(&database, &owner, other, Some(&mailer), &public_url()).await,
        Err(Error::Invalid(Problem::NoRecipients))
    ));

    email::send_test(
        &database,
        &owner,
        organization,
        Some(&mailer),
        &public_url(),
    )
    .await
    .unwrap();
    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert!(received[0].data.contains("Subject: nanobom: test email"));
    assert_eq!(
        received[0].recipients,
        ["alice@example.org", "bob@example.org"]
    );
    assert!(matches!(
        email::send_test(
            &database,
            &owner,
            organization,
            Some(&mailer),
            &public_url()
        )
        .await,
        Err(Error::Conflict(Problem::TestEmailTooSoon { .. }))
    ));
    assert_eq!(sink.received().len(), 1);

    // The SMTP server's reply is shown.
    email::set(
        &database,
        &owner,
        other,
        &settings(&["nobody@example.org"], Language::English),
    )
    .await
    .unwrap();
    sink.reject_next("550 5.1.1 no such user");
    match email::send_test(&database, &owner, other, Some(&mailer), &public_url()).await {
        Err(Error::Invalid(Problem::TestEmailFailed { detail })) => {
            assert!(detail.contains("550"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn without_smtp_emails_are_neither_sent_nor_kept_pending() {
    let database = testing::database().await;
    let owner = actor(&database, "owner").await;
    let organization = organization(&database, &owner, Language::English).await;
    let run = outcome(vec![finding(organization, Severity::Critical, "GHSA-1")]);
    let sink = SmtpSink::start().await;
    let queued = notifications::queue_new_findings(&database, &run, &public_url(), true)
        .await
        .unwrap();

    // A server without a mailer cannot send what an earlier configuration queued.
    let outcomes = Notifier::new()
        .unwrap()
        .attempt_all(&database, &queued)
        .await
        .unwrap();
    assert_eq!(outcomes, [(Channel::Email, Outcome::Abandoned)]);
    let recent = deliveries::recent(&database, &owner, organization, 10)
        .await
        .unwrap();
    assert_eq!(
        recent[0].last_status.as_deref(),
        Some("email is not configured on this server")
    );

    // At startup without SMTP, pending emails are abandoned.
    let queued = notifications::queue_new_findings(
        &database,
        &outcome(vec![finding(organization, Severity::Critical, "GHSA-2")]),
        &public_url(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        deliveries::cancel_pending_emails(&database).await.unwrap(),
        1
    );
    assert!(
        Notifier::new()
            .unwrap()
            .with_mailer(mailer(&sink))
            .attempt_all(&database, &queued)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(sink.received().is_empty());
}
