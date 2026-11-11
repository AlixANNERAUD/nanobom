//! The built binary, run as a script would run it.

use std::process::Command;

use nanobom_domain::{database, organizations};

use crate::common::user;

/// `TOKEN=$(nanobom token create …)` must capture the secret alone: logs go to standard error.
/// Runs the real binary, since which stream the logs use is decided when it starts.
#[tokio::test]
async fn token_create_prints_the_secret_alone_on_standard_output() {
    let directory =
        std::env::temp_dir().join(format!("nanobom-command-line-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a temporary directory");
    let url = format!("sqlite://{}/nanobom.sqlite3", directory.display());
    {
        let connection = database::connect(&url).await.expect("open the database");
        database::migrate(&connection).await.expect("migrate");
        let owner = user(&connection, "owner").await;
        organizations::create(&connection, &owner, "acme", "Acme")
            .await
            .expect("an organization");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_nanobom"))
        .args(["--database-url", &url, "token", "create"])
        .args(["--organization", "acme", "--name", "CI"])
        .env_remove("NANOBOM_LOG_LEVEL")
        .env_remove("NANOBOM_LOG_FORMAT")
        .output()
        .expect("run the nanobom binary");
    std::fs::remove_dir_all(&directory).ok();

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 output");
    assert!(output.status.success(), "token create failed: {stderr}");
    let secret = stdout.trim_end_matches('\n');
    assert!(
        secret.starts_with("nanobom_") && !secret.contains(char::is_whitespace),
        "standard output holds more than the secret: {stdout:?}"
    );
    assert!(
        stderr.contains("token created"),
        "the log line is expected on standard error: {stderr:?}"
    );
    assert!(!stderr.contains(secret), "the secret must not be logged");
}

/// `nanobom project create` prints the new project's upload token alone, `project token` prints
/// it again, and `--renew` replaces it.
#[tokio::test]
async fn project_commands_print_the_project_token() {
    let directory = std::env::temp_dir().join(format!(
        "nanobom-command-line-project-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("a temporary directory");
    let url = format!("sqlite://{}/nanobom.sqlite3", directory.display());
    {
        let connection = database::connect(&url).await.expect("open the database");
        database::migrate(&connection).await.expect("migrate");
        let owner = user(&connection, "owner").await;
        organizations::create(&connection, &owner, "acme", "Acme")
            .await
            .expect("an organization");
    }
    let run = |arguments: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_nanobom"))
            .args(["--database-url", &url])
            .args(arguments)
            .env_remove("NANOBOM_LOG_LEVEL")
            .env_remove("NANOBOM_LOG_FORMAT")
            .output()
            .expect("run the nanobom binary");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 output");
        assert!(output.status.success(), "{arguments:?} failed: {stderr}");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
        let secret = stdout.trim_end_matches('\n').to_owned();
        assert!(
            secret.starts_with("nanobom_") && !secret.contains(char::is_whitespace),
            "standard output holds more than the secret: {stdout:?}"
        );
        assert!(!stderr.contains(&secret), "the secret must not be logged");
        secret
    };

    let created = run(&[
        "project",
        "create",
        "--organization",
        "acme",
        "--project",
        "web",
    ]);
    let shown = run(&[
        "project",
        "token",
        "--organization",
        "acme",
        "--project",
        "web",
    ]);
    assert_eq!(shown, created);
    let renewed = run(&[
        "project",
        "token",
        "--organization",
        "acme",
        "--project",
        "web",
        "--renew",
    ]);
    assert_ne!(renewed, created);

    let connection = database::connect(&url).await.expect("open the database");
    assert!(
        nanobom_domain::tokens::authenticate(&connection, &created)
            .await
            .unwrap()
            .is_none()
    );
    let token = nanobom_domain::tokens::authenticate(&connection, &renewed)
        .await
        .unwrap()
        .expect("the renewed token works");
    assert!(token.project_id.is_some());
    drop(connection);
    std::fs::remove_dir_all(&directory).ok();
}
