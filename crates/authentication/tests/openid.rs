//! OpenID Connect sign-in against a mocked provider: discovery, PKCE, nonce, signed ID tokens,
//! user creation, administrator rights and organization roles from claims.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use nanobom_authentication::{
    OpenId, OpenIdError, OpenIdSettings,
    claims::GroupMapping,
    openid::{ExtraClaims, PendingSignIn},
};
use nanobom_domain::{
    access::{Actor, Role},
    organizations, testing,
};
use openidconnect::{
    AccessToken, Audience, EndUserEmail, EndUserUsername, IdToken, IdTokenClaims, IssuerUrl,
    JsonWebKeyId, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use sea_orm::DatabaseConnection;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, method, path},
};

const CLIENT_ID: &str = "nanobom";
const KEY: &str = include_str!("fixtures/test-only-oidc-signing-key.pem");

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(KEY, Some(JsonWebKeyId::new("test-key".to_owned())))
        .expect("a valid test key")
}

/// A mocked provider. Its token endpoint is mounted per sign-in, once the nonce is known.
struct Provider {
    server: MockServer,
    /// The issuer announced in the discovery document and in ID tokens, exactly as a client
    /// must configure it.
    issuer: String,
    /// The path the provider is served under: empty, or `/application/o/nanobom`.
    root: &'static str,
}

impl Provider {
    /// An issuer that is the bare origin, without a trailing slash.
    async fn start() -> Self {
        Self::serve("", |origin| origin).await
    }

    /// An issuer with a path and a trailing slash, like Authentik's
    /// `https://auth.example.org/application/o/nanobom/`.
    async fn start_with_trailing_slash() -> Self {
        Self::serve("/application/o/nanobom", |origin| {
            format!("{origin}/application/o/nanobom/")
        })
        .await
    }

    async fn serve(root: &'static str, issuer: impl FnOnce(String) -> String) -> Self {
        let server = MockServer::start().await;
        let issuer = issuer(server.uri());
        mount_discovery(&server, &issuer, root).await;
        Self {
            server,
            issuer,
            root,
        }
    }

    fn settings(&self) -> OpenIdSettings {
        OpenIdSettings {
            issuer: self.issuer.clone(),
            client_id: CLIENT_ID.to_owned(),
            client_secret: Some("secret".to_owned()),
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            redirect_url: "https://nanobom.example.org/auth/oidc/callback".to_owned(),
            create_users: true,
            personal_organizations: true,
            administrator_claim: None,
            administrator_value: None,
            groups_claim: None,
            group_mapping: GroupMapping::default(),
        }
    }

    /// Answers the next code exchange with an ID token for `subject` carrying `extra` claims,
    /// and the user information with `information`.
    async fn answer(
        &self,
        nonce: &str,
        subject: &str,
        username: &str,
        extra: Value,
        information: Value,
    ) {
        self.server.reset().await;
        mount_discovery(&self.server, &self.issuer, self.root).await;
        let access_token = AccessToken::new("access-token".to_owned());
        let claims: HashMap<String, Value> = serde_json::from_value(extra).unwrap();
        let id_token = IdToken::<
            ExtraClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >::new(
            IdTokenClaims::new(
                IssuerUrl::new(self.issuer.clone()).unwrap(),
                vec![Audience::new(CLIENT_ID.to_owned())],
                Utc::now() + Duration::minutes(5),
                Utc::now(),
                StandardClaims::new(SubjectIdentifier::new(subject.to_owned()))
                    .set_preferred_username(Some(EndUserUsername::new(username.to_owned())))
                    .set_email(Some(EndUserEmail::new(format!("{username}@example.org")))),
                ExtraClaims { claims },
            )
            .set_nonce(Some(Nonce::new(nonce.to_owned()))),
            &signing_key(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&access_token),
            None,
        )
        .unwrap();
        Mock::given(method("POST"))
            .and(path(format!("{}/token", self.root)))
            .and(body_string_contains("code_verifier="))
            .and(body_string_contains("code=the-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token.to_string()
            })))
            .mount(&self.server)
            .await;
        let mut information = information;
        information["sub"] = json!(subject);
        Mock::given(method("GET"))
            .and(path(format!("{}/userinfo", self.root)))
            .respond_with(ResponseTemplate::new(200).set_body_json(information))
            .mount(&self.server)
            .await;
    }
}

/// Serves the provider's discovery document and keys under `root`. The `issuer` is announced
/// verbatim, so a trailing slash is part of it.
async fn mount_discovery(server: &MockServer, issuer: &str, root: &str) {
    let base = format!("{}{root}", server.uri());
    Mock::given(method("GET"))
        .and(path(format!("{root}/.well-known/openid-configuration")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/userinfo"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{root}/jwks")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"keys": [signing_key().as_verification_key()]})),
        )
        .mount(server)
        .await;
}

fn query_parameter(url: &str, name: &str) -> String {
    let url: reqwest::Url = url.parse().unwrap();
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("{name} is missing from {url}"))
}

async fn sign_in(
    provider: &Provider,
    openid: &OpenId,
    database: &DatabaseConnection,
    subject: &str,
    username: &str,
    extra: Value,
    information: Value,
) -> Result<nanobom_entity::users::Model, OpenIdError> {
    let (url, pending) = openid
        .start(Some("/organizations".to_owned()))
        .await
        .unwrap();
    assert!(url.starts_with(&format!(
        "{}{}/authorize",
        provider.server.uri(),
        provider.root
    )));
    assert_eq!(query_parameter(&url, "code_challenge_method"), "S256");
    assert!(query_parameter(&url, "scope").contains("email"));
    let state = query_parameter(&url, "state");
    let nonce = query_parameter(&url, "nonce");
    provider
        .answer(&nonce, subject, username, extra, information)
        .await;
    openid
        .finish(database, pending, "the-code".to_owned(), &state)
        .await
}

#[tokio::test]
async fn first_sign_in_creates_the_user_and_later_ones_find_it() {
    let provider = Provider::start().await;
    let database = testing::database().await;
    let openid = OpenId::new(provider.settings()).unwrap();

    let user = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "Alice.Martin",
        json!({}),
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(user.username, "alice.martin");
    assert_eq!(user.email.as_deref(), Some("alice.martin@example.org"));
    assert!(user.password_hash.is_none());
    assert!(!user.is_instance_administrator);
    let actor = Actor::from_user(&user);
    assert_eq!(
        organizations::list(&database, &actor).await.unwrap().len(),
        1
    );

    let again = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "renamed",
        json!({}),
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(
        again.id, user.id,
        "matched by issuer and subject, not by name"
    );

    let other = sign_in(
        &provider,
        &openid,
        &database,
        "subject-2",
        "alice.martin",
        json!({}),
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(other.username, "alice.martin-2");
    assert!(
        other.email.is_none(),
        "the email address belongs to another account"
    );
}

/// Providers such as Authentik announce an issuer ending with a slash; the library compares it
/// character for character with the configured one, so it must reach discovery untouched.
#[tokio::test]
async fn an_issuer_with_a_trailing_slash_is_used_as_configured() {
    let provider = Provider::start_with_trailing_slash().await;
    let database = testing::database().await;
    let settings = provider.settings();
    assert!(settings.issuer.ends_with('/'));
    let openid = OpenId::new(settings).unwrap();

    let user = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "alice.martin",
        json!({}),
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(user.username, "alice.martin");
    let identity =
        nanobom_domain::users::find_by_identity(&database, &provider.issuer, "subject-1")
            .await
            .unwrap();
    assert_eq!(
        identity.map(|user| user.id),
        Some(user.id),
        "the identity is stored under the issuer of the ID token, slash included"
    );
}

/// The slash is significant: an issuer configured without it does not match a provider that
/// announces it, and the failure is reported as a discovery error.
#[tokio::test]
async fn a_missing_trailing_slash_fails_discovery() {
    let provider = Provider::start_with_trailing_slash().await;
    let settings = OpenIdSettings {
        issuer: provider.issuer.trim_end_matches('/').to_owned(),
        ..provider.settings()
    };
    let openid = OpenId::new(settings).unwrap();
    assert!(matches!(
        openid.start(None).await,
        Err(OpenIdError::Discovery(_))
    ));
}

#[tokio::test]
async fn unknown_users_are_refused_when_creation_is_off() {
    let provider = Provider::start().await;
    let database = testing::database().await;
    let openid = OpenId::new(OpenIdSettings {
        create_users: false,
        ..provider.settings()
    })
    .unwrap();
    let result = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "alice",
        json!({}),
        json!({}),
    )
    .await;
    assert!(matches!(result, Err(OpenIdError::UnknownUser)));
}

#[tokio::test]
async fn zitadel_roles_grant_administration_and_organizations() {
    let provider = Provider::start().await;
    let database = testing::database().await;
    let openid = OpenId::new(OpenIdSettings {
        administrator_claim: Some("urn:zitadel:iam:org:project:roles".to_owned()),
        administrator_value: Some("nanobom-admin".to_owned()),
        groups_claim: Some("urn:zitadel:iam:org:project:roles".to_owned()),
        group_mapping: GroupMapping::parse("acme-developers=acme:member;acme-leads=acme:admin")
            .unwrap(),
        ..provider.settings()
    })
    .unwrap();
    let roles = json!({"urn:zitadel:iam:org:project:roles": {
        "nanobom-admin": {"1": "example.org"},
        "acme-developers": {"1": "example.org"}
    }});
    let user = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "alice",
        roles,
        json!({}),
    )
    .await
    .unwrap();
    assert!(user.is_instance_administrator);
    let actor = Actor {
        user_id: user.id,
        is_instance_administrator: false,
    };
    assert_eq!(
        organizations::find(&database, &actor, "acme")
            .await
            .unwrap()
            .role,
        Role::Member
    );

    let fewer = json!({"urn:zitadel:iam:org:project:roles": {"acme-leads": {}}});
    let user = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "alice",
        fewer,
        json!({}),
    )
    .await
    .unwrap();
    assert!(
        !user.is_instance_administrator,
        "rights follow the provider"
    );
    assert_eq!(
        organizations::find(&database, &actor, "acme")
            .await
            .unwrap()
            .role,
        Role::Admin
    );
}

#[tokio::test]
async fn groups_can_come_from_the_user_information() {
    let provider = Provider::start().await;
    let database = testing::database().await;
    let openid = OpenId::new(OpenIdSettings {
        groups_claim: Some("groups".to_owned()),
        group_mapping: GroupMapping::parse("/platform=platform:owner").unwrap(),
        administrator_claim: Some("realm_access.roles".to_owned()),
        administrator_value: Some("nanobom-admin".to_owned()),
        ..provider.settings()
    })
    .unwrap();
    let user = sign_in(
        &provider,
        &openid,
        &database,
        "subject-1",
        "bob",
        json!({"realm_access": {"roles": ["nanobom-admin"]}}),
        json!({"groups": ["/platform", "/other"]}),
    )
    .await
    .unwrap();
    assert!(user.is_instance_administrator);
    let actor = Actor {
        user_id: user.id,
        is_instance_administrator: false,
    };
    assert_eq!(
        organizations::find(&database, &actor, "platform")
            .await
            .unwrap()
            .role,
        Role::Owner
    );
}

#[tokio::test]
async fn forged_callbacks_are_refused() {
    let provider = Provider::start().await;
    let database = testing::database().await;
    let openid = OpenId::new(provider.settings()).unwrap();

    let (_, pending) = openid.start(None).await.unwrap();
    let result = openid
        .finish(&database, pending, "the-code".to_owned(), "another-state")
        .await;
    assert!(matches!(result, Err(OpenIdError::StateMismatch)));

    // A token issued for another sign-in carries another nonce.
    let (url, pending) = openid.start(None).await.unwrap();
    let state = query_parameter(&url, "state");
    provider
        .answer(
            "someone-elses-nonce",
            "subject-1",
            "eve",
            json!({}),
            json!({}),
        )
        .await;
    let result = openid
        .finish(&database, pending, "the-code".to_owned(), &state)
        .await;
    assert!(matches!(result, Err(OpenIdError::Verification(_))));
}

#[tokio::test]
async fn pending_sign_ins_survive_a_session_round_trip() {
    let provider = Provider::start().await;
    let openid = OpenId::new(provider.settings()).unwrap();
    let (_, pending) = openid.start(Some("/next".to_owned())).await.unwrap();
    let stored = serde_json::to_string(&pending).unwrap();
    let restored: PendingSignIn = serde_json::from_str(&stored).unwrap();
    assert_eq!(restored.next.as_deref(), Some("/next"));
}
