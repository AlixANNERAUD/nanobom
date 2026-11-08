//! Sign-in with any OpenID Connect provider: authorization code flow with PKCE and a nonce.
//!
//! Users are matched by issuer and subject and, when allowed, created at their first sign-in.
//! At each sign-in, instance administration can be read from a claim, and organization roles
//! from a groups claim through a configured mapping.
//!
//! Security choices worth knowing before changing this module:
//!
//! - users are linked to provider accounts by issuer and subject only. An email address from
//!   the provider is never used to find an existing user, since providers do not all verify
//!   it; a new user whose address is already taken is created without one;
//! - the HTTP client does not follow redirects, as the `openidconnect` crate recommends: a
//!   redirect from the provider's endpoints could otherwise send server-side requests to
//!   internal addresses;
//! - when an administrator claim is configured, the provider is the authority: each sign-in
//!   grants or removes instance administration, whatever was set locally. The same goes for
//!   synchronized memberships when a groups claim is configured, including removing them all
//!   when the claim is missing.
//!
//! The server calls [`OpenId::start`] to redirect the browser, keeps the [`PendingSignIn`] in
//! the session, then calls [`OpenId::finish`] from the callback and signs the user in with
//! [`Credentials::Verified`](crate::Credentials::Verified).

use std::collections::HashMap;

use nanobom_domain::{memberships, users};
use nanobom_entity::users::Model as User;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, Client, ClientId, ClientSecret,
    CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardErrorResponse, StandardTokenResponse, TokenResponse, UserInfoClaims,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
        CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken,
        CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
    reqwest,
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::OnceCell;

use crate::claims::{self, GroupMapping};

/// Every claim of the ID token and user information besides the standard ones.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtraClaims {
    #[serde(flatten)]
    pub claims: HashMap<String, Value>,
}

impl AdditionalClaims for ExtraClaims {}

type ExtraIdTokenFields = IdTokenFields<
    ExtraClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type ExtraTokenResponse = StandardTokenResponse<ExtraIdTokenFields, CoreTokenType>;
type DiscoveredClient = Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    ExtraTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// OpenID Connect settings, from the command line or environment.
#[derive(Debug, Clone)]
pub struct OpenIdSettings {
    /// The issuer URL; discovery reads `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    /// `None` for public clients, which rely on PKCE alone.
    pub client_secret: Option<String>,
    /// Scopes to request; `openid` is always requested and need not be listed.
    pub scopes: Vec<String>,
    /// The callback address registered with the provider.
    pub redirect_url: String,
    /// Create users at their first sign-in; otherwise only linked users may sign in.
    pub create_users: bool,
    /// Give users created at sign-in a personal organization.
    pub personal_organizations: bool,
    /// Claim path granting instance administration (see [`claims::is_administrator`]); when
    /// unset, instance administration is managed locally.
    pub administrator_claim: Option<String>,
    /// The group or role in [`OpenIdSettings::administrator_claim`] that grants it; when unset,
    /// the claim must be the boolean `true`.
    pub administrator_value: Option<String>,
    /// Claim path listing the user's groups; when unset, no membership is synchronized.
    pub groups_claim: Option<String>,
    pub group_mapping: GroupMapping,
}

/// What the callback needs from the start of a sign-in, kept in the session meanwhile: the
/// `state` that ties the callback to this browser, the nonce expected in the ID token and the
/// PKCE verifier. It must be used once and then removed from the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSignIn {
    state: String,
    nonce: String,
    verifier: String,
    /// Where to go after signing in, as given to [`OpenId::start`]; the caller validates it
    /// before redirecting there.
    pub next: Option<String>,
}

/// Why a sign-in through the provider failed. The server logs the message and shows the user
/// a generic page, with a specific one only for [`OpenIdError::UnknownUser`] and
/// [`OpenIdError::Disabled`]: provider and database details stay in the logs.
#[derive(Debug, thiserror::Error)]
pub enum OpenIdError {
    #[error("the identity provider could not be reached: {0}")]
    Discovery(String),
    #[error("the sign-in request does not match the one started here")]
    StateMismatch,
    #[error("the identity provider refused the sign-in: {0}")]
    Exchange(String),
    #[error("the identity provider's answer could not be verified: {0}")]
    Verification(String),
    #[error("this account is not known here and new accounts are not created automatically")]
    UnknownUser,
    #[error("this account is disabled")]
    Disabled,
    #[error(transparent)]
    Domain(#[from] nanobom_domain::Error),
}

/// The OpenID Connect provider, discovered on first use rather than at startup, so the server
/// starts even when the provider is down.
pub struct OpenId {
    settings: OpenIdSettings,
    http: reqwest::Client,
    client: OnceCell<DiscoveredClient>,
}

impl OpenId {
    /// Prepares the client without contacting the provider.
    pub fn new(settings: OpenIdSettings) -> Result<Self, OpenIdError> {
        let http = reqwest::ClientBuilder::new()
            // Following redirects would expose the client to server-side request forgery.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| OpenIdError::Discovery(error.to_string()))?;
        Ok(Self {
            settings,
            http,
            client: OnceCell::new(),
        })
    }

    pub fn settings(&self) -> &OpenIdSettings {
        &self.settings
    }

    /// Discovers the provider, once; a failed discovery is retried at the next sign-in.
    async fn client(&self) -> Result<&DiscoveredClient, OpenIdError> {
        self.client
            .get_or_try_init(|| async {
                let issuer = IssuerUrl::new(self.settings.issuer.clone())
                    .map_err(|error| OpenIdError::Discovery(error.to_string()))?;
                let metadata = CoreProviderMetadata::discover_async(issuer, &self.http)
                    .await
                    .map_err(|error| OpenIdError::Discovery(error.to_string()))?;
                let redirect = RedirectUrl::new(self.settings.redirect_url.clone())
                    .map_err(|error| OpenIdError::Discovery(error.to_string()))?;
                Ok(Client::from_provider_metadata(
                    metadata,
                    ClientId::new(self.settings.client_id.clone()),
                    self.settings.client_secret.clone().map(ClientSecret::new),
                )
                .set_redirect_uri(redirect))
            })
            .await
    }

    /// Starts a sign-in: the provider address to redirect to, and what to keep in the session.
    pub async fn start(
        &self,
        next: Option<String>,
    ) -> Result<(String, PendingSignIn), OpenIdError> {
        let client = self.client().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.settings.scopes {
            if scope != "openid" {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        let (url, state, nonce) = request.set_pkce_challenge(challenge).url();
        Ok((
            url.to_string(),
            PendingSignIn {
                state: state.secret().clone(),
                nonce: nonce.secret().clone(),
                verifier: verifier.secret().clone(),
                next,
            },
        ))
    }

    /// Completes a sign-in from the provider's callback and returns the user, created or
    /// updated from the claims.
    ///
    /// Verifies the state, exchanges the code with the PKCE verifier, and checks the ID token's
    /// signature, nonce and, when present, access token hash. Claims of the ID token win over
    /// those of the user information endpoint, which is read too because providers often put
    /// groups there; if it fails, the ID token alone is used. Does not open a session: the
    /// caller does, with [`Credentials::Verified`](crate::Credentials::Verified).
    pub async fn finish(
        &self,
        database: &DatabaseConnection,
        pending: PendingSignIn,
        code: String,
        state: &str,
    ) -> Result<User, OpenIdError> {
        if state != pending.state {
            return Err(OpenIdError::StateMismatch);
        }
        let client = self.client().await?;
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|error| OpenIdError::Exchange(error.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
            .request_async(&self.http)
            .await
            .map_err(|error| OpenIdError::Exchange(error.to_string()))?;
        let id_token = token
            .id_token()
            .ok_or_else(|| OpenIdError::Verification("no ID token in the answer".to_owned()))?;
        let verifier = client.id_token_verifier();
        let id_claims = id_token
            .claims(&verifier, &Nonce::new(pending.nonce))
            .map_err(|error| OpenIdError::Verification(error.to_string()))?;
        if let Some(expected) = id_claims.access_token_hash() {
            let signing = id_token
                .signing_alg()
                .and_then(|algorithm| id_token.signing_key(&verifier).map(|key| (algorithm, key)))
                .map_err(|error| OpenIdError::Verification(error.to_string()))?;
            let actual = AccessTokenHash::from_token(token.access_token(), signing.0, signing.1)
                .map_err(|error| OpenIdError::Verification(error.to_string()))?;
            if actual != *expected {
                return Err(OpenIdError::Verification(
                    "the access token does not match the ID token".to_owned(),
                ));
            }
        }

        let issuer = id_claims.issuer().to_string();
        let subject = id_claims.subject().to_string();
        let mut claims: Map<String, Value> = id_claims
            .additional_claims()
            .claims
            .clone()
            .into_iter()
            .collect();
        let mut email = id_claims.email().map(|email| email.to_string());
        let mut preferred_username = id_claims.preferred_username().map(|name| name.to_string());
        let mut name = id_claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.to_string());

        // Providers often put groups and roles in the user information only.
        if let Ok(request) = client.user_info(
            token.access_token().clone(),
            Some(id_claims.subject().clone()),
        ) {
            match request.request_async(&self.http).await {
                Ok(information) => {
                    let information: UserInfoClaims<ExtraClaims, CoreGenderClaim> = information;
                    for (key, value) in &information.additional_claims().claims {
                        claims.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                    email = email.or_else(|| information.email().map(|email| email.to_string()));
                    preferred_username = preferred_username.or_else(|| {
                        information
                            .preferred_username()
                            .map(|name| name.to_string())
                    });
                    name = name.or_else(|| {
                        information
                            .name()
                            .and_then(|name| name.get(None))
                            .map(|name| name.to_string())
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "reading the user information failed; using the ID token alone");
                }
            }
        }

        let user = match users::find_by_identity(database, &issuer, &subject).await? {
            Some(user) => user,
            None if self.settings.create_users => {
                let email_local_part = email
                    .as_deref()
                    .and_then(|email| email.split('@').next())
                    .unwrap_or_default()
                    .to_owned();
                let username = users::available_username(
                    database,
                    &[
                        preferred_username.as_deref().unwrap_or_default(),
                        &email_local_part,
                    ],
                )
                .await?;
                let email = match &email {
                    Some(email) if users::find_by_email(database, email).await?.is_none() => {
                        nanobom_domain::names::email(email).ok()
                    }
                    _ => None,
                };
                users::create_with_identity(
                    database,
                    users::NewUser {
                        username,
                        email,
                        display_name: name.clone(),
                        password_hash: None,
                        is_instance_administrator: false,
                    },
                    self.settings.personal_organizations,
                    &issuer,
                    &subject,
                )
                .await?
            }
            None => return Err(OpenIdError::UnknownUser),
        };
        if user.is_disabled {
            return Err(OpenIdError::Disabled);
        }

        let user = match &self.settings.administrator_claim {
            Some(path) => {
                let administrator = claims::is_administrator(
                    &claims,
                    path,
                    self.settings.administrator_value.as_deref(),
                );
                users::synchronize_instance_administrator(database, user, administrator).await?
            }
            None => user,
        };
        if let Some(path) = &self.settings.groups_claim {
            let groups = claims::lookup(&claims, path)
                .map(claims::names)
                .unwrap_or_default();
            let roles = self.settings.group_mapping.roles(&groups);
            memberships::synchronize(database, user.id, &roles).await?;
        }
        Ok(user)
    }
}
