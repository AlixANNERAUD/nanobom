//! The axum-login backend shared by both sign-in methods: local passwords, and identities
//! already verified by the OpenID Connect flow.
//!
//! Password checks take the same time whether or not the login exists (a decoy hash is
//! verified for unknown logins), and every refusal is the same `Ok(None)`, so the sign-in form
//! cannot be used to find accounts. Accounts without a password never sign in with one.

use std::sync::OnceLock;

use axum_login::{AuthUser, AuthnBackend, UserId};
use nanobom_domain::{access::Actor, passwords, users};
use nanobom_entity::users::Model;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};

/// The signed-in user kept in the session.
///
/// It is reloaded from the database on every request ([`AuthnBackend::get_user`]), so its
/// fields reflect the current account, not the one at sign-in.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_instance_administrator: bool,
    /// Changes when the password changes, which ends the user's other sessions. Accounts
    /// without a password use a constant derived from their identifier: their sessions end
    /// when the account is disabled or the session expires, or at sign-out.
    authentication_hash: Vec<u8>,
}

impl std::fmt::Debug for SessionUser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionUser")
            .field("id", &self.id)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl SessionUser {
    /// The session view of a user. It does not check that the user is enabled; the backend
    /// does.
    pub fn from_model(user: &Model) -> Self {
        let authentication_hash = match &user.password_hash {
            Some(hash) => hash.as_bytes().to_vec(),
            None => format!("external:{}", user.id).into_bytes(),
        };
        Self {
            id: user.id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            is_instance_administrator: user.is_instance_administrator,
            authentication_hash,
        }
    }

    /// The actor to pass to domain functions on behalf of this user.
    pub fn actor(&self) -> Actor {
        Actor {
            user_id: self.id,
            is_instance_administrator: self.is_instance_administrator,
        }
    }
}

impl AuthUser for SessionUser {
    type Id = i64;

    fn id(&self) -> i64 {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.authentication_hash
    }
}

/// How a user proves who they are.
#[derive(Clone)]
pub enum Credentials {
    /// A local account's username (or email address) and password.
    Password { login: String, password: String },
    /// A user whose identity the OpenID Connect flow verified. Only build this from the result
    /// of [`crate::OpenId::finish`]: the backend trusts it without further checks, beyond the
    /// account being enabled.
    Verified { user_id: i64 },
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::Password { login, .. } => formatter
                .debug_struct("Password")
                .field("login", login)
                .finish_non_exhaustive(),
            Credentials::Verified { user_id } => formatter
                .debug_struct("Verified")
                .field("user_id", user_id)
                .finish(),
        }
    }
}

/// The axum-login backend: authenticates [`Credentials`] and reloads [`SessionUser`]s.
#[derive(Debug, Clone)]
pub struct Backend {
    database: DatabaseConnection,
    local_accounts: bool,
}

/// A database failure while authenticating; wrong credentials are not errors.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct BackendError(#[from] nanobom_domain::Error);

/// A hash checked when the login matches no account, so that unknown logins take as long as
/// wrong passwords and do not reveal which accounts exist.
fn decoy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| password_auth::generate_hash("nanobom decoy password"))
}

impl Backend {
    /// A backend; with `local_accounts` off, password credentials are always refused, even for
    /// accounts that have a password.
    pub fn new(database: DatabaseConnection, local_accounts: bool) -> Self {
        Self {
            database,
            local_accounts,
        }
    }

    /// Computes the decoy hash ahead of the first sign-in, so the first unknown login does
    /// not take noticeably longer than later ones.
    pub fn prepare(&self) {
        let _ = decoy_hash();
    }
}

impl AuthnBackend for Backend {
    type User = SessionUser;
    type Credentials = Credentials;
    type Error = BackendError;

    async fn authenticate(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user = match credentials {
            Credentials::Password { login, password } => {
                if !self.local_accounts {
                    return Ok(None);
                }
                let user = users::find_by_login(&self.database, &login).await?;
                let hash = user
                    .as_ref()
                    .and_then(|user| user.password_hash.clone())
                    .unwrap_or_else(|| decoy_hash().to_owned());
                let valid = passwords::verify(password, hash).await;
                match user {
                    Some(user) if valid && user.password_hash.is_some() && !user.is_disabled => {
                        user
                    }
                    _ => return Ok(None),
                }
            }
            Credentials::Verified { user_id } => {
                match users::find_by_id(&self.database, user_id).await? {
                    Some(user) if !user.is_disabled => user,
                    _ => return Ok(None),
                }
            }
        };
        users::record_login(&self.database, user.id).await?;
        tracing::info!(user = %user.username, "signed in");
        Ok(Some(SessionUser::from_model(&user)))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(users::find_by_id(&self.database, *user_id)
            .await?
            .filter(|user| !user.is_disabled)
            .map(|user| SessionUser::from_model(&user)))
    }
}

/// The session type handlers receive.
pub type AuthenticationSession = axum_login::AuthSession<Backend>;
