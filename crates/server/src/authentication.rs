//! Sign-in and sign-out routes, sessions and request checks.
//!
//! Sessions live in the database ([`DatabaseSessionStore`]) behind an `HttpOnly`,
//! `SameSite=Lax` cookie, `Secure` when the public URL is HTTPS, and expire after a configurable
//! inactivity period. Interface routes are wrapped in [`csrf::protect`]; the upload API is not,
//! since it is authenticated by a bearer token rather than a cookie.
//!
//! Password sign-in is rate limited per client address. Behind a reverse proxy, the peer
//! address is the proxy's, so every user shares one budget unless `--trust-forwarded-headers`
//! is set; setting it without a proxy lets clients pick their own address and escape the limit.

use std::{sync::Arc, time::Duration};

use axum::{
    Form, Router,
    extract::{Query, State},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_login::AuthManagerLayerBuilder;
use nanobom_authentication::{
    AuthenticationSession, Backend, Credentials, DatabaseSessionStore, OpenId, OpenIdSettings,
    PendingSignIn,
    claims::GroupMapping,
    csrf::{self, AllowedOrigin},
};
use serde::Deserialize;
use tower_governor::{
    GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{PeerIpKeyExtractor, SmartIpKeyExtractor},
};
use tower_sessions::{
    Expiry, Session, SessionManagerLayer, cookie::SameSite, cookie::time,
    session_store::ExpiredDeletion,
};

use crate::{
    command_line::{OpenIdOptions, ServeOptions},
    state::AppState,
};

const PENDING_SIGN_IN: &str = "openid.pending";

/// The OpenID Connect provider from the options, if configured: the issuer and the client
/// identifier must be set together. Empty optional settings count as unset, so environment
/// variables can be blanked out.
pub fn openid(options: &ServeOptions) -> Result<Option<OpenId>, crate::Failure> {
    let OpenIdOptions {
        oidc_issuer,
        oidc_client_id,
        oidc_client_secret,
        oidc_scopes,
        oidc_create_users,
        oidc_administrator_claim,
        oidc_administrator_value,
        oidc_groups_claim,
        oidc_group_mapping,
        ..
    } = &options.openid;
    let (Some(issuer), Some(client_id)) = (oidc_issuer, oidc_client_id) else {
        if oidc_issuer.is_some() || oidc_client_id.is_some() {
            return Err(
                "OpenID Connect needs both NANOBOM_OIDC_ISSUER and NANOBOM_OIDC_CLIENT_ID".into(),
            );
        }
        return Ok(None);
    };
    let redirect_url = options.public_url.join("auth/oidc/callback")?.to_string();
    let group_mapping = GroupMapping::parse(oidc_group_mapping)
        .map_err(|error| format!("invalid NANOBOM_OIDC_GROUP_MAPPING: {error}"))?;
    let openid = OpenId::new(OpenIdSettings {
        // Kept as configured: the library compares it character for character with the issuer
        // the provider announces, and some (Authentik) announce one ending with a slash.
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        client_secret: oidc_client_secret
            .clone()
            .filter(|secret| !secret.is_empty()),
        scopes: oidc_scopes.split_whitespace().map(str::to_owned).collect(),
        redirect_url,
        create_users: *oidc_create_users,
        personal_organizations: options.accounts.personal_organizations,
        administrator_claim: oidc_administrator_claim
            .clone()
            .filter(|claim| !claim.is_empty()),
        administrator_value: oidc_administrator_value
            .clone()
            .filter(|value| !value.is_empty()),
        groups_claim: oidc_groups_claim.clone().filter(|claim| !claim.is_empty()),
        group_mapping,
    })?;
    Ok(Some(openid))
}

/// Adds the sign-in routes and wraps everything in sessions and request checks. Also starts the
/// hourly deletion of expired sessions, so it must be called inside a Tokio runtime.
pub fn layer(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    let mut routes = Router::new()
        .route("/auth/logout", post(sign_out))
        .route("/auth/oidc/login", get(start_openid))
        .route("/auth/oidc/callback", get(finish_openid));
    if state.options.local_accounts {
        routes = routes.merge(rate_limited_sign_in(state.options.trust_forwarded_headers));
    }

    let store = DatabaseSessionStore::new(state.database.clone());
    let cleanup = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(error) = cleanup.delete_expired().await {
                tracing::warn!(%error, "deleting expired sessions failed");
            }
        }
    });
    let sessions = SessionManagerLayer::new(store)
        .with_name("nanobom_session")
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_secure(state.options.public_url.scheme() == "https")
        .with_expiry(Expiry::OnInactivity(time::Duration::days(
            state.options.session_inactivity_days.max(1),
        )));
    let backend = Backend::new(state.database.clone(), state.options.local_accounts);
    backend.prepare();
    let authentication = AuthManagerLayerBuilder::new(backend, sessions).build();
    let origin = AllowedOrigin::new(&state.options.public_url);

    router
        .merge(routes)
        .layer(middleware::from_fn_with_state(origin, csrf::protect))
        .layer(authentication)
}

/// `POST /auth/login`, limited to a burst of 5 attempts per client address, then one every
/// 4 seconds.
fn rate_limited_sign_in(trust_forwarded_headers: bool) -> Router<AppState> {
    let route = post(sign_in);
    let route = if trust_forwarded_headers {
        let configuration = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(4)
                .burst_size(5)
                .key_extractor(SmartIpKeyExtractor)
                .finish()
                .expect("valid rate limits"),
        );
        let limiter = Arc::clone(&configuration);
        forget_old_clients(move || limiter.limiter().retain_recent());
        route.layer(GovernorLayer::new(configuration))
    } else {
        let configuration = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(4)
                .burst_size(5)
                .key_extractor(PeerIpKeyExtractor)
                .finish()
                .expect("valid rate limits"),
        );
        let limiter = Arc::clone(&configuration);
        forget_old_clients(move || limiter.limiter().retain_recent());
        route.layer(GovernorLayer::new(configuration))
    };
    Router::new().route("/auth/login", route)
}

/// Drops the rate-limiting state of clients not seen recently, so it does not grow forever.
fn forget_old_clients(retain_recent: impl Fn() + Send + 'static) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            retain_recent();
        }
    });
}

/// Keeps redirects on this site (see [`nanobom_authentication::redirect::local_path`]):
/// anything that is not a local path becomes `/`.
pub fn safe_next(next: Option<&str>) -> String {
    next.and_then(nanobom_authentication::redirect::local_path)
        .unwrap_or("/")
        .to_owned()
}

fn sign_in_page(error: &str, next: &str) -> Redirect {
    let next = reqwest::Url::parse_with_params("http://local/", [("error", error), ("next", next)])
        .map(|url| url.query().unwrap_or_default().to_owned())
        .unwrap_or_default();
    Redirect::to(&format!("/login?{next}"))
}

#[derive(Deserialize)]
struct SignInForm {
    login: String,
    password: String,
    next: Option<String>,
}

async fn sign_in(mut session: AuthenticationSession, Form(form): Form<SignInForm>) -> Redirect {
    let next = safe_next(form.next.as_deref());
    let credentials = Credentials::Password {
        login: form.login,
        password: form.password,
    };
    match session.authenticate(credentials).await {
        Ok(Some(user)) => match session.login(&user).await {
            Ok(()) => Redirect::to(&next),
            Err(error) => {
                tracing::error!(%error, "starting the session failed");
                sign_in_page("unavailable", &next)
            }
        },
        Ok(None) => sign_in_page("invalid", &next),
        Err(error) => {
            tracing::error!(%error, "sign-in failed");
            sign_in_page("unavailable", &next)
        }
    }
}

async fn sign_out(mut session: AuthenticationSession) -> Redirect {
    if let Err(error) = session.logout().await {
        tracing::warn!(%error, "ending the session failed");
    }
    Redirect::to("/login")
}

#[derive(Deserialize)]
struct StartParameters {
    next: Option<String>,
}

async fn start_openid(
    State(state): State<AppState>,
    session: Session,
    Query(parameters): Query<StartParameters>,
) -> Response {
    let next = safe_next(parameters.next.as_deref());
    let Some(openid) = &state.openid else {
        return sign_in_page("unavailable", &next).into_response();
    };
    match openid.start(Some(next.clone())).await {
        Ok((url, pending)) => {
            if let Err(error) = session.insert(PENDING_SIGN_IN, pending).await {
                tracing::error!(%error, "storing the pending sign-in failed");
                return sign_in_page("unavailable", &next).into_response();
            }
            Redirect::to(&url).into_response()
        }
        Err(error) => {
            tracing::error!(%error, "starting the OpenID Connect sign-in failed");
            sign_in_page("provider", &next).into_response()
        }
    }
}

#[derive(Deserialize)]
struct CallbackParameters {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn finish_openid(
    State(state): State<AppState>,
    mut authentication: AuthenticationSession,
    Query(parameters): Query<CallbackParameters>,
) -> Redirect {
    let pending: Option<PendingSignIn> = authentication
        .session
        .remove(PENDING_SIGN_IN)
        .await
        .ok()
        .flatten();
    let Some(pending) = pending else {
        return sign_in_page("expired", "/");
    };
    let next = safe_next(pending.next.as_deref());
    let (Some(openid), Some(code), Some(returned_state)) =
        (&state.openid, parameters.code, parameters.state)
    else {
        tracing::warn!(
            error = parameters.error.as_deref().unwrap_or("no code"),
            description = parameters.error_description.as_deref().unwrap_or_default(),
            "the identity provider did not sign the user in"
        );
        return sign_in_page("provider", &next);
    };
    let user = match openid
        .finish(&state.database, pending, code, &returned_state)
        .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "OpenID Connect sign-in refused");
            let reason = match error {
                nanobom_authentication::OpenIdError::UnknownUser => "unknown",
                nanobom_authentication::OpenIdError::Disabled => "disabled",
                _ => "provider",
            };
            return sign_in_page(reason, &next);
        }
    };
    match authentication
        .authenticate(Credentials::Verified { user_id: user.id })
        .await
    {
        Ok(Some(user)) => match authentication.login(&user).await {
            Ok(()) => Redirect::to(&next),
            Err(error) => {
                tracing::error!(%error, "starting the session failed");
                sign_in_page("unavailable", &next)
            }
        },
        Ok(None) => sign_in_page("disabled", &next),
        Err(error) => {
            tracing::error!(%error, "sign-in failed");
            sign_in_page("unavailable", &next)
        }
    }
}
