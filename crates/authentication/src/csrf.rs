//! Cross-site request forgery protection for cookie-authenticated requests.
//!
//! Session cookies are `SameSite=Lax`, so browsers do not send them with cross-site `POST`
//! requests. On top of that, state-changing requests are refused when the browser says they
//! come from another site (`Sec-Fetch-Site`) or from another origin (`Origin`). Requests
//! authenticated with an `Authorization` header (upload tokens) are not exposed to this attack
//! and are left alone.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// The origin (`scheme://host[:port]`) the interface is served from.
#[derive(Debug, Clone)]
pub struct AllowedOrigin(Arc<str>);

impl AllowedOrigin {
    pub fn new(public_url: &reqwest::Url) -> Self {
        Self(public_url.origin().ascii_serialization().into())
    }
}

fn is_safe(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Whether a state-changing request may proceed.
pub fn allowed(method: &Method, headers: &HeaderMap, origin: &AllowedOrigin) -> bool {
    if is_safe(method) || headers.contains_key(header::AUTHORIZATION) {
        return true;
    }
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && !matches!(site, "same-origin" | "none")
    {
        return false;
    }
    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        Some(sent) => sent == &*origin.0,
        // Browsers send Origin with every cross-origin POST; requests without it come from
        // non-browser clients or same-origin navigations of older browsers.
        None => true,
    }
}

/// Middleware rejecting cross-site state-changing requests with 403.
pub async fn protect(
    State(origin): State<AllowedOrigin>,
    request: Request,
    next: Next,
) -> Response {
    if allowed(request.method(), request.headers(), &origin) {
        next.run(request).await
    } else {
        tracing::warn!(
            method = %request.method(),
            path = request.uri().path(),
            "cross-site request refused"
        );
        (StatusCode::FORBIDDEN, "cross-site request refused").into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn only_same_origin_state_changes_pass() {
        let origin = AllowedOrigin::new(&"https://nanobom.example.org/app/".parse().unwrap());
        assert!(allowed(
            &Method::GET,
            &headers(&[("origin", "https://evil.example")]),
            &origin
        ));
        assert!(allowed(
            &Method::POST,
            &headers(&[
                ("origin", "https://nanobom.example.org"),
                ("sec-fetch-site", "same-origin")
            ]),
            &origin
        ));
        assert!(!allowed(
            &Method::POST,
            &headers(&[("origin", "https://evil.example")]),
            &origin
        ));
        assert!(!allowed(
            &Method::POST,
            &headers(&[("sec-fetch-site", "cross-site")]),
            &origin
        ));
        assert!(!allowed(
            &Method::DELETE,
            &headers(&[("sec-fetch-site", "same-site")]),
            &origin
        ));
        assert!(!allowed(
            &Method::POST,
            &headers(&[("origin", "null")]),
            &origin
        ));
        assert!(allowed(&Method::POST, &headers(&[]), &origin));
        assert!(allowed(
            &Method::PUT,
            &headers(&[
                ("authorization", "Bearer nanobom_x"),
                ("origin", "https://ci.example")
            ]),
            &origin
        ));
    }
}
