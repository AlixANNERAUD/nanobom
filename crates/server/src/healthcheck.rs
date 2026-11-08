//! The `healthcheck` command: asks a running server's `/healthz` whether it is healthy, for
//! container health checks in images without curl.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use reqwest::Url;

use crate::{Failure, command_line::HealthcheckOptions};

/// Checks the configured URL, or the one derived from the listen address; fails on a timeout,
/// a connection error or an unsuccessful status.
pub async fn run(options: HealthcheckOptions) -> Result<(), Failure> {
    let url = match options.url {
        Some(url) => url,
        None => local_url(options.listen_address)?,
    };
    check(&url, Duration::from_secs(options.timeout_seconds)).await
}

/// Succeeds when `url` answers with a success status within `timeout`.
pub async fn check(url: &Url, timeout: Duration) -> Result<(), Failure> {
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let response = client.get(url.clone()).send().await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url} answered {}", response.status()).into())
    }
}

/// The health endpoint of a server listening on `address`, reached over loopback when it
/// listens on every interface.
pub fn local_url(address: SocketAddr) -> Result<Url, Failure> {
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let address = SocketAddr::new(ip, address.port());
    Ok(Url::parse(&format!("http://{address}/healthz"))?)
}
