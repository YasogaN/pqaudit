pub mod cipher_enum;
pub mod downgrade;
pub mod handshake;
pub mod hrr;
pub mod pqc_probe;
pub mod starttls;

use crate::ProbeError;

/// Map a TCP connect error to a structured probe error.
pub(crate) fn map_connect_error(
    e: std::io::Error,
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> ProbeError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::TimedOut => ProbeError::Timeout {
            after_ms: timeout_ms,
        },
        ErrorKind::NotFound | ErrorKind::AddrNotAvailable => ProbeError::DnsResolutionFailed {
            host: host.to_string(),
        },
        _ => ProbeError::ConnectionRefused {
            host: host.to_string(),
            port,
        },
    }
}

/// Open a TCP connection and perform STARTTLS if the scheme requires it.
pub(crate) async fn connect(
    host: &str,
    port: u16,
    scheme: &str,
    timeout_ms: u64,
) -> Result<tokio::net::TcpStream, ProbeError> {
    let stream = tcp_connect(host, port, timeout_ms)
        .await
        .map_err(|e| map_connect_error(e, host, port, timeout_ms))?;
    starttls::upgrade_to_tls(scheme, stream, port).await
}

/// Connect to `host:port` with per-address fallback.
///
/// Resolves the hostname to all IP addresses and tries each one with a
/// capped per-address timeout (2 s), stopping when `total_timeout_ms`
/// elapses. This avoids a single slow address (e.g. an unreachable IPv6
/// address or a temporarily degraded IPv4 endpoint) from consuming the
/// entire timeout budget before the next address can be attempted.
///
/// Returns `ErrorKind::TimedOut` if the budget ran out without a
/// successful connection, or the last OS error otherwise.
pub(crate) async fn tcp_connect(
    host: &str,
    port: u16,
    total_timeout_ms: u64,
) -> std::io::Result<tokio::net::TcpStream> {
    use std::io::{Error, ErrorKind};
    use tokio::time::{Duration, Instant};

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();

    let deadline = Instant::now() + Duration::from_millis(total_timeout_ms);
    const PER_ADDR_MS: u64 = 2_000;

    let mut last_err = Error::new(ErrorKind::TimedOut, "connection timed out");
    for addr in addrs {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) => d,
            None => break,
        };
        let per_timeout = remaining.min(Duration::from_millis(PER_ADDR_MS));
        match tokio::time::timeout(per_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = e,
            Err(_) => { /* per-address timeout — try next */ }
        }
    }
    Err(last_err)
}
