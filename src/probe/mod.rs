pub mod cipher_enum;
pub mod downgrade;
pub mod handshake;
pub mod hrr;
pub mod pqc_probe;
pub mod starttls;

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
