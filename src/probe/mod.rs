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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn connect_errors_are_classified() {
        assert!(matches!(
            map_connect_error(Error::new(ErrorKind::TimedOut, "x"), "h", 443, 10),
            ProbeError::Timeout { after_ms: 10 }
        ));
        assert!(matches!(
            map_connect_error(Error::new(ErrorKind::NotFound, "x"), "h", 443, 10),
            ProbeError::DnsResolutionFailed { .. }
        ));
        assert!(matches!(
            map_connect_error(Error::new(ErrorKind::AddrNotAvailable, "x"), "h", 443, 10),
            ProbeError::DnsResolutionFailed { .. }
        ));
        assert!(matches!(
            map_connect_error(Error::new(ErrorKind::ConnectionRefused, "x"), "h", 443, 10),
            ProbeError::ConnectionRefused { .. }
        ));
        assert!(matches!(
            map_connect_error(Error::other("x"), "h", 443, 10),
            ProbeError::ConnectionRefused { .. }
        ));
    }

    #[tokio::test]
    async fn tcp_connect_reaches_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = tcp_connect("127.0.0.1", port, 1000).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
        drop(stream);
    }

    #[tokio::test]
    async fn tcp_connect_falls_back_across_addresses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // `localhost` may resolve to ::1 first; the refused IPv6 attempt should
        // fall back to 127.0.0.1.
        let stream = tcp_connect("localhost", port, 1000).await.unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn tcp_connect_reports_refused_and_dns_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = tcp_connect("127.0.0.1", port, 100).await.unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::ConnectionRefused | ErrorKind::TimedOut
        ));

        assert!(tcp_connect("does-not-exist.invalid", 443, 100)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn tcp_connect_times_out_on_unroutable_address() {
        // RFC 5737 TEST-NET-1. This exercises the per-address timeout path.
        assert!(tcp_connect("192.0.2.1", 443, 10).await.is_err());
    }

    #[tokio::test]
    async fn connect_does_direct_tcp_and_starttls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = connect("127.0.0.1", port, "", 1000).await.unwrap();
        drop(stream);

        use crate::test_support::smtp_starttls_server;
        use rustls::crypto::aws_lc_rs;
        let server = smtp_starttls_server(aws_lc_rs::default_provider()).await;
        let stream = connect("127.0.0.1", server.port(), "smtp", 2000)
            .await
            .unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn tcp_connect_zero_timeout_exits_cleanly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // "localhost" can resolve to both ::1 and 127.0.0.1, exercising the
        // deadline break between addresses.
        let _ = tcp_connect("localhost", port, 0).await;
    }

    #[tokio::test]
    async fn connect_propagates_starttls_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let err = connect("127.0.0.1", port, "ftp", 1000).await.unwrap_err();
        assert!(matches!(err, ProbeError::StarttlsUpgradeFailed { .. }));
    }
}
