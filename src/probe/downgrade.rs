use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{DowngradeResult, TlsVersion};
use crate::probe::handshake::{build_client_hello, parse_server_response, ServerResponse};

// Classical-only groups (no PQC)
const CLASSICAL_GROUPS: &[u16] = &[0x001D, 0x0017, 0x0018];

// Classical-only cipher suites for TLS 1.2 downgrade probe
const CLASSICAL_SUITES: &[u16] = &[
    0xC02C, 0xC030, 0xC02B, 0xC02F, // ECDHE-AES
    0x003D, 0x003C, 0x002F, 0x0035, // RSA-AES/3DES
];

fn tls_version_from_u16(v: u16) -> TlsVersion {
    match v {
        0x0304 => TlsVersion::Tls13,
        0x0303 => TlsVersion::Tls12,
        0x0302 => TlsVersion::Tls11,
        0x0301 => TlsVersion::Tls10,
        other => TlsVersion::Unknown(other),
    }
}

/// Classify a ServerResponse as a DowngradeResult.
pub fn classify_downgrade(response: &ServerResponse) -> DowngradeResult {
    match response {
        ServerResponse::ServerHello { tls_version, .. } => DowngradeResult::Accepted {
            negotiated_version: tls_version_from_u16(*tls_version),
        },
        ServerResponse::HandshakeFailure
        | ServerResponse::ConnectionClose
        | ServerResponse::Timeout => DowngradeResult::Rejected,
    }
}

/// Send a TLS 1.2-only ClientHello and classify the response.
/// A ServerHello means the server accepted a downgrade to TLS 1.2.
pub async fn probe_downgrade(host: &str, port: u16, timeout_ms: u64) -> DowngradeResult {
    let hello = build_client_hello(host, CLASSICAL_SUITES, CLASSICAL_GROUPS, 0x0303);
    let mut stream = match tokio::net::TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(_) => return DowngradeResult::Rejected,
    };
    if stream.write_all(&hello).await.is_err() {
        return DowngradeResult::Rejected;
    }
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);
    let mut buf = Vec::with_capacity(4096);
    loop {
        let need = if buf.len() >= 5 {
            5 + u16::from_be_bytes([buf[3], buf[4]]) as usize
        } else {
            5
        };
        if buf.len() >= need {
            break;
        }
        let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
            Some(d) => d,
            None => return DowngradeResult::Rejected,
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    parse_server_response(&buf)
        .map(|r| classify_downgrade(&r))
        .unwrap_or(DowngradeResult::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_hello_is_downgrade_accepted() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x002F,
            selected_group: None,
            tls_version: 0x0303,
        };
        assert!(matches!(classify_downgrade(&r), DowngradeResult::Accepted { .. }));
    }

    #[test]
    fn handshake_failure_is_downgrade_rejected() {
        assert_eq!(classify_downgrade(&ServerResponse::HandshakeFailure), DowngradeResult::Rejected);
    }

    #[test]
    fn connection_close_is_downgrade_rejected() {
        assert_eq!(classify_downgrade(&ServerResponse::ConnectionClose), DowngradeResult::Rejected);
    }

    #[test]
    fn server_hello_tls12_negotiated_version() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x002F,
            selected_group: None,
            tls_version: 0x0303,
        };
        match classify_downgrade(&r) {
            DowngradeResult::Accepted { negotiated_version } => {
                assert_eq!(negotiated_version, TlsVersion::Tls12);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }
}
