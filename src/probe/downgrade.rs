use crate::probe::handshake::{build_client_hello, send_and_receive, ServerResponse};
use crate::{DowngradeResult, TlsVersion};

// Classical-only groups (no PQC)
const CLASSICAL_GROUPS: &[u16] = &[0x001D, 0x0017, 0x0018];

// Classical-only cipher suites for TLS 1.2 downgrade probe
const CLASSICAL_SUITES: &[u16] = &[
    0xC02C, 0xC030, 0xC02B, 0xC02F, // ECDHE-AES
    0x003D, 0x003C, 0x002F, 0x0035, // RSA-AES/3DES
];

/// Classify a ServerResponse as a DowngradeResult.
pub fn classify_downgrade(response: &ServerResponse) -> DowngradeResult {
    match response {
        ServerResponse::ServerHello { tls_version, .. } => DowngradeResult::Accepted {
            negotiated_version: TlsVersion::from_code(*tls_version),
        },
        ServerResponse::Timeout => DowngradeResult::Timeout,
        ServerResponse::HandshakeFailure | ServerResponse::ConnectionClose => {
            DowngradeResult::Rejected
        }
    }
}

/// Send a TLS 1.2-only ClientHello and classify the response.
/// A ServerHello means the server accepted a downgrade to TLS 1.2.
pub async fn probe_downgrade(
    host: &str,
    port: u16,
    scheme: &str,
    timeout_ms: u64,
) -> DowngradeResult {
    let hello = build_client_hello(host, CLASSICAL_SUITES, CLASSICAL_GROUPS, 0x0303);
    let mut stream = match crate::probe::connect(host, port, scheme, timeout_ms).await {
        Ok(s) => s,
        Err(crate::ProbeError::Timeout { .. }) => return DowngradeResult::Timeout,
        Err(_) => return DowngradeResult::Rejected,
    };
    classify_downgrade(&send_and_receive(&mut stream, &hello, timeout_ms).await)
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
        assert!(matches!(
            classify_downgrade(&r),
            DowngradeResult::Accepted { .. }
        ));
    }

    #[test]
    fn handshake_failure_is_downgrade_rejected() {
        assert_eq!(
            classify_downgrade(&ServerResponse::HandshakeFailure),
            DowngradeResult::Rejected
        );
    }

    #[test]
    fn connection_close_is_downgrade_rejected() {
        assert_eq!(
            classify_downgrade(&ServerResponse::ConnectionClose),
            DowngradeResult::Rejected
        );
    }

    #[test]
    fn timeout_is_downgrade_timeout() {
        assert_eq!(
            classify_downgrade(&ServerResponse::Timeout),
            DowngradeResult::Timeout
        );
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

    #[test]
    fn server_hello_tls11_negotiated_version() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x002F,
            selected_group: None,
            tls_version: 0x0302,
        };
        assert_eq!(
            classify_downgrade(&r),
            DowngradeResult::Accepted {
                negotiated_version: TlsVersion::Tls11
            }
        );
    }
}
