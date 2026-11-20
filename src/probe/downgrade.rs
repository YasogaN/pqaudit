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
        // A ServerHello only counts as an accepted downgrade when it selected
        // TLS 1.0-1.2. A TLS 1.3 ServerHello or HRR here is a protocol
        // violation, not evidence that the server accepts TLS 1.2.
        ServerResponse::ServerHello { tls_version, .. } => match *tls_version {
            0x0301..=0x0303 => DowngradeResult::Accepted {
                negotiated_version: TlsVersion::from_code(*tls_version),
            },
            other => DowngradeResult::Error(format!(
                "unexpected ServerHello version 0x{other:04x} for a TLS 1.2-only probe"
            )),
        },
        ServerResponse::Timeout => DowngradeResult::Timeout,
        ServerResponse::HandshakeFailure | ServerResponse::ConnectionClose => {
            DowngradeResult::Rejected
        }
        ServerResponse::Error(reason) => DowngradeResult::Error(reason.clone()),
    }
}

/// Send a TLS 1.2-only ClientHello and classify the response.
/// A ServerHello means the server accepted a downgrade to TLS 1.2.
pub async fn probe_downgrade(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    timeout_ms: u64,
) -> DowngradeResult {
    let hello = build_client_hello(sni, CLASSICAL_SUITES, CLASSICAL_GROUPS, 0x0303);
    let mut stream = match crate::probe::connect(host, port, scheme, timeout_ms).await {
        Ok(s) => s,
        Err(crate::ProbeError::Timeout { .. }) => return DowngradeResult::Timeout,
        Err(e) => return DowngradeResult::Error(format!("connection failed: {e}")),
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
    fn probe_error_is_not_a_rejection() {
        assert_eq!(
            classify_downgrade(&ServerResponse::Error("parse failed".into())),
            DowngradeResult::Error("parse failed".into())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_reports_parse_failure() {
        use crate::test_support::fixed_response_server;

        let server = fixed_response_server(vec![0x17, 0x03, 0x03, 0x00, 0x00]).await;
        let result = probe_downgrade("127.0.0.1", server.port(), "localhost", "", 2000).await;
        assert!(
            matches!(result, DowngradeResult::Error(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn server_hello_tls12_negotiated_version() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x002F,
            selected_group: None,
            tls_version: 0x0303,
        };
        assert!(matches!(
            classify_downgrade(&r),
            DowngradeResult::Accepted {
                negotiated_version: TlsVersion::Tls12
            }
        ));
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

    #[test]
    fn tls13_server_hello_is_not_accepted_as_downgrade() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x1302,
            selected_group: None,
            tls_version: 0x0304,
        };
        assert!(matches!(classify_downgrade(&r), DowngradeResult::Error(_)));
    }

    #[test]
    fn unknown_server_hello_version_is_not_accepted_as_downgrade() {
        let r = ServerResponse::ServerHello {
            selected_suite: 0x002F,
            selected_group: None,
            tls_version: 0x0000,
        };
        assert!(matches!(classify_downgrade(&r), DowngradeResult::Error(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_accepts_tls12_server_hello() {
        use crate::test_support::{fixed_response_server, server_hello};

        let server = fixed_response_server(server_hello(0xC02F, None, 0x0303, None)).await;
        assert_eq!(
            probe_downgrade("127.0.0.1", server.port(), "localhost", "", 2000).await,
            DowngradeResult::Accepted {
                negotiated_version: TlsVersion::Tls12
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_rejects_handshake_failure() {
        use crate::test_support::fixed_response_server;

        let server = fixed_response_server(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
        assert_eq!(
            probe_downgrade("127.0.0.1", server.port(), "localhost", "", 2000).await,
            DowngradeResult::Rejected
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_times_out_and_reports_connection_errors() {
        use crate::test_support::silent_server;

        let silent = silent_server().await;
        assert_eq!(
            probe_downgrade("127.0.0.1", silent.port(), "localhost", "", 50).await,
            DowngradeResult::Timeout
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert!(matches!(
            probe_downgrade("127.0.0.1", port, "localhost", "", 50).await,
            DowngradeResult::Error(_)
        ));

        // RFC 5737 TEST-NET-1: connection cannot complete, so this maps to
        // Timeout on Linux and to Error on platforms that fail fast.
        assert!(matches!(
            probe_downgrade("192.0.2.1", 443, "localhost", "", 10).await,
            DowngradeResult::Timeout | DowngradeResult::Error(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_uses_sni_override() {
        use crate::test_support::{server_hello, sni_checking_server};

        let matching = sni_checking_server(
            "expected.example".into(),
            server_hello(0xC02F, None, 0x0303, None),
        )
        .await;
        assert!(matches!(
            probe_downgrade("127.0.0.1", matching.port(), "expected.example", "", 2000).await,
            DowngradeResult::Accepted { .. }
        ));

        let mismatched = sni_checking_server(
            "other.example".into(),
            server_hello(0xC02F, None, 0x0303, None),
        )
        .await;
        assert_eq!(
            probe_downgrade("127.0.0.1", mismatched.port(), "expected.example", "", 2000).await,
            DowngradeResult::Rejected
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn probe_downgrade_performs_starttls() {
        use crate::test_support::smtp_starttls_server;
        use rustls::crypto::aws_lc_rs;

        let server = smtp_starttls_server(aws_lc_rs::default_provider()).await;
        let result = probe_downgrade("127.0.0.1", server.port(), "localhost", "smtp", 2000).await;
        assert!(matches!(result, DowngradeResult::Accepted { .. }));
    }
}
