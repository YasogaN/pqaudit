use crate::audit::tables::iana_ciphers::{cipher_name, is_tls13_suite, tls12_suites, tls13_suites};
use crate::probe::handshake::{build_client_hello, send_and_receive, ServerResponse};
use crate::{CipherInventory, CipherSuite};

/// Groups offered during cipher enumeration. PQC groups must be included so
/// PQC-only servers can answer (via HelloRetryRequest) instead of rejecting the
/// probe as classical-only.
const PROBE_GROUPS: &[u16] = &[
    0x11EC, // X25519MLKEM768
    0x11EB, // SecP256r1MLKEM768
    0x11ED, // SecP384r1MLKEM1024
    0x0201, // ML-KEM-768
    0x0202, // ML-KEM-1024
    0x001D, // X25519
    0x0017, // secp256r1
];

/// Classify a ServerResponse to extract which cipher suite was selected.
pub fn extract_selected_suite(response: &ServerResponse) -> Option<u16> {
    match response {
        ServerResponse::ServerHello { selected_suite, .. } => Some(*selected_suite),
        _ => None,
    }
}

async fn probe_with_suites(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    suites: &[u16],
    timeout_ms: u64,
    max_version: u16,
) -> Option<u16> {
    let hello = build_client_hello(sni, suites, PROBE_GROUPS, max_version);
    let mut stream = crate::probe::connect(host, port, scheme, timeout_ms)
        .await
        .ok()?;
    extract_selected_suite(&send_and_receive(&mut stream, &hello, timeout_ms).await)
}

async fn run_tls13_pass(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    timeout_ms: u64,
) -> Vec<CipherSuite> {
    let mut remaining: Vec<u16> = tls13_suites().collect();
    let mut found = Vec::new();
    while !remaining.is_empty() {
        match probe_with_suites(host, port, sni, scheme, &remaining, timeout_ms, 0x0304).await {
            // Only accept suites that were actually offered; a server that
            // keeps selecting an already-removed suite must not loop forever.
            Some(id) if remaining.contains(&id) && is_tls13_suite(id) => {
                found.push(CipherSuite {
                    id,
                    name: cipher_name(id),
                });
                remaining.retain(|&s| s != id);
            }
            // No suite from this offer was accepted (or the connection failed).
            _ => break,
        }
    }
    found
}

async fn run_tls12_pass(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    timeout_ms: u64,
) -> Vec<CipherSuite> {
    use std::collections::HashSet;

    let mut remaining: Vec<u16> = tls12_suites().collect();
    let mut found = Vec::new();
    while !remaining.is_empty() {
        let batch: Vec<u16> = remaining.iter().copied().take(64).collect();
        match probe_with_suites(host, port, sni, scheme, &batch, timeout_ms, 0x0303).await {
            Some(id) if batch.contains(&id) => {
                found.push(CipherSuite {
                    id,
                    name: cipher_name(id),
                });
                remaining.retain(|&s| s != id);
            }
            _ => {
                let batch_set: HashSet<u16> = batch.into_iter().collect();
                remaining.retain(|s| !batch_set.contains(s));
            }
        }
    }
    found
}

/// Probe whether the server supports the obsolete X25519Kyber768Draft00 group.
///
/// We offer X25519 as the key share and Kyber-draft only in `supported_groups`.
/// A server that prefers the draft group responds with a HelloRetryRequest
/// selecting 0x6399, which detects support without generating a Kyber key.
async fn probe_kyber_draft(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    timeout_ms: u64,
) -> bool {
    let hello = build_client_hello(sni, &[0x1301, 0x1302, 0x1303], &[0x6399, 0x001D], 0x0304);
    let mut stream = match crate::probe::connect(host, port, scheme, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return false,
    };
    matches!(
        send_and_receive(&mut stream, &hello, timeout_ms).await,
        ServerResponse::ServerHello {
            selected_group: Some(0x6399),
            ..
        }
    )
}

pub async fn enumerate_ciphers(
    host: &str,
    port: u16,
    sni: &str,
    scheme: &str,
    timeout_ms: u64,
) -> CipherInventory {
    let tls13_suites = run_tls13_pass(host, port, sni, scheme, timeout_ms).await;
    let tls12_suites = run_tls12_pass(host, port, sni, scheme, timeout_ms).await;
    let kyber_draft_accepted = probe_kyber_draft(host, port, sni, scheme, timeout_ms).await;
    CipherInventory {
        tls13_suites,
        tls12_suites,
        kyber_draft_accepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_selected_suite_from_server_hello() {
        let response = ServerResponse::ServerHello {
            selected_suite: 0x1302,
            selected_group: None,
            tls_version: 0x0303,
        };
        assert_eq!(extract_selected_suite(&response), Some(0x1302));
    }

    #[test]
    fn extract_selected_suite_from_failure_is_none() {
        assert_eq!(
            extract_selected_suite(&ServerResponse::HandshakeFailure),
            None
        );
        assert_eq!(extract_selected_suite(&ServerResponse::Timeout), None);
        assert_eq!(
            extract_selected_suite(&ServerResponse::ConnectionClose),
            None
        );
    }

    #[test]
    fn tls13_suite_list_has_five_entries() {
        assert_eq!(tls13_suites().count(), 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enumerate_ciphers_discovers_tls13_and_tls12_suites() {
        use crate::test_support::suite_selecting_server;

        let server =
            suite_selecting_server(vec![0x1302, 0x1303, 0xC02C, 0xC030, 0x000A], Some(0x11EC))
                .await;
        let inv = enumerate_ciphers("127.0.0.1", server.port(), "localhost", "", 2000).await;
        assert_eq!(inv.tls13_suites.len(), 2);
        assert_eq!(inv.tls12_suites.len(), 3);
        assert!(inv.tls13_suites.iter().any(|s| s.id == 0x1302));
        assert!(inv.tls13_suites.iter().any(|s| s.id == 0x1303));
        assert!(inv.tls12_suites.iter().any(|s| s.id == 0xC02C));
        assert!(inv.tls12_suites.iter().any(|s| s.id == 0xC030));
        assert!(inv.tls12_suites.iter().any(|s| s.id == 0x000A));
        assert!(!inv.kyber_draft_accepted);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kyber_draft_probe_detects_hrr_selection() {
        use crate::test_support::{fixed_response_server, server_hello, HRR_RANDOM};

        let server =
            fixed_response_server(server_hello(0x1302, Some(0x6399), 0x0303, Some(HRR_RANDOM)))
                .await;
        assert!(probe_kyber_draft("127.0.0.1", server.port(), "localhost", "", 2000).await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enumerate_ciphers_uses_sni_override() {
        use crate::test_support::{server_hello, sni_checking_server};

        let matching = sni_checking_server(
            "expected.example".into(),
            server_hello(0x1302, Some(0x11EC), 0x0303, None),
        )
        .await;
        let inv =
            enumerate_ciphers("127.0.0.1", matching.port(), "expected.example", "", 200).await;
        assert_eq!(inv.tls13_suites.len(), 1);

        let mismatched = sni_checking_server(
            "other.example".into(),
            server_hello(0x1302, Some(0x11EC), 0x0303, None),
        )
        .await;
        let inv =
            enumerate_ciphers("127.0.0.1", mismatched.port(), "expected.example", "", 200).await;
        assert!(inv.tls13_suites.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enumerate_ciphers_stops_on_unoffered_suite() {
        use crate::test_support::{fixed_response_server, server_hello};

        // Always answer with 0x1302, even after it has been removed from the
        // offer. The loop must terminate rather than spinning forever.
        let server = fixed_response_server(server_hello(0x1302, Some(0x11EC), 0x0303, None)).await;
        let inv = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            enumerate_ciphers("127.0.0.1", server.port(), "localhost", "", 200),
        )
        .await
        .expect("cipher enumeration looped forever");
        assert_eq!(inv.tls13_suites.len(), 1);
        assert_eq!(inv.tls13_suites[0].id, 0x1302);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enumerate_ciphers_works_against_pqc_only_servers() {
        use crate::test_support::{provider_with_groups, tls_server};
        use rustls::crypto::aws_lc_rs;

        let server = tls_server(
            provider_with_groups(vec![aws_lc_rs::kx_group::X25519MLKEM768]),
            &[&rustls::version::TLS13],
        )
        .await;
        let inv = enumerate_ciphers("127.0.0.1", server.port(), "localhost", "", 2000).await;
        assert!(
            !inv.tls13_suites.is_empty(),
            "PQC-only server should still report TLS 1.3 suites"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enumerate_ciphers_handles_unreachable_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let inv = enumerate_ciphers("127.0.0.1", port, "localhost", "", 50).await;
        assert!(inv.tls13_suites.is_empty());
        assert!(inv.tls12_suites.is_empty());
        assert!(!inv.kyber_draft_accepted);
    }
}
