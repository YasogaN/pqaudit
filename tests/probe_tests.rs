use pqaudit::probe::handshake::{parse_server_response, ServerResponse};

#[cfg(feature = "live-tests")]
#[tokio::test]
async fn cloudflare_negotiates_pqc() {
    use pqaudit::probe::pqc_probe::{pqc_probe, ScanConfig};
    let config = ScanConfig::default();
    let result = pqc_probe("cloudflare.com", 443, None, &config)
        .await
        .unwrap();
    assert!(
        result.negotiated_group.is_pqc,
        "cloudflare should negotiate PQC"
    );
    assert_eq!(result.negotiated_version, pqaudit::TlsVersion::Tls13);
}

#[test]
fn parses_handshake_failure_alert() {
    let bytes = include_bytes!("fixtures/handshake_failure_alert.bin");
    let response = parse_server_response(bytes).unwrap();
    assert!(matches!(response, ServerResponse::HandshakeFailure));
}

#[test]
fn parses_server_hello_from_fixture() {
    let bytes = include_bytes!("fixtures/pqc_hybrid_server.bin");
    let response = parse_server_response(bytes).unwrap();
    // Fixture contains key_share extension with X25519MLKEM768 (0x11EC)
    assert!(
        matches!(
            response,
            ServerResponse::ServerHello {
                selected_group: Some(0x11EC),
                ..
            }
        ),
        "expected selected_group = Some(0x11EC), got {:?}",
        response
    );
}
