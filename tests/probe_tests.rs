use pqaudit::probe::handshake::{parse_server_response, ServerResponse};

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
    assert!(matches!(response, ServerResponse::ServerHello { .. }));
}
