use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Result of parsing a server's TLS response.
#[derive(Debug)]
pub enum ServerResponse {
    ServerHello {
        selected_suite: u16,
        selected_group: Option<u16>,
        tls_version: u16,
    },
    HandshakeFailure,
    ConnectionClose,
    Timeout,
    /// The probe could not obtain a usable TLS response (transport, write,
    /// read, or parse failure). This is not a statement about the server's
    /// TLS version support.
    Error(String),
}

/// Parse a TLS ServerHello or Alert from raw bytes.
pub fn parse_server_response(bytes: &[u8]) -> Result<ServerResponse, String> {
    if bytes.len() < 5 {
        return Err("too short".into());
    }
    match bytes[0] {
        0x15 => {
            // Alert record: level(1) + description(1)
            // Only fatal handshake_failure (level=2, desc=0x28) is HandshakeFailure.
            // Other alerts (e.g. close_notify level=1) map to ConnectionClose.
            if bytes.len() >= 7 {
                let level = bytes[5];
                let desc = bytes[6];
                if level == 0x02 && desc == 0x28 {
                    Ok(ServerResponse::HandshakeFailure)
                } else {
                    Ok(ServerResponse::ConnectionClose)
                }
            } else {
                Ok(ServerResponse::HandshakeFailure) // short alert, assume fatal
            }
        }
        0x16 => parse_server_hello(bytes), // Handshake record
        b => Err(format!("unexpected record type: 0x{:02x}", b)),
    }
}

fn parse_server_hello(bytes: &[u8]) -> Result<ServerResponse, String> {
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes.
    // The public entry point already rejects inputs shorter than 5 bytes.
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len {
        return Err("record truncated".into());
    }

    // Handshake header: type(1) + length(3) = 4 bytes
    let payload = &bytes[5..5 + record_len];
    if payload.len() < 4 {
        return Err("handshake too short".into());
    }
    if payload[0] != 0x02 {
        return Err(format!(
            "expected ServerHello (0x02), got 0x{:02x}",
            payload[0]
        ));
    }

    // ServerHello body: version(2) + random(32) + session_id_len(1) + ...
    let body = &payload[4..];
    if body.len() < 2 + 32 + 1 {
        return Err("ServerHello body too short".into());
    }
    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    // session_id
    let sid_len = body[34] as usize;
    let after_sid = 35 + sid_len;
    if body.len() < after_sid + 2 {
        return Err("ServerHello truncated after session_id".into());
    }
    let selected_suite = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]);

    // Extensions parsing for key_share group (optional — may not be present in minimal ServerHello)
    // after_sid + 2 (cipher suite) + 1 (compression) = after_sid + 3
    let selected_group = parse_key_share_group(body, after_sid + 3);

    Ok(ServerResponse::ServerHello {
        selected_suite,
        selected_group,
        tls_version,
    })
}

/// Try to extract the key_share group from ServerHello extensions.
/// Returns None if extensions are absent or key_share is not found.
fn parse_key_share_group(body: &[u8], extensions_offset: usize) -> Option<u16> {
    if body.len() < extensions_offset + 2 {
        return None; // no extensions
    }
    let ext_total_len =
        u16::from_be_bytes([body[extensions_offset], body[extensions_offset + 1]]) as usize;
    let mut pos = extensions_offset + 2;
    let end = pos + ext_total_len;
    if body.len() < end {
        return None;
    }
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        // key_share extension type = 0x0033
        // ServerHello: group(2) + key_exchange_len(2) + key_exchange (ext_len >= 4)
        // HelloRetryRequest: group(2) only (ext_len == 2)
        if ext_type == 0x0033 && ext_len >= 2 {
            let group = u16::from_be_bytes([body[pos], body[pos + 1]]);
            return Some(group);
        }
        pos += ext_len;
    }
    None
}

fn push_sni_extension(extensions: &mut Vec<u8>, sni: &str) {
    if sni.is_empty() {
        return;
    }
    let name_bytes = sni.as_bytes();
    let name_len = name_bytes.len();
    let list_len = name_len + 3; // type(1) + len(2)
    let mut sni_ext = vec![0x00, 0x00]; // extension type: server_name
    let total_len = (list_len + 2) as u16;
    sni_ext.extend_from_slice(&total_len.to_be_bytes());
    sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes()); // server_name_list length
    sni_ext.push(0x00); // host_name type
    sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
    sni_ext.extend_from_slice(name_bytes);
    extensions.extend_from_slice(&sni_ext);
}

fn push_supported_groups_extension(extensions: &mut Vec<u8>, named_groups: &[u16]) {
    let groups_bytes: Vec<u8> = named_groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    let list_len = groups_bytes.len() as u16;
    let ext_len = list_len + 2; // +2 for the list_len field
    let mut ext = vec![0x00, 0x0a];
    ext.extend_from_slice(&ext_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.extend_from_slice(&groups_bytes);
    extensions.extend_from_slice(&ext);
}

fn push_supported_versions_extension(extensions: &mut Vec<u8>, max_version: u16) {
    let versions: &[u16] = if max_version >= 0x0304 {
        &[0x0304, 0x0303] // TLS 1.3, TLS 1.2
    } else {
        &[0x0303] // TLS 1.2 only
    };
    let mut ext = vec![0x00, 0x2b]; // extension type
    let versions_len = versions.len() * 2;
    let ext_data_len = (versions_len + 1) as u16; // +1 for the length byte
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.push(versions_len as u8);
    for v in versions {
        ext.extend_from_slice(&v.to_be_bytes());
    }
    extensions.extend_from_slice(&ext);
}

fn push_signature_algorithms_extension(extensions: &mut Vec<u8>) {
    // Mandatory for TLS 1.3 per RFC 8446 §9.2.
    const SIG_ALGS: &[u16] = &[
        0x0403, // ecdsa_secp256r1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0603, // ecdsa_secp521r1_sha512
        0x0804, // rsa_pss_rsae_sha256
        0x0805, // rsa_pss_rsae_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0401, // rsa_pkcs1_sha256
        0x0501, // rsa_pkcs1_sha384
        0x0601, // rsa_pkcs1_sha512
    ];
    let alg_bytes: Vec<u8> = SIG_ALGS.iter().flat_map(|a| a.to_be_bytes()).collect();
    let list_len = alg_bytes.len() as u16;
    let ext_data_len = list_len + 2;
    let mut ext = vec![0x00, 0x0d];
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.extend_from_slice(&alg_bytes);
    extensions.extend_from_slice(&ext);
}

fn push_key_share_extension(extensions: &mut Vec<u8>, named_groups: &[u16]) {
    // Always use X25519 (0x001D) with the base point when X25519 is in named_groups.
    // PQC hybrid groups need ~1184–1216 byte key shares that we don't generate;
    // advertising them in supported_groups is enough to trigger an HRR from PQC-capable
    // servers, which tells us the preferred group without needing a real PQC key share.
    let (ks_group, ks_key): (u16, Vec<u8>) = if named_groups.contains(&0x001D) {
        let mut key = vec![0u8; 32];
        key[0] = 9; // X25519 base point u-coordinate (little-endian)
        (0x001D, key)
    } else {
        let group = named_groups.first().copied().unwrap_or(0x001D);
        (group, vec![0u8; 32])
    };
    let key_len = ks_key.len() as u16;
    let entry_len: u16 = 2 + 2 + key_len; // group(2) + key_len(2) + key
    let list_len: u16 = entry_len;
    let ext_data_len: u16 = list_len + 2;
    let mut ext = vec![0x00, 0x33];
    ext.extend_from_slice(&ext_data_len.to_be_bytes());
    ext.extend_from_slice(&list_len.to_be_bytes());
    ext.extend_from_slice(&ks_group.to_be_bytes());
    ext.extend_from_slice(&key_len.to_be_bytes());
    ext.extend_from_slice(&ks_key);
    extensions.extend_from_slice(&ext);
}

fn build_hello(
    sni: &str,
    cipher_suites: &[u16],
    named_groups: &[u16],
    legacy_version: u16,
    modern: bool,
    max_version: u16,
) -> Vec<u8> {
    let mut extensions = Vec::new();
    push_sni_extension(&mut extensions, sni);
    if modern {
        push_supported_versions_extension(&mut extensions, max_version);
    }
    push_supported_groups_extension(&mut extensions, named_groups);
    if modern {
        push_signature_algorithms_extension(&mut extensions);
        push_key_share_extension(&mut extensions, named_groups);
    }

    // Build cipher suites
    let suites_bytes: Vec<u8> = cipher_suites.iter().flat_map(|s| s.to_be_bytes()).collect();
    let suites_len = suites_bytes.len() as u16;

    // Build ClientHello body
    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&legacy_version.to_be_bytes());
    let mut random = [0u8; 32];
    // ClientHello.random must not be predictable. If the RNG fails, the
    // zero-filled buffer is still structurally valid for a probe.
    let _ = aws_lc_rs::rand::fill(&mut random);
    hello_body.extend_from_slice(&random);
    hello_body.push(0x00); // session_id length = 0
    hello_body.extend_from_slice(&suites_len.to_be_bytes());
    hello_body.extend_from_slice(&suites_bytes);
    hello_body.push(0x01); // compression methods length
    hello_body.push(0x00); // no compression
    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    // Handshake header: type (0x01) + length (3 bytes)
    let hello_len = hello_body.len();
    let mut handshake = vec![
        0x01, // ClientHello
        ((hello_len >> 16) & 0xFF) as u8,
        ((hello_len >> 8) & 0xFF) as u8,
        (hello_len & 0xFF) as u8,
    ];
    handshake.extend_from_slice(&hello_body);

    // TLS record header: content type (0x16) + version (0x03 0x01) + length
    let mut record = vec![
        0x16,
        0x03,
        0x01, // handshake, TLS 1.0 (for compat)
        ((handshake.len() >> 8) & 0xFF) as u8,
        (handshake.len() & 0xFF) as u8,
    ];
    record.extend_from_slice(&handshake);
    record
}

/// Build a minimal TLS 1.3 / 1.2 ClientHello.
pub fn build_client_hello(
    sni: &str,
    cipher_suites: &[u16],
    named_groups: &[u16],
    max_version: u16,
) -> Vec<u8> {
    build_hello(sni, cipher_suites, named_groups, 0x0303, true, max_version)
}

/// Build a legacy TLS 1.0/1.1 ClientHello without TLS 1.3 extensions.
pub fn build_client_hello_legacy(
    sni: &str,
    cipher_suites: &[u16],
    named_groups: &[u16],
    version: u16,
) -> Vec<u8> {
    build_hello(sni, cipher_suites, named_groups, version, false, version)
}

/// Error returned while reading a TLS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    Timeout,
    ConnectionClose,
    Io,
    WriteError,
}

/// Read one complete TLS record from `stream`.
pub async fn read_tls_record<S>(stream: &mut S, timeout_ms: u64) -> Result<Vec<u8>, ReadError>
where
    S: AsyncRead + Unpin,
{
    use tokio::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = Vec::with_capacity(8192);
    loop {
        let need = if buf.len() >= 5 {
            5 + u16::from_be_bytes([buf[3], buf[4]]) as usize
        } else {
            5 // need at least the record header
        };
        if buf.len() >= need {
            return Ok(buf);
        }
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) => d,
            None => return Err(ReadError::Timeout),
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Err(ReadError::ConnectionClose),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return Err(ReadError::Io),
            Err(_) => return Err(ReadError::Timeout),
        }
    }
}

/// Send a ClientHello and return the raw response record bytes.
pub async fn send_and_read_raw<S>(
    stream: &mut S,
    hello: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, ReadError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.write_all(hello).await.is_err() {
        return Err(ReadError::WriteError);
    }
    read_tls_record(stream, timeout_ms).await
}

/// Send a ClientHello and classify the response.
pub async fn send_and_receive<S>(stream: &mut S, hello: &[u8], timeout_ms: u64) -> ServerResponse
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match send_and_read_raw(stream, hello, timeout_ms).await {
        Ok(buf) => parse_server_response(&buf).unwrap_or_else(ServerResponse::Error),
        Err(ReadError::Timeout) => ServerResponse::Timeout,
        Err(ReadError::ConnectionClose) => ServerResponse::ConnectionClose,
        Err(ReadError::Io) => ServerResponse::Error("I/O error while reading TLS response".into()),
        Err(ReadError::WriteError) => ServerResponse::Error("failed to write ClientHello".into()),
    }
}

/// Send ClientHello over an existing TcpStream, read response, classify it.
/// Accumulates bytes until a complete TLS record is received (handles TCP fragmentation).
pub async fn probe_once<S>(stream: &mut S, hello: &[u8], timeout_ms: u64) -> ServerResponse
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_and_receive(stream, hello, timeout_ms).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn server_hello_bytes(selected_suite: u16, group: Option<u16>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend(std::iter::repeat_n(0u8, 32));
        body.push(0); // session id
        body.extend_from_slice(&selected_suite.to_be_bytes());
        body.push(0); // compression
        let mut exts = Vec::new();
        if let Some(group) = group {
            exts.extend_from_slice(&0x0033u16.to_be_bytes());
            exts.extend_from_slice(&4u16.to_be_bytes());
            exts.extend_from_slice(&group.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![
            0x02,
            ((body.len() >> 16) & 0xFF) as u8,
            ((body.len() >> 8) & 0xFF) as u8,
            (body.len() & 0xFF) as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![
            0x16,
            0x03,
            0x03,
            ((hs.len() >> 8) & 0xFF) as u8,
            (hs.len() & 0xFF) as u8,
        ];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_handshake_failure_alert() {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(matches!(
            parse_server_response(&bytes),
            Ok(ServerResponse::HandshakeFailure)
        ));
    }

    #[test]
    fn parses_non_fatal_alert_as_connection_close() {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        assert!(matches!(
            parse_server_response(&bytes),
            Ok(ServerResponse::ConnectionClose)
        ));
    }

    #[test]
    fn short_alert_is_handshake_failure() {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x01, 0x02];
        assert!(matches!(
            parse_server_response(&bytes),
            Ok(ServerResponse::HandshakeFailure)
        ));
    }

    #[test]
    fn too_short_response_is_error() {
        assert!(parse_server_response(&[0x16, 0x03]).is_err());
    }

    #[test]
    fn unexpected_record_type_is_error() {
        let bytes = [0x17, 0x03, 0x03, 0x00, 0x00];
        assert!(parse_server_response(&bytes).is_err());
    }

    #[test]
    fn parses_server_hello_with_key_share_group() {
        let bytes = server_hello_bytes(0x1302, Some(0x11EC));
        assert!(matches!(
            parse_server_response(&bytes).unwrap(),
            ServerResponse::ServerHello {
                selected_suite: 0x1302,
                selected_group: Some(0x11EC),
                tls_version: 0x0303,
            }
        ));
    }

    #[test]
    fn parses_server_hello_without_extensions() {
        let bytes = server_hello_bytes(0x1301, None);
        assert!(matches!(
            parse_server_response(&bytes).unwrap(),
            ServerResponse::ServerHello {
                selected_suite: 0x1301,
                selected_group: None,
                ..
            }
        ));
    }

    #[test]
    fn truncated_record_is_error() {
        let mut bytes = server_hello_bytes(0x1302, None);
        bytes.truncate(bytes.len() - 1);
        assert!(parse_server_response(&bytes).is_err());
    }

    #[test]
    fn short_handshake_is_error() {
        let mut bytes = server_hello_bytes(0x1302, None);
        bytes[4] = 2; // record length 2, so payload < 4
        bytes.truncate(7);
        assert!(parse_server_response(&bytes).is_err());
    }

    #[test]
    fn wrong_handshake_type_is_error() {
        let mut bytes = server_hello_bytes(0x1302, None);
        bytes[5] = 0x01; // ClientHello
        assert!(parse_server_response(&bytes).is_err());
    }

    #[test]
    fn short_server_hello_body_is_error() {
        let mut hs = vec![0x02, 0, 0, 2, 0x03, 0x03];
        let mut rec = vec![0x16, 0x03, 0x03, 0, hs.len() as u8];
        rec.append(&mut hs);
        assert!(parse_server_response(&rec).is_err());
    }

    #[test]
    fn truncated_session_id_is_error() {
        let mut body = vec![0x03, 0x03];
        body.extend(std::iter::repeat_n(0u8, 32));
        body.push(32); // claims 32-byte session id but none follows
        let mut hs = vec![0x02, 0, 0, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03, 0, hs.len() as u8];
        rec.extend_from_slice(&hs);
        assert!(parse_server_response(&rec).is_err());
    }

    #[test]
    fn malformed_extension_length_is_ignored() {
        let mut body = vec![0x03, 0x03];
        body.extend(std::iter::repeat_n(0u8, 32));
        body.push(0);
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(0);
        // Extensions length says 4, but the key_share extension claims more.
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x0033u16.to_be_bytes());
        body.extend_from_slice(&10u16.to_be_bytes());
        let mut hs = vec![0x02, 0, 0, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03, 0, hs.len() as u8];
        rec.extend_from_slice(&hs);
        assert!(matches!(
            parse_server_response(&rec).unwrap(),
            ServerResponse::ServerHello {
                selected_group: None,
                ..
            }
        ));
    }

    #[test]
    fn client_hello_random_bytes_are_not_repeated() {
        let a = build_client_hello("example.com", &[0x1301], &[0x001D], 0x0304);
        let b = build_client_hello("example.com", &[0x1301], &[0x001D], 0x0304);
        // random follows the 5-byte record header, 4-byte handshake header,
        // and 2-byte legacy version.
        assert_ne!(a[11..43], b[11..43]);
    }

    #[test]
    fn modern_client_hello_contains_tls13_extensions() {
        let hello = build_client_hello("example.com", &[0x1301], &[0x11EC, 0x001D], 0x0304);
        assert_eq!(hello[0], 0x16);
        // supported_versions, signature_algorithms, key_share
        let has = |ext: u16| hello.windows(2).any(|w| w == ext.to_be_bytes());
        assert!(has(0x002b));
        assert!(has(0x000d));
        assert!(has(0x0033));
        assert!(has(0x000a));
        assert!(has(0x0000));
    }

    #[test]
    fn legacy_client_hello_omits_tls13_extensions() {
        let hello = build_client_hello_legacy("example.com", &[0x002F], &[0x001D], 0x0301);
        let has = |ext: u16| hello.windows(2).any(|w| w == ext.to_be_bytes());
        assert!(!has(0x002b));
        assert!(!has(0x000d));
        assert!(!has(0x0033));
        assert!(has(0x000a));
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
    }

    #[test]
    fn client_hello_with_empty_sni_omits_sni_extension() {
        let without_sni = build_client_hello("", &[0x1301], &[0x001D], 0x0301);
        let with_sni = build_client_hello("example.com", &[0x1301], &[0x001D], 0x0301);
        assert!(with_sni.len() > without_sni.len());
        assert!(!without_sni
            .windows(b"example.com".len())
            .any(|w| w == b"example.com"));
    }

    #[tokio::test]
    async fn read_tls_record_handles_fragmentation() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let record = server_hello_bytes(0x1302, Some(0x11EC));
        let (a, b) = record.split_at(3);
        let a = a.to_vec();
        let b = b.to_vec();
        tokio::spawn(async move {
            server.write_all(&a).await.unwrap();
            server.write_all(&b).await.unwrap();
        });
        let buf = read_tls_record(&mut client, 1000).await.unwrap();
        assert_eq!(buf, record);
    }

    #[tokio::test]
    async fn read_tls_record_reports_timeout() {
        let (mut client, _server) = tokio::io::duplex(64);
        assert!(matches!(
            read_tls_record(&mut client, 1).await,
            Err(ReadError::Timeout)
        ));
    }

    #[tokio::test]
    async fn read_tls_record_reports_connection_close() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        assert!(matches!(
            read_tls_record(&mut client, 1000).await,
            Err(ReadError::ConnectionClose)
        ));
    }

    #[tokio::test]
    async fn send_and_receive_parses_server_hello() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let record = server_hello_bytes(0x1302, Some(0x11EC));
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            server.write_all(&record).await.unwrap();
        });
        let response = send_and_receive(&mut client, b"hello", 1000).await;
        assert!(matches!(
            response,
            ServerResponse::ServerHello {
                selected_group: Some(0x11EC),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn send_and_receive_reports_write_failure() {
        let (client, server) = tokio::io::duplex(64);
        drop(server);
        let mut client = client;
        assert!(matches!(
            send_and_receive(&mut client, b"hello", 100).await,
            ServerResponse::Error(_)
        ));
    }

    #[tokio::test]
    async fn send_and_receive_reports_parse_failure() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            server
                .write_all(&[0x17, 0x03, 0x03, 0x00, 0x00])
                .await
                .unwrap();
        });
        assert!(matches!(
            send_and_receive(&mut client, b"hello", 1000).await,
            ServerResponse::Error(_)
        ));
    }

    #[tokio::test]
    async fn probe_once_delegates_to_send_and_receive() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let record = server_hello_bytes(0x1301, None);
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server.read(&mut buf).await;
            server.write_all(&record).await.unwrap();
        });
        assert!(matches!(
            probe_once(&mut client, b"hello", 1000).await,
            ServerResponse::ServerHello { .. }
        ));
    }

    fn wrap_record(hs: Vec<u8>) -> Vec<u8> {
        let mut rec = vec![0x16, 0x03, 0x03, 0, hs.len() as u8];
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn server_hello_without_extensions_length_is_accepted() {
        // TLS allows the extensions block to be absent entirely.
        let mut body = vec![0x03, 0x03];
        body.extend(std::iter::repeat_n(0u8, 32));
        body.push(0);
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(0);
        let mut hs = vec![0x02, 0, 0, body.len() as u8];
        hs.extend_from_slice(&body);
        assert!(matches!(
            parse_server_response(&wrap_record(hs)).unwrap(),
            ServerResponse::ServerHello {
                selected_group: None,
                ..
            }
        ));
    }

    #[test]
    fn malformed_extensions_length_is_ignored() {
        let mut body = vec![0x03, 0x03];
        body.extend(std::iter::repeat_n(0u8, 32));
        body.push(0);
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(0);
        // Claim 10 bytes of extensions but provide only 4.
        body.extend_from_slice(&10u16.to_be_bytes());
        body.extend_from_slice(&0x0033u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut hs = vec![0x02, 0, 0, body.len() as u8];
        hs.extend_from_slice(&body);
        assert!(matches!(
            parse_server_response(&wrap_record(hs)).unwrap(),
            ServerResponse::ServerHello {
                selected_group: None,
                ..
            }
        ));
    }

    #[test]
    fn key_share_falls_back_when_x25519_is_not_offered() {
        let hello = build_client_hello("example.com", &[0x1301], &[0x6399], 0x0304);
        let pos = hello
            .windows(2)
            .position(|w| w == 0x0033u16.to_be_bytes())
            .expect("key_share extension present");
        // extension type(2) length(2) list length(2) group(2)
        let group = u16::from_be_bytes([hello[pos + 6], hello[pos + 7]]);
        assert_eq!(group, 0x6399);
    }

    #[tokio::test]
    async fn read_tls_record_zero_timeout_reports_timeout() {
        let (mut client, _server) = tokio::io::duplex(64);
        assert_eq!(
            read_tls_record(&mut client, 0).await,
            Err(ReadError::Timeout)
        );
    }

    struct FailingReader;

    impl tokio::io::AsyncRead for FailingReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("read boom")))
        }
    }

    #[tokio::test]
    async fn read_tls_record_reports_read_errors() {
        let mut reader = FailingReader;
        assert_eq!(read_tls_record(&mut reader, 100).await, Err(ReadError::Io));
    }

    #[tokio::test]
    async fn send_and_read_raw_reports_write_failure() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        assert_eq!(
            send_and_read_raw(&mut client, b"hello", 100).await,
            Err(ReadError::WriteError)
        );
    }
}
