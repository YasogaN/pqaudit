use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes
    if bytes.len() < 5 {
        return Err("record too short".into());
    }
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

/// Build a minimal TLS 1.3 ClientHello.
pub fn build_client_hello(
    sni: &str,
    cipher_suites: &[u16],
    named_groups: &[u16],
    max_version: u16,
) -> Vec<u8> {
    let mut extensions = Vec::new();

    // SNI extension (0x0000)
    if !sni.is_empty() {
        let name_bytes = sni.as_bytes();
        let name_len = name_bytes.len();
        let list_len = name_len + 3; // type(1) + len(2)
        let mut sni_ext = vec![
            0x00, 0x00, // extension type: server_name
        ];
        let total_len = (list_len + 2) as u16;
        sni_ext.extend_from_slice(&total_len.to_be_bytes());
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes()); // server_name_list length
        sni_ext.push(0x00); // host_name type
        sni_ext.extend_from_slice(&(name_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);
        extensions.extend_from_slice(&sni_ext);
    }

    // Supported versions extension (0x002b)
    {
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

    // Supported groups extension (0x000a)
    {
        let groups_bytes: Vec<u8> = named_groups.iter().flat_map(|g| g.to_be_bytes()).collect();
        let list_len = groups_bytes.len() as u16;
        let ext_len = list_len + 2; // +2 for the list_len field
        let mut ext = vec![0x00, 0x0a];
        ext.extend_from_slice(&ext_len.to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.extend_from_slice(&groups_bytes);
        extensions.extend_from_slice(&ext);
    }

    // Key share extension (0x0033)
    // Always use X25519 (0x001D) with the base point when X25519 is in named_groups.
    // PQC hybrid groups need ~1184–1216 byte key shares that we don't generate;
    // advertising them in supported_groups is enough to trigger an HRR from PQC-capable
    // servers, which tells us the preferred group without needing a real PQC key share.
    // If X25519 is not in the list (e.g. Kyber-draft-only probe), fall back to 32 zero bytes
    // for the first group — callers accepting Option returns handle that gracefully.
    {
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

    // Build cipher suites
    let suites_bytes: Vec<u8> = cipher_suites.iter().flat_map(|s| s.to_be_bytes()).collect();
    let suites_len = suites_bytes.len() as u16;

    // Build ClientHello body
    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&max_version.to_be_bytes()); // version (legacy)
    hello_body.extend(std::iter::repeat_n(0u8, 32)); // random (32 zero bytes)
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

/// Send ClientHello over an existing TcpStream, read response, classify it.
/// Accumulates bytes until a complete TLS record is received (handles TCP fragmentation).
pub async fn probe_once(stream: &mut TcpStream, hello: &[u8], timeout_ms: u64) -> ServerResponse {
    use tokio::time::{Duration, Instant};
    if stream.write_all(hello).await.is_err() {
        return ServerResponse::ConnectionClose;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = Vec::with_capacity(8192);
    loop {
        // Determine how many bytes we need
        let need = if buf.len() >= 5 {
            5 + u16::from_be_bytes([buf[3], buf[4]]) as usize
        } else {
            5 // need at least the record header
        };
        if buf.len() >= need {
            break;
        }
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) => d,
            None => return ServerResponse::Timeout,
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return ServerResponse::ConnectionClose,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return ServerResponse::ConnectionClose,
            Err(_) => return ServerResponse::Timeout,
        }
    }
    parse_server_response(&buf).unwrap_or(ServerResponse::ConnectionClose)
}
