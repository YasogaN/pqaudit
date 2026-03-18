use crate::{CipherInventory, CipherSuite};
use crate::probe::handshake::{build_client_hello, parse_server_response, ServerResponse};

// All TLS 1.3 cipher suite IDs
const TLS13_SUITES: &[u16] = &[
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1304, // TLS_AES_128_CCM_SHA256
    0x1305, // TLS_AES_128_CCM_8_SHA256
];

// Common TLS 1.2 suite IDs to probe (IANA registry)
const TLS12_SUITES_TO_PROBE: &[u16] = &[
    // AES-256-GCM
    0xC02C, 0xC030,
    // AES-128-GCM
    0xC02B, 0xC02F,
    // ChaCha20 (TLS 1.2 variants)
    0xCCA8, 0xCCA9,
    // AES-256-CBC (legacy)
    0xC024, 0xC028,
    // AES-128-CBC (legacy)
    0xC023, 0xC027,
    // RSA key exchange variants
    0x003C, 0x003D, 0x0035, 0x002F,
    // 3DES (very legacy)
    0x000A,
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
    suites: &[u16],
    timeout_ms: u64,
    max_version: u16,
) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hello = build_client_hello(host, suites, &[0x001D, 0x0017], max_version);
    let mut stream = match tokio::net::TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(_) => return None,
    };
    if stream.write_all(&hello).await.is_err() {
        return None;
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
            None => return None,
        };
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    parse_server_response(&buf).ok().and_then(|r| extract_selected_suite(&r))
}

async fn run_tls13_pass(host: &str, port: u16, timeout_ms: u64) -> Vec<CipherSuite> {
    let mut remaining: Vec<u16> = TLS13_SUITES.to_vec();
    let mut found = Vec::new();
    loop {
        if remaining.is_empty() {
            break;
        }
        match probe_with_suites(host, port, &remaining, timeout_ms, 0x0304).await {
            Some(id) => {
                found.push(CipherSuite { id, name: format!("0x{:04X}", id) });
                remaining.retain(|&s| s != id);
            }
            None => break,
        }
    }
    found
}

async fn run_tls12_pass(host: &str, port: u16, timeout_ms: u64) -> Vec<CipherSuite> {
    use std::collections::HashSet;

    let mut remaining: Vec<u16> = TLS12_SUITES_TO_PROBE.to_vec();
    let mut found = Vec::new();
    while !remaining.is_empty() {
        let batch: Vec<u16> = remaining.iter().copied().take(64).collect();
        match probe_with_suites(host, port, &batch, timeout_ms, 0x0303).await {
            Some(id) => {
                found.push(CipherSuite { id, name: format!("0x{:04X}", id) });
                remaining.retain(|&s| s != id);
            }
            None => {
                let batch_set: HashSet<u16> = batch.into_iter().collect();
                remaining.retain(|s| !batch_set.contains(s));
            }
        }
    }
    found
}

pub async fn enumerate_ciphers(host: &str, port: u16, timeout_ms: u64) -> CipherInventory {
    let tls13_suites = run_tls13_pass(host, port, timeout_ms).await;
    let tls12_suites = run_tls12_pass(host, port, timeout_ms).await;
    CipherInventory { tls13_suites, tls12_suites }
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
        assert_eq!(extract_selected_suite(&ServerResponse::HandshakeFailure), None);
    }

    #[test]
    fn tls13_suites_list_has_five_entries() {
        assert_eq!(TLS13_SUITES.len(), 5);
    }
}
