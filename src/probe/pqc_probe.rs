use crate::audit::tables::iana_groups::named_group_for_code_point;
use crate::probe::handshake::{build_client_hello, parse_server_response, ServerResponse};
use crate::probe::hrr::is_hrr;
use crate::{CipherSuite, PqcHandshakeResult, ProbeError, TlsVersion};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

/// Configuration for a single probe operation (timeout + SNI override).
/// Scanner-level settings (concurrency, full_scan) live in the scanner config.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub timeout_ms: u64,
    pub sni_override: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            sni_override: None,
        }
    }
}

/// Default PQC cipher suites to offer (TLS 1.3 only).
const DEFAULT_CIPHER_SUITES: &[u16] = &[
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

/// Default named groups in preference order: PQC hybrid first, then classical fallbacks.
const DEFAULT_NAMED_GROUPS: &[u16] = &[
    0x11EC, // X25519MLKEM768
    0x11EB, // SecP256r1MLKEM768
    0x11ED, // SecP384r1MLKEM1024
    0x0201, // ML-KEM-768
    0x0202, // ML-KEM-1024
    0x001D, // X25519 (fallback)
    0x0017, // secp256r1 (fallback)
];

/// The random bytes offset in a raw TLS ServerHello record.
/// record header(5) + handshake header(4) + version(2) = offset 11
const SERVER_HELLO_RANDOM_OFFSET: usize = 11;
const SERVER_HELLO_RANDOM_END: usize = SERVER_HELLO_RANDOM_OFFSET + 32;

/// Send a raw ClientHello and parse the initial ServerHello to extract the negotiated group.
/// Also detects HelloRetryRequests by checking the server random field.
async fn probe_raw_group(
    host: &str,
    port: u16,
    sni: &str,
    timeout_ms: u64,
) -> Result<(u16, bool), ProbeError> {
    let hello = build_client_hello(sni, DEFAULT_CIPHER_SUITES, DEFAULT_NAMED_GROUPS, 0x0304);

    let mut stream = crate::probe::tcp_connect(host, port, timeout_ms)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                ProbeError::Timeout {
                    after_ms: timeout_ms,
                }
            } else {
                ProbeError::ConnectionRefused {
                    host: host.into(),
                    port,
                }
            }
        })?;

    stream
        .write_all(&hello)
        .await
        .map_err(|e| ProbeError::TlsHandshakeFailed {
            reason: e.to_string(),
        })?;

    // Read response — handle TCP fragmentation by accumulating until a complete TLS record
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
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(ProbeError::Timeout {
                after_ms: timeout_ms,
            })?;
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return Err(ProbeError::TlsHandshakeFailed {
                    reason: "connection closed before ServerHello".into(),
                })
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                return Err(ProbeError::TlsHandshakeFailed {
                    reason: e.to_string(),
                })
            }
            Err(_) => {
                return Err(ProbeError::Timeout {
                    after_ms: timeout_ms,
                })
            }
        }
    }

    let response =
        parse_server_response(&buf).map_err(|e| ProbeError::TlsHandshakeFailed { reason: e })?;

    match response {
        ServerResponse::ServerHello { selected_group, .. } => {
            let hrr = if buf.len() >= SERVER_HELLO_RANDOM_END {
                is_hrr(&buf[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_END])
            } else {
                false
            };
            let group_code = selected_group.ok_or_else(|| ProbeError::TlsHandshakeFailed {
                reason: "ServerHello missing key_share extension".into(),
            })?;
            Ok((group_code, hrr))
        }
        ServerResponse::HandshakeFailure => Err(ProbeError::TlsHandshakeFailed {
            reason: "server rejected all offered groups".into(),
        }),
        ServerResponse::ConnectionClose => Err(ProbeError::TlsHandshakeFailed {
            reason: "server closed connection during handshake".into(),
        }),
        ServerResponse::Timeout => Err(ProbeError::Timeout {
            after_ms: timeout_ms,
        }),
    }
}

/// Perform a full PQC-aware TLS handshake using rustls.
/// Returns the negotiated group (from raw probe), cipher suite, TLS version, and cert chain.
pub async fn pqc_probe(
    host: &str,
    port: u16,
    sni_override: Option<&str>,
    config: &ProbeConfig,
) -> Result<PqcHandshakeResult, ProbeError> {
    let sni = sni_override.unwrap_or(host);
    let timeout_ms = config.timeout_ms;

    // Step 1: Raw probe to get negotiated group and HRR status
    let (group_code, hrr_required) = probe_raw_group(host, port, sni, timeout_ms).await?;

    // Step 2: rustls handshake to get cert chain, cipher suite, and TLS version
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let tls_config =
        ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .map_err(|e| ProbeError::TlsHandshakeFailed {
                reason: e.to_string(),
            })?
            .with_root_certificates(root_store)
            .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));

    let stream = crate::probe::tcp_connect(host, port, timeout_ms)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                ProbeError::Timeout {
                    after_ms: timeout_ms,
                }
            } else {
                ProbeError::ConnectionRefused {
                    host: host.into(),
                    port,
                }
            }
        })?;

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|e| {
        ProbeError::TlsHandshakeFailed {
            reason: e.to_string(),
        }
    })?;

    let tls_stream = tokio::time::timeout(
        tokio::time::Duration::from_millis(timeout_ms),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProbeError::Timeout {
        after_ms: timeout_ms,
    })?
    .map_err(|e| ProbeError::TlsHandshakeFailed {
        reason: e.to_string(),
    })?;

    let (_, session) = tls_stream.get_ref();

    // Extract cipher suite
    let suite =
        session
            .negotiated_cipher_suite()
            .ok_or_else(|| ProbeError::TlsHandshakeFailed {
                reason: "no cipher suite negotiated".into(),
            })?;
    let suite_id = u16::from(suite.suite());
    let suite_name = format!("{:?}", suite.suite());
    let negotiated_suite = CipherSuite {
        id: suite_id,
        name: suite_name,
    };

    // Extract TLS version
    let negotiated_version = match session.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
        Some(rustls::ProtocolVersion::TLSv1_2) => TlsVersion::Tls12,
        Some(rustls::ProtocolVersion::TLSv1_1) => TlsVersion::Tls11,
        Some(rustls::ProtocolVersion::TLSv1_0) => TlsVersion::Tls10,
        Some(other) => TlsVersion::Unknown(u16::from(other)),
        None => TlsVersion::Unknown(0),
    };

    // Extract certificate chain DER bytes
    let cert_chain_der = session
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();

    // Resolve NamedGroup from code point using IANA table
    let named_group = named_group_for_code_point(group_code);

    Ok(PqcHandshakeResult {
        negotiated_version,
        negotiated_suite,
        negotiated_group: named_group,
        hrr_required,
        cert_chain_der,
    })
}
