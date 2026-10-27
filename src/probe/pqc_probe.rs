use crate::audit::tables::iana_ciphers::cipher_name;
use crate::audit::tables::iana_groups::named_group_for_code_point;
use crate::probe::handshake::{
    build_client_hello, build_client_hello_legacy, parse_server_response, read_tls_record,
    send_and_receive, ServerResponse,
};
use crate::probe::hrr::is_hrr;
use crate::{CipherSuite, PqcHandshakeResult, ProbeError, TlsVersion};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// Configuration for a single probe operation (timeout + SNI override).
/// Scanner-level settings (concurrency, full_scan) live in the scanner config.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub timeout_ms: u64,
    pub sni_override: Option<String>,
    /// STARTTLS scheme parsed from the target (empty for direct TLS).
    pub scheme: String,
    /// Skip certificate validation. The chain is still captured and audited.
    pub insecure: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            sni_override: None,
            scheme: String::new(),
            insecure: false,
        }
    }
}

/// Default cipher suites: TLS 1.3 suites first, then common TLS 1.2 suites so that
/// TLS 1.2-only servers can respond and we can detect classical-only deployments.
const DEFAULT_CIPHER_SUITES: &[u16] = &[
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
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

/// Cipher suites used for the legacy TLS 1.0/1.1 probes.
const LEGACY_CIPHER_SUITES: &[u16] = &[
    0xC013, // ECDHE_RSA_AES_128_CBC_SHA
    0xC014, // ECDHE_RSA_AES_256_CBC_SHA
    0x002F, // RSA_AES_128_CBC_SHA
    0x0035, // RSA_AES_256_CBC_SHA
    0x000A, // 3DES
];

/// The random bytes offset in a raw TLS ServerHello record.
/// record header(5) + handshake header(4) + version(2) = offset 11
const SERVER_HELLO_RANDOM_OFFSET: usize = 11;
const SERVER_HELLO_RANDOM_END: usize = SERVER_HELLO_RANDOM_OFFSET + 32;

/// A verifier that accepts any certificate. Used only for auditing endpoints
/// with self-signed, expired, or otherwise untrusted chains.
#[derive(Debug)]
struct NoCertificateVerification {
    schemes: Vec<SignatureScheme>,
}

impl NoCertificateVerification {
    fn new() -> Self {
        let schemes = aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes();
        Self { schemes }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

fn client_config(
    provider: CryptoProvider,
    insecure: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ClientConfig, ProbeError> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| ProbeError::TlsHandshakeFailed {
            reason: e.to_string(),
        })?;

    let builder = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
    } else {
        builder.with_root_certificates(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    };

    Ok(builder.with_no_client_auth())
}

/// Connect, complete a rustls handshake, and return the TLS stream.
async fn connect_tls(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, ProbeError> {
    let tls_config = client_config(provider, insecure, versions)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    let stream = crate::probe::connect(host, port, &config.scheme, config.timeout_ms).await?;
    let server_name =
        ServerName::try_from(sni.to_string()).map_err(|e| ProbeError::TlsHandshakeFailed {
            reason: e.to_string(),
        })?;

    tokio::time::timeout(
        tokio::time::Duration::from_millis(config.timeout_ms),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| ProbeError::Timeout {
        after_ms: config.timeout_ms,
    })?
    .map_err(|e| ProbeError::TlsHandshakeFailed {
        reason: e.to_string(),
    })
}

/// Extract the negotiated parameters and certificate chain from a completed handshake.
fn extract_handshake(
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    certificate_validation_error: Option<String>,
) -> Result<PqcHandshakeResult, ProbeError> {
    let (_, session) = tls_stream.get_ref();

    let suite =
        session
            .negotiated_cipher_suite()
            .ok_or_else(|| ProbeError::TlsHandshakeFailed {
                reason: "no cipher suite negotiated".into(),
            })?;
    let suite_id = u16::from(suite.suite());
    let negotiated_suite = CipherSuite {
        id: suite_id,
        name: cipher_name(suite_id),
    };

    let negotiated_version = session
        .protocol_version()
        .map(|v| TlsVersion::from_code(u16::from(v)))
        .unwrap_or(TlsVersion::Unknown(0));

    // Use the group rustls actually completed, rather than inferring it from
    // a HelloRetryRequest.
    let group_code = session
        .negotiated_key_exchange_group()
        .map(|group| u16::from(group.name()))
        .unwrap_or(0);

    let cert_chain_der = session
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();

    Ok(PqcHandshakeResult {
        negotiated_version,
        negotiated_suite,
        negotiated_group: named_group_for_code_point(group_code),
        hrr_required: false,
        cert_chain_der,
        classical_fallback: false,
        legacy_protocols: vec![],
        certificate_validation_error,
    })
}

/// Perform a verified handshake, retrying without certificate validation when
/// the verified handshake fails. This lets us audit self-signed, expired, or
/// otherwise untrusted endpoints instead of returning only an error.
async fn handshake_with_fallback(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
) -> Result<PqcHandshakeResult, ProbeError> {
    let versions: &[&'static rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];

    if config.insecure {
        let stream = connect_tls(
            host,
            port,
            sni,
            config,
            aws_lc_rs::default_provider(),
            versions,
            true,
        )
        .await?;
        return extract_handshake(stream, None);
    }

    match connect_tls(
        host,
        port,
        sni,
        config,
        aws_lc_rs::default_provider(),
        versions,
        false,
    )
    .await
    {
        Ok(stream) => extract_handshake(stream, None),
        Err(e @ ProbeError::TlsHandshakeFailed { .. }) => {
            let reason = e.to_string();
            let stream = connect_tls(
                host,
                port,
                sni,
                config,
                aws_lc_rs::default_provider(),
                versions,
                true,
            )
            .await?;
            extract_handshake(stream, Some(reason))
        }
        Err(e) => Err(e),
    }
}

/// Send a raw ClientHello and parse the initial ServerHello to extract the
/// selected group and detect HelloRetryRequests.
/// Returns `Ok(None)` when the server selected TLS 1.2 (no key_share group).
async fn probe_raw_group(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
) -> Result<Option<(u16, bool)>, ProbeError> {
    let hello = build_client_hello(sni, DEFAULT_CIPHER_SUITES, DEFAULT_NAMED_GROUPS, 0x0304);
    let mut stream = crate::probe::connect(host, port, &config.scheme, config.timeout_ms).await?;

    stream
        .write_all(&hello)
        .await
        .map_err(|e| ProbeError::TlsHandshakeFailed {
            reason: e.to_string(),
        })?;

    let buf = match read_tls_record(&mut stream, config.timeout_ms).await {
        Ok(buf) => buf,
        Err(ServerResponse::Timeout) => {
            return Err(ProbeError::Timeout {
                after_ms: config.timeout_ms,
            })
        }
        Err(ServerResponse::ConnectionClose) => {
            return Err(ProbeError::TlsHandshakeFailed {
                reason: "connection closed before ServerHello".into(),
            })
        }
        Err(_) => {
            return Err(ProbeError::TlsHandshakeFailed {
                reason: "unexpected response".into(),
            })
        }
    };

    let response =
        parse_server_response(&buf).map_err(|e| ProbeError::TlsHandshakeFailed { reason: e })?;

    match response {
        ServerResponse::ServerHello { selected_group, .. } => {
            let hrr = if buf.len() >= SERVER_HELLO_RANDOM_END {
                is_hrr(&buf[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_END])
            } else {
                false
            };
            match selected_group {
                Some(group_code) => Ok(Some((group_code, hrr))),
                // No key_share extension means TLS 1.2 was negotiated.
                None => Ok(None),
            }
        }
        ServerResponse::HandshakeFailure => Err(ProbeError::TlsHandshakeFailed {
            reason: "server rejected all offered cipher suites".into(),
        }),
        ServerResponse::ConnectionClose => Err(ProbeError::TlsHandshakeFailed {
            reason: "server closed connection during handshake".into(),
        }),
        ServerResponse::Timeout => Err(ProbeError::Timeout {
            after_ms: config.timeout_ms,
        }),
    }
}

/// Probe whether the server accepts a TLS 1.3 handshake with only classical
/// key-exchange groups. This distinguishes "PQC available" from "PQC enforced".
async fn probe_classical_fallback(host: &str, port: u16, sni: &str, config: &ProbeConfig) -> bool {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ];

    connect_tls(
        host,
        port,
        sni,
        config,
        provider,
        &[&rustls::version::TLS13],
        true, // isolate key exchange from certificate trust
    )
    .await
    .is_ok()
}

async fn probe_legacy_version(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
    version: u16,
) -> Option<TlsVersion> {
    let hello = build_client_hello_legacy(sni, LEGACY_CIPHER_SUITES, &[0x001D, 0x0017], version);
    let mut stream = crate::probe::connect(host, port, &config.scheme, config.timeout_ms)
        .await
        .ok()?;
    match send_and_receive(&mut stream, &hello, config.timeout_ms).await {
        ServerResponse::ServerHello { tls_version, .. } => {
            let accepted = TlsVersion::from_code(tls_version);
            accepted.is_legacy().then_some(accepted)
        }
        _ => None,
    }
}

/// Probe which legacy TLS versions (1.0/1.1) the server accepts.
async fn probe_legacy_versions(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
) -> Vec<TlsVersion> {
    let mut versions = Vec::new();
    for version in [0x0301u16, 0x0302u16] {
        if let Some(accepted) = probe_legacy_version(host, port, sni, config, version).await {
            versions.push(accepted);
        }
    }
    versions
}

/// Perform a full PQC-aware TLS handshake using rustls.
/// Returns the negotiated group, cipher suite, TLS version, and certificate chain.
pub async fn pqc_probe(
    host: &str,
    port: u16,
    sni_override: Option<&str>,
    config: &ProbeConfig,
) -> Result<PqcHandshakeResult, ProbeError> {
    let sni = sni_override.unwrap_or(host);

    let mut result = handshake_with_fallback(host, port, sni, config).await?;

    // Raw probe for HRR detection and as a group fallback when rustls could not
    // report a group (for example, a TLS 1.2 handshake).
    if let Ok(Some((group_code, hrr))) = probe_raw_group(host, port, sni, config).await {
        result.hrr_required = hrr;
        if result.negotiated_group.code_point == 0 {
            result.negotiated_group = named_group_for_code_point(group_code);
        }
    }

    result.classical_fallback = probe_classical_fallback(host, port, sni, config).await;
    result.legacy_protocols = probe_legacy_versions(host, port, sni, config).await;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_config_defaults_are_sane() {
        let cfg = ProbeConfig::default();
        assert_eq!(cfg.timeout_ms, 5000);
        assert!(cfg.sni_override.is_none());
        assert!(cfg.scheme.is_empty());
        assert!(!cfg.insecure);
    }

    #[test]
    fn no_verifier_accepts_certificate_callbacks() {
        let verifier = NoCertificateVerification::new();
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn tls_version_from_code_is_exhaustive() {
        assert_eq!(TlsVersion::from_code(0x0304), TlsVersion::Tls13);
        assert_eq!(TlsVersion::from_code(0x0303), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_code(0x0302), TlsVersion::Tls11);
        assert_eq!(TlsVersion::from_code(0x0301), TlsVersion::Tls10);
        assert_eq!(TlsVersion::from_code(0x0300), TlsVersion::Unknown(0x0300));
        assert!(TlsVersion::Tls10.is_legacy());
        assert!(TlsVersion::Tls11.is_legacy());
        assert!(!TlsVersion::Tls12.is_legacy());
    }
}
