use crate::audit::tables::iana_ciphers::cipher_name;
use crate::audit::tables::iana_groups::named_group_for_code_point;
use crate::probe::handshake::{
    build_client_hello, build_client_hello_legacy, parse_server_response, send_and_read_raw,
    send_and_receive, ReadError, ServerResponse,
};
use crate::probe::hrr::is_hrr;
use crate::{CipherSuite, PqcHandshakeResult, ProbeError, TlsVersion};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::sync::Arc;

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
    /// Additional trust anchors (for private CAs).
    pub extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            sni_override: None,
            scheme: String::new(),
            insecure: false,
            extra_roots: vec![],
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

/// Provider used for the main handshake: all supported PQC groups, including
/// pure ML-KEM, with the provider's default preference order preserved first.
fn full_provider() -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = aws_lc_rs::ALL_KX_GROUPS.to_vec();
    provider
}

fn client_config(
    provider: CryptoProvider,
    insecure: bool,
    versions: &[&'static rustls::SupportedProtocolVersion],
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
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
        let mut roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for root in extra_roots {
            roots
                .add(root.clone())
                .map_err(|e| ProbeError::CertificateValidationFailed {
                    reason: e.to_string(),
                })?;
        }
        builder.with_root_certificates(roots)
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
    let tls_config = client_config(provider, insecure, versions, &config.extra_roots)?;
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

/// The subset of rustls session state needed by `extract_from_session`.
///
/// A trait is used here so the otherwise-unreachable "no cipher suite"
/// branch can be exercised by a deterministic unit test.
trait SessionInfo {
    fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite>;
    fn protocol_version(&self) -> Option<rustls::ProtocolVersion>;
    fn negotiated_key_exchange_group(
        &self,
    ) -> Option<&'static dyn rustls::crypto::SupportedKxGroup>;
    fn peer_certificates(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]>;
}

impl SessionInfo for rustls::CommonState {
    fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
        rustls::CommonState::negotiated_cipher_suite(self)
    }

    fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        rustls::CommonState::protocol_version(self)
    }

    fn negotiated_key_exchange_group(
        &self,
    ) -> Option<&'static dyn rustls::crypto::SupportedKxGroup> {
        rustls::CommonState::negotiated_key_exchange_group(self)
    }

    fn peer_certificates(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]> {
        rustls::CommonState::peer_certificates(self)
    }
}

/// Extract the negotiated parameters and certificate chain from a completed handshake.
fn extract_handshake(
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    certificate_validation_error: Option<String>,
) -> Result<PqcHandshakeResult, ProbeError> {
    let (_, session) = tls_stream.get_ref();
    extract_from_session(&***session, certificate_validation_error)
}

fn extract_from_session(
    session: &dyn SessionInfo,
    certificate_validation_error: Option<String>,
) -> Result<PqcHandshakeResult, ProbeError> {
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
        let stream = connect_tls(host, port, sni, config, full_provider(), versions, true).await?;
        return extract_handshake(stream, None);
    }

    match connect_tls(host, port, sni, config, full_provider(), versions, false).await {
        Ok(stream) => extract_handshake(stream, None),
        Err(e @ ProbeError::TlsHandshakeFailed { .. }) => {
            let reason = e.to_string();
            let stream =
                connect_tls(host, port, sni, config, full_provider(), versions, true).await?;
            extract_handshake(stream, Some(reason))
        }
        Err(e) => Err(e),
    }
}

/// Send a raw ClientHello and parse the initial ServerHello to extract the
/// selected group and detect HelloRetryRequests.
/// Returns `Ok(None)` when the server selected TLS 1.2 (no key_share group).
fn raw_read_error(error: ReadError, timeout_ms: u64) -> ProbeError {
    match error {
        ReadError::Timeout => ProbeError::Timeout {
            after_ms: timeout_ms,
        },
        ReadError::ConnectionClose => ProbeError::TlsHandshakeFailed {
            reason: "connection closed before ServerHello".into(),
        },
        ReadError::Io => ProbeError::TlsHandshakeFailed {
            reason: "I/O error while reading ServerHello".into(),
        },
        ReadError::WriteError => ProbeError::TlsHandshakeFailed {
            reason: "failed to write ClientHello".into(),
        },
    }
}

async fn probe_raw_group(
    host: &str,
    port: u16,
    sni: &str,
    config: &ProbeConfig,
) -> Result<Option<(u16, bool)>, ProbeError> {
    let hello = build_client_hello(sni, DEFAULT_CIPHER_SUITES, DEFAULT_NAMED_GROUPS, 0x0304);
    let mut stream = crate::probe::connect(host, port, &config.scheme, config.timeout_ms).await?;

    let buf = send_and_read_raw(&mut stream, &hello, config.timeout_ms)
        .await
        .map_err(|error| raw_read_error(error, config.timeout_ms))?;

    let response =
        parse_server_response(&buf).map_err(|e| ProbeError::TlsHandshakeFailed { reason: e })?;

    match response {
        ServerResponse::ServerHello { selected_group, .. } => {
            let hrr = is_hrr(&buf[SERVER_HELLO_RANDOM_OFFSET..SERVER_HELLO_RANDOM_END]);
            match selected_group {
                Some(group_code) => Ok(Some((group_code, hrr))),
                // No key_share extension means TLS 1.2 was negotiated.
                None => Ok(None),
            }
        }
        ServerResponse::HandshakeFailure => Err(ProbeError::TlsHandshakeFailed {
            reason: "server rejected all offered cipher suites".into(),
        }),
        _ => Err(ProbeError::TlsHandshakeFailed {
            reason: "server closed connection during handshake".into(),
        }),
    }
}

fn apply_raw_probe(result: &mut PqcHandshakeResult, raw: Option<(u16, bool)>) {
    if let Some((group_code, hrr)) = raw {
        result.hrr_required = hrr;
        if result.negotiated_group.code_point == 0 {
            result.negotiated_group = named_group_for_code_point(group_code);
        }
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
            if !versions.contains(&accepted) {
                versions.push(accepted);
            }
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
    let raw = probe_raw_group(host, port, sni, config)
        .await
        .ok()
        .flatten();
    apply_raw_probe(&mut result, raw);

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

    use crate::test_support::{
        classical_provider, fixed_response_server, provider_with_groups, silent_server,
        smtp_starttls_server, tls_server, tls_server_with_identity, HRR_RANDOM,
    };

    fn config(insecure: bool) -> ProbeConfig {
        ProbeConfig {
            timeout_ms: 2000,
            sni_override: Some("localhost".into()),
            scheme: String::new(),
            insecure,
            extra_roots: vec![],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_detects_hybrid_group_hrr_and_classical_fallback() {
        let server = tls_server(
            aws_lc_rs::default_provider(),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await;
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &config(true))
            .await
            .unwrap();

        assert_eq!(result.negotiated_version, TlsVersion::Tls13);
        assert!(result.negotiated_group.is_pqc);
        assert_eq!(result.negotiated_group.code_point, 0x11EC);
        assert!(result.hrr_required, "raw probe should observe an HRR");
        assert!(result.classical_fallback);
        assert!(result.certificate_validation_error.is_none());
        assert!(!result.cert_chain_der.is_empty());
        assert!(!result.negotiated_suite.name.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_accepts_untrusted_certificate_and_reports_error() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let result = pqc_probe(
            "127.0.0.1",
            server.port(),
            Some("localhost"),
            &config(false),
        )
        .await
        .unwrap();
        assert!(result.certificate_validation_error.is_some());
        assert!(!result.cert_chain_der.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_validates_with_extra_root() {
        let (chain, key, root) = crate::test_support::test_ca_and_leaf();
        let server = tls_server_with_identity(
            aws_lc_rs::default_provider(),
            &[&rustls::version::TLS13],
            chain,
            key,
        )
        .await;
        let mut cfg = config(false);
        cfg.extra_roots.push(root);
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &cfg)
            .await
            .unwrap();
        assert!(result.certificate_validation_error.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_classical_only_server_is_not_pqc_and_allows_fallback() {
        let server = tls_server(
            classical_provider(),
            &[&rustls::version::TLS13, &rustls::version::TLS12],
        )
        .await;
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &config(true))
            .await
            .unwrap();
        assert!(!result.negotiated_group.is_pqc);
        assert!(!result.hrr_required);
        assert!(result.classical_fallback);
        assert!(result.legacy_protocols.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_pqc_only_server_does_not_allow_classical_fallback() {
        let provider = provider_with_groups(vec![aws_lc_rs::kx_group::X25519MLKEM768]);
        let server = tls_server(provider, &[&rustls::version::TLS13]).await;
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &config(true))
            .await
            .unwrap();
        assert!(result.negotiated_group.is_pqc);
        assert!(!result.classical_fallback);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_tls12_only_server() {
        let server = tls_server(classical_provider(), &[&rustls::version::TLS12]).await;
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &config(true))
            .await
            .unwrap();
        assert_eq!(result.negotiated_version, TlsVersion::Tls12);
        assert!(
            !result.classical_fallback,
            "fallback probe requires TLS 1.3"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_performs_smtp_starttls() {
        let server = smtp_starttls_server(aws_lc_rs::default_provider()).await;
        let mut cfg = config(true);
        cfg.scheme = "smtp".into();
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &cfg)
            .await
            .unwrap();
        assert_eq!(result.negotiated_version, TlsVersion::Tls13);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_reports_connection_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = pqc_probe("127.0.0.1", port, None, &config(true))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProbeError::ConnectionRefused { .. } | ProbeError::Timeout { .. }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_rejects_invalid_sni() {
        let server = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let err = pqc_probe("127.0.0.1", server.port(), Some("bad name"), &config(true))
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::TlsHandshakeFailed { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_times_out_on_silent_server() {
        let server = silent_server().await;
        let mut cfg = config(true);
        cfg.timeout_ms = 50;
        let err = pqc_probe("127.0.0.1", server.port(), None, &cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Timeout { .. }));
    }

    #[tokio::test]
    async fn raw_probe_extracts_group_and_detects_hrr() {
        let normal = fixed_response_server(crate::test_support::server_hello(
            0x1302,
            Some(0x11EC),
            0x0303,
            None,
        ))
        .await;
        let group = probe_raw_group("127.0.0.1", normal.port(), "localhost", &config(true))
            .await
            .unwrap();
        assert_eq!(group, Some((0x11EC, false)));

        let hrr = fixed_response_server(crate::test_support::server_hello(
            0x1302,
            Some(0x11EC),
            0x0303,
            Some(HRR_RANDOM),
        ))
        .await;
        let group = probe_raw_group("127.0.0.1", hrr.port(), "localhost", &config(true))
            .await
            .unwrap();
        assert_eq!(group, Some((0x11EC, true)));
    }

    #[tokio::test]
    async fn raw_probe_returns_none_for_tls12_server_hello() {
        let server = fixed_response_server(crate::test_support::server_hello(
            0xC02F, None, 0x0303, None,
        ))
        .await;
        let group = probe_raw_group("127.0.0.1", server.port(), "localhost", &config(true))
            .await
            .unwrap();
        assert_eq!(group, None);
    }

    #[tokio::test]
    async fn raw_probe_maps_failure_close_timeout_and_garbage() {
        let failure = fixed_response_server(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
        assert!(
            probe_raw_group("127.0.0.1", failure.port(), "localhost", &config(true))
                .await
                .is_err()
        );

        let close = fixed_response_server(vec![]).await;
        assert!(
            probe_raw_group("127.0.0.1", close.port(), "localhost", &config(true))
                .await
                .is_err()
        );

        let silent = silent_server().await;
        let mut cfg = config(true);
        cfg.timeout_ms = 50;
        assert!(matches!(
            probe_raw_group("127.0.0.1", silent.port(), "localhost", &cfg).await,
            Err(ProbeError::Timeout { .. })
        ));

        let garbage = fixed_response_server(vec![0x17, 0x03, 0x03, 0x00, 0x00]).await;
        assert!(
            probe_raw_group("127.0.0.1", garbage.port(), "localhost", &config(true))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn legacy_probe_detects_tls10_and_ignores_tls12() {
        let legacy = fixed_response_server(crate::test_support::server_hello(
            0x002F, None, 0x0301, None,
        ))
        .await;
        assert_eq!(
            probe_legacy_version(
                "127.0.0.1",
                legacy.port(),
                "localhost",
                &config(true),
                0x0301
            )
            .await,
            Some(TlsVersion::Tls10)
        );
        let versions =
            probe_legacy_versions("127.0.0.1", legacy.port(), "localhost", &config(true)).await;
        assert!(versions.contains(&TlsVersion::Tls10));

        let modern = fixed_response_server(crate::test_support::server_hello(
            0xC02F, None, 0x0303, None,
        ))
        .await;
        assert_eq!(
            probe_legacy_version(
                "127.0.0.1",
                modern.port(),
                "localhost",
                &config(true),
                0x0301
            )
            .await,
            None
        );

        let failure = fixed_response_server(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]).await;
        assert_eq!(
            probe_legacy_version(
                "127.0.0.1",
                failure.port(),
                "localhost",
                &config(true),
                0x0301
            )
            .await,
            None
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            probe_legacy_version("127.0.0.1", port, "localhost", &config(true), 0x0301).await,
            None
        );
    }

    #[test]
    fn client_config_rejects_empty_protocol_version_list() {
        let err = client_config(aws_lc_rs::default_provider(), true, &[], &[]).unwrap_err();
        assert!(matches!(err, ProbeError::TlsHandshakeFailed { .. }));
    }

    #[test]
    fn client_config_rejects_invalid_extra_root() {
        let bad_root = rustls::pki_types::CertificateDer::from(vec![0u8; 3]);
        let err = client_config(
            aws_lc_rs::default_provider(),
            false,
            &[&rustls::version::TLS13],
            &[bad_root],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ProbeError::CertificateValidationFailed { .. }
        ));
    }

    struct FakeSession;

    impl SessionInfo for FakeSession {
        fn negotiated_cipher_suite(&self) -> Option<rustls::SupportedCipherSuite> {
            None
        }
        fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
            None
        }
        fn negotiated_key_exchange_group(
            &self,
        ) -> Option<&'static dyn rustls::crypto::SupportedKxGroup> {
            None
        }
        fn peer_certificates(&self) -> Option<&[rustls::pki_types::CertificateDer<'static>]> {
            None
        }
    }

    #[test]
    fn extract_from_session_reports_missing_cipher_suite() {
        let err = extract_from_session(&FakeSession, None).unwrap_err();
        assert!(matches!(err, ProbeError::TlsHandshakeFailed { .. }));
    }

    #[test]
    fn fake_session_accessors_return_none() {
        let session = FakeSession;
        assert!(session.protocol_version().is_none());
        assert!(session.negotiated_key_exchange_group().is_none());
        assert!(session.peer_certificates().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pqc_probe_propagates_non_handshake_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let err = pqc_probe("127.0.0.1", port, None, &config(false))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProbeError::ConnectionRefused { .. } | ProbeError::Timeout { .. }
        ));
    }

    #[test]
    fn raw_read_errors_map_to_probe_errors() {
        assert!(matches!(
            raw_read_error(ReadError::Timeout, 25),
            ProbeError::Timeout { after_ms: 25 }
        ));
        for error in [
            ReadError::ConnectionClose,
            ReadError::Io,
            ReadError::WriteError,
        ] {
            assert!(matches!(
                raw_read_error(error, 25),
                ProbeError::TlsHandshakeFailed { .. }
            ));
        }
    }

    #[test]
    fn apply_raw_probe_fills_missing_group_and_hrr() {
        let mut result = PqcHandshakeResult {
            negotiated_version: TlsVersion::Tls12,
            negotiated_suite: CipherSuite {
                id: 0xC02F,
                name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            },
            negotiated_group: named_group_for_code_point(0),
            hrr_required: false,
            cert_chain_der: vec![],
            classical_fallback: false,
            legacy_protocols: vec![],
            certificate_validation_error: None,
        };
        apply_raw_probe(&mut result, Some((0x11EC, true)));
        assert_eq!(result.negotiated_group.code_point, 0x11EC);
        assert!(result.hrr_required);

        apply_raw_probe(&mut result, None);
        assert_eq!(result.negotiated_group.code_point, 0x11EC);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_provider_can_negotiate_pure_mlkem1024() {
        let provider =
            crate::test_support::provider_with_groups(vec![aws_lc_rs::kx_group::MLKEM1024]);
        let server = crate::test_support::tls_server(provider, &[&rustls::version::TLS13]).await;
        let result = pqc_probe("127.0.0.1", server.port(), Some("localhost"), &config(true))
            .await
            .unwrap();
        assert_eq!(result.negotiated_group.code_point, 0x0202);
        assert!(result.negotiated_group.is_pqc);
    }

    #[tokio::test]
    async fn raw_probe_reports_close_notify_alert() {
        let server = fixed_response_server(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]).await;
        let err = probe_raw_group("127.0.0.1", server.port(), "localhost", &config(true))
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::TlsHandshakeFailed { .. }));
    }
}
