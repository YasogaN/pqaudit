//! Local network test harness used by unit tests.
//!
//! This module is compiled only for `cfg(test)`. It provides real TCP and
//! rustls servers so the probe code is exercised end-to-end instead of only
//! through parser unit tests.
use rustls::crypto::aws_lc_rs;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub struct TestServer {
    pub addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl TestServer {
    fn new(addr: SocketAddr, handle: JoinHandle<()>) -> Self {
        Self { addr, handle }
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub fn test_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate test certificate");
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    (vec![cert], key)
}

/// Generate a CA and a leaf certificate for `localhost`. Returns the leaf
/// chain, the leaf private key, and the CA trust anchor.
pub fn test_ca_and_leaf() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "pqaudit Test CA");
    let ca_key = KeyPair::generate().expect("CA key");
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA cert");

    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params.signed_by(&leaf_key, &ca).expect("leaf cert");

    let chain = vec![leaf.der().clone(), ca.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (chain, key, ca.der().clone())
}

pub fn provider_with_groups(groups: Vec<&'static dyn SupportedKxGroup>) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = groups;
    provider
}

pub fn classical_provider() -> CryptoProvider {
    provider_with_groups(vec![
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::SECP384R1,
    ])
}

/// Start a real TLS server. Each accepted connection is driven through a full
/// handshake and then closed when the client disconnects.
pub async fn tls_server(
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> TestServer {
    let (certs, key) = test_identity();
    tls_server_with_identity(provider, versions, certs, key).await
}

pub async fn tls_server_with_identity(
    provider: CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> TestServer {
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                }
            });
        }
    });
    TestServer::new(addr, handle)
}

/// Start a server that reads one ClientHello and replies with a fixed byte
/// string. An empty response closes the connection immediately.
pub async fn fixed_response_server(response: Vec<u8>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                if !response.is_empty() {
                    let _ = stream.write_all(&response).await;
                    let _ = stream.flush().await;
                }
            });
        }
    });
    TestServer::new(addr, handle)
}

/// Build a ServerHello. `random` can be supplied to simulate a
/// HelloRetryRequest (use `HRR_RANDOM`).
pub fn server_hello(
    selected_suite: u16,
    selected_group: Option<u16>,
    tls_version: u16,
    random: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&tls_version.to_be_bytes());
    body.extend_from_slice(&random.unwrap_or([0u8; 32]));
    body.push(0); // session id
    body.extend_from_slice(&selected_suite.to_be_bytes());
    body.push(0); // compression
    let mut exts = Vec::new();
    if let Some(group) = selected_group {
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        // HRR key_share is just the group; the parser only reads the group.
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.extend_from_slice(&group.to_be_bytes());
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

/// The RFC 8446 HelloRetryRequest random value.
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parse the cipher suites and supported groups from a ClientHello record.
pub fn parse_client_hello(bytes: &[u8]) -> (Vec<u16>, Vec<u16>) {
    if bytes.len() < 5 + 4 + 2 + 32 + 1 {
        return (vec![], vec![]);
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    let payload = &bytes[5..5 + record_len.min(bytes.len() - 5)];
    let body = &payload[4..];
    let sid_len = body[34] as usize;
    let mut pos = 35 + sid_len;
    if body.len() < pos + 2 {
        return (vec![], vec![]);
    }
    let suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if body.len() < pos + suites_len + 1 {
        return (vec![], vec![]);
    }
    let suites = body[pos..pos + suites_len]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    pos += suites_len;
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if body.len() < pos + 2 {
        return (suites, vec![]);
    }
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_len).min(body.len());
    let mut groups = Vec::new();
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        if ext_type == 0x000a && ext_len >= 2 {
            let list_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            let list = &body[pos + 2..(pos + 2 + list_len).min(pos + ext_len)];
            groups = list
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
        }
        pos += ext_len;
    }
    (suites, groups)
}

/// Start a server that selects the first suite it finds in both `accepted` and
/// the client's offer. Returns a ServerHello; if nothing matches, closes.
pub async fn suite_selecting_server(accepted: Vec<u16>, selected_group: Option<u16>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let accepted = accepted.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let (suites, _) = parse_client_hello(&buf[..n]);
                if let Some(selected) = accepted.iter().find(|s| suites.contains(s)) {
                    let response = server_hello(*selected, selected_group, 0x0303, None);
                    let _ = stream.write_all(&response).await;
                }
            });
        }
    });
    TestServer::new(addr, handle)
}

/// Start a server that performs SMTP STARTTLS and then accepts TLS.
pub async fn smtp_starttls_server(provider: CryptoProvider) -> TestServer {
    let (certs, key) = test_identity();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::with_capacity(256, stream);
                let mut line = String::new();
                let _ = reader.write_all(b"220 test ESMTP\r\n").await;
                let _ = reader.read_line(&mut line).await;
                line.clear();
                let _ = reader
                    .write_all(b"250-test\r\n250-STARTTLS\r\n250 OK\r\n")
                    .await;
                let _ = reader.read_line(&mut line).await;
                let _ = reader.write_all(b"220 go ahead\r\n").await;
                let stream = reader.into_inner();
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                }
            });
        }
    });
    TestServer::new(addr, handle)
}

/// Start a server that accepts connections but never writes a response, so
/// clients hit their read timeout.
pub async fn silent_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut stream = stream;
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            });
        }
    });
    TestServer::new(addr, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::handshake::{build_client_hello, parse_server_response, ServerResponse};

    #[test]
    fn parse_client_hello_rejects_short_and_truncated_inputs() {
        assert_eq!(parse_client_hello(&[]), (vec![], vec![]));
        assert_eq!(
            parse_client_hello(&[0x16, 0x03, 0x03, 0, 0]),
            (vec![], vec![])
        );

        let hello = build_client_hello("example.com", &[0x1301, 0x1302], &[0x11EC, 0x001D], 0x0304);
        // Truncate inside the suite list / extension block.
        for len in [5, 40, 45, 50, 60, 80] {
            let _ = parse_client_hello(&hello[..len.min(hello.len())]);
        }
    }

    #[test]
    fn parse_client_hello_extracts_suites_and_groups() {
        let hello = build_client_hello("example.com", &[0x1301, 0x1302], &[0x11EC, 0x001D], 0x0304);
        let (suites, groups) = parse_client_hello(&hello);
        assert_eq!(suites, vec![0x1301, 0x1302]);
        assert_eq!(groups, vec![0x11EC, 0x001D]);
    }

    #[test]
    fn server_hello_builder_round_trips() {
        let bytes = server_hello(0x1302, Some(0x11EC), 0x0303, None);
        assert!(matches!(
            parse_server_response(&bytes).unwrap(),
            ServerResponse::ServerHello {
                selected_suite: 0x1302,
                selected_group: Some(0x11EC),
                ..
            }
        ));

        let hrr = server_hello(0x1302, Some(0x11EC), 0x0303, Some(HRR_RANDOM));
        assert!(matches!(
            parse_server_response(&hrr).unwrap(),
            ServerResponse::ServerHello {
                selected_group: Some(0x11EC),
                ..
            }
        ));
    }

    #[test]
    fn test_identity_is_usable() {
        let (certs, _key) = test_identity();
        assert_eq!(certs.len(), 1);
        let (chain, _key, root) = test_ca_and_leaf();
        assert_eq!(chain.len(), 2);
        assert!(!root.as_ref().is_empty());
    }
}
