use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use crate::{ProbeError, StarttlsProtocol};

/// Parsed target: scheme, host, port.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// Parse "scheme://host:port", "host:port", or "host" into parts.
/// Scheme defaults to "" and port defaults to 443 when absent.
pub fn parse_scheme(target: &str) -> ParsedTarget {
    const SCHEMES: &[(&str, &str, u16)] = &[
        ("smtp://",  "smtp",  25),
        ("smtps://", "smtps", 465),
        ("imap://",  "imap",  143),
        ("imaps://", "imaps", 993),
        ("pop3://",  "pop3",  110),
        ("pop3s://", "pop3s", 995),
        ("ldap://",  "ldap",  389),
        ("ldaps://", "ldaps", 636),
        ("https://", "https", 443),
        ("http://",  "http",  80),
    ];

    for (prefix, scheme, default_port) in SCHEMES {
        if let Some(rest) = target.strip_prefix(prefix) {
            let (host, port) = split_host_port(rest, *default_port);
            return ParsedTarget {
                scheme: scheme.to_string(),
                host: host.to_string(),
                port,
            };
        }
    }
    let (host, port) = split_host_port(target, 443);
    ParsedTarget { scheme: String::new(), host: host.to_string(), port }
}

fn split_host_port(s: &str, default_port: u16) -> (&str, u16) {
    if s.starts_with('[') {
        // IPv6 literal: "[::1]:443" or "[::1]"
        if let Some(bracket_pos) = s.find(']') {
            let host = &s[..=bracket_pos];
            let rest = &s[bracket_pos + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                return (host, port_str.parse().unwrap_or(default_port));
            }
            return (host, default_port);
        }
    }
    if let Some(colon) = s.rfind(':') {
        if let Ok(port) = s[colon + 1..].parse::<u16>() {
            return (&s[..colon], port);
        }
    }
    (s, default_port)
}

/// Upgrade a stream to TLS-ready state by performing a STARTTLS handshake where required.
///
/// For implicit-TLS schemes (smtps, imaps, pop3s, ldaps, https, bare ""), returns the stream
/// unchanged so the caller can begin the TLS handshake immediately.
pub async fn upgrade_to_tls<S>(scheme: &str, stream: S, port: u16) -> Result<S, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    match scheme {
        "smtp" => {
            if port == 465 {
                return Err(ProbeError::StarttlsUpgradeFailed {
                    protocol: StarttlsProtocol::Smtp,
                    reason: "port 465 uses implicit TLS; use smtps:// scheme instead".into(),
                });
            }
            smtp_upgrade(stream).await
        }
        "imap" => imap_upgrade(stream).await,
        "pop3" => pop3_upgrade(stream).await,
        "ldap" => ldap_upgrade(stream).await,
        // Implicit TLS — pass stream through unchanged
        "smtps" | "imaps" | "pop3s" | "ldaps" | "https" | "http" | "" => Ok(stream),
        other => Err(ProbeError::StarttlsUpgradeFailed {
            protocol: StarttlsProtocol::Smtp,
            reason: format!("unknown scheme: {other}"),
        }),
    }
}

/// Perform the SMTP STARTTLS upgrade sequence (RFC 3207).
async fn smtp_upgrade<S>(stream: S) -> Result<S, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // BufReader takes ownership so we can get the stream back via into_inner().
    // Capacity 256: large enough for any SMTP response line, small enough to avoid
    // reading ahead into TLS handshake bytes (server sends those only after our ClientHello).
    let mut buf = BufReader::with_capacity(256, stream);
    let mut line = String::new();

    // 1. Read server greeting (220 ...)
    buf.read_line(&mut line).await
        .map_err(|e| smtp_err(e.to_string()))?;
    if !line.starts_with("220") {
        return Err(smtp_err(format!("unexpected greeting: {}", line.trim())));
    }

    // 2. Send EHLO
    buf.get_mut().write_all(b"EHLO pqaudit\r\n").await
        .map_err(|e| smtp_err(e.to_string()))?;

    // 3. Read EHLO response (multi-line 250-... ending with 250 ...)
    let mut has_starttls = false;
    loop {
        line.clear();
        buf.read_line(&mut line).await
            .map_err(|e| smtp_err(e.to_string()))?;
        if line.to_ascii_uppercase().contains("STARTTLS") {
            has_starttls = true;
        }
        if line.starts_with("250 ") {
            break; // last line of multi-line EHLO response
        } else if !line.starts_with("250-") {
            return Err(smtp_err(format!("unexpected EHLO response: {}", line.trim())));
        }
    }
    if !has_starttls {
        return Err(smtp_err("server does not advertise STARTTLS capability".into()));
    }

    // 4. Send STARTTLS
    buf.get_mut().write_all(b"STARTTLS\r\n").await
        .map_err(|e| smtp_err(e.to_string()))?;

    // 5. Read "220 Ready" (or equivalent 220 response)
    line.clear();
    buf.read_line(&mut line).await
        .map_err(|e| smtp_err(e.to_string()))?;
    if !line.starts_with("220") {
        return Err(smtp_err(format!("STARTTLS rejected: {}", line.trim())));
    }

    Ok(buf.into_inner())
}

/// Perform the IMAP STARTTLS upgrade sequence (RFC 2595).
async fn imap_upgrade<S>(stream: S) -> Result<S, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut buf = BufReader::with_capacity(256, stream);
    let mut line = String::new();

    // 1. Read greeting: "* OK ..."
    buf.read_line(&mut line).await
        .map_err(|e| imap_err(e.to_string()))?;
    if !line.starts_with("* OK") {
        return Err(imap_err(format!("unexpected greeting: {}", line.trim())));
    }

    // 2. Send STARTTLS command
    buf.get_mut().write_all(b"A001 STARTTLS\r\n").await
        .map_err(|e| imap_err(e.to_string()))?;

    // 3. Read tagged OK response
    line.clear();
    buf.read_line(&mut line).await
        .map_err(|e| imap_err(e.to_string()))?;
    if !line.contains("OK") {
        return Err(imap_err(format!("STARTTLS rejected: {}", line.trim())));
    }

    Ok(buf.into_inner())
}

/// Perform the POP3 STLS upgrade sequence (RFC 2595).
async fn pop3_upgrade<S>(stream: S) -> Result<S, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let mut buf = BufReader::with_capacity(256, stream);
    let mut line = String::new();

    // 1. Read greeting: "+OK ..."
    buf.read_line(&mut line).await
        .map_err(|e| pop3_err(e.to_string()))?;
    if !line.starts_with("+OK") {
        return Err(pop3_err(format!("unexpected greeting: {}", line.trim())));
    }

    // 2. Send STLS
    buf.get_mut().write_all(b"STLS\r\n").await
        .map_err(|e| pop3_err(e.to_string()))?;

    // 3. Read "+OK ..."
    line.clear();
    buf.read_line(&mut line).await
        .map_err(|e| pop3_err(e.to_string()))?;
    if !line.starts_with("+OK") {
        return Err(pop3_err(format!("STLS rejected: {}", line.trim())));
    }

    Ok(buf.into_inner())
}

/// LDAP StartTLS (RFC 2830) requires ASN.1/BER encoding — out of scope for v1.
/// Use ldaps:// for implicit TLS on port 636.
async fn ldap_upgrade<S>(_stream: S) -> Result<S, ProbeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    Err(ProbeError::StarttlsUpgradeFailed {
        protocol: StarttlsProtocol::Ldap,
        reason: "LDAP STARTTLS not yet implemented; use ldaps:// for implicit TLS".into(),
    })
}

fn smtp_err(reason: String) -> ProbeError {
    ProbeError::StarttlsUpgradeFailed { protocol: StarttlsProtocol::Smtp, reason }
}

fn imap_err(reason: String) -> ProbeError {
    ProbeError::StarttlsUpgradeFailed { protocol: StarttlsProtocol::Imap, reason }
}

fn pop3_err(reason: String) -> ProbeError {
    ProbeError::StarttlsUpgradeFailed { protocol: StarttlsProtocol::Pop3, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // ── parse_scheme ────────────────────────────────────────────────────────────

    #[test]
    fn parse_scheme_smtp_with_port() {
        let t = parse_scheme("smtp://mail.example.com:25");
        assert_eq!(t.scheme, "smtp");
        assert_eq!(t.host, "mail.example.com");
        assert_eq!(t.port, 25);
    }

    #[test]
    fn parse_scheme_smtps_default_port() {
        let t = parse_scheme("smtps://mail.example.com");
        assert_eq!(t.scheme, "smtps");
        assert_eq!(t.port, 465);
    }

    #[test]
    fn parse_scheme_bare_host_defaults() {
        let t = parse_scheme("example.com");
        assert_eq!(t.scheme, "");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_scheme_host_with_port() {
        let t = parse_scheme("example.com:8443");
        assert_eq!(t.scheme, "");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn parse_scheme_imap() {
        let t = parse_scheme("imap://imap.example.com:143");
        assert_eq!(t.scheme, "imap");
        assert_eq!(t.port, 143);
    }

    #[test]
    fn parse_scheme_pop3() {
        let t = parse_scheme("pop3://pop.example.com");
        assert_eq!(t.scheme, "pop3");
        assert_eq!(t.port, 110);
    }

    // ── upgrade_to_tls error cases ──────────────────────────────────────────────

    #[tokio::test]
    async fn smtp_on_port_465_returns_smtps_hint() {
        let (client, _server) = tokio::io::duplex(64);
        let result = upgrade_to_tls("smtp", client, 465).await;
        assert!(matches!(result, Err(ProbeError::StarttlsUpgradeFailed { .. })));
        let err = result.unwrap_err().to_string();
        assert!(err.contains("smtps"), "error should mention smtps://, got: {err}");
    }

    #[tokio::test]
    async fn unknown_scheme_returns_error() {
        let (client, _server) = tokio::io::duplex(64);
        let result = upgrade_to_tls("ftp", client, 21).await;
        assert!(matches!(result, Err(ProbeError::StarttlsUpgradeFailed { .. })));
    }

    #[tokio::test]
    async fn ldap_returns_not_implemented_error() {
        let (client, _server) = tokio::io::duplex(64);
        let result = upgrade_to_tls("ldap", client, 389).await;
        assert!(matches!(
            result,
            Err(ProbeError::StarttlsUpgradeFailed { protocol: StarttlsProtocol::Ldap, .. })
        ));
    }

    // ── implicit TLS pass-through ───────────────────────────────────────────────

    #[tokio::test]
    async fn implicit_tls_schemes_pass_through_without_upgrade() {
        for scheme in &["smtps", "imaps", "pop3s", "ldaps", "https", ""] {
            let (client, _server) = tokio::io::duplex(64);
            let result = upgrade_to_tls(scheme, client, 443).await;
            assert!(result.is_ok(), "scheme '{scheme}' should pass through without STARTTLS");
        }
    }

    // ── SMTP STARTTLS sequence ──────────────────────────────────────────────────

    #[tokio::test]
    async fn smtp_starttls_upgrade_sequence() {
        let (client, mut server) = tokio::io::duplex(4096);
        // Write all server responses into the buffer BEFORE running the upgrade.
        // Keep `server` alive so client writes (EHLO, STARTTLS) don't hit broken-pipe.
        server.write_all(
            b"220 mail.test ESMTP\r\n\
              250-mail.test\r\n\
              250-STARTTLS\r\n\
              250 OK\r\n\
              220 Go ahead\r\n",
        ).await.unwrap();

        let result = smtp_upgrade(client).await;
        drop(server);
        assert!(result.is_ok(), "SMTP STARTTLS upgrade should succeed: {:?}", result.err());
    }

    #[tokio::test]
    async fn smtp_upgrade_fails_when_no_starttls_capability() {
        let (client, mut server) = tokio::io::duplex(4096);
        server.write_all(
            b"220 mail.test ESMTP\r\n\
              250-mail.test\r\n\
              250 OK\r\n",
        ).await.unwrap();

        let result = smtp_upgrade(client).await;
        drop(server);
        assert!(
            matches!(result, Err(ProbeError::StarttlsUpgradeFailed { .. })),
            "should fail when STARTTLS not advertised"
        );
    }

    // ── IMAP STARTTLS sequence ──────────────────────────────────────────────────

    #[tokio::test]
    async fn imap_starttls_upgrade_sequence() {
        let (client, mut server) = tokio::io::duplex(4096);
        server.write_all(
            b"* OK Dovecot ready\r\n\
              A001 OK Begin TLS negotiation now\r\n",
        ).await.unwrap();

        let result = imap_upgrade(client).await;
        drop(server);
        assert!(result.is_ok(), "IMAP STARTTLS upgrade should succeed: {:?}", result.err());
    }

    // ── POP3 STLS sequence ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn pop3_stls_upgrade_sequence() {
        let (client, mut server) = tokio::io::duplex(4096);
        server.write_all(
            b"+OK Dovecot ready\r\n\
              +OK Begin TLS negotiation\r\n",
        ).await.unwrap();

        let result = pop3_upgrade(client).await;
        drop(server);
        assert!(result.is_ok(), "POP3 STLS upgrade should succeed: {:?}", result.err());
    }
}
