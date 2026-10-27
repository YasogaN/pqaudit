use rmcp::{
    handler::server::{
        tool::ToolRouter,
        wrapper::{Json, Parameters},
    },
    model::{Implementation, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── Parameter types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanEndpointParams {
    /// Host to scan, e.g. "example.com", "example.com:8443", "smtp://mail.example.com"
    pub target: String,
    /// Probe timeout in milliseconds (default: 5000)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Enumerate all cipher suites (slower)
    #[serde(default)]
    pub full_scan: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareEndpointsParams {
    /// List of hosts to compare
    pub targets: Vec<String>,
    /// Probe timeout in milliseconds (default: 5000)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCbomParams {
    /// Host to scan, e.g. "example.com"
    pub target: String,
    /// Probe timeout in milliseconds (default: 5000)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    5000
}

// ── Response wrapper ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema)]
pub struct TextResult {
    pub content: String,
}

// ── MCP server ─────────────────────────────────────────────────────────────────

pub struct PqauditMcpServer {
    pub tool_router: ToolRouter<Self>,
}

impl PqauditMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

impl Default for PqauditMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl PqauditMcpServer {
    /// Scan a single TLS endpoint and return a JSON ScanReport.
    #[tool(
        name = "scan_endpoint",
        description = "Scan a TLS endpoint for post-quantum cryptography readiness and return a JSON report."
    )]
    async fn scan_endpoint(
        &self,
        Parameters(params): Parameters<ScanEndpointParams>,
    ) -> Json<TextResult> {
        let config = crate::scanner::ScanConfig {
            timeout_ms: params.timeout_ms,
            full_scan: params.full_scan,
            ..crate::scanner::ScanConfig::default()
        };
        let report = crate::scanner::scan(vec![params.target], &config).await;
        Json(TextResult {
            content: crate::output::json::render_json(&report),
        })
    }

    /// Scan multiple TLS endpoints and return a comparison JSON report.
    #[tool(
        name = "compare_endpoints",
        description = "Scan multiple TLS endpoints and return a JSON report with a side-by-side comparison of their PQC readiness scores."
    )]
    async fn compare_endpoints(
        &self,
        Parameters(params): Parameters<CompareEndpointsParams>,
    ) -> Json<TextResult> {
        let config = crate::scanner::ScanConfig {
            timeout_ms: params.timeout_ms,
            ..crate::scanner::ScanConfig::default()
        };
        let mut report = crate::scanner::scan(params.targets, &config).await;
        report.comparison = Some(crate::output::compare::build_comparison(&report));
        Json(TextResult {
            content: crate::output::json::render_json(&report),
        })
    }

    /// Scan a TLS endpoint and return a CycloneDX CBOM (with full cipher enumeration).
    #[tool(
        name = "get_cbom",
        description = "Scan a TLS endpoint with full cipher enumeration and return a CycloneDX 1.6 CBOM in JSON format."
    )]
    async fn get_cbom(&self, Parameters(params): Parameters<GetCbomParams>) -> Json<TextResult> {
        let config = crate::scanner::ScanConfig {
            timeout_ms: params.timeout_ms,
            full_scan: true,
            ..crate::scanner::ScanConfig::default()
        };
        let report = crate::scanner::scan(vec![params.target], &config).await;
        Json(TextResult {
            content: crate::output::cbom::render_cbom(&report),
        })
    }
}

#[tool_handler]
impl ServerHandler for PqauditMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default()
            .with_server_info(Implementation::new("pqaudit", env!("CARGO_PKG_VERSION")))
    }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Build a new MCP server instance (useful for testing).
pub fn build_mcp_server() -> PqauditMcpServer {
    PqauditMcpServer::new()
}

/// Run the MCP server over an arbitrary reader/writer pair.
///
/// This is public so tests (and embedders) can drive the server over an
/// in-memory transport instead of process stdio.
pub async fn run_mcp_server_with<R, W>(
    reader: R,
    writer: W,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: tokio::io::AsyncRead + Send + Unpin + 'static,
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    use rmcp::ServiceExt as _;
    let server = build_mcp_server();
    server.serve((reader, writer)).await?.waiting().await?;
    Ok(())
}

/// Run the MCP server over stdio until the transport closes.
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (stdin, stdout) = rmcp::transport::stdio();
    run_mcp_server_with(stdin, stdout).await
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_tools_are_registered() {
        let server = build_mcp_server();
        let tools = server.tool_router.list_all();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            names.contains(&"scan_endpoint"),
            "scan_endpoint not registered; found: {names:?}"
        );
        assert!(
            names.contains(&"compare_endpoints"),
            "compare_endpoints not registered; found: {names:?}"
        );
        assert!(
            names.contains(&"get_cbom"),
            "get_cbom not registered; found: {names:?}"
        );
    }

    #[test]
    fn mcp_server_has_correct_name() {
        let server = build_mcp_server();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "pqaudit");
    }

    #[test]
    fn default_timeout_is_5000ms() {
        assert_eq!(default_timeout_ms(), 5000);
    }

    #[test]
    fn server_default_and_builder_are_equivalent() {
        let _ = PqauditMcpServer::default();
        let _ = build_mcp_server();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_mcp_server_with_exits_on_transport_eof() {
        let (server_read, client_write) = tokio::io::duplex(1024);
        let (_client_read, server_write) = tokio::io::duplex(1024);
        drop(client_write);
        // EOF on the transport should cause the server loop to finish.
        let _ = run_mcp_server_with(server_read, server_write).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_mcp_server_with_completes_initialize_handshake() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (server_read, mut client_write) = tokio::io::duplex(8192);
        let (client_read, server_write) = tokio::io::duplex(8192);
        let task =
            tokio::spawn(async move { run_mcp_server_with(server_read, server_write).await });

        let initialize = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n";
        client_write.write_all(initialize).await.unwrap();
        let mut reader = BufReader::new(client_read);
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut line),
        )
        .await
        .expect("initialize response timed out")
        .unwrap();
        assert!(line.contains("result"), "unexpected response: {line}");

        let initialized = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        client_write.write_all(initialized).await.unwrap();
        drop(client_write);
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("server did not stop")
            .unwrap();
        assert!(result.is_ok(), "server returned: {result:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scan_endpoint_tool_returns_json() {
        use crate::test_support::tls_server;
        use rustls::crypto::aws_lc_rs;
        let listener = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let server = build_mcp_server();
        let response = server
            .scan_endpoint(Parameters(ScanEndpointParams {
                target: format!("127.0.0.1:{}", listener.port()),
                timeout_ms: 2000,
                full_scan: false,
            }))
            .await;
        let json: serde_json::Value = serde_json::from_str(&response.0.content).unwrap();
        assert!(json["targets"].is_array());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compare_endpoints_tool_adds_comparison() {
        use crate::test_support::tls_server;
        use rustls::crypto::aws_lc_rs;
        let listener = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let server = build_mcp_server();
        let target = format!("127.0.0.1:{}", listener.port());
        let response = server
            .compare_endpoints(Parameters(CompareEndpointsParams {
                targets: vec![target.clone(), target],
                timeout_ms: 2000,
            }))
            .await;
        let json: serde_json::Value = serde_json::from_str(&response.0.content).unwrap();
        assert!(json["comparison"].is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_cbom_tool_returns_cyclonedx() {
        use crate::test_support::tls_server;
        use rustls::crypto::aws_lc_rs;
        let listener = tls_server(aws_lc_rs::default_provider(), &[&rustls::version::TLS13]).await;
        let server = build_mcp_server();
        let response = server
            .get_cbom(Parameters(GetCbomParams {
                target: format!("127.0.0.1:{}", listener.port()),
                timeout_ms: 2000,
            }))
            .await;
        let json: serde_json::Value = serde_json::from_str(&response.0.content).unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
    }
}
