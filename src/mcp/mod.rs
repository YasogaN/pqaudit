use rmcp::{
    ServerHandler,
    handler::server::{
        tool::ToolRouter,
        wrapper::{Json, Parameters},
    },
    model::{Implementation, ServerInfo},
    tool, tool_handler, tool_router,
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

fn default_timeout_ms() -> u64 { 5000 }

// ── Response wrapper ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, JsonSchema)]
pub struct TextResult {
    pub content: String,
}

// ── MCP server ─────────────────────────────────────────────────────────────────

pub struct PqauditMcpServer {
    pub tool_router: ToolRouter<Self>,
}

#[tool_router]
impl PqauditMcpServer {
    pub fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }

    /// Scan a single TLS endpoint and return a JSON ScanReport.
    #[tool(name = "scan_endpoint", description = "Scan a TLS endpoint for post-quantum cryptography readiness and return a JSON report.")]
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
        Json(TextResult { content: crate::output::json::render_json(&report) })
    }

    /// Scan multiple TLS endpoints and return a comparison JSON report.
    #[tool(name = "compare_endpoints", description = "Scan multiple TLS endpoints and return a JSON report with a side-by-side comparison of their PQC readiness scores.")]
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
        Json(TextResult { content: crate::output::json::render_json(&report) })
    }

    /// Scan a TLS endpoint and return a CycloneDX CBOM (with full cipher enumeration).
    #[tool(name = "get_cbom", description = "Scan a TLS endpoint with full cipher enumeration and return a CycloneDX 1.5 CBOM in JSON format.")]
    async fn get_cbom(
        &self,
        Parameters(params): Parameters<GetCbomParams>,
    ) -> Json<TextResult> {
        let config = crate::scanner::ScanConfig {
            timeout_ms: params.timeout_ms,
            full_scan: true,
            ..crate::scanner::ScanConfig::default()
        };
        let report = crate::scanner::scan(vec![params.target], &config).await;
        Json(TextResult { content: crate::output::cbom::render_cbom(&report) })
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

/// Run the MCP server over stdio until the transport closes.
pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rmcp::ServiceExt as _;
    let server = build_mcp_server();
    server.serve(rmcp::transport::stdio()).await?.waiting().await?;
    Ok(())
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
        assert!(names.contains(&"scan_endpoint"), "scan_endpoint not registered; found: {names:?}");
        assert!(names.contains(&"compare_endpoints"), "compare_endpoints not registered; found: {names:?}");
        assert!(names.contains(&"get_cbom"), "get_cbom not registered; found: {names:?}");
    }

    #[test]
    fn mcp_server_has_correct_name() {
        let server = build_mcp_server();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "pqaudit");
    }
}
