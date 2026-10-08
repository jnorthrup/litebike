// LITERBIKE Gate System (AGPL Licensed)
// Enhanced hierarchical gating for protocols, crypto, and Knox integration
// Integrated with ../literbike gate patterns

use std::sync::Arc;
use parking_lot::RwLock;
use async_trait::async_trait;
use tokio::net::TcpStream;
use serde_json::json;
use std::collections::HashMap;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

pub mod shadowsocks_gate;
pub mod crypto_gate;
pub mod htx_gate;
pub mod knox_gate;
pub mod proxy_gate;

/// Enhanced gate trait with Knox awareness and connection handling
#[async_trait]
pub trait Gate: Send + Sync {
    /// Check if gate allows passage for this data
    async fn is_open(&self, data: &[u8]) -> bool;
    
    /// Process data through gate (legacy interface)
    async fn process(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    
    /// Enhanced process with connection handling
    async fn process_connection(&self, data: &[u8], _stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        // Default implementation delegates to legacy process method
        self.process(data).await.map_err(|e| GateError::ProcessingFailed(e))
    }
    
    /// Gate identifier
    fn name(&self) -> &str;
    
    /// Child gates (default: none)
    fn children(&self) -> Vec<Arc<dyn Gate>> {
        vec![]
    }
    
    /// Gate priority (higher = checked first)
    fn priority(&self) -> u8 {
        50 // Default priority
    }
    
    /// Check if gate can handle this protocol
    fn can_handle_protocol(&self, protocol: &str) -> bool {
        // Default implementation checks common protocols
        matches!(protocol, "http" | "https" | "tcp")
    }
}

/// Gate processing errors with Knox-specific error types
#[derive(Debug, Clone)]
pub enum GateError {
    ProtocolNotSupported(String),
    ProcessingFailed(String),
    ConnectionFailed(String),
    Timeout,
    Knox(String),
    Legacy(String),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::ProtocolNotSupported(proto) => write!(f, "Protocol not supported: {}", proto),
            GateError::ProcessingFailed(reason) => write!(f, "Processing failed: {}", reason),
            GateError::ConnectionFailed(reason) => write!(f, "Connection failed: {}", reason),
            GateError::Timeout => write!(f, "Operation timed out"),
            GateError::Knox(reason) => write!(f, "Knox gate error: {}", reason),
            GateError::Legacy(reason) => write!(f, "Legacy error: {}", reason),
        }
    }
}

impl std::error::Error for GateError {}

// CC-Cache Gate for LITEBIKE - Routes AI API requests through cc-switch proxy
// Detects Claude/OpenAI/Gemini API formats and forwards to cc-cache backend

/// CC-Cache configuration
#[derive(Debug, Clone)]
pub struct CCCacheConfig {
    pub enabled: bool,
    pub backend_host: String,
    pub backend_port: u16,
    pub auto_detect: bool,
    pub serve_static: bool,
    pub static_port: u16,
}

impl Default for CCCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend_host: "127.0.0.1".to_string(),
            backend_port: 9527,
            auto_detect: true,
            serve_static: true,
            static_port: 8888,
        }
    }
}

pub struct CCCacheGate {
    enabled: Arc<RwLock<bool>>,
    config: Arc<RwLock<CCCacheConfig>>,
    backend_host: Arc<RwLock<String>>,
    backend_port: Arc<RwLock<u16>>,
    agent_backends: Arc<RwLock<HashMap<String, (String, u16)>>>,
}

impl CCCacheGate {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(RwLock::new(true)),
            config: Arc::new(RwLock::new(CCCacheConfig::default())),
            backend_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            backend_port: Arc::new(RwLock::new(9527)),
            agent_backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_config(config: CCCacheConfig) -> Self {
        Self {
            enabled: Arc::new(RwLock::new(config.enabled)),
            backend_host: Arc::new(RwLock::new(config.backend_host.clone())),
            backend_port: Arc::new(RwLock::new(config.backend_port)),
            config: Arc::new(RwLock::new(config)),
            agent_backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    pub fn set_backend(&self, host: &str, port: u16) {
        *self.backend_host.write() = host.to_string();
        *self.backend_port.write() = port;
    }

    pub fn set_agent_backend(&self, agent: &str, host: &str, port: u16) {
        let agent = normalize_agent_id(agent);
        if agent.is_empty() {
            return;
        }
        self.agent_backends
            .write()
            .insert(agent, (host.to_string(), port));
    }

    pub fn clear_agent_backend(&self, agent: &str) {
        let agent = normalize_agent_id(agent);
        if agent.is_empty() {
            return;
        }
        self.agent_backends.write().remove(&agent);
    }

    fn extract_target_agent(&self, data: &[u8]) -> Option<String> {
        let request = String::from_utf8_lossy(data);
        let mut lines = request.lines();
        let first = lines.next()?;
        if let Some(path) = first.split_whitespace().nth(1) {
            if let Some(agent) = extract_agent_from_path(path) {
                return Some(agent);
            }
        }

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }

            let lower = trimmed.to_ascii_lowercase();
            if let Some(value) = lower
                .strip_prefix("x-agent-target:")
                .or_else(|| lower.strip_prefix("x-agent-name:"))
                .or_else(|| lower.strip_prefix("x-cc-agent:"))
            {
                let agent = normalize_agent_id(value);
                if !agent.is_empty() {
                    return Some(agent);
                }
            }
        }

        None
    }

    fn resolve_backend_for_request(&self, data: &[u8]) -> (String, u16, Option<String>) {
        if let Some(agent) = self.extract_target_agent(data) {
            if let Some((host, port)) = self.agent_backends.read().get(&agent).cloned() {
                return (host, port, Some(agent));
            }
        }

        (
            self.backend_host.read().clone(),
            *self.backend_port.read(),
            None,
        )
    }

    /// Detect Claude API requests (Anthropic format)
    fn detect_claude_api(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);

        // Claude API paths
        let claude_paths = [
            "POST /v1/messages",
            "POST /claude/v1/messages",
            "/v1/messages/count_tokens",
        ];

        for path in &claude_paths {
            if data_str.contains(path) {
                return true;
            }
        }

        // Check for Anthropic headers
        data_str.contains("x-api-key:") || data_str.contains("anthropic-version:")
    }

    /// Detect OpenAI API requests
    fn detect_openai_api(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);

        // OpenAI API paths
        let openai_paths = [
            "POST /v1/chat/completions",
            "POST /chat/completions",
            "POST /v1/responses",
            "POST /responses",
            "POST /codex/v1/chat/completions",
        ];

        for path in &openai_paths {
            if data_str.contains(path) {
                return true;
            }
        }

        // Check for OpenAI headers
        data_str.contains("Authorization: Bearer") &&
            (data_str.contains("openai") || data_str.contains("api.openai.com"))
    }

    /// Detect Gemini API requests
    fn detect_gemini_api(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);

        // Gemini API paths
        let gemini_paths = [
            "/v1beta/models/",
            "/v1beta/chat/completions",
            "/gemini/v1beta/",
        ];

        for path in &gemini_paths {
            if data_str.contains(path) {
                return true;
            }
        }

        // Check for Gemini headers
        data_str.contains("x-goog-api-key")
    }

    /// Detect cc-cache status/health requests
    fn detect_cccache_status(&self, data: &[u8]) -> bool {
        if data.len() < 10 {
            return false;
        }

        let data_str = String::from_utf8_lossy(data);

        data_str.contains("GET /health") ||
            data_str.contains("GET /status") ||
            data_str.contains("GET /cc-cache")
    }

    /// Get the API type from detected request
    fn detect_api_type(&self, data: &[u8]) -> Option<String> {
        if self.detect_claude_api(data) {
            Some("claude".to_string())
        } else if self.detect_openai_api(data) {
            Some("openai".to_string())
        } else if self.detect_gemini_api(data) {
            Some("gemini".to_string())
        } else if self.detect_cccache_status(data) {
            Some("status".to_string())
        } else {
            None
        }
    }

    /// Forward request to cc-cache backend
    async fn forward_to_backend(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        let (host, port, agent) = self.resolve_backend_for_request(data);

        if let Some(agent) = agent {
            println!(
                "🔄 Forwarding AI API request to agent-scoped cc-cache backend {} at {}:{}",
                agent, host, port
            );
        } else {
            println!("🔄 Forwarding AI API request to cc-cache backend at {}:{}", host, port);
        }

        // Connect to backend
        let mut backend_stream = TcpStream::connect(format!("{}:{}", host, port)).await
            .map_err(|e| GateError::ConnectionFailed(format!("Failed to connect to cc-cache backend: {}", e)))?;

        // Forward the request
        backend_stream.write_all(data).await
            .map_err(|e| GateError::ProcessingFailed(format!("Failed to forward request: {}", e)))?;

        // Read response
        let mut response = vec![0u8; 65536];
        let n = backend_stream.read(&mut response).await
            .map_err(|e| GateError::ProcessingFailed(format!("Failed to read response: {}", e)))?;
        response.truncate(n);

        // Send response back to client if stream provided
        if let Some(mut client_stream) = stream {
            client_stream.write_all(&response).await
                .map_err(|e| GateError::ConnectionFailed(format!("Failed to send response to client: {}", e)))?;
        }

        Ok(response)
    }

    /// Handle status/health check requests
    async fn handle_status_request(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        let data_str = String::from_utf8_lossy(data);
        let config = self.config.read().clone();

        let response = if data_str.contains("GET /health") {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                15, r#"{"status":"ok"}"#
            )
        } else if data_str.contains("GET /status") {
            let routes = self
                .agent_backends
                .read()
                .iter()
                .map(|(agent, (host, port))| {
                    json!({"agent": agent, "backend": format!("{}:{}", host, port)})
                })
                .collect::<Vec<_>>();
            let status = json!({
                "cccache": {
                    "enabled": config.enabled,
                    "backend": format!("{}:{}", config.backend_host, config.backend_port),
                    "static_port": config.static_port,
                    "agent_routes": routes
                }
            })
            .to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                status.len(), status
            )
        } else {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                19, r#"{"name":"cc-cache"}"#
            )
        };

        let response_bytes = response.into_bytes();

        if let Some(mut client_stream) = stream {
            client_stream.write_all(&response_bytes).await
                .map_err(|e| GateError::ConnectionFailed(format!("Failed to send response: {}", e)))?;
        }

        Ok(response_bytes)
    }

    async fn process_connection(
        &self,
        data: &[u8],
        stream: Option<TcpStream>,
    ) -> Result<Vec<u8>, GateError> {
        if !self.is_open(data).await {
            return Err(GateError::ProtocolNotSupported(
                "CC-Cache gate is closed or no AI API patterns detected".to_string(),
            ));
        }

        let api_type = self.detect_api_type(data);
        println!("🎯 CC-Cache detected API type: {:?}", api_type);

        match api_type.as_deref() {
            Some("status") => self.handle_status_request(data, stream).await,
            Some("claude") | Some("openai") | Some("gemini") => {
                self.forward_to_backend(data, stream).await
            }
            _ => Err(GateError::ProtocolNotSupported(
                "Unknown AI API format".to_string(),
            )),
        }
    }
}

fn normalize_agent_id(raw: &str) -> String {
    raw.trim().trim_matches('/').to_ascii_lowercase()
}

fn extract_agent_from_path(path: &str) -> Option<String> {
    let normalized = path.trim().trim_matches('/');
    let mut segments = normalized.split('/');
    while let Some(segment) = segments.next() {
        if segment.eq_ignore_ascii_case("agents") {
            let next = segments.next()?;
            let agent = normalize_agent_id(next);
            if !agent.is_empty() {
                return Some(agent);
            }
        }
    }
    None
}

#[async_trait]
impl Gate for CCCacheGate {
    async fn is_open(&self, data: &[u8]) -> bool {
        if !*self.enabled.read() {
            return false;
        }

        // Gate is open if we detect AI API patterns
        self.detect_claude_api(data) ||
            self.detect_openai_api(data) ||
            self.detect_gemini_api(data) ||
            self.detect_cccache_status(data)
    }

    async fn process(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.process_connection(data, None).await {
            Ok(result) => Ok(result),
            Err(e) => Err(e.to_string()),
        }
    }

    fn name(&self) -> &str {
        "cc-cache"
    }

    fn priority(&self) -> u8 {
        90 // High priority for AI API requests
    }
}

/// Enhanced LITEBIKE master gate controller with Knox integration
pub struct LitebikeGateController {
    gates: Arc<RwLock<Vec<Arc<dyn Gate>>>>,
    shadowsocks_gate: Arc<shadowsocks_gate::ShadowsocksGate>,
    crypto_gate: Arc<crypto_gate::CryptoGate>,
    htx_gate: Arc<htx_gate::HTXGate>,
    knox_gate: Arc<knox_gate::KnoxGate>,
    proxy_gate: Arc<proxy_gate::ProxyGate>,
    cccache_gate: Arc<CCCacheGate>,
}

impl LitebikeGateController {
    pub fn new() -> Self {
        let shadowsocks_gate = Arc::new(shadowsocks_gate::ShadowsocksGate::new());
        let crypto_gate = Arc::new(crypto_gate::CryptoGate::new());
        let htx_gate = Arc::new(htx_gate::HTXGate::new());
        let knox_gate = Arc::new(knox_gate::KnoxGate::new());
        let proxy_gate = Arc::new(proxy_gate::ProxyGate::new());
        let cccache_gate = Arc::new(CCCacheGate::new());
        
        let mut gates: Vec<Arc<dyn Gate>> = vec![
            cccache_gate.clone() as Arc<dyn Gate>,
            knox_gate.clone() as Arc<dyn Gate>,
            proxy_gate.clone() as Arc<dyn Gate>,
            shadowsocks_gate.clone() as Arc<dyn Gate>,
            crypto_gate.clone() as Arc<dyn Gate>,
            htx_gate.clone() as Arc<dyn Gate>,
        ];
        
        gates.sort_by(|a, b| b.priority().cmp(&a.priority()));
        
        Self {
            gates: Arc::new(RwLock::new(gates)),
            shadowsocks_gate,
            crypto_gate,
            htx_gate,
            knox_gate,
            proxy_gate,
            cccache_gate,
        }
    }
    
    /// Enhanced routing with connection handling (legacy interface)
    pub async fn route(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.route_with_connection(data, None).await {
            Ok(result) => Ok(result),
            Err(e) => Err(e.to_string()),
        }
    }
    
    /// Route data through appropriate gate with connection support
    pub async fn route_with_connection(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        // Collect clones before any .await to avoid holding the parking_lot guard across awaits
        let gates: Vec<Arc<dyn Gate>> = self.gates.read().iter().cloned().collect();
        let mut stream = stream;

        for gate in gates.iter() {
            if gate.is_open(data).await {
                println!("🚪 Routing through gate: {} (priority: {})", gate.name(), gate.priority());

                // Give the stream to the first open gate; subsequent gates get None
                let gate_stream = stream.take();
                match gate.process_connection(data, gate_stream).await {
                    Ok(result) => return Ok(result),
                    Err(GateError::ProcessingFailed(_)) => {
                        // Fall back to legacy processing
                        if let Ok(result) = gate.process(data).await {
                            return Ok(result);
                        }
                    }
                    Err(e) => {
                        println!("⚠ Gate {} failed: {}", gate.name(), e);
                        continue;
                    }
                }
            }
        }

        Err(GateError::ProtocolNotSupported("No gate could process data".to_string()))
    }
    
    /// Route by specific protocol
    pub async fn route_by_protocol(&self, protocol: &str, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        // Collect clones before any .await to avoid holding the parking_lot guard across awaits
        let gates: Vec<Arc<dyn Gate>> = self.gates.read().iter().cloned().collect();
        let mut stream = stream;

        for gate in gates.iter() {
            if gate.can_handle_protocol(protocol) && gate.is_open(data).await {
                println!("🎯 Protocol-specific routing: {} -> {}", protocol, gate.name());
                return gate.process_connection(data, stream.take()).await;
            }
        }
        
        Err(GateError::ProtocolNotSupported(format!("No gate for protocol: {}", protocol)))
    }
    
    /// List all gates with their status
    pub async fn list_gates(&self) -> Vec<GateInfo> {
        let gates: Vec<Arc<dyn Gate>> = self.gates.read().iter().cloned().collect();
        let mut gate_info = Vec::new();

        for gate in gates.iter() {
            let test_data = b"test";
            let is_open = gate.is_open(test_data).await;
            
            gate_info.push(GateInfo {
                name: gate.name().to_string(),
                priority: gate.priority(),
                is_open,
                children_count: gate.children().len(),
            });
        }
        
        gate_info
    }
    
    /// Enable Knox mode for adverse network conditions
    pub fn enable_knox_mode(&self) {
        self.knox_gate.enable();
        println!("🔒 Knox mode enabled for adverse network conditions");
    }
    
    /// Disable Knox mode  
    pub fn disable_knox_mode(&self) {
        self.knox_gate.disable();
        println!("🔓 Knox mode disabled");
    }
    
    /// Enable CC-Cache mode for AI API routing
    pub fn enable_cccache_mode(&self) {
        self.cccache_gate.enable();
        println!("🤖 CC-Cache mode enabled for AI API routing");
    }
    
    /// Disable CC-Cache mode
    pub fn disable_cccache_mode(&self) {
        self.cccache_gate.disable();
        println!("📴 CC-Cache mode disabled");
    }
    
    /// Configure CC-Cache backend
    pub fn set_cccache_backend(&self, host: &str, port: u16) {
        self.cccache_gate.set_backend(host, port);
        println!("🔗 CC-Cache backend set to {}:{}", host, port);
    }
    
    /// Add HTX as a downstream consumer (legacy interface)
    pub fn connect_htx_downstream(&self, htx_endpoint: String) {
        self.htx_gate.set_endpoint(htx_endpoint);
    }
    
    /// Add custom gate
    pub fn add_gate(&self, gate: Arc<dyn Gate>) {
        let mut gates = self.gates.write();
        gates.push(gate);
        
        // Re-sort by priority
        gates.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }
}

/// Gate information for status reporting
#[derive(Debug, Clone)]
pub struct GateInfo {
    pub name: String,
    pub priority: u8,
    pub is_open: bool,
    pub children_count: usize,
}

impl Default for LitebikeGateController {
    fn default() -> Self {
        Self::new()
    }
}