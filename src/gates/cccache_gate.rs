// CC-Cache Gate for LITEBIKE - Routes AI API requests through cc-switch proxy
// Detects Claude/OpenAI/Gemini API formats and forwards to cc-cache backend

use super::{Gate, GateError};
use async_trait::async_trait;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

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
}

impl CCCacheGate {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(RwLock::new(true)),
            config: Arc::new(RwLock::new(CCCacheConfig::default())),
            backend_host: Arc::new(RwLock::new("127.0.0.1".to_string())),
            backend_port: Arc::new(RwLock::new(9527)),
        }
    }

    pub fn with_config(config: CCCacheConfig) -> Self {
        Self {
            enabled: Arc::new(RwLock::new(config.enabled)),
            backend_host: Arc::new(RwLock::new(config.backend_host.clone())),
            backend_port: Arc::new(RwLock::new(config.backend_port)),
            config: Arc::new(RwLock::new(config)),
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
        let host = self.backend_host.read().clone();
        let port = *self.backend_port.read();

        println!("🔄 Forwarding AI API request to cc-cache backend at {}:{}", host, port);

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
            let status = format!(
                r#"{{"cccache":{{"enabled":{},"backend":"{}:{}","static_port":{}}}}}"#,
                config.enabled, config.backend_host, config.backend_port, config.static_port
            );
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

    async fn process_connection(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        if !self.is_open(data).await {
            return Err(GateError::ProtocolNotSupported("CC-Cache gate is closed or no AI API patterns detected".to_string()));
        }

        let api_type = self.detect_api_type(data);
        println!("🎯 CC-Cache detected API type: {:?}", api_type);

        match api_type.as_deref() {
            Some("status") => self.handle_status_request(data, stream).await,
            Some("claude") | Some("openai") | Some("gemini") => {
                self.forward_to_backend(data, stream).await
            }
            _ => Err(GateError::ProtocolNotSupported("Unknown AI API format".to_string()))
        }
    }

    fn name(&self) -> &str {
        "cc-cache"
    }

    fn children(&self) -> Vec<Arc<dyn Gate>> {
        vec![]
    }

    fn priority(&self) -> u8 {
        90 // High priority for AI API requests
    }

    fn can_handle_protocol(&self, protocol: &str) -> bool {
        matches!(protocol, "claude" | "openai" | "gemini" | "anthropic" | "ai-api")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cc_cache_gate_claude_detection() {
        let gate = CCCacheGate::new();

        let claude_request = b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nx-api-key: test\r\n\r\n";
        assert!(gate.is_open(claude_request).await);

        let claude_count = b"POST /v1/messages/count_tokens HTTP/1.1\r\n\r\n";
        assert!(gate.is_open(claude_count).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_openai_detection() {
        let gate = CCCacheGate::new();

        let openai_request = b"POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer sk-test\r\n\r\n";
        assert!(gate.is_open(openai_request).await);

        let responses_request = b"POST /v1/responses HTTP/1.1\r\n\r\n";
        assert!(gate.is_open(responses_request).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_gemini_detection() {
        let gate = CCCacheGate::new();

        let gemini_request = b"POST /v1beta/models/gemini-pro HTTP/1.1\r\nx-goog-api-key: test\r\n\r\n";
        assert!(gate.is_open(gemini_request).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_status_detection() {
        let gate = CCCacheGate::new();

        let health_request = b"GET /health HTTP/1.1\r\n\r\n";
        assert!(gate.is_open(health_request).await);

        let status_request = b"GET /status HTTP/1.1\r\n\r\n";
        assert!(gate.is_open(status_request).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_non_ai_request() {
        let gate = CCCacheGate::new();

        let regular_http = b"GET /index.html HTTP/1.1\r\n\r\n";
        assert!(!gate.is_open(regular_http).await);

        let random_data = b"some random data that is not an api request";
        assert!(!gate.is_open(random_data).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_disabled() {
        let gate = CCCacheGate::new();
        gate.disable();

        let claude_request = b"POST /v1/messages HTTP/1.1\r\n\r\n";
        assert!(!gate.is_open(claude_request).await);
    }

    #[tokio::test]
    async fn cc_cache_gate_status_response() {
        let gate = CCCacheGate::new();

        let health_request = b"GET /health HTTP/1.1\r\n\r\n";
        let result = gate.process_connection(health_request, None).await.unwrap();
        let response = String::from_utf8(result).unwrap();
        assert!(response.contains("200 OK"));
        assert!(response.contains("ok"));
    }

    #[test]
    fn cc_cache_config_default() {
        let config = CCCacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.backend_port, 9527);
        assert_eq!(config.static_port, 8888);
    }
}
