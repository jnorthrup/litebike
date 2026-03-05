// Knox Gate for LITEBIKE - Handles Knox-aware connections and bypass
// Uses litebike-local KnoxProxyConfig; tethering bypass lives in literbike

use super::{Gate, GateError};
use crate::proxy_config::KnoxProxyConfig;
use async_trait::async_trait;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

pub struct KnoxGate {
    enabled: Arc<RwLock<bool>>,
    config: Arc<RwLock<KnoxProxyConfig>>,
}

impl KnoxGate {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(RwLock::new(false)),
            config: Arc::new(RwLock::new(KnoxProxyConfig::default())),
        }
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
        let config = self.config.read();
        if config.enable_tethering_bypass {
            println!("📡 TTL spoofing configured (TTL: {})", config.ttl_spoofing);
        }
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    pub fn set_config(&self, config: KnoxProxyConfig) {
        *self.config.write() = config;
    }

    /// Detect Knox-related traffic patterns
    fn detect_knox_patterns(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        if data.windows(4).any(|w| w == b"Knox") {
            return true;
        }

        if data.windows(7).any(|w| w == b"Android") {
            return true;
        }

        if self.detect_carrier_patterns(data) {
            return true;
        }

        if let Ok(s) = std::str::from_utf8(data) {
            if s.contains("rmnet_") || s.contains("wlan0") {
                return true;
            }
        }

        false
    }

    /// Detect carrier-specific traffic patterns
    fn detect_carrier_patterns(&self, data: &[u8]) -> bool {
        let carrier_patterns: &[&[u8]] = &[
            b"tether",
            b"hotspot",
            b"carrier",
            b"mobile",
            b"cellular",
        ];

        for pattern in carrier_patterns {
            if data.windows(pattern.len()).any(|w| w.eq_ignore_ascii_case(pattern)) {
                return true;
            }
        }

        false
    }

    /// Apply Knox-specific processing
    async fn process_knox_traffic(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        // Extract config values before any await points
        let (enable_tethering_bypass, ttl_spoofing) = {
            let config = self.config.read();
            (config.enable_tethering_bypass, config.ttl_spoofing)
        };

        println!("🔒 Processing Knox traffic (tethering_bypass: {}, ttl: {})",
            enable_tethering_bypass, ttl_spoofing);

        let mut processed_data = Vec::with_capacity(data.len() + 16);
        processed_data.extend_from_slice(b"KNOX:");
        processed_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
        processed_data.extend_from_slice(data);

        if let Some(mut stream) = stream {
            match stream.write_all(&processed_data).await {
                Ok(()) => {
                    let mut response = vec![0u8; 4096];
                    match stream.read(&mut response).await {
                        Ok(n) if n > 0 => {
                            response.truncate(n);
                            return Ok(response);
                        }
                        _ => return Ok(processed_data),
                    }
                }
                Err(e) => return Err(GateError::Knox(format!("Stream write failed: {}", e))),
            }
        }

        Ok(processed_data)
    }
}

#[async_trait]
impl Gate for KnoxGate {
    async fn is_open(&self, data: &[u8]) -> bool {
        if !*self.enabled.read() {
            return false;
        }
        self.detect_knox_patterns(data)
    }

    async fn process(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.process_connection(data, None).await {
            Ok(result) => Ok(result),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn process_connection(&self, data: &[u8], stream: Option<TcpStream>) -> Result<Vec<u8>, GateError> {
        if !self.is_open(data).await {
            return Err(GateError::Knox("Knox gate is closed or no Knox patterns detected".to_string()));
        }
        self.process_knox_traffic(data, stream).await
    }

    fn name(&self) -> &str {
        "knox"
    }

    fn children(&self) -> Vec<Arc<dyn Gate>> {
        vec![]
    }

    fn priority(&self) -> u8 {
        90
    }

    fn can_handle_protocol(&self, protocol: &str) -> bool {
        matches!(protocol, "http" | "https" | "tcp" | "knox" | "mobile" | "android")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn knox_gate_detection() {
        let gate = KnoxGate::new();
        gate.enable();

        let knox_data = b"Android Knox system";
        assert!(gate.is_open(knox_data).await);

        let carrier_data = b"tether hotspot data";
        assert!(gate.is_open(carrier_data).await);

        let regular_data = b"regular http request";
        assert!(!gate.is_open(regular_data).await);
    }

    #[tokio::test]
    async fn knox_gate_processing() {
        let gate = KnoxGate::new();
        gate.enable();

        let test_data = b"Knox test data";
        let result = gate.process_connection(test_data, None).await.unwrap();

        assert!(result.starts_with(b"KNOX:"));
        assert!(result.len() > test_data.len());
    }

    #[tokio::test]
    async fn knox_gate_disabled() {
        let gate = KnoxGate::new();

        let knox_data = b"Android Knox system";
        assert!(!gate.is_open(knox_data).await);

        let result = gate.process_connection(knox_data, None).await;
        assert!(matches!(result, Err(GateError::Knox(_))));
    }
}
