// HTX Gate for LITEBIKE
// Gates connection to Betanet HTX (without modifying HTX)

use async_trait::async_trait;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use super::Gate;

pub struct HTXGate {
    enabled: Arc<RwLock<bool>>,
    endpoint: Arc<RwLock<String>>,
    connected: Arc<RwLock<bool>>,
}

impl HTXGate {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(RwLock::new(true)),
            endpoint: Arc::new(RwLock::new("127.0.0.1:443".to_string())),
            connected: Arc::new(RwLock::new(false)),
        }
    }

    pub fn set_endpoint(&self, endpoint: String) {
        *self.endpoint.write() = endpoint;
        *self.connected.write() = false;
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
        *self.connected.write() = false;
    }

    async fn forward_to_htx(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let endpoint = self.endpoint.read().clone();

        let mut stream = TcpStream::connect(&endpoint).await
            .map_err(|e| format!("Failed to connect to HTX at {}: {}", endpoint, e))?;

        stream.write_all(data).await
            .map_err(|e| format!("Failed to write to HTX: {}", e))?;

        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).await
            .map_err(|e| format!("Failed to read from HTX: {}", e))?;

        Ok(buffer[..n].to_vec())
    }
}

impl Default for HTXGate {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Gate for HTXGate {
    async fn is_open(&self, _data: &[u8]) -> bool {
        *self.enabled.read()
    }

    async fn process(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if !*self.enabled.read() {
            return Err("HTX gate is disabled".to_string());
        }

        self.forward_to_htx(data).await
    }

    fn name(&self) -> &str {
        "htx"
    }
}

impl HTXGate {
    fn detect_htx(&self, data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        data.starts_with(b"HTX/") ||
        data.starts_with(b"betanet/htx") ||
        (data.len() >= 24 && data.len() <= 64)
    }
}
