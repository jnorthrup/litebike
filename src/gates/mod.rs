// LiteBike Gate System
// Simplified gate controller for protocol routing

use std::sync::Arc;
use parking_lot::RwLock;
use async_trait::async_trait;

pub mod shadowsocks_gate;
pub mod crypto_gate;
pub mod htx_gate;
pub mod knox_gate;
pub mod proxy_gate;
pub mod cccache_gate;

/// Gate trait for protocol handling
#[async_trait]
pub trait Gate: Send + Sync {
    /// Check if gate allows passage
    async fn is_open(&self, data: &[u8]) -> bool;

    /// Process data through gate
    async fn process(&self, data: &[u8]) -> Result<Vec<u8>, String>;

    /// Gate identifier
    fn name(&self) -> &str;

    /// Gate priority (higher = checked first)
    fn priority(&self) -> u8 {
        50
    }
}

/// Gate processing errors
#[derive(Debug, Clone)]
pub enum GateError {
    ProtocolNotSupported(String),
    ProcessingFailed(String),
    ConnectionFailed(String),
    Knox(String),
    Timeout,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::ProtocolNotSupported(proto) => write!(f, "Protocol not supported: {}", proto),
            GateError::ProcessingFailed(reason) => write!(f, "Processing failed: {}", reason),
            GateError::ConnectionFailed(reason) => write!(f, "Connection failed: {}", reason),
            GateError::Knox(reason) => write!(f, "Knox error: {}", reason),
            GateError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for GateError {}

/// Gate information for monitoring
#[derive(Debug, Clone)]
pub struct GateInfo {
    pub name: String,
    pub enabled: bool,
    pub requests_handled: u64,
}

/// LiteBike gate controller
pub struct LitebikeGateController {
    gates: Arc<RwLock<Vec<Arc<dyn Gate>>>>,
    enabled: Arc<RwLock<bool>>,
}

impl LitebikeGateController {
    pub fn new() -> Self {
        Self {
            gates: Arc::new(RwLock::new(Vec::new())),
            enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Register a gate
    pub fn register_gate(&self, gate: Arc<dyn Gate>) {
        self.gates.write().push(gate);
    }

    /// Enable Knox mode
    pub fn enable_knox_mode(&self) {
        *self.enabled.write() = true;
    }

    /// Get all registered gates
    pub fn get_gates(&self) -> Vec<GateInfo> {
        self.gates
            .read()
            .iter()
            .map(|g| GateInfo {
                name: g.name().to_string(),
                enabled: true,
                requests_handled: 0,
            })
            .collect()
    }

    /// Check if controller is enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }
}

impl Default for LitebikeGateController {
    fn default() -> Self {
        Self::new()
    }
}
