// Integrated Proxy Server for LiteBike
// Simplified version with health monitoring integration

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::time::Instant;
use log::{info, warn, error};
use literbike::model_serving_taxonomy::classify_http_request_prefix;

/// Integrated proxy server configuration
#[derive(Debug, Clone)]
pub struct IntegratedProxyConfig {
    pub bind_address: String,
    pub enable_logging: bool,
    pub max_connections: usize,
    pub connection_timeout_seconds: u64,
}

impl Default for IntegratedProxyConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8888".to_string(),
            enable_logging: true,
            max_connections: 1000,
            connection_timeout_seconds: 300,
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
}

/// Integrated proxy server statistics
#[derive(Debug, Clone)]
pub struct IntegratedProxyStats {
    pub uptime_secs: u64,
    pub connections: ConnectionStats,
    pub health_status: String,
    pub decoded_model_routes: HashMap<String, u64>,
}

/// Connection information for monitoring
#[derive(Debug, Clone)]
struct ConnectionInfo {
    peer_addr: std::net::SocketAddr,
    start_time: Instant,
    bytes_transferred: u64,
}

/// Integrated proxy server combining litebike components
pub struct IntegratedProxyServer {
    config: IntegratedProxyConfig,
    start_time: Instant,
    total_connections: Arc<RwLock<u64>>,
    active_connections: Arc<RwLock<HashMap<String, ConnectionInfo>>>,
    bytes_in: Arc<RwLock<u64>>,
    bytes_out: Arc<RwLock<u64>>,
    errors: Arc<RwLock<u64>>,
    decoded_model_routes: Arc<RwLock<HashMap<String, u64>>>,
}

impl IntegratedProxyServer {
    /// Create new integrated proxy server
    pub fn new(config: IntegratedProxyConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            total_connections: Arc::new(RwLock::new(0)),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            bytes_in: Arc::new(RwLock::new(0)),
            bytes_out: Arc::new(RwLock::new(0)),
            errors: Arc::new(RwLock::new(0)),
            decoded_model_routes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the integrated proxy server
    pub async fn start(&self) -> Result<(), IntegratedProxyError> {
        info!("🚀 Starting Integrated LiteBike Proxy Server");
        info!("   Bind address: {}", self.config.bind_address);
        info!("   Max connections: {}", self.config.max_connections);

        let listener = TcpListener::bind(&self.config.bind_address)
            .await
            .map_err(|e| IntegratedProxyError::BindFailed(e.to_string()))?;

        info!("   Listening on {}", self.config.bind_address);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let total_conns = self.total_connections.clone();
                    let active_conns = self.active_connections.clone();
                    let bytes_in = self.bytes_in.clone();
                    let bytes_out = self.bytes_out.clone();
                    let errors = self.errors.clone();
                    let decoded_model_routes = self.decoded_model_routes.clone();
                    let timeout = self.config.connection_timeout_seconds;

                    tokio::spawn(async move {
                        // Increment total connections
                        *total_conns.write().await += 1;

                        // Add to active connections
                        let conn_id = format!("{}:{}", addr.ip(), addr.port());
                        active_conns.write().await.insert(
                            conn_id.clone(),
                            ConnectionInfo {
                                peer_addr: addr,
                                start_time: Instant::now(),
                                bytes_transferred: 0,
                            },
                        );

                        // Handle connection
                        match handle_connection(stream, timeout).await {
                            Ok((rx, tx, decoded_key)) => {
                                *bytes_in.write().await += rx;
                                *bytes_out.write().await += tx;
                                if let Some(key) = decoded_key {
                                    let mut counts = decoded_model_routes.write().await;
                                    *counts.entry(key).or_insert(0) += 1;
                                }
                            }
                            Err(e) => {
                                warn!("Connection error: {}", e);
                                *errors.write().await += 1;
                            }
                        }

                        // Remove from active connections
                        active_conns.write().await.remove(&conn_id);
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                    *self.errors.write().await += 1;
                }
            }
        }
    }

    /// Get proxy server statistics
    pub async fn get_stats(&self) -> IntegratedProxyStats {
        let active_conns = self.active_connections.read().await;
        let total_conns = *self.total_connections.read().await;
        let bytes_in = *self.bytes_in.read().await;
        let bytes_out = *self.bytes_out.read().await;
        let errors = *self.errors.read().await;
        let decoded_model_routes = self.decoded_model_routes.read().await.clone();

        IntegratedProxyStats {
            uptime_secs: self.start_time.elapsed().as_secs(),
            connections: ConnectionStats {
                total_connections: total_conns,
                active_connections: active_conns.len() as u64,
                bytes_in,
                bytes_out,
                errors,
            },
            health_status: "healthy".to_string(),
            decoded_model_routes,
        }
    }
}

/// Handle individual TCP connections
async fn handle_connection(
    mut stream: TcpStream,
    _timeout_secs: u64,
) -> Result<(u64, u64, Option<String>), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0u8; 4096];
    let mut bytes_in = 0u64;
    let mut bytes_out = 0u64;
    let mut decoded_key: Option<String> = None;

    // Read initial data
    match stream.read(&mut buffer).await {
        Ok(n) => {
            bytes_in += n as u64;
            if let Some(decoded) = classify_http_request_prefix(&buffer[..n]) {
                let key = format!(
                    "{:?}/{:?}/{:?}/{:?}",
                    decoded.family, decoded.template, decoded.action, decoded.default_mux
                );
                info!(
                    "🧭 facade decode {} path={} host={:?} confidence={}",
                    key, decoded.path, decoded.host, decoded.confidence
                );
                decoded_key = Some(key);
            }

            // Simple echo response for testing
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK\r\n";
            if let Err(e) = stream.write_all(response).await {
                return Err(format!("Write error: {}", e));
            }
            bytes_out += response.len() as u64;
        }
        Err(e) => {
            return Err(format!("Read error: {}", e));
        }
    }

    Ok((bytes_in, bytes_out, decoded_key))
}

/// Proxy server errors
#[derive(Debug)]
pub enum IntegratedProxyError {
    BindFailed(String),
    ConnectionFailed(String),
    Timeout,
    Other(String),
}

impl std::fmt::Display for IntegratedProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegratedProxyError::BindFailed(msg) => write!(f, "Bind failed: {}", msg),
            IntegratedProxyError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            IntegratedProxyError::Timeout => write!(f, "Connection timed out"),
            IntegratedProxyError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for IntegratedProxyError {}
