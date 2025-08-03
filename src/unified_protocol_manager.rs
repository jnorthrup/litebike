use std::sync::Arc;
use tokio::sync::RwLock;

use crate::protocol_registry::{ProtocolRegistry, ProtocolDetector, ProtocolHandler};
use crate::protocol_handlers::{HttpDetector, HttpHandler, Socks5Detector, Socks5Handler, TlsDetector, TlsHandler, DohDetector, DohHandler};

/// Manages the registration and handling of various network protocols.
pub struct UnifiedProtocolManager {
    registry: Arc<RwLock<ProtocolRegistry>>,
}

impl UnifiedProtocolManager {
    /// Create a new unified protocol manager with all core protocols registered
    pub async fn new() -> Self {
        let mut registry = ProtocolRegistry::new();

        // Register HTTP
        registry.register(
            Box::new(HttpDetector::new()),
            Box::new(HttpHandler::new()),
            100, // High priority
        );

        // Register SOCKS5
        registry.register(
            Box::new(Socks5Detector::new()),
            Box::new(Socks5Handler::new()),
            90, // High priority
        );

        // Register TLS
        registry.register(
            Box::new(TlsDetector::new()),
            Box::new(TlsHandler::new()),
            80, // Medium priority
        );

        // Register DoH
        
        registry.register(
            Box::new(DohDetector::new()),
            Box::new(DohHandler::new().await),
            110, // Higher priority than HTTP
        );

        Self {
            registry: Arc::new(RwLock::new(registry)),
        }
    }

    /// Create a new manager with custom configuration
    pub async fn with_config(config: UnifiedPortConfig) -> Self {
        let mut registry = ProtocolRegistry::new();
        registry.set_max_detection_bytes(config.max_detection_bytes);

        if config.enable_http {
            registry.register(
                Box::new(HttpDetector::new()),
                Box::new(HttpHandler::new()),
                100,
            );
        }

        if config.enable_socks5 {
            registry.register(
                Box::new(Socks5Detector::new()),
                Box::new(Socks5Handler::new()),
                90,
            );
        }

        if config.enable_tls {
            registry.register(
                Box::new(TlsDetector::new()),
                Box::new(TlsHandler::new()),
                80,
            );
        }

        
        if config.enable_doh {
            registry.register(
                Box::new(DohDetector::new()),
                Box::new(DohHandler::new().await),
                110,
            );
        }

        if config.enable_fallback {
            // Fallback to a generic HTTP handler if no other protocol is detected
            registry.set_fallback(Box::new(HttpHandler::new()));
        }

        Self {
            registry: Arc::new(RwLock::new(registry)),
        }
    }

    pub fn get_registry(&self) -> Arc<RwLock<ProtocolRegistry>> {
        self.registry.clone()
    }

    pub async fn get_stats(&self) -> crate::protocol_registry::ProtocolRegistryStats {
        let registry = self.registry.read().await;
        registry.get_stats()
    }

    pub async fn register_custom_protocol(
        &self,
        detector: Box<dyn ProtocolDetector>,
        handler: Box<dyn ProtocolHandler>,
        priority: u8,
    ) {
        let mut registry = self.registry.write().await;
        registry.register(detector, handler, priority);
    }
}

/// Configuration for the unified port manager.
pub struct UnifiedPortConfig {
    pub max_detection_bytes: usize,
    pub enable_fallback: bool,
    pub enable_doh: bool,
    pub enable_socks5: bool,
    pub enable_http: bool,
    pub enable_tls: bool,
}

impl Default for UnifiedPortConfig {
    fn default() -> Self {
        Self {
            max_detection_bytes: 2048,
            enable_fallback: true,
            enable_doh: true,
            enable_socks5: true,
            enable_http: true,
            enable_tls: true,
        }
    }
}