use std::collections::HashMap;
use std::sync::Arc;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use log::{debug, info, warn};
use async_trait::async_trait;

use crate::universal_listener::PrefixedStream;

/// Represents the result of a protocol detection attempt.
#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult {
    pub protocol_name: String,
    pub confidence: u8,  // 0-255, higher is more confident
    pub bytes_consumed: usize,
    pub metadata: Option<String>,
}

impl ProtocolDetectionResult {
    pub fn new(protocol_name: &str, confidence: u8, bytes_consumed: usize) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            confidence,
            bytes_consumed,
            metadata: None,
        }
    }

    pub fn unknown() -> Self {
        Self {
            protocol_name: "unknown".to_string(),
            confidence: 0,
            bytes_consumed: 0,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Trait for protocol detectors.
#[async_trait]
pub trait ProtocolDetector: Send + Sync {
    /// Detect protocol from initial bytes
    fn detect(&self, data: &[u8]) -> ProtocolDetectionResult;
    /// Minimum bytes required for a meaningful detection
    fn required_bytes(&self) -> usize;
    /// Minimum confidence level for a positive detection
    fn confidence_threshold(&self) -> u8;
    /// Name of the protocol this detector handles
    fn protocol_name(&self) -> &str;
}

/// Trait for protocol handlers.
#[async_trait]
pub trait ProtocolHandler: Send + Sync {
    /// Handle a connection using this protocol
    async fn handle(&self, stream: PrefixedStream<TcpStream>) -> io::Result<()>;
    /// Check if this handler can process a given detection result
    fn can_handle(&self, detection: &ProtocolDetectionResult) -> bool;
    /// Name of the protocol this handler handles
    fn protocol_name(&self) -> &str;
}

/// Entry in the protocol registry.
pub struct ProtocolEntry {
    pub detector: Box<dyn ProtocolDetector>,
    pub handler: Box<dyn ProtocolHandler>,
    pub priority: u8,  // Higher priority = checked first
}

/// Registry for managing protocol detectors and handlers.
pub struct ProtocolRegistry {
    entries: Vec<ProtocolEntry>,
    fallback_handler: Option<Box<dyn ProtocolHandler>>,
    max_detection_bytes: usize,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            fallback_handler: None,
            max_detection_bytes: 2048, // Default to 2KB for initial detection
        }
    }

    /// Register a new protocol detector and handler.
    pub fn register(&mut self, detector: Box<dyn ProtocolDetector>, handler: Box<dyn ProtocolHandler>, priority: u8) {
        self.entries.push(ProtocolEntry { detector, handler, priority });
        // Sort by priority (descending) so higher priority protocols are checked first
        self.entries.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Set a fallback handler for unknown protocols.
    pub fn set_fallback(&mut self, handler: Box<dyn ProtocolHandler>) {
        self.fallback_handler = Some(handler);
    }

    /// Set the maximum number of bytes to use for initial protocol detection.
    pub fn set_max_detection_bytes(&mut self, bytes: usize) {
        self.max_detection_bytes = bytes;
    }

    /// Handle an incoming connection by detecting its protocol and dispatching to the appropriate handler.
    pub async fn handle_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(self.max_detection_bytes);
        let mut bytes_read = 0;

        // Read enough bytes for initial detection
        loop {
            let mut chunk = vec![0u8; 512]; // Read in small chunks
            let n = stream.peek(&mut chunk).await?;
            if n == 0 { break; } // No more data

            buffer.extend_from_slice(&chunk[..n]);
            bytes_read += n;

            if bytes_read >= self.max_detection_bytes { break; }
        }

        let mut best_detection: Option<ProtocolDetectionResult> = None;

        for entry in &self.entries {
            if buffer.len() >= entry.detector.required_bytes() {
                let detection = entry.detector.detect(&buffer);
                if detection.confidence >= entry.detector.confidence_threshold() {
                    // Found a confident detection
                    if best_detection.is_none() || detection.confidence > best_detection.as_ref().unwrap().confidence {
                        best_detection = Some(detection);
                    }
                }
            }
        }

        let (protocol_name, bytes_consumed) = if let Some(detection) = best_detection {
            info!("Detected protocol: {} (confidence: {}, bytes: {})", 
                  detection.protocol_name, detection.confidence, detection.bytes_consumed);
            (detection.protocol_name, detection.bytes_consumed)
        } else {
            info!("No confident protocol detected, falling back if available.");
            ("unknown".to_string(), 0)
        };

        let mut prefixed_stream = PrefixedStream::new(stream, buffer);
        // PrefixedStream handles consumed bytes automatically

        for entry in &self.entries {
            if entry.handler.protocol_name() == protocol_name {
                info!("Dispatching to {} handler.", protocol_name);
                return entry.handler.handle(prefixed_stream).await;
            }
        }

        if let Some(handler) = &self.fallback_handler {
            info!("Dispatching to fallback handler.");
            return handler.handle(prefixed_stream).await;
        }

        warn!("No handler found for protocol: {}. Closing connection.", protocol_name);
        Err(io::Error::new(io::ErrorKind::Other, format!("No handler for protocol: {}", protocol_name)))
    }

    /// Get statistics about the protocol registry.
    pub fn get_stats(&self) -> ProtocolRegistryStats {
        ProtocolRegistryStats {
            registered_protocols: self.entries.len(),
            max_detection_bytes: self.max_detection_bytes,
            has_fallback_handler: self.fallback_handler.is_some(),
        }
    }
}

/// Statistics about the protocol registry.
#[derive(Debug, Default)]
pub struct ProtocolRegistryStats {
    pub registered_protocols: usize,
    pub max_detection_bytes: usize,
    pub has_fallback_handler: bool,
}

/// Convenience function to create a shared protocol registry.
pub fn create_shared_registry() -> Arc<ProtocolRegistry> {
    Arc::new(ProtocolRegistry::new())
}
