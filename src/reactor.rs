// Perfect Channelized Reactor - The overdue first thing we built
// Implements discrete sequence execution with channelized event dispatch

use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use tokio::sync::{mpsc, oneshot};
use tokio::net::TcpStream;
use std::time::{Duration, Instant};

use crate::taxonomy::{
    WamBlock, SequenceId, SessionState,
    Protocol, mapping
};
use crate::rbcursive::RBCursive;

/// Channelized Reactor - Perfect event loop for WAM block execution
pub struct ChannelizedReactor {
    /// Protocol-specific channels for WAM block dispatch
    channels: HashMap<u8, ReactorChannel>,
    
    /// Event loop executor
    event_loop: Option<ReactorLoop>,
    
    /// Active sequence tracking
    active_sequences: Arc<AtomicUsize>,
    
    /// Reactor configuration
    config: ReactorConfig,
    
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    
    /// RBCursive instance for protocol detection
    rbcursive: RBCursive,
}

/// Reactor Channel - Type alias for WAM block message passing
pub type ReactorChannel = mpsc::UnboundedSender<ChannelMessage>;

/// Reactor Loop - Type alias for event processing function
pub type ReactorLoop = Box<dyn FnMut(ChannelMessage) -> Result<(), ReactorError> + Send>;

/// Channel Message - Protocol-agnostic message container
#[derive(Debug)]
pub struct ChannelMessage {
    pub sequence_id: SequenceId,
    pub wam_block: WamBlock,
    pub stream: Option<TcpStream>,
    pub response_tx: Option<oneshot::Sender<ChannelResponse>>,
    pub timestamp: Instant,
}

/// Channel Response - Response message for completed sequences
#[derive(Debug)]
pub struct ChannelResponse {
    pub sequence_id: SequenceId,
    pub result: Result<SessionState, ReactorError>,
    pub duration: Duration,
}

/// Reactor Configuration
#[derive(Debug, Clone)]
pub struct ReactorConfig {
    /// Maximum concurrent sequences
    pub max_sequences: usize,
    
    /// Channel buffer size per protocol
    pub channel_buffer_size: usize,
    
    /// Sequence timeout
    pub sequence_timeout: Duration,
    
    /// Enable sequence metrics
    pub enable_metrics: bool,
    
    /// Protocol priorities (lower number = higher priority)
    pub protocol_priorities: HashMap<u8, u8>,
}

impl Default for ReactorConfig {
    fn default() -> Self {
        let mut priorities = HashMap::new();
        priorities.insert(Protocol::Http as u8, 1);   // High priority
        priorities.insert(Protocol::Socks5 as u8, 1); // High priority
        priorities.insert(Protocol::Tls as u8, 2);    // Medium priority
        priorities.insert(Protocol::Dns as u8, 3);    // Low priority
        priorities.insert(Protocol::Json as u8, 4);   // Lowest priority
        
        Self {
            max_sequences: 1000,
            channel_buffer_size: 100,
            sequence_timeout: Duration::from_secs(30),
            enable_metrics: true,
            protocol_priorities: priorities,
        }
    }
}

/// Reactor Error Types
#[derive(Debug)]
pub enum ReactorError {
    SequenceLimitExceeded { current: usize, max: usize },
    ChannelNotFound { protocol_id: u8 },
    SequenceTimeout { sequence_id: SequenceId },
    TransformError { message: String },
    ProtocolDetectionFailed,
    ChannelSendError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for ReactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceLimitExceeded { current, max } => 
                write!(f, "Sequence limit exceeded: {}/{}", current, max),
            Self::ChannelNotFound { protocol_id } => 
                write!(f, "Protocol channel not found: {}", protocol_id),
            Self::SequenceTimeout { sequence_id } => 
                write!(f, "Sequence timeout: {}", sequence_id),
            Self::TransformError { message } => 
                write!(f, "Transform error: {}", message),
            Self::ProtocolDetectionFailed => 
                write!(f, "Protocol detection failed"),
            Self::ChannelSendError(msg) => 
                write!(f, "Channel send error: {}", msg),
            Self::IoError(err) => 
                write!(f, "IO error: {}", err),
        }
    }
}

impl std::error::Error for ReactorError {}

impl From<std::io::Error> for ReactorError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl ChannelizedReactor {
    /// Create new channelized reactor with default configuration
    pub fn new() -> Self {
        Self::with_config(ReactorConfig::default())
    }
    
    /// Create new channelized reactor with custom configuration
    pub fn with_config(config: ReactorConfig) -> Self {
        let mut channels = HashMap::new();
        
        // Create channels for all supported protocols
        for protocol_id in [
            Protocol::Http as u8,
            Protocol::Socks5 as u8,
            Protocol::Tls as u8,
            Protocol::Dns as u8,
            Protocol::Json as u8,
            Protocol::Http2 as u8,
            Protocol::WebSocket as u8,
        ] {
            let (tx, _rx) = mpsc::unbounded_channel();
            channels.insert(protocol_id, tx);
        }
        
        Self {
            channels,
            event_loop: None,
            active_sequences: Arc::new(AtomicUsize::new(0)),
            config,
            shutdown_tx: None,
            rbcursive: RBCursive::new(),
        }
    }
    
    /// Start the channelized reactor event loop
    pub async fn start(&mut self) -> Result<(), ReactorError> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);
        
        // Create receivers for all protocol channels
        let mut receivers = HashMap::new();
        let protocol_ids: Vec<u8> = self.channels.keys().cloned().collect();
        for protocol_id in protocol_ids {
            let (tx, rx) = mpsc::unbounded_channel();
            self.channels.insert(protocol_id, tx);
            receivers.insert(protocol_id, rx);
        }
        
        // Main event loop
        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = &mut shutdown_rx => {
                    println!("Channelized reactor shutting down");
                    break;
                }
                
                // Process messages from all protocol channels
                result = self.process_channel_messages(&mut receivers) => {
                    if let Err(e) = result {
                        eprintln!("Reactor error: {}", e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Process incoming channel messages from all protocols
    async fn process_channel_messages(
        &self,
        receivers: &mut HashMap<u8, mpsc::UnboundedReceiver<ChannelMessage>>
    ) -> Result<(), ReactorError> {
        // Process messages with priority ordering
        let mut priority_protocols: Vec<_> = self.config.protocol_priorities.iter()
            .map(|(protocol, priority)| (*protocol, *priority))
            .collect();
        priority_protocols.sort_by_key(|(_, priority)| *priority);
        
        for (protocol_id, _priority) in priority_protocols {
            if let Some(receiver) = receivers.get_mut(&protocol_id) {
                // Non-blocking receive to check for messages
                if let Ok(message) = receiver.try_recv() {
                    self.process_message(message).await?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Process individual channel message
    async fn process_message(&self, message: ChannelMessage) -> Result<(), ReactorError> {
        let start_time = Instant::now();
        
        // Check sequence limit
        let current_sequences = self.active_sequences.load(Ordering::Relaxed);
        if current_sequences >= self.config.max_sequences {
            return Err(ReactorError::SequenceLimitExceeded {
                current: current_sequences,
                max: self.config.max_sequences,
            });
        }
        
        self.active_sequences.fetch_add(1, Ordering::Relaxed);
        
        // Execute WAM block transformation
        let result = self.execute_wam_block(message.wam_block).await;
        
        self.active_sequences.fetch_sub(1, Ordering::Relaxed);
        
        // Send response if channel provided
        if let Some(response_tx) = message.response_tx {
            let response = ChannelResponse {
                sequence_id: message.sequence_id,
                result,
                duration: start_time.elapsed(),
            };
            
            if let Err(_) = response_tx.send(response) {
                // Response channel closed, ignore
            }
        }
        
        Ok(())
    }
    
    /// Execute WAM block transformation (pure function)
    async fn execute_wam_block(&self, wam_block: WamBlock) -> Result<SessionState, ReactorError> {
        // Apply transformation using WAM key (pure function)
        let transformed_state = wam_block.key.apply(&wam_block.element);
        
        // Handle continuation if present
        if let Some(next_sequence) = wam_block.next {
            // For now, just return the transformed state
            // In full implementation, this would chain to next sequence
            Ok(transformed_state)
        } else {
            Ok(transformed_state)
        }
    }
    
    /// Submit WAM block for processing
    pub async fn submit_wam_block(
        &self,
        wam_block: WamBlock,
        stream: Option<TcpStream>
    ) -> Result<oneshot::Receiver<ChannelResponse>, ReactorError> {
        let protocol_id = wam_block.element.protocol_spec;
        
        let channel = self.channels.get(&protocol_id)
            .ok_or_else(|| ReactorError::ChannelNotFound { protocol_id })?;
        
        let (response_tx, response_rx) = oneshot::channel();
        
        let message = ChannelMessage {
            sequence_id: wam_block.sequence_id,
            wam_block,
            stream,
            response_tx: Some(response_tx),
            timestamp: Instant::now(),
        };
        
        channel.send(message)
            .map_err(|e| ReactorError::ChannelSendError(e.to_string()))?;
        
        Ok(response_rx)
    }
    
    /// Process incoming TCP stream with protocol detection
    pub async fn process_stream(
        &self,
        mut stream: TcpStream,
        sequence_id: SequenceId
    ) -> Result<oneshot::Receiver<ChannelResponse>, ReactorError> {
        // Read initial data for protocol detection
        let mut buffer = vec![0u8; 512];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await?;
        
        if n == 0 {
            return Err(ReactorError::ProtocolDetectionFailed);
        }
        
        buffer.truncate(n);
        
        // Detect protocol using RBCursive
        let protocol = self.rbcursive.detect_protocol(&buffer);
        
        // Create WAM block from detected protocol
        let wam_block = mapping::create_wam_block(sequence_id, &protocol, buffer);
        
        // Submit for processing
        self.submit_wam_block(wam_block, Some(stream)).await
    }
    
    /// Get reactor metrics
    pub fn metrics(&self) -> ReactorMetrics {
        ReactorMetrics {
            active_sequences: self.active_sequences.load(Ordering::Relaxed),
            max_sequences: self.config.max_sequences,
            channel_count: self.channels.len(),
            protocol_priorities: self.config.protocol_priorities.clone(),
        }
    }
    
    /// Shutdown the reactor
    pub fn shutdown(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
    }
}

/// Reactor Metrics
#[derive(Debug, Clone)]
pub struct ReactorMetrics {
    pub active_sequences: usize,
    pub max_sequences: usize,
    pub channel_count: usize,
    pub protocol_priorities: HashMap<u8, u8>,
}

/// Reactor Builder - Fluent API for reactor configuration
pub struct ReactorBuilder {
    config: ReactorConfig,
}

impl ReactorBuilder {
    pub fn new() -> Self {
        Self {
            config: ReactorConfig::default(),
        }
    }
    
    pub fn max_sequences(mut self, max: usize) -> Self {
        self.config.max_sequences = max;
        self
    }
    
    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.config.channel_buffer_size = size;
        self
    }
    
    pub fn sequence_timeout(mut self, timeout: Duration) -> Self {
        self.config.sequence_timeout = timeout;
        self
    }
    
    pub fn enable_metrics(mut self, enabled: bool) -> Self {
        self.config.enable_metrics = enabled;
        self
    }
    
    pub fn protocol_priority(mut self, protocol: Protocol, priority: u8) -> Self {
        self.config.protocol_priorities.insert(protocol as u8, priority);
        self
    }
    
    pub fn build(self) -> ChannelizedReactor {
        ChannelizedReactor::with_config(self.config)
    }
}

impl Default for ChannelizedReactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience functions for common reactor operations

/// Create HTTP-focused reactor
pub fn create_http_reactor() -> ChannelizedReactor {
    ReactorBuilder::new()
        .protocol_priority(Protocol::Http, 1)
        .protocol_priority(Protocol::Tls, 2)
        .max_sequences(500)
        .build()
}

/// Create SOCKS5-focused reactor
pub fn create_socks5_reactor() -> ChannelizedReactor {
    ReactorBuilder::new()
        .protocol_priority(Protocol::Socks5, 1)
        .protocol_priority(Protocol::Http, 2)
        .max_sequences(1000)
        .build()
}

/// Create balanced protocol reactor
pub fn create_balanced_reactor() -> ChannelizedReactor {
    ReactorBuilder::new()
        .protocol_priority(Protocol::Http, 1)
        .protocol_priority(Protocol::Socks5, 1)
        .protocol_priority(Protocol::Tls, 2)
        .protocol_priority(Protocol::Dns, 3)
        .max_sequences(2000)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbcursive::HttpMethod;
    
    #[test]
    fn test_reactor_creation() {
        let reactor = ChannelizedReactor::new();
        assert_eq!(reactor.channels.len(), 7); // All supported protocols
        assert_eq!(reactor.active_sequences.load(Ordering::Relaxed), 0);
    }
    
    #[test]
    fn test_reactor_builder() {
        let reactor = ReactorBuilder::new()
            .max_sequences(100)
            .protocol_priority(Protocol::Http, 1)
            .build();
        
        assert_eq!(reactor.config.max_sequences, 100);
        assert_eq!(reactor.config.protocol_priorities[&(Protocol::Http as u8)], 1);
    }
    
    #[test]
    fn test_wam_block_execution() {
        let reactor = ChannelizedReactor::new();
        
        let session_state = SessionState::new(Protocol::Http as u8);
        let transform = TransformCode::HttpTransform(HttpMethod::Get);
        let wam_block = crate::taxonomy::DiscreteSequence::new(1, session_state, transform);
        
        // This would be an async test in full implementation
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let result = reactor.execute_wam_block(wam_block).await;
            assert!(result.is_ok());
        });
    }
    
    #[test]
    fn test_reactor_metrics() {
        let reactor = ChannelizedReactor::new();
        let metrics = reactor.metrics();
        
        assert_eq!(metrics.active_sequences, 0);
        assert_eq!(metrics.channel_count, 7);
        assert!(metrics.protocol_priorities.contains_key(&(Protocol::Http as u8)));
    }
    
    #[test]
    fn test_specialized_reactors() {
        let http_reactor = create_http_reactor();
        let socks5_reactor = create_socks5_reactor();
        let balanced_reactor = create_balanced_reactor();
        
        assert_eq!(http_reactor.config.max_sequences, 500);
        assert_eq!(socks5_reactor.config.max_sequences, 1000);
        assert_eq!(balanced_reactor.config.max_sequences, 2000);
    }
}