// LiteBike channel management — standalone, no literbike dependency

use crate::proxy_config::KnoxProxyConfig;
use tokio::net::TcpStream;
use std::collections::HashMap;

/// Minimal channel abstraction (ported from Kotlin AbstractChannelProvider)
pub trait AbstractChannelProvider: Send + Sync {
    fn open_channel(&self, name: &str) -> bool;
}

/// Channel type for routing decisions
#[derive(Debug, Clone, PartialEq)]
pub enum ChannelType {
    Knox,
    Direct,
    Proxy,
}

/// Proxy channel backed by Knox config
pub struct ProxyChannel {
    pub config: KnoxProxyConfig,
}

impl ProxyChannel {
    pub fn with_knox_config(config: KnoxProxyConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
pub trait ChannelProvider: Send + Sync {
    async fn handle_connection(&self, stream: TcpStream, name: &str) -> Result<(), String>;
    fn open_channel(&self, name: &str) -> bool;
}

#[async_trait::async_trait]
impl ChannelProvider for ProxyChannel {
    async fn handle_connection(&self, _stream: TcpStream, _name: &str) -> Result<(), String> {
        Ok(())
    }
    fn open_channel(&self, _name: &str) -> bool {
        true
    }
}

/// Manages named proxy channels
pub struct ChannelManager {
    pub channels: HashMap<String, Box<dyn ChannelProvider>>,
    active: HashMap<String, ChannelType>,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            active: HashMap::new(),
        }
    }

    pub fn register_channel(&mut self, name: String, provider: Box<dyn ChannelProvider>) {
        self.channels.insert(name, provider);
    }

    pub async fn open_channel(&mut self, name: &str, channel_type: ChannelType) -> Result<(), String> {
        if self.channels.contains_key(name) {
            self.active.insert(name.to_string(), channel_type);
            Ok(())
        } else {
            Err(format!("Channel '{}' not registered", name))
        }
    }

    pub fn list_active_channels(&self) -> Vec<(String, ChannelType)> {
        self.active.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}
