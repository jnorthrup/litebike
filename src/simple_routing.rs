use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;
use std::io;
use log::{info, warn};
use crate::types::ProtocolFlags;

/// Configuration for a specific route/interface.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub interface: String,
    pub bind_ip: IpAddr,
    pub http_port: u16,
    pub socks_port: u16,
    pub protocol_flags: ProtocolFlags,
}

impl RouteConfig {
    pub fn new(interface: &str, bind_ip: IpAddr, http_port: u16, socks_port: u16, protocol_flags: ProtocolFlags) -> Self {
        Self {
            interface: interface.to_string(),
            bind_ip,
            http_port,
            socks_port,
            protocol_flags,
        }
    }
    
    /// Create a new route config from a list of protocol names
    pub fn new_from_protocols(interface: &str, bind_ip: IpAddr, http_port: u16, socks_port: u16, protocols: Vec<String>) -> Self {
        let mut flags = ProtocolFlags::NONE;
        
        for protocol in protocols {
            match protocol.to_lowercase().as_str() {
                "http" => flags.enable_protocol(ProtocolFlags::HTTP),
                "https" => flags.enable_protocol(ProtocolFlags::HTTPS),
                "socks5" => flags.enable_protocol(ProtocolFlags::SOCKS5),
                "connect" => flags.enable_protocol(ProtocolFlags::CONNECT),
                "doh" => flags.enable_protocol(ProtocolFlags::DOH),
                "upnp" => flags.enable_protocol(ProtocolFlags::UPNP),
                "bonjour" => flags.enable_protocol(ProtocolFlags::BONJOUR),
                "pac" => flags.enable_protocol(ProtocolFlags::PAC),
                "wpad" => flags.enable_protocol(ProtocolFlags::WPAD),
                "tls" => flags.enable_protocol(ProtocolFlags::TLS),
                "websocket" => flags.enable_protocol(ProtocolFlags::WEBSOCKET),
                "auto-discovery" => flags.enable_protocol(ProtocolFlags::AUTO_DISCOVERY),
                "posix-sockets" => flags.enable_protocol(ProtocolFlags::POSIX_SOCKETS),
                "universal-port" => flags.enable_protocol(ProtocolFlags::UNIVERSAL_PORT),
                _ => warn!("Unknown protocol: {}", protocol),
            }
        }
        
        Self::new(interface, bind_ip, http_port, socks_port, flags)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.bind_ip, self.http_port) // Assuming HTTP port is the primary bind
    }
}

/// Simple router that attempts to bind to specific interfaces.
pub struct SimpleRouter {
    primary_config: RouteConfig,
    fallback_config: RouteConfig,
}

impl SimpleRouter {
    pub fn new() -> Self {
        // Use the full protocol set for the monolithic build
        let protocol_flags = ProtocolFlags::FULL;

        // Primary: swlan0 (mobile data interface on Android)
        let primary = RouteConfig::new(
            "swlan0",
            "0.0.0.0".parse().unwrap(), // Bind to all for swlan0
            8888,
            8888,
            protocol_flags,
        );

        // Fallback: localhost
        let fallback = RouteConfig::new(
            "lo",
            "127.0.0.1".parse().unwrap(),
            8888,
            8888,
            protocol_flags,
        );

        Self {
            primary_config: primary,
            fallback_config: fallback,
        }
    }

    pub fn with_primary(primary: RouteConfig) -> Self {
        let mut router = Self::new();
        router.primary_config = primary;
        router
    }

    pub async fn bind_with_fallback(&self) -> io::Result<(TcpListener, &RouteConfig)> {
        // Try primary config first
        info!("Attempting to bind to primary interface: {} ({})", 
              self.primary_config.interface, self.primary_config.bind_ip);
        match TcpListener::bind(self.primary_config.socket_addr()).await {
            Ok(listener) => {
                info!("Successfully bound to primary interface.");
                Ok((listener, &self.primary_config))
            }
            Err(e) => {
                warn!("Failed to bind to primary interface ({}): {}. Falling back to {}.", 
                      self.primary_config.interface, e, self.fallback_config.interface);
                // Fallback to secondary config
                let listener = TcpListener::bind(self.fallback_config.socket_addr()).await?;
                info!("Successfully bound to fallback interface.");
                Ok((listener, &self.fallback_config))
            }
        }
    }

    pub fn primary_config(&self) -> &RouteConfig {
        &self.primary_config
    }

    pub fn fallback_config(&self) -> &RouteConfig {
        &self.fallback_config
    }
}

pub fn get_supported_protocols(config: &RouteConfig) -> Vec<&'static str> {
    config.protocol_flags.enabled_protocols()
}

pub fn supports_all_protocols(config: &RouteConfig) -> bool {
    config.protocol_flags.has_protocol(ProtocolFlags::HTTP) &&
    config.protocol_flags.has_protocol(ProtocolFlags::SOCKS5) &&
    config.protocol_flags.has_protocol(ProtocolFlags::TLS) &&
    config.protocol_flags.has_protocol(ProtocolFlags::DOH) &&
    config.protocol_flags.has_protocol(ProtocolFlags::PAC) &&
    config.protocol_flags.has_protocol(ProtocolFlags::WPAD) &&
    config.protocol_flags.has_protocol(ProtocolFlags::BONJOUR) &&
    config.protocol_flags.has_protocol(ProtocolFlags::UPNP)
}
