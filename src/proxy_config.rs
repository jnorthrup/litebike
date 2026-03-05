// KnoxProxyConfig - owned by litebike (proxy foundation)
// Mirrors literbike's knox_proxy::KnoxProxyConfig but lives here independently

/// Knox proxy configuration
#[derive(Debug, Clone)]
pub struct KnoxProxyConfig {
    pub bind_addr: String,
    pub socks_port: u16,
    pub enable_knox_bypass: bool,
    pub enable_tethering_bypass: bool,
    pub ttl_spoofing: u8,
    pub max_connections: usize,
    pub buffer_size: usize,
    pub tcp_fingerprint_enabled: bool,
    pub packet_fragmentation_enabled: bool,
    pub tls_fingerprint_enabled: bool,
}

impl Default for KnoxProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            socks_port: 1080,
            enable_knox_bypass: true,
            enable_tethering_bypass: true,
            ttl_spoofing: 64,
            max_connections: 100,
            buffer_size: 4096,
            tcp_fingerprint_enabled: true,
            packet_fragmentation_enabled: true,
            tls_fingerprint_enabled: true,
        }
    }
}
