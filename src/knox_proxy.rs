#[derive(Debug, Clone)]
pub struct KnoxProxyConfig {
    pub enable_knox_bypass: bool,
    pub enable_tethering_bypass: bool,
    pub ttl_spoofing: u8,
}

impl Default for KnoxProxyConfig {
    fn default() -> Self {
        Self {
            enable_knox_bypass: false,
            enable_tethering_bypass: false,
            ttl_spoofing: 65,
        }
    }
}
