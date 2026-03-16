use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Http = 0x01,
    Https = 0x02,
    Socks5 = 0x03,
    Connect = 0x04,
    Doh = 0x05,
    Upnp = 0x06,
    Bonjour = 0x07,
    Shadowsocks = 0x08,
    Tls = 0x09,
    Udp = 0x0A,
    Tcp = 0x0B,
    Pac = 0x0C,
    WebRtc = 0x0D,
    Quic = 0x0E,
    Ssh = 0x0F,
    Ftp = 0x10,
    Smtp = 0x11,
    Pop3 = 0x12,
    Imap = 0x13,
    Irc = 0x14,
    Xmpp = 0x15,
    Mqtt = 0x16,
    Websocket = 0x17,
    H2c = 0x18,
    Rtsp = 0x19,
    Sip = 0x1A,
    Dns = 0x1B,
    Dhcp = 0x1C,
    Snmp = 0x1D,
    Ntp = 0x1E,
    Ldap = 0x1F,
    Kerberos = 0x20,
    Radius = 0x21,
    Syslog = 0x22,
    Telnet = 0x23,
    Rlogin = 0x24,
    Vnc = 0x25,
    Rdp = 0x26,
    X11 = 0x27,
    Smb = 0x28,
    Nfs = 0x29,
    Tftp = 0x2A,
    BitTorrent = 0x2B,
    Gnutella = 0x2C,
    Kazaa = 0x2D,
    Skype = 0x2E,
    TeamViewer = 0x2F,
    Tor = 0x30,
    I2p = 0x31,
    Onion = 0x32,
    Freenet = 0x33,
    Raw = 0xFF,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get = 0x01,
    Post = 0x02,
    Put = 0x03,
    Delete = 0x04,
    Head = 0x05,
    Options = 0x06,
    Connect = 0x07,
    Trace = 0x08,
    Patch = 0x09,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowsocksMethod {
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Aes128Gcm,
    Aes192Gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpnpAction {
    Search,
    Notify,
    Subscribe,
    Unsubscribe,
    AddPortMapping,
    DeletePortMapping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddress {
    Ipv4 { addr: Ipv4Addr, port: u16 },
    Ipv6 { addr: Ipv6Addr, port: u16 },
    Domain { host: String, port: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle = 0x00,
    Handshaking = 0x01,
    Authenticating = 0x02,
    ProtocolDetection = 0x03,
    Connected = 0x04,
    Relaying = 0x05,
    Closing = 0x06,
    Closed = 0x07,
    Error = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UsernamePassword = 0x02,
    NoAcceptable = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitFlags(pub u8);

impl BitFlags {
    pub const NONE: BitFlags = BitFlags(0x00);
    pub const KEEP_ALIVE: BitFlags = BitFlags(0x01);  
    pub const CLOSE: BitFlags = BitFlags(0x02);
    pub const UPGRADE: BitFlags = BitFlags(0x04);
    pub const CHUNKED: BitFlags = BitFlags(0x08);
    pub const GZIP: BitFlags = BitFlags(0x10);
    pub const DEFLATE: BitFlags = BitFlags(0x20);
    pub const ENCRYPTED: BitFlags = BitFlags(0x40);
    pub const AUTHENTICATED: BitFlags = BitFlags(0x80);

    pub fn has_flag(self, flag: BitFlags) -> bool {
        (self.0 & flag.0) != 0
    }

    pub fn set_flag(&mut self, flag: BitFlags) {
        self.0 |= flag.0;
    }

    pub fn clear_flag(&mut self, flag: BitFlags) {
        self.0 &= !flag.0;
    }

    pub fn toggle_flag(&mut self, flag: BitFlags) {
        self.0 ^= flag.0;
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult {
    pub protocol: ProtocolType,
    pub confidence: u8,
    pub flags: BitFlags,
    pub metadata: Option<Vec<u8>>,
}

impl Display for ProtocolType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "HTTP"),
            ProtocolType::Https => write!(f, "HTTPS"),
            ProtocolType::Socks5 => write!(f, "SOCKS5"),
            ProtocolType::Connect => write!(f, "CONNECT"),
            ProtocolType::Doh => write!(f, "DoH"),
            ProtocolType::Upnp => write!(f, "UPnP"),
            ProtocolType::Bonjour => write!(f, "Bonjour"),
            ProtocolType::Shadowsocks => write!(f, "Shadowsocks"),
            ProtocolType::Tls => write!(f, "TLS"),
            ProtocolType::Udp => write!(f, "UDP"),
            ProtocolType::Tcp => write!(f, "TCP"),
            ProtocolType::Pac => write!(f, "PAC"),
            ProtocolType::WebRtc => write!(f, "WebRTC"),
            ProtocolType::Quic => write!(f, "QUIC"),
            ProtocolType::Ssh => write!(f, "SSH"),
            ProtocolType::Ftp => write!(f, "FTP"),
            ProtocolType::Smtp => write!(f, "SMTP"),
            ProtocolType::Pop3 => write!(f, "POP3"),
            ProtocolType::Imap => write!(f, "IMAP"),
            ProtocolType::Irc => write!(f, "IRC"),
            ProtocolType::Xmpp => write!(f, "XMPP"),
            ProtocolType::Mqtt => write!(f, "MQTT"),
            ProtocolType::Websocket => write!(f, "WebSocket"),
            ProtocolType::H2c => write!(f, "HTTP/2"),
            ProtocolType::Rtsp => write!(f, "RTSP"),
            ProtocolType::Sip => write!(f, "SIP"),
            ProtocolType::Dns => write!(f, "DNS"),
            ProtocolType::Dhcp => write!(f, "DHCP"),
            ProtocolType::Snmp => write!(f, "SNMP"),
            ProtocolType::Ntp => write!(f, "NTP"),
            ProtocolType::Ldap => write!(f, "LDAP"),
            ProtocolType::Kerberos => write!(f, "Kerberos"),
            ProtocolType::Radius => write!(f, "RADIUS"),
            ProtocolType::Syslog => write!(f, "Syslog"),
            ProtocolType::Telnet => write!(f, "Telnet"),
            ProtocolType::Rlogin => write!(f, "Rlogin"),
            ProtocolType::Vnc => write!(f, "VNC"),
            ProtocolType::Rdp => write!(f, "RDP"),
            ProtocolType::X11 => write!(f, "X11"),
            ProtocolType::Smb => write!(f, "SMB"),
            ProtocolType::Nfs => write!(f, "NFS"),
            ProtocolType::Tftp => write!(f, "TFTP"),
            ProtocolType::BitTorrent => write!(f, "BitTorrent"),
            ProtocolType::Gnutella => write!(f, "Gnutella"),
            ProtocolType::Kazaa => write!(f, "Kazaa"),
            ProtocolType::Skype => write!(f, "Skype"),
            ProtocolType::TeamViewer => write!(f, "TeamViewer"),
            ProtocolType::Tor => write!(f, "Tor"),
            ProtocolType::I2p => write!(f, "I2P"),
            ProtocolType::Onion => write!(f, "Onion"),
            ProtocolType::Freenet => write!(f, "Freenet"),
            ProtocolType::Raw => write!(f, "RAW"),
        }
    }
}


impl TargetAddress {
    pub fn new(host: &str, port: u16) -> Self {
        if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
            Self::Ipv4 { addr: ipv4, port }
        } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
            Self::Ipv6 { addr: ipv6, port }
        } else {
            Self::Domain { host: host.to_string(), port }
        }
    }

    pub fn to_socket_addr(&self, resolved_ip: Option<IpAddr>) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 { addr, port } => Some(SocketAddr::new(IpAddr::V4(*addr), *port)),
            Self::Ipv6 { addr, port } => Some(SocketAddr::new(IpAddr::V6(*addr), *port)),
            Self::Domain { port, .. } => resolved_ip.map(|ip| SocketAddr::new(ip, *port)),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4 { port, .. } | Self::Ipv6 { port, .. } | Self::Domain { port, .. } => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ipv4 { addr, .. } => addr.to_string(),
            Self::Ipv6 { addr, .. } => format!("[{}]", addr),
            Self::Domain { host, .. } => host.clone(),
        }
    }

    pub fn is_local_domain(&self) -> bool {
        match self {
            Self::Domain { host, .. } => host.ends_with(".local"),
            _ => false,
        }
    }
}

impl Display for TargetAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 { addr, port } => write!(f, "{}:{}", addr, port),
            Self::Ipv6 { addr, port } => write!(f, "[{}]:{}", addr, port),
            Self::Domain { host, port } => write!(f, "{}:{}", host, port),
        }
    }
}

impl ShadowsocksMethod {
    pub fn key_length(&self) -> usize {
        match self {
            ShadowsocksMethod::Aes128Gcm => 16,
            ShadowsocksMethod::Aes192Gcm => 24, 
            ShadowsocksMethod::Aes256Gcm => 32,
            ShadowsocksMethod::Chacha20IetfPoly1305 => 32,
        }
    }

    pub fn nonce_length(&self) -> usize {
        match self {
            ShadowsocksMethod::Aes128Gcm | 
            ShadowsocksMethod::Aes192Gcm | 
            ShadowsocksMethod::Aes256Gcm => 12,
            ShadowsocksMethod::Chacha20IetfPoly1305 => 12,
        }
    }
}

impl From<&str> for ShadowsocksMethod {
    fn from(method: &str) -> Self {
        match method.to_lowercase().as_str() {
            "aes-128-gcm" => ShadowsocksMethod::Aes128Gcm,
            "aes-192-gcm" => ShadowsocksMethod::Aes192Gcm,
            "aes-256-gcm" => ShadowsocksMethod::Aes256Gcm,
            "chacha20-ietf-poly1305" => ShadowsocksMethod::Chacha20IetfPoly1305,
            _ => ShadowsocksMethod::Aes256Gcm,
        }
    }
}

pub fn bitbang_u16(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

pub fn bitbang_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn unbang_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub fn unbang_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn extract_bits(value: u8, start: u8, length: u8) -> u8 {
    let mask = (1u8 << length) - 1;
    (value >> start) & mask
}

pub fn set_bits(value: u8, start: u8, length: u8, bits: u8) -> u8 {
    let mask = ((1u8 << length) - 1) << start;
    (value & !mask) | ((bits << start) & mask)
}

// Standard port definitions for auto-discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardPort {
    pub port: u16,
    pub protocol: &'static str,
    pub description: &'static str,
}

impl StandardPort {
    pub const HTTP: StandardPort = StandardPort { port: 80, protocol: "HTTP", description: "Web traffic" };
    pub const HTTPS: StandardPort = StandardPort { port: 443, protocol: "HTTPS", description: "Secure web traffic" };
    pub const SOCKS5: StandardPort = StandardPort { port: 1080, protocol: "SOCKS5", description: "SOCKS proxy" };
    pub const PAC: StandardPort = StandardPort { port: 8888, protocol: "PAC", description: "Proxy auto-config" };
}

/// Protocol flags for runtime protocol management
/// Replaces the old feature gate system with bit flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFlags(pub u64);

impl ProtocolFlags {
    // Core protocols - always enabled
    pub const HTTP: ProtocolFlags = ProtocolFlags(1 << 0);
    pub const HTTPS: ProtocolFlags = ProtocolFlags(1 << 1);
    pub const SOCKS5: ProtocolFlags = ProtocolFlags(1 << 2);
    pub const CONNECT: ProtocolFlags = ProtocolFlags(1 << 3);
    
    // Extended protocols - configurable
    pub const DOH: ProtocolFlags = ProtocolFlags(1 << 4);
    pub const UPNP: ProtocolFlags = ProtocolFlags(1 << 5);
    pub const BONJOUR: ProtocolFlags = ProtocolFlags(1 << 6);
    pub const PAC: ProtocolFlags = ProtocolFlags(1 << 7);
    pub const WPAD: ProtocolFlags = ProtocolFlags(1 << 8);
    pub const TLS: ProtocolFlags = ProtocolFlags(1 << 9);
    pub const WEBSOCKET: ProtocolFlags = ProtocolFlags(1 << 10);
    
    // Advanced protocols
    pub const SHADOWSOCKS: ProtocolFlags = ProtocolFlags(1 << 11);
    pub const SSH: ProtocolFlags = ProtocolFlags(1 << 12);
    pub const FTP: ProtocolFlags = ProtocolFlags(1 << 13);
    pub const SMTP: ProtocolFlags = ProtocolFlags(1 << 14);
    pub const IMAP: ProtocolFlags = ProtocolFlags(1 << 15);
    pub const DNS: ProtocolFlags = ProtocolFlags(1 << 16);
    pub const QUIC: ProtocolFlags = ProtocolFlags(1 << 17);
    
    // Network services
    pub const MDNS: ProtocolFlags = ProtocolFlags(1 << 18);
    pub const DHCP: ProtocolFlags = ProtocolFlags(1 << 19);
    pub const SNMP: ProtocolFlags = ProtocolFlags(1 << 20);
    pub const NTP: ProtocolFlags = ProtocolFlags(1 << 21);
    
    // Security protocols
    pub const TOR: ProtocolFlags = ProtocolFlags(1 << 22);
    pub const I2P: ProtocolFlags = ProtocolFlags(1 << 23);
    
    // Operating modes
    pub const POSIX_SOCKETS: ProtocolFlags = ProtocolFlags(1 << 60);
    pub const ADVANCED_NETWORKING: ProtocolFlags = ProtocolFlags(1 << 61);
    pub const AUTO_DISCOVERY: ProtocolFlags = ProtocolFlags(1 << 62);
    pub const UNIVERSAL_PORT: ProtocolFlags = ProtocolFlags(1 << 63);
    
    // Predefined configurations
    pub const BASIC: ProtocolFlags = ProtocolFlags(
        Self::HTTP.0 | Self::HTTPS.0 | Self::SOCKS5.0 | Self::CONNECT.0
    );
    
    pub const FULL: ProtocolFlags = ProtocolFlags(
        Self::BASIC.0 | Self::DOH.0 | Self::UPNP.0 | Self::BONJOUR.0 | 
        Self::PAC.0 | Self::WPAD.0 | Self::TLS.0 | Self::WEBSOCKET.0 |
        Self::AUTO_DISCOVERY.0 | Self::POSIX_SOCKETS.0 | Self::UNIVERSAL_PORT.0
    );
    
    pub const NONE: ProtocolFlags = ProtocolFlags(0);
    
    pub fn has_protocol(self, flag: ProtocolFlags) -> bool {
        (self.0 & flag.0) != 0
    }
    
    pub fn enable_protocol(&mut self, flag: ProtocolFlags) {
        self.0 |= flag.0;
    }
    
    pub fn disable_protocol(&mut self, flag: ProtocolFlags) {
        self.0 &= !flag.0;
    }
    
    pub fn toggle_protocol(&mut self, flag: ProtocolFlags) {
        self.0 ^= flag.0;
    }
    
    pub fn count_enabled_protocols(self) -> u32 {
        self.0.count_ones()
    }
    
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    
    pub fn enabled_protocols(self) -> Vec<&'static str> {
        let mut protocols = Vec::new();
        
        if self.has_protocol(Self::HTTP) { protocols.push("HTTP"); }
        if self.has_protocol(Self::HTTPS) { protocols.push("HTTPS"); }
        if self.has_protocol(Self::SOCKS5) { protocols.push("SOCKS5"); }
        if self.has_protocol(Self::CONNECT) { protocols.push("CONNECT"); }
        if self.has_protocol(Self::DOH) { protocols.push("DoH"); }
        if self.has_protocol(Self::UPNP) { protocols.push("UPnP"); }
        if self.has_protocol(Self::BONJOUR) { protocols.push("Bonjour"); }
        if self.has_protocol(Self::PAC) { protocols.push("PAC"); }
        if self.has_protocol(Self::WPAD) { protocols.push("WPAD"); }
        if self.has_protocol(Self::TLS) { protocols.push("TLS"); }
        if self.has_protocol(Self::WEBSOCKET) { protocols.push("WebSocket"); }
        if self.has_protocol(Self::SHADOWSOCKS) { protocols.push("Shadowsocks"); }
        if self.has_protocol(Self::SSH) { protocols.push("SSH"); }
        if self.has_protocol(Self::FTP) { protocols.push("FTP"); }
        if self.has_protocol(Self::SMTP) { protocols.push("SMTP"); }
        if self.has_protocol(Self::IMAP) { protocols.push("IMAP"); }
        if self.has_protocol(Self::DNS) { protocols.push("DNS"); }
        if self.has_protocol(Self::QUIC) { protocols.push("QUIC"); }
        if self.has_protocol(Self::MDNS) { protocols.push("mDNS"); }
        if self.has_protocol(Self::DHCP) { protocols.push("DHCP"); }
        if self.has_protocol(Self::SNMP) { protocols.push("SNMP"); }
        if self.has_protocol(Self::NTP) { protocols.push("NTP"); }
        if self.has_protocol(Self::TOR) { protocols.push("Tor"); }
        if self.has_protocol(Self::I2P) { protocols.push("I2P"); }
        
        // Operating modes
        if self.has_protocol(Self::POSIX_SOCKETS) { protocols.push("POSIX-Sockets"); }
        if self.has_protocol(Self::ADVANCED_NETWORKING) { protocols.push("Advanced-Networking"); }
        if self.has_protocol(Self::AUTO_DISCOVERY) { protocols.push("Auto-Discovery"); }
        if self.has_protocol(Self::UNIVERSAL_PORT) { protocols.push("Universal-Port"); }
        
        protocols
    }
}

impl Default for ProtocolFlags {
    fn default() -> Self {
        Self::FULL
    }
}

impl From<ProtocolType> for ProtocolFlags {
    fn from(protocol: ProtocolType) -> Self {
        match protocol {
            ProtocolType::Http => Self::HTTP,
            ProtocolType::Https => Self::HTTPS,
            ProtocolType::Socks5 => Self::SOCKS5,
            ProtocolType::Connect => Self::CONNECT,
            ProtocolType::Doh => Self::DOH,
            ProtocolType::Upnp => Self::UPNP,
            ProtocolType::Bonjour => Self::BONJOUR,
            ProtocolType::Pac => Self::PAC,
            ProtocolType::Tls => Self::TLS,
            ProtocolType::Websocket => Self::WEBSOCKET,
            ProtocolType::Shadowsocks => Self::SHADOWSOCKS,
            ProtocolType::Ssh => Self::SSH,
            ProtocolType::Ftp => Self::FTP,
            ProtocolType::Smtp => Self::SMTP,
            ProtocolType::Imap => Self::IMAP,
            ProtocolType::Dns => Self::DNS,
            ProtocolType::Quic => Self::QUIC,
            _ => Self::NONE,
        }
    }
}

impl Display for ProtocolFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let protocols = self.enabled_protocols();
        if protocols.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", protocols.join(" | "))
        }
    }
}