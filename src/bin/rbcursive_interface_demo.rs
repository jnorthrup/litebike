// RBCursive Interface Discovery Demo
// Shows dynamic interface discovery with basic protocol detection

use std::io;
use std::os::raw::c_void;
use std::mem;
use std::ptr;
use std::ffi::CStr;
use libc::{
    socket, bind, listen, close, setsockopt,
    AF_INET, SOCK_STREAM, sockaddr_in, sockaddr, 
    SOL_SOCKET, SO_REUSEADDR,
    getifaddrs, freeifaddrs, ifaddrs, IFF_UP, IFF_RUNNING, IFF_LOOPBACK
};

fn main() -> io::Result<()> {
    println!("🚀 RBCursive Interface Discovery Demo");
    println!("=====================================");
    
    // Step 1: Discover interfaces dynamically
    let interfaces = discover_network_interfaces()?;
    
    println!("\n📡 Discovered {} network interfaces:", interfaces.len());
    for (i, iface) in interfaces.iter().enumerate() {
        let status = if iface.is_loopback { "loopback" } else { "physical" };
        println!("  {}: {} -> {} ({})", i + 1, iface.name, iface.ip, status);
    }
    
    // Step 2: Filter interfaces for binding
    let bindable = filter_bindable_interfaces(&interfaces);
    
    println!("\n🔧 Found {} bindable interfaces:", bindable.len());
    for iface in &bindable {
        println!("  - {} ({})", iface.name, iface.ip);
    }
    
    // Step 3: Test binding to each interface
    let mut successful_binds = 0;
    
    for iface in &bindable {
        println!("\n🔌 Testing bind to {} ({})", iface.name, iface.ip);
        
        match test_interface_binding(iface) {
            Ok(port) => {
                successful_binds += 1;
                println!("  ✅ Successfully bound to {}:{}", iface.ip, port);
                
                // Step 4: Basic protocol detection demo
                demo_protocol_detection(iface, port);
            }
            Err(e) => {
                println!("  ❌ Failed to bind: {}", e);
            }
        }
    }
    
    println!("\n📊 Summary:");
    println!("  - Total interfaces: {}", interfaces.len());
    println!("  - Bindable interfaces: {}", bindable.len());
    println!("  - Successful binds: {}", successful_binds);
    
    if successful_binds > 0 {
        println!("\n✅ RBCursive interface discovery successful!");
        println!("   Ready for SIMD-accelerated protocol parsing");
    } else {
        println!("\n⚠  No interfaces could be bound to");
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
struct NetworkInterface {
    name: String,
    ip: String,
    is_loopback: bool,
    is_up: bool,
}

fn discover_network_interfaces() -> io::Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    
    unsafe {
        let mut ifaddrs_ptr: *mut ifaddrs = ptr::null_mut();
        
        if getifaddrs(&mut ifaddrs_ptr) != 0 {
            return Err(io::Error::last_os_error());
        }
        
        let mut current = ifaddrs_ptr;
        while !current.is_null() {
            let ifa = &*current;
            
            // Skip if no address or not IPv4
            if ifa.ifa_addr.is_null() {
                current = ifa.ifa_next;
                continue;
            }
            
            let addr_family = (*(ifa.ifa_addr as *const sockaddr_in)).sin_family;
            if addr_family != AF_INET as u16 {
                current = ifa.ifa_next;
                continue;
            }
            
            // Get interface name
            let name_cstr = CStr::from_ptr(ifa.ifa_name);
            let name = name_cstr.to_string_lossy().to_string();
            
            // Get IP address
            let sockaddr = ifa.ifa_addr as *const sockaddr_in;
            let ip_addr = (*sockaddr).sin_addr.s_addr;
            let ip = format!("{}.{}.{}.{}", 
                (ip_addr & 0xFF) as u8,
                ((ip_addr >> 8) & 0xFF) as u8,
                ((ip_addr >> 16) & 0xFF) as u8,
                ((ip_addr >> 24) & 0xFF) as u8
            );
            
            // Check interface flags
            let flags = ifa.ifa_flags;
            let is_up = (flags & IFF_UP as u32) != 0 && (flags & IFF_RUNNING as u32) != 0;
            let is_loopback = (flags & IFF_LOOPBACK as u32) != 0;
            
            if is_up {
                interfaces.push(NetworkInterface {
                    name,
                    ip,
                    is_loopback,
                    is_up,
                });
            }
            
            current = ifa.ifa_next;
        }
        
        freeifaddrs(ifaddrs_ptr);
    }
    
    Ok(interfaces)
}

fn filter_bindable_interfaces(interfaces: &[NetworkInterface]) -> Vec<NetworkInterface> {
    interfaces.iter()
        .filter(|iface| !iface.is_loopback && !should_skip_interface(&iface.name))
        .cloned()
        .collect()
}

fn should_skip_interface(name: &str) -> bool {
    // Filter out system, debug, and virtual interfaces
    let skip_prefixes = [
        "proc", "sys", "debug", "dummy", "teql", "tunl", "sit", "ip6tnl",
        "ip6gre", "ip_vti", "ip6_vti", "nlmon", "bond", "team", "bridge",
        "vlan", "macvlan", "ipvlan", "vxlan", "geneve", "gre", "vti",
        "vcan", "veth", "tun", "tap"
    ];
    
    // Check prefixes
    for prefix in &skip_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }
    
    // Skip test/debug interfaces
    name.starts_with("test") || name.starts_with("debug")
}

fn test_interface_binding(iface: &NetworkInterface) -> io::Result<u16> {
    unsafe {
        // Create socket
        let socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if socket_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Enable SO_REUSEADDR
        let opt_val: i32 = 1;
        if setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, 
                     &opt_val as *const _ as *const c_void, 
                     mem::size_of::<i32>() as u32) < 0 {
            close(socket_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Parse IP string to network byte order
        let ip_parts: Vec<&str> = iface.ip.split('.').collect();
        if ip_parts.len() != 4 {
            close(socket_fd);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IP format"));
        }
        
        let ip_bytes: Result<Vec<u8>, _> = ip_parts.iter().map(|s| s.parse::<u8>()).collect();
        let ip_bytes = match ip_bytes {
            Ok(bytes) => bytes,
            Err(_) => {
                close(socket_fd);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IP bytes"));
            }
        };
        
        let ip_u32 = ((ip_bytes[0] as u32) << 0) |
                     ((ip_bytes[1] as u32) << 8) | 
                     ((ip_bytes[2] as u32) << 16) | 
                     ((ip_bytes[3] as u32) << 24);
        
        // Bind to interface on port 0 (let OS choose)
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = ip_u32;
        addr.sin_port = 0; // Let OS choose port
        
        if bind(socket_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        // Get the actual port assigned
        let mut addr_len = mem::size_of::<sockaddr_in>() as u32;
        if libc::getsockname(socket_fd, &mut addr as *mut _ as *mut sockaddr, &mut addr_len) < 0 {
            close(socket_fd);
            return Err(io::Error::last_os_error());
        }
        
        let port = u16::from_be(addr.sin_port);
        
        // Test listen
        if listen(socket_fd, 1) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        close(socket_fd);
        Ok(port)
    }
}

fn demo_protocol_detection(iface: &NetworkInterface, port: u16) {
    println!("  🔍 Protocol detection demo for {}:{}", iface.ip, port);
    
    // Simulate different protocol data
    let protocols: Vec<(&str, &[u8])> = vec![
        ("HTTP GET", b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("HTTP POST", b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"),
        ("SOCKS5", b"\x05\x01\x00"),
        ("JSON", b"{\"proxy\": \"PROXY proxy.example.com:8080\"}"),
    ];
    
    for (name, data) in &protocols {
        let detected = detect_protocol_simple(data);
        println!("    - {}: {}", name, detected);
    }
}

fn detect_protocol_simple(data: &[u8]) -> &'static str {
    if data.len() >= 2 && data[0] == 0x05 {
        return "SOCKS5";
    }
    
    if data.starts_with(b"GET ") || data.starts_with(b"POST ") || 
       data.starts_with(b"PUT ") || data.starts_with(b"DELETE ") ||
       data.starts_with(b"HEAD ") || data.starts_with(b"OPTIONS ") ||
       data.starts_with(b"CONNECT ") || data.starts_with(b"PATCH ") {
        return "HTTP";
    }
    
    if data.starts_with(b"{") && data.contains(&b'"') {
        return "JSON";
    }
    
    "Unknown"
}