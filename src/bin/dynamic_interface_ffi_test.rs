// Dynamic Interface FFI Test - Enumerate and bind to unknown interfaces
// Uses getifaddrs() to discover interfaces, then tests binding to each one

use std::io;
use std::os::raw::{c_int, c_void};
use std::mem;
use std::ptr;
use std::ffi::CStr;
use libc::{
    socket, bind, listen, accept, recv, close, setsockopt,
    AF_INET, SOCK_STREAM, MSG_PEEK, sockaddr_in, sockaddr, 
    SOL_SOCKET, SO_REUSEADDR,
    getifaddrs, freeifaddrs, ifaddrs, IFF_UP, IFF_RUNNING, IFF_LOOPBACK
};

fn main() -> io::Result<()> {
    println!("🔧 Dynamic Interface FFI Test - Discover and bind to unknown interfaces");
    
    test_interface_enumeration_and_binding()?;
    
    println!("✅ Dynamic interface test completed");
    Ok(())
}

fn test_interface_enumeration_and_binding() -> io::Result<()> {
    println!("\n📡 Enumerating all network interfaces...");
    
    let interfaces = get_all_interfaces()?;
    
    if interfaces.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No interfaces found"));
    }
    
    println!("✓ Found {} interfaces", interfaces.len());
    for (i, iface) in interfaces.iter().enumerate() {
        println!("  {}: {} -> {}", i + 1, iface.name, iface.ip);
    }
    
    // Test binding to each suitable interface (avoid system/debug interfaces)
    let mut successful_binds = 0;
    
    for iface in &interfaces {
        if should_skip_interface(&iface.name) {
            println!("⏭ Skipping system/debug interface: {}", iface.name);
        } else if iface.is_loopback {
            println!("⏭ Skipping loopback interface: {}", iface.name);
        } else {
            println!("\n🔧 Testing bind to interface: {} ({})", iface.name, iface.ip);
            match test_bind_to_interface(iface) {
                Ok(_) => {
                    successful_binds += 1;
                    println!("✅ Successfully bound to {}", iface.name);
                }
                Err(e) => {
                    println!("⚠ Failed to bind to {}: {}", iface.name, e);
                }
            }
        }
    }
    
    if successful_binds > 0 {
        println!("\n✅ Successfully bound to {} interfaces", successful_binds);
    } else {
        println!("\n⚠ Could not bind to any non-loopback interfaces");
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

fn get_all_interfaces() -> io::Result<Vec<NetworkInterface>> {
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

fn test_bind_to_interface(iface: &NetworkInterface) -> io::Result<()> {
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
        
        let ip_u32 = ((ip_bytes[0] as u32) << 0) |   // Little endian for network order
                     ((ip_bytes[1] as u32) << 8) | 
                     ((ip_bytes[2] as u32) << 16) | 
                     ((ip_bytes[3] as u32) << 24);
        
        // Bind to discovered interface on port 9999
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = ip_u32; // Already in network order
        addr.sin_port = (9999u16).to_be(); // Port 9999 in network byte order
        
        if bind(socket_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        // Listen briefly to verify bind worked
        if listen(socket_fd, 1) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        println!("   ✓ Bound to {}:9999 successfully", iface.ip);
        
        // Test non-blocking accept to see if we can accept connections
        libc::fcntl(socket_fd, libc::F_SETFL, libc::O_NONBLOCK);
        
        // Try to accept (will fail with EAGAIN if no connections, which is fine)
        let connection_fd = accept(socket_fd, ptr::null_mut(), ptr::null_mut());
        if connection_fd >= 0 {
            println!("   ✓ Unexpected connection received - testing micromethod");
            test_micromethod_on_connection(connection_fd)?;
            close(connection_fd);
        }
        
        close(socket_fd);
    }
    
    Ok(())
}

fn test_micromethod_on_connection(connection_fd: c_int) -> io::Result<()> {
    println!("🔍 Testing micromethod on discovered interface connection...");
    
    unsafe {
        // Wait briefly for data
        std::thread::sleep(std::time::Duration::from_millis(50));
        
        // Single-byte peek micromethod
        let mut buffer = [0u8; 1];
        let result = recv(
            connection_fd,
            buffer.as_mut_ptr() as *mut c_void,
            1,
            MSG_PEEK
        );
        
        if result <= 0 {
            println!("   ℹ️ No data for micromethod test");
            return Ok(());
        }
        
        println!("   ✅ Micromethod peek: {} bytes", result);
        println!("   First byte: 0x{:02x} ('{}')", 
                 buffer[0], 
                 if buffer[0].is_ascii_graphic() { buffer[0] as char } else { '?' });
        
        // Protocol detection
        let protocol = match buffer[0] {
            0x05 => "SOCKS5",
            b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => "HTTP",
            0x16 => "TLS",
            _ => "Unknown"
        };
        
        println!("   ✅ Protocol detected: {}", protocol);
    }
    
    Ok(())
}

fn should_skip_interface(name: &str) -> bool {
    // Filter out system, debug, and virtual interfaces that shouldn't be used for binding
    let skip_prefixes = [
        "proc", "sys", "debug", "dummy", "teql", "tunl", "sit", "ip6tnl",
        "ip6gre", "ip_vti", "ip6_vti", "nlmon", "bond", "team", "bridge",
        "vlan", "macvlan", "ipvlan", "vxlan", "geneve", "gre", "vti",
        "vcan", "veth", "tun", "tap"
    ];
    
    let skip_exact = [
        "any", "none", "null"
    ];
    
    // Check prefixes
    for prefix in &skip_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }
    
    // Check exact matches
    for exact in &skip_exact {
        if name == *exact {
            return true;
        }
    }
    
    // Skip interfaces with numbers that look like debug/test interfaces
    if name.starts_with("test") || name.starts_with("debug") {
        return true;
    }
    
    false
}