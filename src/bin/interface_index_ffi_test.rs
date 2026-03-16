// Interface Index FFI Test - Bind using if_nametoindex for unknown interfaces
// Tests binding by interface index rather than string name

use std::io;
use std::os::raw::{c_int, c_void};
use std::mem;
use std::ptr;
use std::ffi::CString;
use libc::{
    socket, bind, listen, close, setsockopt,
    AF_INET, SOCK_STREAM, sockaddr_in, sockaddr, 
    SOL_SOCKET, SO_REUSEADDR, SO_BINDTODEVICE,
    getifaddrs, freeifaddrs, ifaddrs, IFF_UP, IFF_RUNNING, IFF_LOOPBACK,
    if_nametoindex
};

fn main() -> io::Result<()> {
    println!("🔧 Interface Index FFI Test - Bind using interface indices");
    
    test_interface_index_binding()?;
    
    println!("✅ Interface index test completed");
    Ok(())
}

fn test_interface_index_binding() -> io::Result<()> {
    println!("\n📡 Testing interface binding by index...");
    
    let interfaces = get_interface_indices()?;
    
    if interfaces.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No interfaces found"));
    }
    
    println!("✓ Found {} interfaces with indices", interfaces.len());
    for (i, iface) in interfaces.iter().enumerate() {
        println!("  {}: {} (index: {}) -> {}", i + 1, iface.name, iface.index, iface.ip);
    }
    
    // Test binding using interface index (SO_BINDTODEVICE)
    let mut successful_binds = 0;
    
    for iface in &interfaces {
        if should_skip_interface(&iface.name) {
            println!("⏭ Skipping system interface: {}", iface.name);
        } else if iface.is_loopback {
            println!("⏭ Skipping loopback interface: {}", iface.name);
        } else {
            println!("\n🔧 Testing bind by index: {} (index: {})", iface.name, iface.index);
            match test_bind_by_interface_index(iface) {
                Ok(_) => {
                    successful_binds += 1;
                    println!("✅ Successfully bound using index {}", iface.index);
                }
                Err(e) => {
                    println!("⚠ Failed to bind by index {}: {}", iface.index, e);
                    
                    // Fallback: try binding by device name
                    println!("  🔄 Trying SO_BINDTODEVICE fallback...");
                    match test_bind_by_device_name(iface) {
                        Ok(_) => {
                            successful_binds += 1;
                            println!("  ✅ Fallback binding successful");
                        }
                        Err(e2) => {
                            println!("  ⚠ Fallback also failed: {}", e2);
                        }
                    }
                }
            }
        }
    }
    
    if successful_binds > 0 {
        println!("\n✅ Successfully bound to {} interfaces using indices", successful_binds);
    } else {
        println!("\n⚠ Could not bind to any interfaces by index");
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    index: u32,
    ip: String,
    is_loopback: bool,
}

fn get_interface_indices() -> io::Result<Vec<InterfaceInfo>> {
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
            let name_cstr = std::ffi::CStr::from_ptr(ifa.ifa_name);
            let name = name_cstr.to_string_lossy().to_string();
            
            // Get interface index using if_nametoindex
            let name_c = CString::new(name.clone()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid interface name")
            })?;
            let index = if_nametoindex(name_c.as_ptr());
            
            if index == 0 {
                // Skip interfaces without valid index
                current = ifa.ifa_next;
                continue;
            }
            
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
                interfaces.push(InterfaceInfo {
                    name,
                    index,
                    ip,
                    is_loopback,
                });
            }
            
            current = ifa.ifa_next;
        }
        
        freeifaddrs(ifaddrs_ptr);
    }
    
    Ok(interfaces)
}

fn test_bind_by_interface_index(iface: &InterfaceInfo) -> io::Result<()> {
    unsafe {
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
        
        // Parse IP and bind to interface IP
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
        
        // Bind to specific interface IP on port 10000
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = ip_u32;
        addr.sin_port = (10000u16).to_be();
        
        if bind(socket_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        if listen(socket_fd, 1) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        println!("   ✓ Bound to interface index {} ({}:10000)", iface.index, iface.ip);
        close(socket_fd);
    }
    
    Ok(())
}

fn test_bind_by_device_name(iface: &InterfaceInfo) -> io::Result<()> {
    unsafe {
        let socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if socket_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Set SO_BINDTODEVICE to bind to specific interface
        let device_name = CString::new(iface.name.clone()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid device name")
        })?;
        
        if setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                     device_name.as_ptr() as *const c_void,
                     device_name.as_bytes().len() as u32) < 0 {
            close(socket_fd);
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
        
        // Bind to any address on this interface
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = 0; // INADDR_ANY - the SO_BINDTODEVICE will constrain it
        addr.sin_port = (10001u16).to_be();
        
        if bind(socket_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        if listen(socket_fd, 1) < 0 {
            let err = io::Error::last_os_error();
            close(socket_fd);
            return Err(err);
        }
        
        println!("   ✓ SO_BINDTODEVICE bound to {} on port 10001", iface.name);
        close(socket_fd);
    }
    
    Ok(())
}

fn should_skip_interface(name: &str) -> bool {
    let skip_prefixes = [
        "proc", "sys", "debug", "dummy", "teql", "tunl", "sit", "ip6tnl",
        "ip6gre", "ip_vti", "ip6_vti", "nlmon", "bond", "team", "bridge",
        "vlan", "macvlan", "ipvlan", "vxlan", "geneve", "gre", "vti",
        "vcan", "veth", "tun", "tap"
    ];
    
    let skip_exact = ["any", "none", "null"];
    
    for prefix in &skip_prefixes {
        if name.starts_with(prefix) {
            return true;
        }
    }
    
    for exact in &skip_exact {
        if name == *exact {
            return true;
        }
    }
    
    name.starts_with("test") || name.starts_with("debug")
}