// Test binding directly to swlan0 interface using pure POSIX calls
// Verify the micromethod works on the actual target interface

use std::io;
use std::os::raw::c_void;
use std::mem;
use std::ptr;
use libc::{socket, bind, listen, accept, recv, send, close, setsockopt, AF_INET, SOCK_STREAM, MSG_PEEK, 
           sockaddr_in, sockaddr, SOL_SOCKET, SO_REUSEADDR, INADDR_ANY};

fn main() -> io::Result<()> {
    println!("🔧 Testing swlan0 Interface Binding with Micromethod");
    
    test_swlan0_binding()?;
    
    println!("✅ swlan0 binding test completed");
    Ok(())
}

fn test_swlan0_binding() -> io::Result<()> {
    println!("\n📡 Testing direct binding to swlan0 interface...");
    
    unsafe {
        // Create socket
        let server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if server_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Enable SO_REUSEADDR to avoid "Address already in use"
        let opt_val: i32 = 1;
        if setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, 
                     &opt_val as *const _ as *const c_void, 
                     mem::size_of::<i32>() as u32) < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Get swlan0 IP address using the proven ifconfig method
        let swlan0_ip = get_swlan0_ip()?;
        println!("✓ swlan0 IP detected: {}", swlan0_ip);
        
        // Parse IP string to u32
        let ip_parts: Vec<&str> = swlan0_ip.split('.').collect();
        if ip_parts.len() != 4 {
            close(server_fd);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IP format"));
        }
        
        let ip_bytes: Result<Vec<u8>, _> = ip_parts.iter().map(|s| s.parse::<u8>()).collect();
        let ip_bytes = match ip_bytes {
            Ok(bytes) => bytes,
            Err(_) => {
                close(server_fd);
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid IP bytes"));
            }
        };
        
        let ip_u32 = ((ip_bytes[0] as u32) << 24) | 
                     ((ip_bytes[1] as u32) << 16) | 
                     ((ip_bytes[2] as u32) << 8) | 
                     (ip_bytes[3] as u32);
        let ip_network_order = ip_u32.to_be(); // Convert to network byte order
        
        // Bind to swlan0 IP on port 8888 (the universal port)
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = ip_network_order;
        addr.sin_port = (8888u16).to_be(); // Port 8888 in network byte order
        
        if bind(server_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            let err = io::Error::last_os_error();
            close(server_fd);
            println!("❌ Failed to bind to {}:8888 - {}", swlan0_ip, err);
            return Err(err);
        }
        
        println!("✅ Successfully bound to {}:8888", swlan0_ip);
        
        // Listen
        if listen(server_fd, 5) < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("✅ Listening on swlan0:8888 for connections...");
        println!("   Test with: curl --proxy http://{}:8888 http://httpbin.org/ip", swlan0_ip);
        println!("   Or: curl --socks5 {}:8888 http://httpbin.org/ip", swlan0_ip);
        println!("   Waiting 5 seconds for connections...");
        
        // Wait for connection with timeout
        let mut connection_count = 0;
        for i in 0..50 { // 5 seconds total (50 * 100ms)
            // Non-blocking accept check
            libc::fcntl(server_fd, libc::F_SETFL, libc::O_NONBLOCK);
            
            let connection_fd = accept(server_fd, ptr::null_mut(), ptr::null_mut());
            if connection_fd >= 0 {
                connection_count += 1;
                println!("✅ Connection #{} accepted", connection_count);
                
                // Test micromethod on real connection
                test_micromethod_on_connection(connection_fd)?;
                
                close(connection_fd);
                
                if connection_count >= 3 {
                    break; // Test max 3 connections
                }
            } else {
                // No connection yet, wait a bit
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        
        close(server_fd);
        
        if connection_count > 0 {
            println!("✅ swlan0 binding test successful - {} connections handled", connection_count);
        } else {
            println!("ℹ️  swlan0 binding successful, no test connections received");
            println!("   This is normal - the binding itself worked");
        }
    }
    
    Ok(())
}

fn test_micromethod_on_connection(connection_fd: i32) -> io::Result<()> {
    println!("🔍 Testing micromethod on real connection...");
    
    unsafe {
        // Wait briefly for data to arrive
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
            println!("ℹ️  No data available for micromethod test");
            return Ok(());
        }
        
        println!("✅ Micromethod peek successful: {} bytes", result);
        println!("   First byte: 0x{:02x} ('{}')", 
                 buffer[0], 
                 if buffer[0].is_ascii_graphic() { buffer[0] as char } else { '?' });
        
        // Protocol detection using micromethod
        let protocol_bits = match buffer[0] {
            0x05 => 0b001,  // SOCKS5
            b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => 0b010, // HTTP  
            0x16 => 0b100,  // TLS
            _ => 0b000      // Unknown
        };
        
        let protocol_name = match protocol_bits {
            0b001 => "SOCKS5",
            0b010 => "HTTP", 
            0b100 => "TLS",
            _ => "Unknown"
        };
        
        println!("✅ Protocol detected: {} (bits: {:03b})", protocol_name, protocol_bits);
        
        // Send a simple response to acknowledge
        if protocol_bits == 0b010 { // HTTP
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nMicromethod test success!";
            send(connection_fd, response.as_ptr() as *const c_void, response.len(), 0);
        }
    }
    
    Ok(())
}

fn get_swlan0_ip() -> io::Result<String> {
    use std::process::Command;
    
    // Use the proven ifconfig method from the proxy-bridge script
    let output = Command::new("sh")
        .arg("-c")
        .arg("ifconfig 2>/dev/null | grep -A2 swlan0 | grep 'inet ' | awk '{print $2}'")
        .output()?;
    
    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to get swlan0 IP"));
    }
    
    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if ip.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "swlan0 IP not found"));
    }
    
    Ok(ip)
}