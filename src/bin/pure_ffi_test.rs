// Pure FFI Test - Just handles and POSIX calls
// No tokio, no async - just raw sockets and recv()

use std::io;
use std::os::raw::{c_int, c_void};
use libc::{socket, bind, listen, accept, recv, send, close, AF_INET, SOCK_STREAM, MSG_PEEK, sockaddr_in, sockaddr};
use std::mem;
use std::ptr;

fn main() -> io::Result<()> {
    println!("🔧 Pure FFI Test - Raw POSIX sockets only");
    
    test_raw_socket_peek()?;
    
    println!("✅ Pure FFI test completed");
    Ok(())
}

fn test_raw_socket_peek() -> io::Result<()> {
    println!("\n📡 Testing raw POSIX socket with MSG_PEEK...");
    
    unsafe {
        // Create server socket
        let server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if server_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        
        // Bind to any port
        let mut addr: sockaddr_in = mem::zeroed();
        addr.sin_family = AF_INET as u16;
        addr.sin_addr.s_addr = 0; // INADDR_ANY
        addr.sin_port = 0; // Any port
        
        if bind(server_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Listen
        if listen(server_fd, 1) < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("✓ Server socket created and listening");
        
        // Create client socket
        let client_fd = socket(AF_INET, SOCK_STREAM, 0);
        if client_fd < 0 {
            close(server_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Get actual server address
        let mut server_len = mem::size_of::<sockaddr_in>() as u32;
        if libc::getsockname(server_fd, &mut addr as *mut _ as *mut sockaddr, &mut server_len) < 0 {
            close(server_fd);
            close(client_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Connect client to server
        addr.sin_addr.s_addr = libc::htonl(libc::INADDR_LOOPBACK);
        if libc::connect(client_fd, &addr as *const _ as *const sockaddr, mem::size_of::<sockaddr_in>() as u32) < 0 {
            close(server_fd);
            close(client_fd);
            return Err(io::Error::last_os_error());
        }
        
        // Accept connection
        let connection_fd = accept(server_fd, ptr::null_mut(), ptr::null_mut());
        if connection_fd < 0 {
            close(server_fd);
            close(client_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("✓ Connection established");
        
        // Send test data from client
        let test_data = b"GET / HTTP/1.1\r\n";
        if send(client_fd, test_data.as_ptr() as *const c_void, test_data.len(), 0) < 0 {
            close(server_fd);
            close(client_fd);
            close(connection_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("✓ Test data sent");
        
        // **THE KEY TEST**: Single-byte POSIX peek
        let mut buffer = [0u8; 1];
        let result = recv(
            connection_fd,
            buffer.as_mut_ptr() as *mut c_void,
            1,
            MSG_PEEK
        );
        
        if result < 0 {
            println!("❌ POSIX recv with MSG_PEEK failed: {}", io::Error::last_os_error());
            close(server_fd);
            close(client_fd);
            close(connection_fd);
            return Err(io::Error::last_os_error());
        }
        
        println!("✅ POSIX MSG_PEEK successful: {} bytes", result);
        println!("   First byte: 0x{:02x} ('{}')", 
                 buffer[0], 
                 if buffer[0].is_ascii_graphic() { buffer[0] as char } else { '?' });
        
        // Test micromethod protocol detection (1-bit per protocol)
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
        
        println!("✅ Micromethod detection: {} (bits: {:03b})", protocol_name, protocol_bits);
        
        // Verify it's HTTP 'G' from GET
        if buffer[0] == b'G' {
            println!("✅ Correctly detected HTTP GET request via 1-byte peek");
        }
        
        // Cleanup
        close(connection_fd);
        close(client_fd);
        close(server_fd);
        
        println!("✅ Pure POSIX FFI test successful - no tokio needed!");
    }
    
    Ok(())
}