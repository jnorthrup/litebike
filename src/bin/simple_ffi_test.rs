// Simple FFI Test - Single-byte peek micromethod
// Minimal test to verify POSIX recv() works in Knox

use std::io;
use std::os::fd::AsRawFd;
use tokio::net::{TcpListener, TcpStream};

fn main() -> io::Result<()> {
    println!("🔧 Simple FFI Test - Single-byte POSIX peek");
    
    // Test direct POSIX recv with MSG_PEEK
    test_posix_peek_direct()?;
    
    println!("✅ FFI micromethod test completed");
    Ok(())
}

fn test_posix_peek_direct() -> io::Result<()> {
    println!("\n📡 Testing direct POSIX recv with MSG_PEEK...");
    
    use libc::{recv, MSG_PEEK, c_void, size_t, ssize_t};
    
    // Create a simple test socket pair
    let rt = tokio::runtime::Runtime::new()?;
    
    rt.block_on(async {
        // Bind to any available port
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        
        // Create client connection
        let mut client_stream = TcpStream::connect(addr).await?;
        let (server_stream, _) = listener.accept().await?;
        
        // Send test data from client  
        tokio::io::AsyncWriteExt::write_all(&mut client_stream, b"GET / HTTP/1.1\r\n").await?;
        
        // Give data time to arrive
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        // Test POSIX peek on server side
        let fd = server_stream.as_raw_fd();
        let mut buffer = [0u8; 1];
        
        let result = unsafe {
            recv(
                fd,
                buffer.as_mut_ptr() as *mut c_void,
                1 as size_t,
                MSG_PEEK
            )
        };
        
        if result < 0 {
            println!("❌ POSIX recv failed: {}", io::Error::last_os_error());
            return Err(io::Error::last_os_error());
        }
        
        println!("✅ POSIX peek successful: {} bytes", result);
        println!("   First byte: 0x{:02x} ('{}')", 
                 buffer[0], 
                 if buffer[0].is_ascii_graphic() { buffer[0] as char } else { '?' });
        
        // Verify it's the 'G' from GET
        if buffer[0] == b'G' {
            println!("✅ Correctly detected HTTP GET request");
            
            // Test micromethod protocol detection
            let protocol = match buffer[0] {
                0x05 => "SOCKS5",
                b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => "HTTP",
                0x16 => "TLS",
                _ => "Unknown"
            };
            
            println!("✅ Micromethod detected: {}", protocol);
        } else {
            println!("⚠ Unexpected first byte for HTTP request");
        }
        
        Ok::<(), io::Error>(())
    })?;
    
    println!("✅ Direct POSIX FFI test successful");
    Ok(())
}