// Unified FFI Dispatcher
// Binds to a single port and dispatches to the correct FFI handler.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::thread;
use log::{debug, error, info};

use crate::posix_sockets::posix_peek;
use crate::ffi_http::handle_http_ffi;
use crate::ffi_socks5::handle_socks5_ffi;

const UNIFIED_PORT: u16 = 8888;

/// Starts the unified FFI dispatcher.
pub fn start_unified_ffi_dispatcher() -> io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", UNIFIED_PORT))?;
    info!("Unified FFI dispatcher listening on port {}", UNIFIED_PORT);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = dispatch_stream(stream) {
                        error!("Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }

    Ok(())
}

/// Dispatches a raw TCP stream to the appropriate FFI handler.
fn dispatch_stream(stream: TcpStream) -> io::Result<()> {
    let mut peek_buf = [0u8; 1];
    let n = posix_peek(&stream, &mut peek_buf)?;

    if n == 0 {
        return Ok(()); // Connection closed
    }

    match peek_buf[0] {
        0x05 => {
            debug!("Dispatching to SOCKS5 FFI handler");
            handle_socks5_ffi(stream)
        }
        b'G' | b'P' | b'H' | b'D' | b'O' | b'C' | b'T' => {
            debug!("Dispatching to HTTP FFI handler");
            handle_http_ffi(stream)
        }
        _ => {
            error!("Unknown protocol, first byte: 0x{:02x}", peek_buf[0]);
            Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown protocol"))
        }
    }
}
