// POSIX socket operations for litebike
// Copied from literbike/src/posix_sockets.rs — self-contained, no /proc access

use libc::{recv, MSG_PEEK, c_void, size_t};
use nix::sys::socket::{getsockopt, sockopt};
use std::io::{self, Error, ErrorKind};
use std::os::fd::AsRawFd;
use tokio::net::TcpStream;

/// POSIX peek using direct recv(MSG_PEEK) — avoids /proc restrictions.
pub fn posix_peek(stream: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    let fd = stream.as_raw_fd();
    let result = unsafe {
        recv(
            fd,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as size_t,
            MSG_PEEK,
        )
    };
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// Basic socket metadata obtainable without /proc.
pub struct SocketInfo {
    pub socket_type: nix::sys::socket::SockType,
    pub receive_buffer_size: usize,
}

/// Extract socket information without /proc access.
pub fn get_socket_info(stream: &TcpStream) -> io::Result<SocketInfo> {
    let socket_type = getsockopt(stream, sockopt::SockType)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let rcv_buf = getsockopt(stream, sockopt::RcvBuf)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    Ok(SocketInfo {
        socket_type,
        receive_buffer_size: rcv_buf,
    })
}
