//! I/O Substrate - Userspace kernel emulation integration
//!
//! This module provides integration with the userspace library for
//! emulating various Linux I/O flavors including:
//! - Non-blocking I/O (nio)
//! - io_uring operations (Linux)
//! - POSIX socket abstractions
//!
//! # Example
//!
//! ```rust
//! use litebike::io_substrate::{SystemCapabilities, SimpleReactor, NioChannel};
//!
//! fn main() {
//!     let caps = SystemCapabilities::detect();
//!     println!("io_uring available: {}", caps.io_uring_available);
//!     
//!     let reactor = SimpleReactor::new();
//!     println!("Reactor created with {} channels", reactor.channel_count());
//! }
//! ```

use std::io::{self, Read, Write};
use std::time::Duration;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;

pub use userspace::kernel::nio::{NioChannel, Reactor, SimpleReactor};
pub use userspace::kernel::kernel_capabilities::SystemCapabilities;

#[cfg(all(feature = "kernel", target_os = "linux"))]
pub use userspace::kernel::io_uring::{KernelUring, KernelSQE, KernelCQE, OpCode};

#[cfg(feature = "syscall-net")]
pub use userspace::kernel::posix_sockets::{PosixSocket, SocketPair};

#[cfg(feature = "syscall-net")]
pub use userspace::kernel::syscall_net::{SocketOps, NetworkInterface};

pub mod async_io;

pub use async_io::{AsyncReader, AsyncWriter, AsyncIo};

pub fn capabilities() -> SystemCapabilities {
    SystemCapabilities::detect()
}
