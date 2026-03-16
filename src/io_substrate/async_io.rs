//! Async I/O wrappers using userspace nio substrate

use std::io::{self, Read, Write, Result as IoResult};
use std::time::Duration;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;

use crate::io_substrate::NioChannel;

pub struct AsyncReader<C: NioChannel> {
    channel: C,
    buffer: Vec<u8>,
    position: usize,
}

impl<C: NioChannel> AsyncReader<C> {
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            buffer: Vec::with_capacity(4096),
            position: 0,
        }
    }

    pub fn with_capacity(channel: C, capacity: usize) -> Self {
        Self {
            channel,
            buffer: Vec::with_capacity(capacity),
            position: 0,
        }
    }

    pub fn poll_read(&mut self, cx: &mut Context<'_>, timeout: Option<Duration>) -> Poll<IoResult<usize>> {
        match self.channel.poll_readable(timeout) {
            Ok(true) => {
                let mut temp = [0u8; 4096];
                match self.channel.try_read(&mut temp) {
                    Ok(n) => {
                        self.buffer.extend_from_slice(&temp[..n]);
                        Poll::Ready(Ok(n))
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Ok(false) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub async fn read(&mut self) -> IoResult<usize> {
        let mut this = self;
        futures::future::poll_fn(|cx| this.poll_read(cx, None)).await
    }

    pub fn read_available(&mut self) -> IoResult<Vec<u8>> {
        let mut temp = [0u8; 4096];
        let mut result = Vec::new();
        loop {
            match self.channel.try_read(&mut temp) {
                Ok(0) => break,
                Ok(n) => result.extend_from_slice(&temp[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(result)
    }
}

pub struct AsyncWriter<C: NioChannel> {
    channel: C,
    buffer: Vec<u8>,
}

impl<C: NioChannel> AsyncWriter<C> {
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            buffer: Vec::new(),
        }
    }

    pub fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8], timeout: Option<Duration>) -> Poll<IoResult<usize>> {
        match self.channel.poll_writable(timeout) {
            Ok(true) => {
                match self.channel.try_write(buf) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Ok(false) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let mut this = self;
        futures::future::poll_fn(|cx| this.poll_write(cx, buf, None)).await
    }

    pub async fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

pub struct AsyncIo<C: NioChannel> {
    reader: AsyncReader<C>,
    writer: AsyncWriter<C>,
}

impl<C: NioChannel + Clone> AsyncIo<C> {
    pub fn new(channel: C) -> Self {
        Self {
            reader: AsyncReader::new(channel.clone()),
            writer: AsyncWriter::new(channel),
        }
    }

    pub fn reader(&mut self) -> &mut AsyncReader<C> {
        &mut self.reader
    }

    pub fn writer(&mut self) -> &mut AsyncWriter<C> {
        &mut self.writer
    }
}

impl<C: NioChannel + Clone> Clone for AsyncIo<C> {
    fn clone(&self) -> Self {
        Self::new(self.reader.channel.clone())
    }
}
