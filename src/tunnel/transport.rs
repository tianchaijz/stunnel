use async_trait::async_trait;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Tunnel;

// Opens a tunnel on the transport connection: opens a stream and wraps it in
// a Tunnel. Used by the client for forward and control tunnels and by the
// server to send reverse tunnels back to the client.
#[async_trait]
pub trait OpenTunnel: Clone + Send + 'static {
    type S: AsyncWrite + Send + Unpin;
    type R: AsyncRead + Send + Unpin;

    async fn open_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>>;
}

// Accepts the next tunnel of a connection: accepts a stream and wraps it in
// a Tunnel, or errors when the connection is closed.
#[async_trait]
pub trait AcceptTunnel: Send + 'static {
    type S: AsyncWrite + Send + Unpin;
    type R: AsyncRead + Send + Unpin;

    async fn accept_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>>;
}

pub(crate) struct OwnedIo<T, O> {
    pub(crate) stream: T,
    pub(crate) _owner: O,
}

impl<T: AsyncRead + Unpin, O: Unpin> AsyncRead for OwnedIo<T, O> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin, O: Unpin> AsyncWrite for OwnedIo<T, O> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
