use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::session::{DataWritePermit, StreamReader, WriteReceipt};
use crate::Stream;

type IoFuture<T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send>>;

enum ReadState {
    Idle,
    Acquiring(Pin<Box<dyn Future<Output = StreamReader> + Send>>),
    Reading(StreamReader),
}

enum WriteState {
    Open,
    ShuttingDown(Option<IoFuture<()>>),
    Closed,
    Failed(std::io::Error),
}

/// A Tokio byte stream with at most one accepted write awaiting physical completion.
/// Flush and shutdown wait for accepted bytes to reach the transport.
pub struct StreamIo {
    stream: Arc<Stream>,
    read_state: ReadState,
    write_reservation: Option<IoFuture<DataWritePermit>>,
    write_receipt: Option<WriteReceipt>,
    write_state: WriteState,
}

impl StreamIo {
    pub fn new(stream: Stream) -> Self {
        Self {
            stream: Arc::new(stream),
            read_state: ReadState::Idle,
            write_reservation: None,
            write_receipt: None,
            write_state: WriteState::Open,
        }
    }

    fn write_error(&self) -> Option<std::io::Error> {
        if let WriteState::Failed(error) = &self.write_state {
            Some(std::io::Error::new(error.kind(), error.to_string()))
        } else {
            None
        }
    }

    fn fail_write(&mut self, error: std::io::Error) -> std::io::Error {
        let result = std::io::Error::new(error.kind(), error.to_string());
        self.write_state = WriteState::Failed(error);
        self.write_reservation = None;
        self.write_receipt = None;
        result
    }

    fn poll_receipt(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(error) = self.write_error() {
            return Poll::Ready(Err(error));
        }
        if let Some(receipt) = &mut self.write_receipt {
            let result = std::task::ready!(Pin::new(receipt).poll(cx));
            self.write_receipt = None;
            if let Err(error) = result {
                return Poll::Ready(Err(self.fail_write(error)));
            }
        }
        Poll::Ready(Ok(()))
    }

    pub fn stream(&self) -> Arc<Stream> {
        Arc::clone(&self.stream)
    }

    pub async fn handshake_success(&mut self) -> std::io::Result<()> {
        self.stream.handshake_success().await
    }

    pub async fn handshake_failure(&mut self, error: &str) -> std::io::Result<()> {
        self.stream.handshake_failure(error).await
    }
}

impl AsyncRead for StreamIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if matches!(this.read_state, ReadState::Idle) {
            let stream = Arc::clone(&this.stream);
            this.read_state = ReadState::Acquiring(Box::pin(async move { stream.lock_reader_owned().await }));
        }
        if let ReadState::Acquiring(future) = &mut this.read_state {
            let reader = std::task::ready!(future.as_mut().poll(cx));
            this.read_state = ReadState::Reading(reader);
        }
        let ReadState::Reading(reader) = &mut this.read_state else {
            unreachable!("reader lock acquired");
        };
        let filled = buf.filled().len();
        let result = std::task::ready!(Pin::new(&mut **reader).poll_read(cx, buf));
        this.read_state = ReadState::Idle;
        Poll::Ready(result.and_then(|()| {
            if buf.filled().len() == filled {
                this.stream.read_eof()
            } else {
                Ok(())
            }
        }))
    }
}

impl AsyncWrite for StreamIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.write_error() {
            return Poll::Ready(Err(error));
        }
        if !matches!(this.write_state, WriteState::Open) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS write side shut down",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(this.poll_receipt(cx))?;
        if this.write_reservation.is_none() {
            let stream = Arc::clone(&this.stream);
            this.write_reservation = Some(Box::pin(async move { stream.reserve_write().await }));
        }
        let result = std::task::ready!(this.write_reservation.as_mut().expect("reservation installed").as_mut().poll(cx));
        this.write_reservation = None;
        match result.and_then(|permit| permit.send(data)) {
            Ok((size, receipt)) => {
                this.write_receipt = Some(receipt);
                Poll::Ready(Ok(size))
            }
            Err(error) => Poll::Ready(Err(this.fail_write(error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.write_reservation = None;
        this.poll_receipt(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.write_error() {
            return Poll::Ready(Err(error));
        }
        if matches!(this.write_state, WriteState::Closed) {
            return Poll::Ready(Ok(()));
        }
        if matches!(this.write_state, WriteState::Open) {
            this.write_state = WriteState::ShuttingDown(None);
        }
        this.write_reservation = None;
        std::task::ready!(this.poll_receipt(cx))?;
        let WriteState::ShuttingDown(future) = &mut this.write_state else {
            unreachable!("shutdown is in progress");
        };
        let future = future.get_or_insert_with(|| {
            let stream = Arc::clone(&this.stream);
            Box::pin(async move { stream.shutdown_write_by_send_fin_to_remote().await })
        });
        match std::task::ready!(future.as_mut().poll(cx)) {
            Ok(()) => {
                this.write_state = WriteState::Closed;
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(this.fail_write(error))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_MAX_SESSION_AGE, DEFAULT_SCHEME, PaddingFactory, Session};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
        let mut future = std::pin::pin!(future);
        std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
    }

    async fn gated_stream() -> (
        Arc<Session>,
        StreamIo,
        tokio::io::DuplexStream,
        Arc<super::super::session::tests::WriteGate>,
    ) {
        let (transport, mut peer, gate) = super::super::session::tests::gated_transport();
        let padding = Arc::new(tokio::sync::RwLock::new(PaddingFactory::new(b"stop=0").unwrap()));
        let session = Session::new_client(1, transport, padding, DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().command, crate::Command::Settings);
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().command, crate::Command::Syn);
        (session, StreamIo::new(stream), peer, gate)
    }

    #[tokio::test]
    async fn pending_receipt_retains_flush_but_not_cancelled_write_bytes() {
        let (session, mut io, mut peer, gate) = gated_stream().await;
        gate.block();
        assert_eq!(io.write(b"first").await.unwrap(), 5);
        gate.wait_pending().await;
        assert!(poll_once(io.write(b"cancelled payload")).await.is_pending());
        assert_eq!(io.write(&[]).await.unwrap(), 0);
        assert!(poll_once(io.flush()).await.is_pending());
        assert!(poll_once(io.flush()).await.is_pending(), "cancelled flush retains the receipt");
        gate.release();
        assert_eq!(io.write(b"x").await.unwrap(), 1);
        io.flush().await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().data, b"first");
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().data, b"x");
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().command, crate::Command::Fin);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_flushes_payload_before_fin() {
        let (session, mut io, mut peer, gate) = gated_stream().await;
        gate.block();
        assert_eq!(io.write(b"payload").await.unwrap(), 7);
        assert!(poll_once(io.shutdown()).await.is_pending());
        assert_eq!(io.write(b"late").await.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        gate.wait_pending().await;
        assert!(poll_once(io.shutdown()).await.is_pending());
        gate.release();
        io.shutdown().await.unwrap();
        io.shutdown().await.unwrap();
        let push = crate::Frame::read_from(&mut peer).await.unwrap();
        assert_eq!(push.command, crate::Command::Push);
        assert_eq!(push.data, b"payload");
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().command, crate::Command::Fin);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_shutdown_retains_pending_fin() {
        let (session, mut io, mut peer, gate) = gated_stream().await;
        gate.block();
        assert!(poll_once(io.shutdown()).await.is_pending());
        gate.wait_pending().await;
        assert!(poll_once(io.shutdown()).await.is_pending());
        assert_eq!(io.write(b"late").await.unwrap_err().kind(), std::io::ErrorKind::BrokenPipe);
        gate.release();
        io.shutdown().await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().command, crate::Command::Fin);
        let mut byte = [0];
        assert!(poll_once(peer.read(&mut byte)).await.is_pending(), "FIN is sent once");
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn physical_writer_failure_sticks_across_write_flush_and_shutdown() {
        let (session, mut io, peer, gate) = gated_stream().await;
        gate.block();
        io.write_all(b"payload").await.unwrap();
        gate.wait_pending().await;
        assert!(poll_once(io.flush()).await.is_pending());
        drop(peer);
        gate.release();
        let kind = io.flush().await.unwrap_err().kind();
        assert_eq!(kind, std::io::ErrorKind::BrokenPipe);
        assert_eq!(io.write(b"later").await.unwrap_err().kind(), kind);
        assert_eq!(io.flush().await.unwrap_err().kind(), kind);
        assert_eq!(io.shutdown().await.unwrap_err().kind(), kind);
        assert_eq!(io.shutdown().await.unwrap_err().kind(), kind);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn direct_stream_write_waits_for_physical_completion() {
        let (session, io, mut peer, gate) = gated_stream().await;
        let stream = io.stream();
        gate.block();
        let mut write = Box::pin(stream.write(b"payload"));
        assert!(poll_once(&mut write).await.is_pending());
        gate.wait_pending().await;
        assert!(poll_once(&mut write).await.is_pending());
        gate.release();
        assert_eq!(write.await.unwrap(), 7);
        assert_eq!(crate::Frame::read_from(&mut peer).await.unwrap().data, b"payload");
        session.shutdown().await.unwrap();
    }

    async fn paired_streams() -> (Arc<Session>, Arc<Session>, StreamIo, StreamIo) {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let padding = Arc::new(tokio::sync::RwLock::new(PaddingFactory::new(DEFAULT_SCHEME).unwrap()));
        let client = Session::new_client(1, Box::new(client_io), Arc::clone(&padding), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(2, Box::new(server_io), padding, DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();
        let outgoing = client.open_stream().await.unwrap();
        let incoming = server.accept_stream().await.unwrap();
        incoming.handshake_success().await.unwrap();
        (client, server, StreamIo::new(outgoing), StreamIo::new(incoming))
    }

    #[tokio::test]
    async fn direct_large_write_preserves_bytes() {
        let (client, server, mut outgoing, mut incoming) = paired_streams().await;
        let payload = vec![7u8; 128 * 1024];
        outgoing
            .write_all(&payload)
            .await
            .expect("byte stream accepts large application writes");
        outgoing.shutdown().await.unwrap();
        let mut actual = Vec::new();
        incoming.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, payload);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn frame_boundary_writes_preserve_bytes_and_half_close_response() {
        for size in [0, 1, crate::MAX_FRAME_DATA_SIZE, crate::MAX_FRAME_DATA_SIZE + 1, 128 * 1024] {
            let (client, server, mut outgoing, mut incoming) = paired_streams().await;
            let payload: Vec<_> = (0..size).map(|index| (index % 251) as u8).collect();
            let accepted = outgoing.write(&payload).await.unwrap();
            assert_eq!(accepted, size.min(crate::MAX_FRAME_DATA_SIZE));
            outgoing.write_all(&payload[accepted..]).await.unwrap();
            outgoing.shutdown().await.unwrap();
            let mut actual = Vec::new();
            incoming.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, payload);
            incoming.write_all(b"response").await.unwrap();
            incoming.shutdown().await.unwrap();
            let mut response = Vec::new();
            outgoing.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"response");
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn direct_stream_write_returns_one_frame_at_a_time() {
        let (session, io, mut peer, _) = gated_stream().await;
        let stream = io.stream();
        let payload: Vec<_> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let mut actual = Vec::new();
        while actual.len() < payload.len() {
            let remaining = &payload[actual.len()..];
            let size = stream.write(remaining).await.unwrap();
            assert_eq!(size, remaining.len().min(crate::MAX_FRAME_DATA_SIZE));
            let frame = crate::Frame::read_from(&mut peer).await.unwrap();
            assert_eq!(frame.command, crate::Command::Push);
            assert_eq!(frame.data.len(), size);
            actual.extend_from_slice(&frame.data);
        }
        assert_eq!(actual, payload);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_read_can_resume_with_a_smaller_buffer() {
        let (client, server, mut outgoing, mut incoming) = paired_streams().await;
        let mut large = [0u8; 8];
        let pending = std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut outgoing).poll_read(cx, &mut ReadBuf::new(&mut large)))).await;
        assert!(pending.is_pending());
        incoming.write_all(b"12345678").await.unwrap();
        let mut small = [0u8; 2];
        outgoing.read_exact(&mut small).await.expect("changed read buffer must not panic");
        assert_eq!(&small, b"12");
        let mut rest = [0u8; 6];
        outgoing.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"345678");
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn empty_read_preserves_pending_read_and_all_bytes() {
        let (client, server, mut outgoing, mut incoming) = paired_streams().await;
        let mut large = [0u8; 8];
        assert!(poll_once(outgoing.read(&mut large)).await.is_pending());
        let mut empty = [];
        assert!(matches!(poll_once(outgoing.read(&mut empty)).await, Poll::Ready(Ok(0))));
        incoming.write_all(b"12345678").await.unwrap();
        incoming.shutdown().await.unwrap();
        assert!(matches!(poll_once(outgoing.read(&mut empty)).await, Poll::Ready(Ok(0))));
        let mut small = [0u8; 2];
        outgoing.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"12");
        let mut rest = Vec::new();
        outgoing.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"345678");
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_read_lock_acquisition_wakes_with_current_buffer() {
        let (client, server, mut outgoing, mut incoming) = paired_streams().await;
        let stream = outgoing.stream();
        let mut first = [0u8; 1];
        let mut direct_read = Box::pin(stream.read(&mut first));
        assert!(poll_once(&mut direct_read).await.is_pending());
        let mut large = [0u8; 8];
        assert!(poll_once(outgoing.read(&mut large)).await.is_pending());
        let (waiting, ready) = tokio::sync::oneshot::channel();
        let adapter_read = tokio::spawn(async move {
            let mut small = [0u8; 1];
            assert!(poll_once(outgoing.read(&mut small)).await.is_pending());
            waiting.send(()).unwrap();
            outgoing.read_exact(&mut small).await.unwrap();
            assert_eq!(&small, b"2");
            outgoing.read_exact(&mut small).await.unwrap();
            assert_eq!(&small, b"3");
            outgoing
        });
        ready.await.unwrap();
        incoming.write_all(b"123").await.unwrap();
        incoming.flush().await.unwrap();
        assert_eq!(direct_read.await.unwrap(), 1);
        assert_eq!(&first, b"1");
        let _outgoing = tokio::time::timeout(Duration::from_secs(1), adapter_read).await.unwrap().unwrap();
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn read_uses_remaining_capacity_and_releases_reader_on_ready() {
        let (client, server, mut outgoing, mut incoming) = paired_streams().await;
        incoming.write_all(b"1234").await.unwrap();
        incoming.shutdown().await.unwrap();
        let mut data = [b'x'; 4];
        let mut buffer = ReadBuf::new(&mut data);
        buffer.advance(2);
        std::future::poll_fn(|cx| Pin::new(&mut outgoing).poll_read(cx, &mut buffer))
            .await
            .unwrap();
        assert_eq!(buffer.filled(), b"xx12");
        let stream = outgoing.stream();
        let mut rest = [0; 2];
        let size = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(size, 2);
        assert_eq!(&rest, b"34");
        assert_eq!(outgoing.read(&mut rest).await.unwrap(), 0);
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn forced_close_remains_an_error_after_cancelled_read() {
        let (client, server, mut outgoing, _incoming) = paired_streams().await;
        let mut large = [0u8; 8];
        assert!(poll_once(outgoing.read(&mut large)).await.is_pending());
        client.shutdown().await.unwrap();
        let mut empty = [];
        assert!(matches!(poll_once(outgoing.read(&mut empty)).await, Poll::Ready(Ok(0))));
        let mut small = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), outgoing.read(&mut small))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert_eq!(
            outgoing.read(&mut small).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionReset
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_sends_fin_and_peer_observes_eof() {
        // env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let padding = Arc::new(tokio::sync::RwLock::new(PaddingFactory::new(DEFAULT_SCHEME).unwrap()));
        let client = Session::new_client(1, Box::new(client_io), Arc::clone(&padding), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(10, Box::new(server_io), padding, DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let stream = client.open_stream().await.unwrap();
        let peer = server.accept_stream().await.unwrap();
        let mut io = StreamIo::new(stream);
        io.write_all(b"payload").await.unwrap();
        io.shutdown().await.unwrap();

        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut buffer = [0u8; 32];
            loop {
                let size = peer.read(&mut buffer).await.unwrap();
                if size == 0 {
                    break;
                }
                received.extend_from_slice(&buffer[..size]);
            }
        })
        .await
        .expect("peer should observe FIN");
        assert_eq!(received, b"payload");

        let mut peer = StreamIo::new(peer);
        let len = peer.write(b"response").await.unwrap();
        assert_eq!(len, b"response".len());
        peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), io.read_to_end(&mut response))
            .await
            .expect("response should still flow after write-side shutdown")
            .unwrap();
        assert_eq!(response, b"response");

        let _ = client.shutdown().await;
        let _ = server.shutdown().await;
    }
}
