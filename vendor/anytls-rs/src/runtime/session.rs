use method_name::method_name_unstable;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Notify, OwnedMutexGuard, RwLock, mpsc, oneshot},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use crate::{CHECK_MARK, Command, Frame, HEADER_OVERHEAD_SIZE, PaddingFactory, from_bytes, runtime::BoxTransport, to_bytes};

const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_QUEUE_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(15);
const INBOUND_PUSH_QUEUE_BYTES: usize = 1024 * 1024;
const INBOUND_PUSH_QUEUE_MESSAGES: usize = 64;
const _: () = assert!(INBOUND_PUSH_QUEUE_BYTES >= crate::MAX_FRAME_DATA_SIZE);
pub const DEFAULT_MAX_SESSION_AGE: Duration = Duration::from_secs(60 * 60);

static NEXT_STREAM_ID: AtomicU32 = AtomicU32::new(0);

fn allocate_stream_id(counter: &AtomicU32) -> u32 {
    loop {
        let stream_id = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if stream_id != 0 {
            return stream_id;
        }
    }
}

pub fn is_peer_disconnect(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::ConnectionReset
}

struct WriteRequest {
    bytes: Vec<u8>,
    disable_buffering_after: bool,
    local_session_id: usize,
    peer_session_id: Option<usize>,
    enqueue_wait: Duration,
    queue_depth_at_enqueue: usize,
    enqueued_at: std::time::Instant,
    heartbeat_session_id: Option<usize>,
    heartbeat_response_session_id: Option<usize>,
    result_sender: Option<oneshot::Sender<WriteCompletion>>,
}

struct WriteTimings {
    enqueue_wait: Duration,
    queue_depth_at_enqueue: usize,
    queue_wait: Duration,
    write_duration: Duration,
}

struct WriteCompletion {
    result: std::io::Result<()>,
    timings: WriteTimings,
}

pub(crate) struct DataWritePermit {
    permit: mpsc::OwnedPermit<WriteRequest>,
    active: OwnedMutexGuard<Option<(u32, StreamState)>>,
    session: Arc<Session>,
    enqueue_started: std::time::Instant,
}

impl DataWritePermit {
    pub(crate) fn send(self, data: &[u8]) -> std::io::Result<(usize, WriteReceipt)> {
        let data = &data[..data.len().min(crate::MAX_FRAME_DATA_SIZE)];
        let (stream_id, stream) = self.active.as_ref().expect("active stream validated during reservation");
        if self.session.is_closed() || stream.read_state.write_close_token.is_cancelled() {
            return Err(stream.read_state.write_error("AnyTLS stream closed"));
        }
        let bytes = Frame::encode_parts(Command::Push, *stream_id, data)?;
        let (result_sender, receiver) = oneshot::channel();
        self.permit.send(WriteRequest {
            bytes,
            disable_buffering_after: false,
            local_session_id: self.session.id(),
            peer_session_id: self.session.peer_session_id(),
            enqueue_wait: self.enqueue_started.elapsed(),
            queue_depth_at_enqueue: self
                .session
                .data_sender
                .max_capacity()
                .saturating_sub(self.session.data_sender.capacity())
                .saturating_sub(1),
            enqueued_at: std::time::Instant::now(),
            heartbeat_session_id: None,
            heartbeat_response_session_id: None,
            result_sender: Some(result_sender),
        });
        Ok((data.len(), WriteReceipt { receiver }))
    }
}

pub(crate) struct WriteReceipt {
    receiver: oneshot::Receiver<WriteCompletion>,
}

impl Future for WriteReceipt {
    type Output = std::io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::task::ready!(Pin::new(&mut self.receiver).poll(cx)) {
            Ok(completion) => Poll::Ready(completion.result),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "AnyTLS writer task closed",
            ))),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ReadTermination {
    Open,
    Clean,
    Failed,
    Refused(Arc<str>),
}

struct StreamReadState {
    termination: std::sync::Mutex<ReadTermination>,
    close_token: CancellationToken,
    write_close_token: CancellationToken,
}

impl StreamReadState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            termination: std::sync::Mutex::new(ReadTermination::Open),
            close_token: CancellationToken::new(),
            write_close_token: CancellationToken::new(),
        })
    }

    fn finish(&self, termination: ReadTermination) {
        let mut current = self.termination.lock().unwrap();
        if *current == ReadTermination::Open {
            *current = termination;
        }
    }

    fn refuse(&self, reason: Arc<str>) {
        let mut current = self.termination.lock().unwrap();
        if *current == ReadTermination::Open {
            *current = ReadTermination::Refused(reason);
        }
        drop(current);
        self.close_token.cancel();
    }

    fn refusal(&self) -> Option<Arc<str>> {
        match &*self.termination.lock().unwrap() {
            ReadTermination::Refused(reason) => Some(Arc::clone(reason)),
            _ => None,
        }
    }

    fn write_error(&self, fallback: &str) -> std::io::Error {
        match self.refusal() {
            Some(reason) => std::io::Error::new(std::io::ErrorKind::BrokenPipe, format!("remote: {reason}")),
            None => std::io::Error::new(std::io::ErrorKind::BrokenPipe, fallback),
        }
    }

    fn abort(&self) {
        self.finish(ReadTermination::Failed);
        self.close_token.cancel();
        if matches!(
            *self.termination.lock().unwrap(),
            ReadTermination::Failed | ReadTermination::Refused(_)
        ) {
            self.write_close_token.cancel();
        }
    }

    fn eof(&self) -> std::io::Result<()> {
        match &*self.termination.lock().unwrap() {
            ReadTermination::Clean => Ok(()),
            ReadTermination::Refused(reason) => Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, format!("remote: {reason}"))),
            ReadTermination::Open | ReadTermination::Failed => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "AnyTLS stream closed before ordered FIN",
            )),
        }
    }
}

/// Represents an status of a logical stream within a session.
pub(crate) struct StreamState {
    push_sender: mpsc::Sender<PushMessage>,
    push_slots: Arc<tokio::sync::Semaphore>,
    /// Indicates whether the local side has sent a FIN for this stream.
    pub(crate) local_fin: bool,
    /// Indicates whether the remote side has sent a FIN for this stream.
    pub(crate) remote_fin: bool,
    /// Indicates whether all queued inbound data has drained to the application.
    pub(crate) read_closed: bool,
    read_state: Arc<StreamReadState>,
}

enum PushMessage {
    Data(Vec<u8>, tokio::sync::OwnedSemaphorePermit),
    Fin,
}

impl StreamState {
    fn new(writer: tokio::io::DuplexStream, stream_id: u32, session: Weak<Session>, read_state: Arc<StreamReadState>) -> Self {
        let push_slots = Arc::new(tokio::sync::Semaphore::new(INBOUND_PUSH_QUEUE_BYTES));
        let (push_sender, push_receiver) = mpsc::channel(INBOUND_PUSH_QUEUE_MESSAGES + 1);
        let task_read_state = Arc::clone(&read_state);
        let session_id = session.upgrade().map(|s| s.id()).unwrap_or_default();
        tokio::spawn(Self::background_task_for_pump_data_to_stream(
            stream_id,
            session_id,
            session,
            task_read_state,
            push_receiver,
            writer,
        ));
        Self {
            push_sender,
            push_slots,
            local_fin: false,
            remote_fin: false,
            read_closed: false,
            read_state,
        }
    }

    async fn background_task_for_pump_data_to_stream(
        stream_id: u32,
        session_id: usize,
        session: Weak<Session>,
        read_state: Arc<StreamReadState>,
        mut push_receiver: mpsc::Receiver<PushMessage>,
        mut task_writer: tokio::io::DuplexStream,
    ) {
        let result = loop {
            let message = tokio::select! {
                message = push_receiver.recv() => message,
                _ = read_state.close_token.cancelled() => break Ok(()),
            };
            let Some(message) = message else {
                if read_state.close_token.is_cancelled() {
                    break Ok(());
                }
                break Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "push_receiver closed"));
            };
            let (data, _permit) = match message {
                PushMessage::Data(data, permit) => (data, permit),
                PushMessage::Fin => {
                    read_state.finish(ReadTermination::Clean);
                    break task_writer.shutdown().await;
                }
            };
            let result = tokio::select! {
                result = task_writer.write_all(&data) => result,
                _ = read_state.close_token.cancelled() => break Ok(()),
            };
            if let Err(e) = result {
                break Err(e);
            }
        };
        let unexpected_failure = result.is_err() && !read_state.close_token.is_cancelled();
        read_state.abort();
        drop(push_receiver);
        drop(task_writer);
        if let Some(session) = session.upgrade() {
            if unexpected_failure {
                let _ = session.shutdown().await;
            } else {
                session.on_stream_read_closed(stream_id).await;
            }
        }
        let mn = method_name_unstable!();
        let peer_session_id = session.upgrade().and_then(|session| session.peer_session_id());
        if let Err(e) = result {
            log::warn!("{mn} -- Session {session_id} peer={peer_session_id:?} stream {stream_id} task encountered an error: {e}");
        } else {
            log::trace!("{mn} -- Session {session_id} peer={peer_session_id:?} stream {stream_id} task completed successfully");
        }
    }
}

pub struct Session {
    session_id: usize,
    created_at: std::time::Instant,
    max_age: Duration,
    control_sender: mpsc::Sender<WriteRequest>,
    data_sender: mpsc::Sender<WriteRequest>,
    streams: Arc<Mutex<Option<(u32, StreamState)>>>,
    stream_epoch: AtomicU64,
    /// Indicates whether the session has been closed.
    closed: Arc<std::sync::atomic::AtomicBool>,
    is_client: bool,
    peer_session_id: std::sync::RwLock<Option<usize>>,
    peer_version: std::sync::atomic::AtomicU8,
    received_settings: std::sync::atomic::AtomicBool,
    padding: Arc<RwLock<PaddingFactory>>,
    reader: Mutex<Option<tokio::io::ReadHalf<BoxTransport>>>,
    close_token: CancellationToken,
    heart_response: Notify,
    incoming: Mutex<Option<mpsc::Receiver<Stream>>>,
    incoming_sender: Option<mpsc::Sender<Stream>>,
    idle_sender: Mutex<Option<mpsc::UnboundedSender<Arc<Session>>>>,
}

impl Session {
    pub fn new_client(session_id: usize, transport: BoxTransport, padding: Arc<RwLock<PaddingFactory>>, max_age: Duration) -> Arc<Self> {
        let cancel_token = CancellationToken::new();
        Arc::new(Self::new(session_id, transport, padding, true, max_age, cancel_token, None))
    }

    pub fn new_server(session_id: usize, transport: BoxTransport, padding: Arc<RwLock<PaddingFactory>>, max_age: Duration) -> Arc<Self> {
        let incoming = Some(mpsc::channel(1));
        let cancel_token = CancellationToken::new();
        Arc::new(Self::new(session_id, transport, padding, false, max_age, cancel_token, incoming))
    }

    fn new(
        session_id: usize,
        transport: BoxTransport,
        padding: Arc<RwLock<PaddingFactory>>,
        is_client: bool,
        max_age: Duration,
        close_token: CancellationToken,
        incoming: Option<(mpsc::Sender<Stream>, mpsc::Receiver<Stream>)>,
    ) -> Self {
        let side = if is_client { "client" } else { "server" };
        let mn = method_name_unstable!();
        log::trace!("{mn} -- Session {session_id} peer=None creating {side} session");
        let (reader, writer) = tokio::io::split(transport);
        let incoming_sender = incoming.as_ref().map(|(sender, _)| sender.clone());
        let writer_close_token = close_token.clone();
        let packet_counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let writer_packet_counter = Arc::clone(&packet_counter);
        let (control_sender, control_receiver) = mpsc::channel::<WriteRequest>(64);
        let (data_sender, data_receiver) = mpsc::channel::<WriteRequest>(64);
        let writer_padding = Arc::clone(&padding);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_closed = Arc::clone(&closed);
        tokio::spawn(Self::background_task(
            writer,
            is_client,
            writer_packet_counter,
            control_receiver,
            data_receiver,
            writer_close_token,
            writer_closed,
            writer_padding,
        ));
        Self {
            session_id,
            created_at: std::time::Instant::now(),
            max_age,
            control_sender,
            data_sender,
            streams: Arc::new(Mutex::new(None)),
            stream_epoch: AtomicU64::new(0),
            closed,
            is_client,
            peer_session_id: std::sync::RwLock::new(None),
            peer_version: std::sync::atomic::AtomicU8::new(0),
            received_settings: std::sync::atomic::AtomicBool::new(false),
            padding,
            reader: Mutex::new(Some(reader)),
            close_token,
            heart_response: Notify::new(),
            incoming: Mutex::new(incoming.map(|(_, receiver)| receiver)),
            incoming_sender,
            idle_sender: Mutex::new(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn background_task(
        writer: tokio::io::WriteHalf<BoxTransport>,
        buffering: bool,
        writer_packet_counter: Arc<std::sync::atomic::AtomicU32>,
        mut control_receiver: mpsc::Receiver<WriteRequest>,
        mut data_receiver: mpsc::Receiver<WriteRequest>,
        writer_close_token: CancellationToken,
        writer_closed: Arc<std::sync::atomic::AtomicBool>,
        writer_padding: Arc<RwLock<PaddingFactory>>,
    ) {
        let mut writer = Writer {
            transport: writer,
            buffering,
            buffered: Vec::new(),
            send_padding: true,
            packet_counter: writer_packet_counter,
        };
        loop {
            let request = tokio::select! {
                biased;
                request = control_receiver.recv() => request,
                request = data_receiver.recv() => request,
                _ = writer_close_token.cancelled() => None,
            };
            let Some(request) = request else {
                break;
            };
            let queue_wait = request.enqueued_at.elapsed();
            let write_started = std::time::Instant::now();
            let result = tokio::select! {
                biased;
                _ = writer_close_token.cancelled() => break,
                result = tokio::time::timeout(WRITE_TIMEOUT, async {
                    writer.write_conn(request.bytes, &writer_padding).await?;
                    if request.disable_buffering_after {
                        writer.buffering = false;
                        if !writer.buffered.is_empty() {
                            writer.write_conn(Vec::new(), &writer_padding).await?;
                        }
                    }
                    Ok(())
                }) => result.unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "AnyTLS transport write timed out"))),
            };
            let completion = WriteCompletion {
                result,
                timings: WriteTimings {
                    enqueue_wait: request.enqueue_wait,
                    queue_depth_at_enqueue: request.queue_depth_at_enqueue,
                    queue_wait,
                    write_duration: write_started.elapsed(),
                },
            };
            let failed = completion.result.is_err();
            let mn = method_name_unstable!();
            if let Some(session_id) = request.heartbeat_session_id {
                if let Some(error) = completion.result.as_ref().err() {
                    log::warn!(
                        "{mn} -- Session {} peer={:?} Session {session_id} heartbeat writer failed: enqueue_wait={:?} queue_depth={} queue_wait={:?} transport_write={:?} error={error}",
                        request.local_session_id,
                        request.peer_session_id,
                        completion.timings.enqueue_wait,
                        completion.timings.queue_depth_at_enqueue,
                        completion.timings.queue_wait,
                        completion.timings.write_duration,
                    );
                } else {
                    log::debug!(
                        "{mn} -- Session {} peer={:?} Session {session_id} heartbeat writer: enqueue_wait={:?} queue_depth={} queue_wait={:?} transport_write={:?} result=written",
                        request.local_session_id,
                        request.peer_session_id,
                        completion.timings.enqueue_wait,
                        completion.timings.queue_depth_at_enqueue,
                        completion.timings.queue_wait,
                        completion.timings.write_duration,
                    );
                }
            }
            if let Some(session_id) = request.heartbeat_response_session_id {
                if let Some(error) = completion.result.as_ref().err() {
                    log::warn!(
                        "{mn} -- Session {} peer={:?} Session {session_id} HeartResponse write failed: queue_depth={} queue_wait={:?} transport_write={:?} total_since_enqueue={:?} error={error}",
                        request.local_session_id,
                        request.peer_session_id,
                        completion.timings.queue_depth_at_enqueue,
                        completion.timings.queue_wait,
                        completion.timings.write_duration,
                        request.enqueued_at.elapsed(),
                    );
                } else {
                    log::trace!(
                        "{mn} -- Session {} peer={:?} Session {session_id} HeartResponse written: queue_depth={} queue_wait={:?} transport_write={:?} total_since_enqueue={:?}",
                        request.local_session_id,
                        request.peer_session_id,
                        completion.timings.queue_depth_at_enqueue,
                        completion.timings.queue_wait,
                        completion.timings.write_duration,
                        request.enqueued_at.elapsed(),
                    );
                }
            }
            if let Some(result_sender) = request.result_sender {
                let _ = result_sender.send(completion);
            }
            if failed {
                writer_closed.store(true, std::sync::atomic::Ordering::Release);
                writer_close_token.cancel();
                break;
            }
        }
    }

    pub fn id(&self) -> usize {
        self.session_id
    }

    pub(crate) fn close_signal(&self) -> CancellationToken {
        self.close_token.clone()
    }

    pub fn peer_session_id(&self) -> Option<usize> {
        *self.peer_session_id.read().unwrap_or_else(|error| error.into_inner())
    }

    fn set_peer_session_id(&self, session_id: usize) {
        *self.peer_session_id.write().unwrap_or_else(|error| error.into_inner()) = Some(session_id);
    }

    pub fn is_expired(&self) -> bool {
        !self.max_age.is_zero() && self.created_at.elapsed() >= self.max_age
    }

    pub(crate) async fn is_idle(&self) -> bool {
        self.streams.lock().await.is_none()
    }

    pub async fn set_idle_sender(&self, sender: mpsc::UnboundedSender<Arc<Session>>) {
        // The client pool installs this before the session is exposed.
        *self.idle_sender.lock().await = Some(sender);
    }

    pub async fn run(self: &Arc<Self>) -> std::io::Result<()> {
        if self.is_client {
            let padding = self.padding.read().await;
            let mut settings = HashMap::new();
            settings.insert("v".to_owned(), "2".to_owned());
            settings.insert("client".to_owned(), crate::PROGRAM_VERSION_NAME.to_owned());
            settings.insert("padding-md5".to_owned(), padding.md5.clone());
            settings.insert("session".to_owned(), self.id().to_string());
            drop(padding);
            let mut frame = Frame::new(Command::Settings, 0);
            frame.data = to_bytes(&settings);
            self.write_control(frame).await?;
        }

        let reader = self
            .reader
            .lock()
            .await
            .take()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AlreadyExists, "session reader already taken"))?;
        let session = Arc::clone(self);
        let session_id = self.id();
        tokio::spawn(Self::do_main_loop_task(session, session_id, reader));
        if self.is_client {
            let session = Arc::downgrade(self);
            let close_token = self.close_token.clone();
            tokio::spawn(Session::do_heartbeat_task(session, session_id, close_token));
        }
        if !self.max_age.is_zero() {
            let session = Arc::downgrade(self);
            let close_token = self.close_token.clone();
            let remaining = self.max_age.saturating_sub(self.created_at.elapsed());
            tokio::spawn(Self::do_wait_expiration(session, session_id, close_token, remaining));
        }
        Ok(())
    }

    async fn do_main_loop_task(session: Arc<Session>, session_id: usize, reader: tokio::io::ReadHalf<BoxTransport>) {
        let mn = method_name_unstable!();
        let result = Arc::clone(&session).receive_loop(reader).await;
        let peer_session_id = session.peer_session_id();
        match result {
            Ok(()) => log::debug!("{mn} -- Session {session_id} peer={peer_session_id:?} receive loop stopped",),
            Err(error) => log::warn!("{mn} -- Session {session_id} peer={peer_session_id:?} receive loop failed: {error}"),
        }
        let _ = session.shutdown().await;
        log::debug!("{mn} -- Session {session_id} peer={peer_session_id:?} shut down");
    }

    async fn do_heartbeat_task(session: Weak<Session>, session_id: usize, close_token: CancellationToken) {
        let mn = method_name_unstable!();
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = close_token.cancelled() => break,
                _ = ticker.tick() => {}
            }
            let Some(session) = session.upgrade() else {
                break;
            };
            let peer_session_id = session.peer_session_id();
            if session.peer_version.load(std::sync::atomic::Ordering::Acquire) < 2 {
                continue;
            }

            let epoch = {
                let streams = session.streams.lock().await;
                if streams.is_some() || session.is_closed() {
                    continue;
                }
                session.stream_epoch.load(Ordering::Relaxed)
            };
            log::trace!("{mn} -- Session {session_id} peer={peer_session_id:?} sending idle heartbeat");

            let response = session.heart_response.notified();
            tokio::pin!(response);
            response.as_mut().enable();
            let dispatch_started = std::time::Instant::now();
            let timings = tokio::select! {
                _ = close_token.cancelled() => break,
                result = session.write_heartbeat(epoch) => match result {
                    Ok(timings) => timings,
                    Err(error) => {
                        if !session.retire_idle_probe(epoch).await {
                            continue;
                        }
                        log::warn!("{mn} -- Session {session_id} peer={peer_session_id:?} heartbeat dispatch/write failed after {:?}: {error}", dispatch_started.elapsed());
                        break;
                    }
                },
            };
            log::debug!(
                "{mn} -- Session {session_id} peer={peer_session_id:?} heartbeat written: enqueue_wait={:?} queue_depth={} queue_wait={:?} transport_write={:?}; awaiting response",
                timings.enqueue_wait,
                timings.queue_depth_at_enqueue,
                timings.queue_wait,
                timings.write_duration,
            );
            let response_started = std::time::Instant::now();
            let result = tokio::select! {
                _ = close_token.cancelled() => break,
                result = tokio::time::timeout(HEARTBEAT_TIMEOUT, response.as_mut()) => result,
            };
            match result {
                Ok(()) => log::trace!(
                    "{mn} -- Session {session_id} peer={peer_session_id:?} heartbeat response received after {:?}",
                    response_started.elapsed()
                ),
                Err(_) => {
                    if !session.retire_idle_probe(epoch).await {
                        continue;
                    }
                    log::warn!(
                        "{mn} -- Session {session_id} peer={peer_session_id:?} heartbeat response timed out after {:?}: enqueue_wait={:?} queue_depth={} queue_wait={:?} transport_write={:?}; closing stalled transport",
                        response_started.elapsed(),
                        timings.enqueue_wait,
                        timings.queue_depth_at_enqueue,
                        timings.queue_wait,
                        timings.write_duration,
                    );
                    break;
                }
            }
        }
    }

    async fn retire_idle_probe(&self, epoch: u64) -> bool {
        {
            let streams = self.streams.lock().await;
            if streams.is_some() || self.stream_epoch.load(Ordering::Relaxed) != epoch {
                return false;
            }
            self.closed.store(true, Ordering::Release);
            self.close_token.cancel();
        }
        let _ = self.shutdown().await;
        true
    }

    async fn do_wait_expiration(session: Weak<Session>, session_id: usize, close_token: CancellationToken, remaining: Duration) {
        tokio::select! {
            _ = close_token.cancelled() => return,
            _ = tokio::time::sleep(remaining) => {}
        }
        if let Some(session) = session.upgrade()
            && session.is_idle().await
        {
            let mn = method_name_unstable!();
            let psid = session.peer_session_id();
            log::debug!("{mn} -- Session {session_id} peer={psid:?} reached maximum age while idle; closing");
            let _ = session.shutdown().await;
        }
    }

    /// Accepts an incoming stream from the session.
    /// It's used by the server to receive streams initiated by the client.
    pub async fn accept_stream(&self) -> std::io::Result<Stream> {
        use std::io::{Error, ErrorKind::BrokenPipe, ErrorKind::Unsupported};
        let mut incoming = self.incoming.lock().await;
        let session_id = self.id();
        let receiver = incoming
            .as_mut()
            .ok_or_else(|| Error::new(Unsupported, "client sessions do not accept streams"))?;
        let stream = tokio::select! {
            stream = receiver.recv() => stream.ok_or_else(|| Error::new(BrokenPipe, format!("session {session_id} closed because of remote closure")))?,
            _ = self.close_token.cancelled() => return Err(Error::new(BrokenPipe, format!("session {session_id} closed because of cancellation"))),
        };
        if stream.is_closed() {
            return Err(Error::new(BrokenPipe, format!("session {session_id} stream closed")));
        }
        Ok(stream)
    }

    /// Opens a new outgoing stream in the session.
    /// It's used by the client to initiate streams to the server.
    pub async fn open_stream(self: &Arc<Self>) -> std::io::Result<Stream> {
        let stream = self.reserve_stream().await?;
        self.open_reserved_stream(stream).await
    }

    pub(crate) async fn reserve_stream(self: &Arc<Self>) -> std::io::Result<Stream> {
        use std::io::{Error, ErrorKind::BrokenPipe, ErrorKind::TimedOut, ErrorKind::WouldBlock};
        let session_id = self.id();
        if self.is_closed() {
            return Err(Error::new(BrokenPipe, format!("session {session_id} closed")));
        }
        let id = allocate_stream_id(&NEXT_STREAM_ID);
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let read_state = StreamReadState::new();

        {
            let mut active_stream = self.streams.lock().await;
            // Re-check under the streams lock so we cannot insert after shutdown drained.
            if self.is_closed() {
                return Err(Error::new(BrokenPipe, format!("session {session_id} closed")));
            }
            if self.is_expired() {
                return Err(Error::new(TimedOut, format!("session {session_id} reached its maximum age")));
            }
            if active_stream.is_some() {
                return Err(Error::new(WouldBlock, format!("session {session_id} stream limit reached")));
            }
            *active_stream = Some((id, StreamState::new(remote, id, Arc::downgrade(self), Arc::clone(&read_state))));
            self.stream_epoch.fetch_add(1, Ordering::Relaxed);
            let mn = method_name_unstable!();
            let psid = self.peer_session_id();
            log::debug!("{mn} -- Session {session_id} peer={psid:?} reserved stream {id}");
        }
        Ok(Stream::new(id, Arc::downgrade(self), local, read_state))
    }

    pub(crate) async fn open_reserved_stream(self: &Arc<Self>, stream: Stream) -> std::io::Result<Stream> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let session_id = self.id();
        let stream_id = stream.id();
        if let Err(error) = self.enqueue_frame(Frame::new(Command::Syn, stream_id), true).await {
            self.remove_stream_by_id(stream_id).await;
            return Err(error);
        }
        if self.is_closed() {
            self.remove_stream_by_id(stream_id).await;
            return Err(Error::new(BrokenPipe, format!("session {session_id} closed")));
        }

        Ok(stream)
    }

    pub(crate) async fn send_fin_by_id(self: &Arc<Self>, stream_id: u32) -> std::io::Result<Option<()>> {
        let remote_fin = {
            let mut active = self.streams.lock().await;
            let Some((active_id, stream)) = active.as_mut() else {
                return Ok(None);
            };
            if *active_id != stream_id {
                return Ok(None);
            }
            if stream.local_fin {
                return Ok(Some(()));
            }
            stream.local_fin = true;
            stream.read_state.write_close_token.cancel();
            stream.remote_fin
        };
        self.enqueue_fin(stream_id).await?;
        if remote_fin {
            self.finish_stream_if_closed(stream_id).await;
        }
        Ok(Some(()))
    }

    async fn enqueue_fin(&self, stream_id: u32) -> std::io::Result<()> {
        self.write_control(Frame::new(Command::Fin, stream_id)).await
    }

    pub(crate) async fn close_stream_by_id(self: &Arc<Self>, stream_id: u32) -> std::io::Result<()> {
        if self.is_closed() {
            return Ok(());
        }
        let result = self.send_fin_by_id(stream_id).await;
        if matches!(result, Ok(None)) {
            return Ok(());
        }
        if let Err(error) = &result {
            let mn = method_name_unstable!();
            let session_id = self.id();
            let peer = self.peer_session_id();
            log::warn!("{mn} -- Session {session_id} peer={peer:?} failed to send FIN for stream {stream_id}: {error}");
        }
        self.finish_or_retire_stream(stream_id, result.is_ok()).await;
        if let Err(error) = result
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error);
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> std::io::Result<()> {
        self.closed.store(true, std::sync::atomic::Ordering::Release);
        self.close_token.cancel();
        self.reader.lock().await.take();
        if let Some((_, entry)) = self.streams.lock().await.take() {
            entry.read_state.abort();
        }
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    async fn write_control(&self, frame: Frame) -> std::io::Result<()> {
        self.enqueue_frame(frame, false).await
    }

    async fn write_heartbeat(&self, epoch: u64) -> std::io::Result<WriteTimings> {
        self.enqueue_encoded_with_mode(
            &self.control_sender,
            Frame::new(Command::HeartRequest, 0).encode()?,
            false,
            Some(epoch),
            Some(HEARTBEAT_QUEUE_TIMEOUT),
        )
        .await
    }

    fn queue_control(&self, frame: Frame) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        let heartbeat_response_session_id = (frame.command == Command::HeartResponse).then_some(self.id());
        let queue_depth_at_enqueue = self.control_sender.max_capacity().saturating_sub(self.control_sender.capacity());
        let enqueued_at = std::time::Instant::now();
        self.control_sender
            .try_send(WriteRequest {
                bytes: frame.encode()?,
                disable_buffering_after: false,
                local_session_id: self.id(),
                peer_session_id: self.peer_session_id(),
                enqueue_wait: Duration::ZERO,
                queue_depth_at_enqueue,
                enqueued_at,
                heartbeat_session_id: None,
                heartbeat_response_session_id,
                result_sender: None,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::new(ErrorKind::WouldBlock, "AnyTLS control queue is full"),
                mpsc::error::TrySendError::Closed(_) => Error::new(ErrorKind::BrokenPipe, "AnyTLS writer task closed"),
            })
    }

    async fn enqueue_frame(&self, frame: Frame, disable_buffering_after: bool) -> std::io::Result<()> {
        self.enqueue_encoded_with_mode(&self.control_sender, frame.encode()?, disable_buffering_after, None, None)
            .await
            .map(|_| ())
    }

    #[cfg(test)]
    async fn enqueue_bytes(&self, bytes: Vec<u8>, disable_buffering_after: bool) -> std::io::Result<()> {
        self.enqueue_encoded_with_mode(&self.data_sender, bytes, disable_buffering_after, None, None)
            .await
            .map(|_| ())
    }

    async fn enqueue_encoded_with_mode(
        &self,
        sender: &mpsc::Sender<WriteRequest>,
        bytes: Vec<u8>,
        disable_buffering_after: bool,
        idle_probe_epoch: Option<u64>,
        queue_timeout: Option<Duration>,
    ) -> std::io::Result<WriteTimings> {
        use std::io::{Error, ErrorKind};
        let session_id = self.id();
        let enqueue_started = std::time::Instant::now();
        let heartbeat_session_id = idle_probe_epoch.map(|_| session_id);
        let permit = if let Some(queue_timeout) = queue_timeout {
            tokio::select! {
                result = tokio::time::timeout(queue_timeout, sender.reserve()) => match result {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return Err(Error::new(ErrorKind::BrokenPipe, "writer task closed")),
                    Err(_) => {
                        if let Some(session_id) = heartbeat_session_id {
                            let queue_depth = self
                                .control_sender
                                .max_capacity()
                                .saturating_sub(self.control_sender.capacity());
                            let mn = method_name_unstable!();
                            log::warn!(
                                "{mn} -- Session {session_id} peer={:?} heartbeat queue admission timed out: enqueue_wait={:?} queue_depth={queue_depth}",
                                self.peer_session_id(),
                                enqueue_started.elapsed(),
                            );
                        }
                        return Err(Error::new(ErrorKind::TimedOut, "AnyTLS heartbeat write queue admission timed out"));
                    }
                },
                _ = self.close_token.cancelled() => return Err(Error::new(ErrorKind::BrokenPipe, format!("session {session_id} closed in enqueue_encoded_with_mode"))),
            }
        } else {
            tokio::select! {
                result = sender.reserve() => result.map_err(|_| Error::new(ErrorKind::BrokenPipe, "writer task closed"))?,
                _ = self.close_token.cancelled() => return Err(Error::new(ErrorKind::BrokenPipe, format!("session {session_id} closed in enqueue_encoded_with_mode"))),
            }
        };
        let enqueue_wait = enqueue_started.elapsed();
        let queue_depth_at_enqueue = sender.max_capacity().saturating_sub(sender.capacity()).saturating_sub(1);
        let idle_guard = if let Some(epoch) = idle_probe_epoch {
            let streams = self.streams.lock().await;
            if streams.is_some() || self.stream_epoch.load(Ordering::Relaxed) != epoch || self.is_closed() {
                return Err(Error::new(ErrorKind::Interrupted, "idle heartbeat superseded by stream activity"));
            }
            Some(streams)
        } else {
            None
        };
        let (result_sender, result_receiver) = oneshot::channel();
        permit.send(WriteRequest {
            bytes,
            disable_buffering_after,
            local_session_id: self.id(),
            peer_session_id: self.peer_session_id(),
            enqueue_wait,
            queue_depth_at_enqueue,
            enqueued_at: std::time::Instant::now(),
            heartbeat_session_id,
            heartbeat_response_session_id: None,
            result_sender: Some(result_sender),
        });
        drop(idle_guard);
        tokio::select! {
            result = result_receiver => {
                let completion = result.map_err(|_| Error::new(ErrorKind::BrokenPipe, "writer task closed"))?;
                let timings = completion.timings;
                completion.result?;
                Ok(timings)
            },
            _ = self.close_token.cancelled() => Err(Error::new(ErrorKind::BrokenPipe, format!("session {session_id} closed in enqueue_encoded_with_mode (result_receiver)"))),
        }
    }

    async fn receive_loop(self: Arc<Self>, mut reader: tokio::io::ReadHalf<BoxTransport>) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::InvalidData};
        let session_id = self.id();
        let mn = method_name_unstable!();
        loop {
            let result = tokio::select! {
                result = Frame::read_from_or_eof(&mut reader) => result,
                _ = self.close_token.cancelled() => break Ok(()),
            };
            let psid = self.peer_session_id();
            let frame = match result {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    log::debug!("{mn} -- Session {session_id} peer={psid:?} peer closed transport");
                    break Ok(());
                }
                Err(error) if is_peer_disconnect(&error) => {
                    log::debug!("{mn} -- Session {session_id} peer={psid:?} transport reset: {error}");
                    break Ok(());
                }
                Err(error) => break Err(error),
            };
            let stream_id = frame.stream_id;
            if !frame.command.valid_stream_id(stream_id) {
                break Err(Error::new(InvalidData, "invalid stream id for command"));
            }
            if !frame.command.allows_data() && !frame.data.is_empty() {
                break Err(Error::new(InvalidData, "command must not contain data"));
            }
            match frame.command {
                Command::Push => {
                    let stream = self.streams.lock().await.as_ref().and_then(|(active_id, entry)| {
                        (*active_id == stream_id && !entry.remote_fin).then(|| {
                            (
                                entry.push_sender.clone(),
                                Arc::clone(&entry.push_slots),
                                entry.read_state.close_token.clone(),
                            )
                        })
                    });
                    if let Some((push_sender, push_slots, close_token)) = stream {
                        let permit = tokio::select! {
                            biased;
                            _ = self.close_token.cancelled() => break Ok(()),
                            _ = close_token.cancelled() => continue,
                            permit = push_slots.acquire_many_owned(frame.data.len() as u32) => {
                                permit.map_err(|_| Error::new(std::io::ErrorKind::BrokenPipe, "inbound byte budget closed"))?
                            }
                        };
                        tokio::select! {
                            biased;
                            _ = self.close_token.cancelled() => break Ok(()),
                            _ = close_token.cancelled() => continue,
                            result = push_sender.send(PushMessage::Data(frame.data, permit)) => {
                                result.map_err(|_| Error::new(std::io::ErrorKind::BrokenPipe, "inbound push worker closed"))?;
                            }
                        }
                    }
                }
                Command::Waste => {}
                Command::Syn => self.on_receive_syn_cmd(stream_id).await?,
                Command::Fin => self.on_receive_fin_cmd(stream_id).await?,
                Command::Settings => self.on_receive_settings(&frame.data).await?,
                Command::SynAck => {
                    if !frame.data.is_empty() {
                        let i = String::from_utf8_lossy(&frame.data);
                        let peer = self.peer_session_id();
                        log::warn!(
                            "{mn} -- Session {session_id} peer={peer:?} stream {stream_id} received SynAck with unexpected data: {i}",
                        );
                        if self.is_client {
                            let reason: Arc<str> = String::from_utf8_lossy(&frame.data).into_owned().into();
                            self.refuse_stream_by_id(stream_id, reason).await;
                        } else {
                            self.remove_stream_by_id(stream_id).await;
                        }
                    }
                }
                Command::HeartRequest => {
                    let peer = self.peer_session_id();
                    log::trace!("{mn} -- Session {session_id} peer={peer:?} received HeartRequest");
                    if let Err(error) = self.queue_control(Frame::new(Command::HeartResponse, stream_id)) {
                        log::warn!("{mn} -- Session {session_id} peer={peer:?} failed to enqueue HeartResponse: {error}");
                        return Err(error);
                    }
                }
                Command::HeartResponse => {
                    let peer = self.peer_session_id();
                    log::trace!("{mn} -- Session {session_id} peer={peer:?} received HeartResponse");
                    self.heart_response.notify_waiters();
                }
                Command::ServerSettings => {
                    let map = from_bytes(&frame.data);
                    if self.is_client
                        && let Some(version) = map.get("v").and_then(|value| value.parse().ok())
                    {
                        self.peer_version.store(version, std::sync::atomic::Ordering::Release);
                    }
                    if self.is_client
                        && let Some(session_id) = map.get("session").and_then(|value| value.parse().ok())
                    {
                        self.set_peer_session_id(session_id);
                    }
                }
                Command::UpdatePaddingScheme => {
                    if self.is_client
                        && let Some(factory) = PaddingFactory::new(&frame.data)
                    {
                        *self.padding.write().await = factory;
                    }
                }
                Command::Alert => {
                    let info = String::from_utf8_lossy(&frame.data);
                    let peer = self.peer_session_id();
                    log::warn!("{mn} -- Session {session_id} peer={peer:?} received alert: {info}");
                    break Ok(());
                }
            }
        }
    }

    async fn on_receive_settings(&self, data: &[u8]) -> std::io::Result<()> {
        if self.is_client {
            return Ok(());
        }
        self.received_settings.store(true, std::sync::atomic::Ordering::Release);
        let map = from_bytes(data);
        if let Some(session_id) = map.get("session").and_then(|value| value.parse().ok()) {
            self.set_peer_session_id(session_id);
        }
        let psid = self.peer_session_id();
        let mn = method_name_unstable!();
        let session_id = self.id();
        log::debug!("{mn} -- Session {session_id} peer={psid:?} received cmdSettings");
        let update_scheme = {
            let padding = self.padding.read().await;
            (map.get("padding-md5") != Some(&padding.md5)).then(|| padding.raw_scheme().to_vec())
        };
        if let Some(scheme) = update_scheme {
            let mut update = Frame::new(Command::UpdatePaddingScheme, 0);
            update.data = scheme;
            self.queue_control(update)?;
        }
        if map.get("v").and_then(|value| value.parse::<u8>().ok()).unwrap_or(0) >= 2 {
            self.peer_version.store(2, std::sync::atomic::Ordering::Release);
            let mut server_settings = HashMap::new();
            server_settings.insert("v".to_owned(), "2".to_owned());
            server_settings.insert("session".to_owned(), self.id().to_string());
            let mut frame = Frame::new(Command::ServerSettings, 0);
            frame.data = to_bytes(&server_settings);
            self.queue_control(frame)?;
        }
        Ok(())
    }

    async fn on_receive_fin_cmd(self: &Arc<Self>, stream_id: u32) -> std::io::Result<()> {
        let stream = {
            let mut active = self.streams.lock().await;
            match active.as_mut() {
                Some((active_id, stream)) if *active_id == stream_id && !stream.remote_fin => {
                    stream.remote_fin = true;
                    Some((stream.push_sender.clone(), stream.read_state.close_token.clone()))
                }
                Some(_) | None => None,
            }
        };
        if let Some((push_sender, close_token)) = stream {
            tokio::select! {
                biased;
                _ = self.close_token.cancelled() => {}
                _ = close_token.cancelled() => self.on_stream_read_closed(stream_id).await,
                result = push_sender.send(PushMessage::Fin) => {
                    result.map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "inbound push worker closed"))?;
                }
            }
        }
        Ok(())
    }

    async fn on_stream_read_closed(self: &Arc<Self>, stream_id: u32) {
        if let Some((active_id, stream)) = self.streams.lock().await.as_mut()
            && *active_id == stream_id
        {
            stream.read_closed = true;
        }
        self.finish_stream_if_closed(stream_id).await;
    }

    async fn finish_stream_if_closed(self: &Arc<Self>, stream_id: u32) {
        let should_finish = self
            .streams
            .lock()
            .await
            .as_ref()
            .is_some_and(|(active_id, stream)| *active_id == stream_id && stream.local_fin && stream.remote_fin && stream.read_closed);
        if should_finish {
            self.remove_stream_by_id(stream_id).await;
        }
    }

    async fn finish_or_retire_stream(self: &Arc<Self>, stream_id: u32, fin_sent: bool) {
        if !self.is_client {
            self.remove_stream_by_id(stream_id).await;
            return;
        }
        if !fin_sent {
            let _ = self.shutdown().await;
            return;
        }

        let retire = {
            let active = self.streams.lock().await;
            if !active.as_ref().is_some_and(|(active_id, _)| *active_id == stream_id) {
                return;
            }
            if self.is_expired() {
                self.closed.store(true, Ordering::Release);
                self.close_token.cancel();
                true
            } else {
                false
            }
        };
        if retire {
            let _ = self.shutdown().await;
            return;
        }

        let session = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(STREAM_CLOSE_TIMEOUT).await;
            let Some(session) = session.upgrade() else {
                return;
            };
            {
                let active = session.streams.lock().await;
                if !active.as_ref().is_some_and(|(active_id, _)| *active_id == stream_id) {
                    return;
                }
                session.closed.store(true, Ordering::Release);
                session.close_token.cancel();
            }
            let mn = method_name_unstable!();
            let peer = session.peer_session_id();
            let id = session.id();
            log::warn!("{mn} -- Session {id} peer={peer:?} stream {stream_id} close handshake timed out; closing session");
            let _ = session.shutdown().await;
        });
    }

    /// Finish the stream state identified by `stream_id` by removing it from the container of active stream states and dropping its resources.
    /// If this was the last active stream state, mark the session as idle.
    async fn remove_stream_by_id(self: &Arc<Self>, stream_id: u32) {
        let mn = method_name_unstable!();
        let session_id = self.id();
        let psid = self.peer_session_id();
        let became_idle = {
            let mut active = self.streams.lock().await;
            let removed = if active.as_ref().is_some_and(|(active_id, _)| *active_id == stream_id) {
                active.take()
            } else {
                None
            };
            let Some((_, entry)) = removed else {
                return;
            };
            entry.read_state.abort();
            log::trace!("{mn} -- Session {session_id} peer={psid:?} removed stream {stream_id}");
            active.is_none()
        };

        if became_idle {
            if self.is_expired() {
                log::debug!("{mn} -- Session {session_id} peer={psid:?} expired session drained; shutting it down");
                let _ = self.shutdown().await;
                return;
            }
            let sender = self.idle_sender.lock().await.clone();
            if let Some(sender) = sender
                && let Err(e) = sender.send(Arc::clone(self))
            {
                log::warn!("{mn} -- Session {session_id} peer={psid:?} failed to send session to idle pool: {e}");
            }
            log::trace!("{mn} -- Session {session_id} peer={psid:?} session became idle",);
        }
    }

    async fn refuse_stream_by_id(self: &Arc<Self>, stream_id: u32, reason: Arc<str>) {
        {
            let mut active = self.streams.lock().await;
            if let Some((active_id, stream)) = active.as_mut()
                && *active_id == stream_id
            {
                stream.read_state.refuse(reason);
                stream.read_state.write_close_token.cancel();
            }
        }
        self.remove_stream_by_id(stream_id).await;
    }

    async fn on_receive_syn_cmd(self: &Arc<Self>, stream_id: u32) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::BrokenPipe, ErrorKind::InvalidData};
        if self.is_client || self.incoming_sender.is_none() {
            return Ok(());
        }
        if !self.received_settings.load(std::sync::atomic::Ordering::Acquire) {
            let mut alert = Frame::new(Command::Alert, 0);
            alert.data = b"client did not send its settings".to_vec();
            self.queue_control(alert)?;
            return Err(Error::new(InvalidData, "settings required before SYN"));
        }
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let read_state = StreamReadState::new();
        let rejection = {
            let mut rejection = None;
            let mut active = self.streams.lock().await;
            if active.as_ref().is_some_and(|(active_id, _)| *active_id == stream_id) {
                return Ok(());
            }
            if self.is_closed() {
                return Err(Error::new(BrokenPipe, "session closed"));
            }
            if self.is_expired() {
                rejection = Some("session reached its maximum age");
            } else if active.is_some() {
                rejection = Some("session stream limit reached");
            } else {
                *active = Some((
                    stream_id,
                    StreamState::new(remote, stream_id, Arc::downgrade(self), Arc::clone(&read_state)),
                ));
                self.stream_epoch.fetch_add(1, Ordering::Relaxed);
                let mn = method_name_unstable!();
                let id = self.id();
                let psid = self.peer_session_id();
                log::debug!("{mn} -- Session {id} peer={psid:?} accepted stream {stream_id}");
            }
            rejection
        };
        if let Some(message) = rejection {
            let mut frame = Frame::new(Command::SynAck, stream_id);
            frame.data = message.as_bytes().to_vec();
            self.queue_control(frame)?;
            return Ok(());
        }
        let stream = Stream::new(stream_id, Arc::downgrade(self), local, read_state);
        let sender = self.incoming_sender.as_ref().unwrap().clone();
        match sender.try_send(stream) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let mut rejection = Frame::new(Command::SynAck, stream_id);
                rejection.data = b"incoming stream queue is full".to_vec();
                self.queue_control(rejection)?;
                self.remove_stream_by_id(stream_id).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.remove_stream_by_id(stream_id).await;
                return Err(Error::new(BrokenPipe, "stream receiver closed"));
            }
        }
        Ok(())
    }
}

struct Writer {
    transport: tokio::io::WriteHalf<BoxTransport>,

    /// Client Settings and SYN are buffered until the initial SYN write request
    /// disables buffering, then flushed before subsequent data frames.
    buffering: bool,

    /// Buffer frames that have not yet been truly written to the underlying connection.
    buffered: Vec<u8>,

    /// Indicates whether padding still needs to be sent.
    /// Once the padding scheme's termination condition is met, this is set to false, and subsequent frames are sent directly without padding.
    send_padding: bool,

    /// Records the number of logical writes, used to select the padding record size.
    packet_counter: Arc<std::sync::atomic::AtomicU32>,
}

impl Writer {
    async fn write_conn(&mut self, mut bytes: Vec<u8>, padding: &Arc<RwLock<PaddingFactory>>) -> std::io::Result<usize> {
        if self.buffering {
            self.buffered.extend_from_slice(&bytes);
            return Ok(bytes.len());
        }
        if !self.buffered.is_empty() {
            let mut buffered = std::mem::take(&mut self.buffered);
            buffered.append(&mut bytes);
            bytes = buffered;
        }
        if self.send_padding {
            let packet_counter = self.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let factory = padding.read().await;
            let sizes = (packet_counter < factory.stop).then(|| factory.generate_record_payload_sizes(packet_counter));
            drop(factory);
            if let Some(sizes) = sizes {
                for size in sizes {
                    if size == CHECK_MARK {
                        if bytes.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let size = size as usize;
                    if bytes.len() > size {
                        self.transport.write_all(&bytes[..size]).await?;
                        bytes.drain(..size);
                    } else if !bytes.is_empty() {
                        let padding_len = size.saturating_sub(bytes.len() + HEADER_OVERHEAD_SIZE);
                        if padding_len > 0 {
                            let mut waste = Frame::new(Command::Waste, 0).encode()?;
                            waste[5..7].copy_from_slice(&(padding_len as u16).to_be_bytes());
                            waste.resize(HEADER_OVERHEAD_SIZE + padding_len, 0);
                            bytes.extend_from_slice(&waste);
                        }
                        self.transport.write_all(&bytes).await?;
                        bytes.clear();
                    } else {
                        let mut waste = Frame::new(Command::Waste, 0).encode()?;
                        waste[5..7].copy_from_slice(&(size as u16).to_be_bytes());
                        waste.resize(HEADER_OVERHEAD_SIZE + size, 0);
                        self.transport.write_all(&waste).await?;
                    }
                }
            } else {
                self.send_padding = false;
            }
        }
        if !bytes.is_empty() {
            self.transport.write_all(&bytes).await?;
        }
        self.transport.flush().await?;
        Ok(bytes.len())
    }
}

pub(crate) type StreamReader = OwnedMutexGuard<tokio::io::ReadHalf<tokio::io::DuplexStream>>;

pub struct Stream {
    id: u32,
    session: Weak<Session>,
    session_id: usize,
    reader: Arc<Mutex<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    writer: Arc<Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    closed: bool,
    read_state: Arc<StreamReadState>,
    handshake_reported: std::sync::atomic::AtomicBool,
}

impl Stream {
    fn new(id: u32, session: Weak<Session>, io: tokio::io::DuplexStream, read_state: Arc<StreamReadState>) -> Self {
        let mn = method_name_unstable!();
        let (reader, writer) = tokio::io::split(io);
        let session_ref = session.upgrade();
        let session_id = session_ref.as_ref().map(|session| session.id()).unwrap_or_default();
        let peer_session_id = session_ref.as_ref().and_then(|session| session.peer_session_id());
        log::trace!("{mn} -- Session {session_id} peer={peer_session_id:?} creating stream {id}");
        Self {
            id,
            session,
            session_id,
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            closed: false,
            read_state,
            handshake_reported: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn session_id(&self) -> usize {
        self.session_id
    }

    #[cfg(test)]
    pub(crate) fn session(&self) -> Option<Arc<Session>> {
        self.session.upgrade()
    }

    pub(crate) async fn lock_reader_owned(&self) -> StreamReader {
        Arc::clone(&self.reader).lock_owned().await
    }

    pub(crate) fn read_eof(&self) -> std::io::Result<()> {
        self.read_state.eof()
    }

    pub async fn read(&self, data: &mut [u8]) -> std::io::Result<usize> {
        let size = self.reader.lock().await.read(data).await?;
        if size == 0 && !data.is_empty() {
            self.read_eof()?;
        }
        Ok(size)
    }

    /// Writes at most one protocol frame and waits for its physical completion.
    /// The returned count can be smaller than the supplied slice.
    pub async fn write(&self, data: &[u8]) -> std::io::Result<usize> {
        let permit = self.reserve_write().await?;
        let (size, receipt) = permit.send(data)?;
        receipt.await?;
        Ok(size)
    }

    pub(crate) async fn reserve_write(&self) -> std::io::Result<DataWritePermit> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let session = self
            .session
            .upgrade()
            .ok_or_else(|| self.read_state.write_error("AnyTLS session closed"))?;
        let enqueue_started = std::time::Instant::now();
        let (permit, active) = tokio::select! {
            biased;
            _ = self.read_state.write_close_token.cancelled() => return Err(self.read_state.write_error("AnyTLS stream closed")),
            _ = session.close_token.cancelled() => return Err(Error::new(BrokenPipe, "AnyTLS session closed")),
            result = async {
                let permit = session.data_sender.clone().reserve_owned().await.map_err(|_| Error::new(BrokenPipe, "AnyTLS writer task closed"))?;
                let active = Arc::clone(&session.streams).lock_owned().await;
                Ok::<_, Error>((permit, active))
            } => result?,
        };
        if session.is_closed() || !active.as_ref().is_some_and(|(id, stream)| *id == self.id && !stream.local_fin) {
            return Err(self.read_state.write_error("AnyTLS stream closed"));
        }
        Ok(DataWritePermit {
            permit,
            active,
            session,
            enqueue_started,
        })
    }

    pub async fn handshake_success(&self) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        let session = self
            .session
            .upgrade()
            .ok_or_else(|| Error::new(BrokenPipe, format!("session {} closed", self.session_id)))?;
        if session.peer_version.load(Acquire) >= 2 && self.handshake_reported.compare_exchange(false, true, AcqRel, Acquire).is_ok() {
            session.write_control(Frame::new(Command::SynAck, self.id)).await?;
        }
        Ok(())
    }

    pub async fn handshake_failure(&self, error: &str) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        use std::sync::atomic::Ordering::{AcqRel, Acquire};
        let session = self
            .session
            .upgrade()
            .ok_or_else(|| Error::new(BrokenPipe, format!("session {} closed", self.session_id)))?;
        if session.peer_version.load(Acquire) >= 2 && self.handshake_reported.compare_exchange(false, true, AcqRel, Acquire).is_ok() {
            let mut frame = Frame::new(Command::SynAck, self.id);
            frame.data = error.as_bytes().to_vec();
            session.write_control(frame).await?;
        }
        Ok(())
    }

    pub async fn close(&mut self) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.read_state.write_close_token.cancel();
        self.read_state.abort();
        let close_result = match self.session.upgrade() {
            Some(session) => session.close_stream_by_id(self.id).await,
            None => Err(Error::new(BrokenPipe, format!("session {} closed already", self.session_id))),
        };
        let shutdown_result = self.writer.lock().await.shutdown().await;
        close_result.and(shutdown_result)
    }

    pub async fn shutdown_write_by_send_fin_to_remote(&self) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind::BrokenPipe};
        let session_id = self.session_id;
        match self.session.upgrade() {
            Some(session) => session
                .send_fin_by_id(self.id)
                .await?
                .ok_or_else(|| Error::new(BrokenPipe, format!("stream {} closed", self.id))),
            None => Err(Error::new(BrokenPipe, format!("can't send FIN for session {session_id} closed"))),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let id = self.id;
        let session_id = self.session_id;
        let mn = method_name_unstable!();
        let psid = self.session.upgrade().as_ref().and_then(|session| session.peer_session_id());

        log::trace!("{mn} -- Session {session_id} peer={psid:?} dropping stream {id}");
        if self.closed {
            log::debug!("{mn} -- Session {session_id} peer={psid:?} stream {id} already closed, skipping drop");
            return;
        }
        self.closed = true;
        self.read_state.write_close_token.cancel();
        self.read_state.abort();

        let Some(session) = self.session.upgrade() else {
            log::debug!("{mn} -- Session {session_id} peer={psid:?} already closed but stream {id} lifecycle is incomplete, skipping drop");
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = session.close_stream_by_id(id).await;
                log::debug!("{mn} -- Session {session_id} peer={psid:?} dropped stream {id} successfully");
            });
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::DEFAULT_SCHEME;

    #[test]
    fn stream_ids_skip_zero_when_wrapping() {
        let counter = AtomicU32::new(u32::MAX - 1);
        assert_eq!(allocate_stream_id(&counter), u32::MAX);
        assert_eq!(allocate_stream_id(&counter), 1);
    }

    #[test]
    fn stream_ids_are_allocated_globally() {
        let first = allocate_stream_id(&NEXT_STREAM_ID);
        let second = allocate_stream_id(&NEXT_STREAM_ID);
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
    }

    #[derive(Default)]
    pub(crate) struct WriteGate {
        blocked: std::sync::atomic::AtomicBool,
        dropped: std::sync::atomic::AtomicBool,
        waker: std::sync::Mutex<Option<std::task::Waker>>,
        pending: Notify,
    }

    impl WriteGate {
        pub(crate) fn block(&self) {
            self.blocked.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        pub(crate) fn release(&self) {
            self.blocked.store(false, std::sync::atomic::Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }

        pub(crate) async fn wait_pending(&self) {
            tokio::time::timeout(Duration::from_secs(1), self.pending.notified()).await.unwrap();
        }
    }

    struct GatedTransport {
        inner: tokio::io::DuplexStream,
        gate: Arc<WriteGate>,
    }

    impl Drop for GatedTransport {
        fn drop(&mut self) {
            self.gate.dropped.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl tokio::io::AsyncRead for GatedTransport {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl tokio::io::AsyncWrite for GatedTransport {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.gate.blocked.load(std::sync::atomic::Ordering::SeqCst) {
                *self.gate.waker.lock().unwrap() = Some(context.waker().clone());
                self.gate.pending.notify_one();
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_write(context, data)
        }

        fn poll_flush(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    pub(crate) fn gated_transport() -> (BoxTransport, tokio::io::DuplexStream, Arc<WriteGate>) {
        let (inner, peer) = tokio::io::duplex(128 * 1024);
        let gate = Arc::new(WriteGate::default());
        (
            Box::new(GatedTransport {
                inner,
                gate: Arc::clone(&gate),
            }),
            peer,
            gate,
        )
    }

    #[tokio::test]
    async fn cancelled_adapter_write_uses_only_replacement_bytes() {
        use tokio::io::AsyncWrite;
        let (transport, mut peer, _) = gated_transport();
        let session = Session::new_client(
            1,
            transport,
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        let mut io = crate::StreamIo::new(stream);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        let reserved = session.data_sender.reserve_many(64).await.unwrap();
        let pending =
            std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut io).poll_write(cx, b"cancelled payload"))).await;
        assert!(pending.is_pending(), "all data queue slots are reserved");
        drop(reserved);
        let size = io.write(b"x").await.unwrap();
        assert_eq!(size, 1, "only the replacement slice may be accepted");
        io.shutdown().await.unwrap();
        let push = Frame::read_from(&mut peer).await.unwrap();
        assert_eq!(push.command, Command::Push);
        assert_eq!(push.data, b"x");
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pending_write_reservation_rechecks_local_fin() {
        use tokio::io::AsyncWrite;
        let (transport, mut peer, _) = gated_transport();
        let session = Session::new_client(
            1,
            transport,
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        let mut io = crate::StreamIo::new(stream);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        let reserved = session.data_sender.reserve_many(64).await.unwrap();
        assert!(
            std::future::poll_fn(|cx| { std::task::Poll::Ready(std::pin::Pin::new(&mut io).poll_write(cx, b"pending")) })
                .await
                .is_pending()
        );
        let stream = io.stream();
        stream.shutdown_write_by_send_fin_to_remote().await.unwrap();
        let pending_error = tokio::time::timeout(Duration::from_secs(1), io.write(b"late"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(pending_error.kind(), std::io::ErrorKind::BrokenPipe);
        let new_error = tokio::time::timeout(Duration::from_secs(1), stream.write(b"late"))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(new_error.kind(), std::io::ErrorKind::BrokenPipe);
        drop(reserved);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pending_write_reservation_wakes_on_forced_close() {
        use tokio::io::AsyncWrite;
        for close_session in [false, true] {
            let (transport, _peer, _) = gated_transport();
            let session = Session::new_client(
                1,
                transport,
                Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
                DEFAULT_MAX_SESSION_AGE,
            );
            session.run().await.unwrap();
            let stream = session.open_stream().await.unwrap();
            let mut io = crate::StreamIo::new(stream);
            let reserved = session.data_sender.reserve_many(64).await.unwrap();
            assert!(
                std::future::poll_fn(|cx| { std::task::Poll::Ready(std::pin::Pin::new(&mut io).poll_write(cx, b"pending")) })
                    .await
                    .is_pending()
            );
            if close_session {
                session.shutdown().await.unwrap();
            } else {
                session.streams.lock().await.as_ref().unwrap().1.read_state.abort();
            }
            let error = tokio::time::timeout(Duration::from_secs(1), io.write(b"late"))
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            drop(reserved);
            session.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn control_frames_overtake_queued_data_frames() {
        let (transport, mut peer, gate) = gated_transport();
        let session = Session::new_client(
            1,
            transport,
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        session.enqueue_frame(Frame::new(Command::Syn, 1), true).await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);

        let mut first_data = Frame::new(Command::Push, 1);
        first_data.data = b"first".to_vec();
        gate.block();
        let first_session = Arc::clone(&session);
        let first_write = tokio::spawn(async move { first_session.enqueue_bytes(first_data.encode().unwrap(), false).await });
        gate.wait_pending().await;

        let mut second_data = Frame::new(Command::Push, 1);
        second_data.data = b"second".to_vec();
        let second_session = Arc::clone(&session);
        let second_write = tokio::spawn(async move { second_session.enqueue_bytes(second_data.encode().unwrap(), false).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.data_sender.capacity() != 63 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second data frame should be queued behind the blocked write");
        session.queue_control(Frame::new(Command::HeartRequest, 0)).unwrap();

        gate.release();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().data, b"first");
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::HeartRequest);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().data, b"second");
        first_write.await.unwrap().unwrap();
        second_write.await.unwrap().unwrap();
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn blocked_heart_response_does_not_block_inbound_data() {
        let (transport, mut peer, gate) = gated_transport();
        let session = Session::new_client(1, transport, padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        gate.block();
        peer.write_all(&Frame::new(Command::HeartRequest, 0).encode().unwrap())
            .await
            .unwrap();
        gate.wait_pending().await;
        let mut push = Frame::new(Command::Push, stream.id());
        push.data = b"response".to_vec();
        peer.write_all(&push.encode().unwrap()).await.unwrap();
        let mut received = [0u8; 8];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut received))
                .await
                .unwrap()
                .unwrap(),
            8
        );
        assert_eq!(&received, b"response");
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_interrupts_blocked_writer_and_releases_transport() {
        let (transport, _peer, gate) = gated_transport();
        let session = Session::new_client(1, transport, padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        gate.block();
        let write = tokio::spawn(async move { stream.write(b"pending").await });
        gate.wait_pending().await;
        session.shutdown().await.unwrap();
        assert!(write.await.unwrap().is_err());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.dropped.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown must release transport without unblocking the peer");
        assert!(session.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_writer_times_out_and_closes_session() {
        let (transport, _peer, gate) = gated_transport();
        let session = Session::new_client(1, transport, padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        gate.block();
        let write = tokio::spawn(async move { stream.write(b"pending").await });
        gate.wait_pending().await;
        tokio::time::advance(WRITE_TIMEOUT).await;
        session.close_token.cancelled().await;
        assert!(session.is_closed());
        assert!(write.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn unanswered_v2_heartbeat_closes_silent_session() {
        let (transport, _peer, _gate) = gated_transport();
        let session = Session::new_client(1, transport, padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        session.remove_stream_by_id(stream.id()).await;
        session.peer_version.store(2, std::sync::atomic::Ordering::Release);
        tokio::task::yield_now().await;
        tokio::time::advance(HEARTBEAT_INTERVAL).await;
        tokio::task::yield_now().await;
        tokio::time::advance(HEARTBEAT_TIMEOUT).await;
        session.close_token.cancelled().await;
        assert!(session.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_response_timeout_starts_after_frame_is_written() {
        let (transport, mut peer, gate) = gated_transport();
        let padding = Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap()));
        let session = Session::new_client(1, transport, padding, DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        session.peer_version.store(2, std::sync::atomic::Ordering::Release);

        session.remove_stream_by_id(stream.id()).await;
        gate.block();
        tokio::time::advance(HEARTBEAT_INTERVAL).await;
        gate.wait_pending().await;
        tokio::time::advance(HEARTBEAT_TIMEOUT).await;
        assert!(!session.is_closed(), "a queued heartbeat is not an unanswered heartbeat");

        gate.release();
        let request = Frame::read_from(&mut peer).await.unwrap();
        assert_eq!(request.command, Command::HeartRequest);
        peer.write_all(&Frame::new(Command::HeartResponse, 0).encode().unwrap())
            .await
            .unwrap();
        for _turn in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!session.is_closed());
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn v1_session_does_not_send_proactive_heartbeats() {
        let (local, mut peer) = tokio::io::duplex(128 * 1024);
        let padding = Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap()));
        let session = Session::new_client(1, Box::new(local), padding, DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let _stream = session.open_stream().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        tokio::time::advance(HEARTBEAT_INTERVAL * 4).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), Frame::read_from(&mut peer))
                .await
                .is_err()
        );
        assert!(!session.is_closed());
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeats_keep_healthy_v2_session_open() {
        let (local, peer) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(local), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(2, Box::new(peer), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();
        let _stream = client.open_stream().await.unwrap();
        let _peer_stream = server.accept_stream().await.unwrap();
        for _probe in 0..4 {
            tokio::time::advance(HEARTBEAT_INTERVAL).await;
            for _turn in 0..20 {
                tokio::task::yield_now().await;
            }
            assert!(!client.is_closed());
            assert!(!server.is_closed());
        }
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[cfg(all(feature = "client", feature = "server"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_tls_bidirectional_load_does_not_lose_heartbeat_responses() {
        use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::task::JoinSet;

        tokio::time::timeout(Duration::from_secs(30), async {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let certificate = certified.cert.der().clone();
            let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key.into())
                .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate).unwrap();
            let client_config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (client_io, server_io) = tokio::join!(
                async {
                    let tcp = TcpStream::connect(address).await.unwrap();
                    connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap()
                },
                async {
                    let (tcp, _) = listener.accept().await.unwrap();
                    acceptor.accept(tcp).await.unwrap()
                }
            );
            let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
            let server = Session::new_server(2, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
            client.run().await.unwrap();
            server.run().await.unwrap();

            let mut transfers = JoinSet::new();
            let local = Arc::new(client.open_stream().await.unwrap());
            let remote = Arc::new(server.accept_stream().await.unwrap());
            for endpoint in [local, remote] {
                let writer = Arc::clone(&endpoint);
                transfers.spawn(async move {
                    let data = vec![0xa5; 16 * 1024];
                    for _chunk in 0..256 {
                        assert_eq!(writer.write(&data).await.unwrap(), data.len());
                        tokio::task::yield_now().await;
                    }
                });
                transfers.spawn(async move {
                    let mut remaining = 4 * 1024 * 1024;
                    let mut data = vec![0; 16 * 1024];
                    while remaining > 0 {
                        let size = endpoint.read(&mut data).await.unwrap();
                        assert!(size > 0 && size <= remaining);
                        assert!(data[..size].iter().all(|byte| *byte == 0xa5));
                        remaining -= size;
                    }
                });
            }
            for _probe in 0..128 {
                let response = client.heart_response.notified();
                tokio::pin!(response);
                response.as_mut().enable();
                client.write_control(Frame::new(Command::HeartRequest, 0)).await.unwrap();
                tokio::time::timeout(HEARTBEAT_TIMEOUT, response).await.unwrap();
            }
            while let Some(result) = transfers.join_next().await {
                result.unwrap();
            }
            assert!(!client.is_closed());
            assert!(!server.is_closed());
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
        })
        .await
        .expect("real TLS traffic and heartbeat probes should complete without a stall");
    }

    #[test]
    fn classifies_peer_disconnect_errors() {
        use std::io::ErrorKind;

        for kind in [
            ErrorKind::InvalidData,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::NotConnected,
        ] {
            assert!(!is_peer_disconnect(&std::io::Error::from(kind)));
        }
        assert!(is_peer_disconnect(&std::io::Error::from(ErrorKind::ConnectionReset)));
    }

    #[tokio::test]
    async fn peer_eof_shuts_down_session_without_receive_error() {
        let (session_io, peer_io) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(1, Box::new(session_io), padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();

        drop(peer_io);
        tokio::time::timeout(Duration::from_secs(1), session.close_token.cancelled())
            .await
            .unwrap();
        assert!(session.is_closed());
    }

    fn padding() -> Arc<RwLock<PaddingFactory>> {
        Arc::new(RwLock::new(PaddingFactory::new(DEFAULT_SCHEME).unwrap()))
    }

    #[tokio::test]
    async fn direct_session_api_rejects_new_streams_after_max_age_and_drains_existing_streams() {
        let (local, _peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(1, Box::new(local), padding(), Duration::from_millis(30));
        session.run().await.unwrap();
        let mut existing = session.open_stream().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;

        let error = match session.open_stream().await {
            Ok(_) => panic!("expired session must reject new streams"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(!session.is_closed(), "existing streams should be allowed to drain");

        existing.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), session.close_token.cancelled())
            .await
            .expect("expired session should close after its final stream drains");
    }

    #[tokio::test]
    async fn session_rejects_second_active_stream() {
        let (local, _peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(1, Box::new(local), padding(), DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let mut stream = session.open_stream().await.unwrap();

        let error = match session.open_stream().await {
            Ok(_) => panic!("a Session must not multiplex concurrent streams"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        stream.close().await.unwrap();
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn server_rejects_incoming_stream_after_max_age() {
        let (transport, mut peer, _gate) = gated_transport();
        let session = Session::new_server(1, transport, padding(), Duration::from_millis(1));
        session.received_settings.store(true, std::sync::atomic::Ordering::Release);
        tokio::time::sleep(Duration::from_millis(5)).await;

        session.on_receive_syn_cmd(1).await.unwrap();
        assert!(session.is_idle().await);
        let rejection = tokio::time::timeout(Duration::from_secs(1), Frame::read_from(&mut peer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rejection.command, Command::SynAck);
        assert_eq!(rejection.data, b"session reached its maximum age");
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn refusal_during_pending_syn_receipt_keeps_session_and_reports_reason() {
        use tokio::io::AsyncWriteExt;
        let (transport, mut peer, gate) = gated_transport();
        let session = Session::new_client(
            1,
            transport,
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        gate.block();
        let opening = tokio::spawn({
            let session = Arc::clone(&session);
            async move { session.open_stream().await }
        });
        gate.wait_pending().await;
        let stream_id = session.streams.lock().await.as_ref().unwrap().0;
        let mut refusal = Frame::new(Command::SynAck, stream_id);
        refusal.data = b"refused during syn".to_vec();
        peer.write_all(&refusal.encode().unwrap()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.streams.lock().await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the refusal must remove the reserved slot before the gate is released");
        assert!(!session.is_closed(), "a stream refusal must not close the session");
        gate.release();
        let stream = opening.await.unwrap().unwrap();
        let mut buffer = [0u8; 1];
        let error = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .expect("a refused read must not hang")
            .expect_err("a refused stream must fail reads");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("refused during syn"), "{error}");
    }

    #[tokio::test]
    async fn refusal_wakes_reservation_while_all_data_slots_are_held() {
        let (local, _peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(
            1,
            Box::new(local),
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        let held = session.data_sender.reserve_many(64).await.unwrap();
        let mut reservation = Box::pin(stream.reserve_write());
        let pending = std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(reservation.as_mut(), cx))).await;
        assert!(pending.is_pending(), "the reservation must wait while every data slot is held");
        session.refuse_stream_by_id(stream.id(), "refused under load".into()).await;
        let result = tokio::time::timeout(Duration::from_secs(1), &mut reservation)
            .await
            .expect("the refusal must wake the waiting reservation");
        assert!(result.is_err(), "the reservation must fail after a refusal");
        let error = result.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("refused under load"), "{error}");
        assert_eq!(held.len(), 64, "the refusal must not free data capacity");
    }

    #[tokio::test]
    async fn late_refusal_for_old_stream_does_not_poison_the_active_stream() {
        use tokio::io::AsyncWriteExt;
        let (local, mut peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(
            1,
            Box::new(local),
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let old = session.open_stream().await.unwrap();
        let old_id = old.id();
        session.refuse_stream_by_id(old_id, "refused old".into()).await;
        for _ in 0..100 {
            if session.streams.lock().await.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let active = session.open_stream().await.unwrap();
        let active_id = active.id();
        let mut late = Frame::new(Command::SynAck, old_id);
        late.data = b"late refusal".to_vec();
        peer.write_all(&late.encode().unwrap()).await.unwrap();
        peer.write_all(&Frame::new(Command::HeartRequest, 0).encode().unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if Frame::read_from(&mut peer).await.unwrap().command == Command::HeartResponse {
                    break;
                }
            }
        })
        .await
        .expect("the late refusal must be consumed before the barrier returns");
        assert!(!session.is_closed());
        let state = session.streams.lock().await;
        let (id, stream) = state.as_ref().unwrap();
        assert_eq!(*id, active_id);
        assert!(
            stream.read_state.refusal().is_none(),
            "an old refusal must not poison the active stream"
        );
        drop(state);
        assert_eq!(active.write(b"x").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn stream_io_reports_refusal_on_fresh_read_and_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (local, _peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(
            1,
            Box::new(local),
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        let stream_id = stream.id();
        let mut io = crate::StreamIo::new(stream);
        session.refuse_stream_by_id(stream_id, "refused adapter".into()).await;
        let write = tokio::time::timeout(Duration::from_secs(1), io.write(b"x"))
            .await
            .expect("a refused adapter write must not hang")
            .expect_err("a refused adapter must fail writes");
        assert_eq!(write.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(write.to_string().contains("refused adapter"), "{write}");
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), io.read(&mut buffer))
            .await
            .expect("a refused adapter read must not hang")
            .expect_err("a refused adapter must fail reads");
        assert_eq!(read.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(read.to_string().contains("refused adapter"), "{read}");
    }

    #[tokio::test]
    async fn refusal_reason_survives_session_drop_for_fresh_operations() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (local, _peer) = tokio::io::duplex(128 * 1024);
        let session = Session::new_client(
            1,
            Box::new(local),
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            DEFAULT_MAX_SESSION_AGE,
        );
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        let stream_id = stream.id();
        session.refuse_stream_by_id(stream_id, "refused then dropped".into()).await;
        session.shutdown().await.unwrap();
        let session_ref = Arc::downgrade(&session);
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), async {
            while session_ref.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the session must be fully dropped before the write path is tested");
        let mut io = crate::StreamIo::new(stream);
        let mut buffer = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), io.read(&mut buffer))
            .await
            .expect("a refused read must not hang")
            .expect_err("a refused stream must fail reads");
        assert_eq!(read.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(read.to_string().contains("refused then dropped"), "{read}");
        let write = tokio::time::timeout(Duration::from_secs(1), io.write(b"x"))
            .await
            .expect("a refused write must not hang")
            .expect_err("a refused stream must fail writes");
        assert_eq!(write.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(write.to_string().contains("refused then dropped"), "{write}");
    }

    #[tokio::test]
    async fn exchanges_settings_syn_data_and_synack() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(11, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(22, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let mut client_stream = client.open_stream().await.unwrap();
        assert_ne!(client_stream.id(), 0);

        client_stream.write(b"hello").await.unwrap();
        let server_stream = server.accept_stream().await.unwrap();
        assert_eq!(server_stream.id(), client_stream.id());
        assert_eq!(server.peer_session_id(), Some(11));
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.peer_session_id() != Some(22) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client should learn server session ID from ServerSettings");
        let mut received = [0u8; 5];
        server_stream.read(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");

        server_stream.handshake_success().await.unwrap();
        server_stream.write(b"world").await.unwrap();
        let mut response = [0u8; 5];
        client_stream.read(&mut response).await.unwrap();
        assert_eq!(&response, b"world");

        client_stream.close().await.unwrap();
        let _ = server.shutdown().await;
        let _ = client.shutdown().await;
    }

    #[tokio::test]
    async fn server_settings_returns_local_session_id_to_legacy_client() {
        let (transport, mut peer, _gate) = gated_transport();
        let server = Session::new_server(22, transport, padding(), DEFAULT_MAX_SESSION_AGE);
        let mut legacy_settings = HashMap::new();
        legacy_settings.insert("v".to_owned(), "2".to_owned());
        legacy_settings.insert("client".to_owned(), "legacy".to_owned());
        legacy_settings.insert("padding-md5".to_owned(), padding().read().await.md5.clone());

        server.on_receive_settings(&to_bytes(&legacy_settings)).await.unwrap();

        assert_eq!(server.peer_session_id(), None);
        let response = Frame::read_from(&mut peer).await.unwrap();
        assert_eq!(response.command, Command::ServerSettings);
        let settings = from_bytes(&response.data);
        assert_eq!(settings.get("v").map(String::as_str), Some("2"));
        assert_eq!(settings.get("session").map(String::as_str), Some("22"));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn flushes_syn_without_waiting_for_stream_data() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(1, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let _client_stream = client.open_stream().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), server.accept_stream())
            .await
            .unwrap()
            .unwrap();

        let _ = server.shutdown().await;
        let _ = client.shutdown().await;
    }

    #[tokio::test]
    async fn drains_large_push_queue_before_fin_eof() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(1, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let client_stream = client.open_stream().await.unwrap();
        let server_stream = server.accept_stream().await.unwrap();
        let expected = vec![0x5a; 512 * 1024];
        let send_payload = expected.clone();
        let sender = tokio::spawn(async move {
            for chunk in send_payload.chunks(16 * 1024) {
                server_stream.write(chunk).await.unwrap();
            }
            let mut server_stream = server_stream;
            server_stream.close().await.unwrap();
        });

        let mut received = Vec::with_capacity(expected.len());
        let mut buffer = [0u8; 8192];
        loop {
            let size = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut buffer))
                .await
                .expect("stream data should keep arriving")
                .unwrap();
            if size == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..size]);
        }

        sender.await.unwrap();
        assert_eq!(received, expected);
        drop(client_stream);
        let _ = client.shutdown().await;
        let _ = server.shutdown().await;
    }

    async fn raw_stream() -> (Arc<Session>, Stream, tokio::io::DuplexStream) {
        let (transport, mut peer, _) = gated_transport();
        let padding = Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap()));
        let session = Session::new_client(1, transport, padding, DEFAULT_MAX_SESSION_AGE);
        session.run().await.unwrap();
        let stream = session.open_stream().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Settings);
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        (session, stream, peer)
    }

    async fn backpressured_payload(chunk_size: usize) {
        let (session, stream, mut peer) = raw_stream().await;
        session.peer_version.store(2, Ordering::Release);
        let id = stream.id();
        stream.shutdown_write_by_send_fin_to_remote().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        let expected: Vec<u8> = (0..3 * INBOUND_PUSH_QUEUE_BYTES).map(|i| (i % 251) as u8).collect();
        let payload = expected.clone();
        let mut sender = tokio::spawn(async move {
            for chunk in payload.chunks(chunk_size) {
                let mut frame = Frame::new(Command::Push, id);
                frame.data = chunk.to_vec();
                peer.write_all(&frame.encode().unwrap()).await.unwrap();
            }
            peer.write_all(&Frame::new(Command::Fin, id).encode().unwrap()).await.unwrap();
            peer
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut sender).await.is_err(),
            "bounded admission must backpressure the sender"
        );
        tokio::time::advance(HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT + Duration::from_secs(1)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!session.is_closed(), "an active slow reader is not an idle heartbeat failure");
        let mut io = crate::StreamIo::new(stream);
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        let _peer = sender.await.unwrap();
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn byte_budget_backpressure_preserves_exact_payload_and_fin() {
        backpressured_payload(crate::MAX_FRAME_DATA_SIZE).await;
    }

    #[tokio::test(start_paused = true)]
    async fn message_queue_backpressure_preserves_exact_payload_and_fin() {
        backpressured_payload(512).await;
    }

    #[tokio::test(start_paused = true)]
    async fn active_stream_does_not_send_idle_heartbeat() {
        let (session, _stream, mut peer) = raw_stream().await;
        session.peer_version.store(2, Ordering::Release);
        tokio::task::yield_now().await;
        tokio::time::advance(HEARTBEAT_INTERVAL).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), Frame::read_from(&mut peer))
                .await
                .is_err()
        );
        tokio::time::advance(HEARTBEAT_TIMEOUT).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn completed_stream_invalidates_outstanding_idle_probe() {
        let (session, stream, mut peer) = raw_stream().await;
        session.remove_stream_by_id(stream.id()).await;
        session.peer_version.store(2, Ordering::Release);
        tokio::task::yield_now().await;
        tokio::time::advance(HEARTBEAT_INTERVAL).await;
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::HeartRequest);
        let next = session.reserve_stream().await.unwrap();
        session.remove_stream_by_id(next.id()).await;
        tokio::time::advance(HEARTBEAT_TIMEOUT).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!session.is_closed(), "activity invalidates a probe even after the stream finishes");
        session.shutdown().await.unwrap();
    }

    async fn stream_activity_during_heartbeat_admission(expire: bool) {
        let (session, stream, mut peer) = raw_stream().await;
        session.remove_stream_by_id(stream.id()).await;
        let reservations = session
            .control_sender
            .reserve_many(session.control_sender.max_capacity())
            .await
            .unwrap();
        session.peer_version.store(2, Ordering::Release);
        tokio::task::yield_now().await;
        tokio::time::advance(HEARTBEAT_INTERVAL).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        let active = session.reserve_stream().await.unwrap();
        session.remove_stream_by_id(active.id()).await;
        if expire {
            tokio::time::advance(HEARTBEAT_QUEUE_TIMEOUT).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert!(!session.is_closed(), "queue admission timeout must not retire a stale probe");
        }
        drop(reservations);
        if !expire {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), Frame::read_from(&mut peer))
                    .await
                    .is_err(),
                "stale probe must not enter the writer queue"
            );
        }
        assert!(!session.is_closed());
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stream_activity_cancels_queued_idle_probe() {
        stream_activity_during_heartbeat_admission(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stream_activity_invalidates_heartbeat_queue_timeout() {
        stream_activity_during_heartbeat_admission(true).await;
    }

    #[derive(Clone, Copy, Debug)]
    enum AbandonStream {
        Close,
        Drop,
        Abort,
        ShutdownSession,
    }

    async fn cancel_saturated_admission(chunk_size: usize, action: AbandonStream) {
        let (session, mut stream, mut peer) = raw_stream().await;
        let id = stream.id();
        let slots = Arc::clone(&session.streams.lock().await.as_ref().unwrap().1.push_slots);
        let mut sender = tokio::spawn(async move {
            let mut frame = Frame::new(Command::Push, id);
            frame.data = vec![0x5a; chunk_size];
            let encoded = frame.encode().unwrap();
            for _ in 0..(3 * INBOUND_PUSH_QUEUE_BYTES / chunk_size + 1) {
                peer.write_all(&encoded).await?;
            }
            peer.write_all(&Frame::new(Command::Fin, id).encode().unwrap()).await?;
            peer.write_all(&Frame::new(Command::HeartRequest, 0).encode().unwrap()).await?;
            let mut received_fin = false;
            loop {
                let frame = Frame::read_from(&mut peer).await?;
                if frame.command == Command::Fin {
                    received_fin = true;
                }
                if frame.command == Command::HeartResponse {
                    assert!(received_fin, "explicit abandonment must keep the FIN handshake");
                    return std::io::Result::Ok(peer);
                }
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut sender).await.is_err(),
            "must saturate admission before {action:?}"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            match action {
                AbandonStream::Close => stream.close().await.unwrap(),
                AbandonStream::Drop => drop(stream),
                AbandonStream::Abort => {
                    let (ready, started) = oneshot::channel();
                    let owner = tokio::spawn(async move {
                        let _stream = stream;
                        ready.send(()).unwrap();
                        std::future::pending::<()>().await;
                    });
                    started.await.unwrap();
                    owner.abort();
                    assert!(owner.await.unwrap_err().is_cancelled());
                }
                AbandonStream::ShutdownSession => session.shutdown().await.unwrap(),
            }
            let result = sender.await.unwrap();
            if matches!(action, AbandonStream::ShutdownSession) {
                assert!(result.is_err());
            } else {
                let _peer = result.unwrap();
                while session.streams.lock().await.is_some() {
                    tokio::task::yield_now().await;
                }
                assert!(!session.is_closed());
            }
            while slots.available_permits() != INBOUND_PUSH_QUEUE_BYTES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandonment must unblock admission and release all byte permits promptly");
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_unblocks_byte_budget_admission() {
        for action in [
            AbandonStream::Close,
            AbandonStream::Drop,
            AbandonStream::Abort,
            AbandonStream::ShutdownSession,
        ] {
            cancel_saturated_admission(crate::MAX_FRAME_DATA_SIZE, action).await;
        }
    }

    #[tokio::test]
    async fn cancellation_unblocks_message_queue_admission() {
        for action in [
            AbandonStream::Close,
            AbandonStream::Drop,
            AbandonStream::Abort,
            AbandonStream::ShutdownSession,
        ] {
            cancel_saturated_admission(512, action).await;
        }
    }

    #[tokio::test]
    async fn unexpected_pump_failure_is_read_error_at_peer() {
        let (local, remote) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(local), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(2, Box::new(remote), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();
        let stream = client.open_stream().await.unwrap();
        let peer = server.accept_stream().await.unwrap();
        let (replacement, _other) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(replacement);
        *stream.reader.lock().await = reader;
        *stream.writer.lock().await = writer;
        let _ = peer.write(b"undeliverable").await;
        let mut peer = crate::StreamIo::new(peer);
        let error = tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut Vec::new()))
            .await
            .expect("pump failure must reach the peer before the close-handshake timeout")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(client.is_closed());
        client.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn refused_half_close_remains_broken_pipe() {
        let (session, stream, _peer) = raw_stream().await;
        session.refuse_stream_by_id(stream.id(), "refused".into()).await;
        let error = stream.shutdown_write_by_send_fin_to_remote().await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(!session.is_closed());
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn fin_failure_retires_session_even_after_stream_removal() {
        for remove_during_fin in [false, true] {
            let (transport, peer, gate) = gated_transport();
            let session = Session::new_client(
                1,
                transport,
                Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
                DEFAULT_MAX_SESSION_AGE,
            );
            let mut stream = session.open_stream().await.unwrap();
            let id = stream.id();
            gate.block();
            let closing = tokio::spawn(async move { stream.close().await });
            gate.wait_pending().await;
            let replacement = if remove_during_fin {
                session.remove_stream_by_id(id).await;
                Some(session.reserve_stream().await.unwrap())
            } else {
                None
            };
            drop(peer);
            gate.release();
            closing.await.unwrap().unwrap();
            assert!(session.is_closed(), "a real FIN write failure must retire the transport");
            assert!(session.is_idle().await, "shutdown must drain even a replacement stream");
            drop(replacement);
        }
    }

    #[tokio::test]
    async fn stale_cleanup_after_expiration_preserves_replacement() {
        for drop_old in [false, true] {
            let (transport, mut peer, gate) = gated_transport();
            let max_age = Duration::from_secs(1);
            let session = Session::new_client(
                1,
                transport,
                Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
                max_age,
            );
            let old = session.open_stream().await.unwrap();
            let old_id = old.id();
            let closing = if drop_old {
                None
            } else {
                gate.block();
                let session = Arc::clone(&session);
                let closing = tokio::spawn(async move { session.close_stream_by_id(old_id).await });
                gate.wait_pending().await;
                Some(closing)
            };
            session.remove_stream_by_id(old_id).await;
            let replacement = session.reserve_stream().await.unwrap();
            tokio::time::sleep(max_age).await;
            assert!(session.is_expired());
            if let Some(closing) = closing {
                gate.release();
                closing.await.unwrap().unwrap();
            }
            assert_eq!(Arc::strong_count(&session), 1);
            drop(old);
            tokio::time::timeout(Duration::from_secs(1), async {
                while Arc::strong_count(&session) != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the old stream's Drop cleanup must finish");
            let active = session.streams.lock().await;
            assert_eq!(active.as_ref().unwrap().0, replacement.id());
            assert!(!session.is_closed());
            drop(active);
            replacement.write(b"alive").await.unwrap();
            loop {
                let frame = Frame::read_from(&mut peer).await.unwrap();
                if frame.command == Command::Push {
                    assert_eq!(frame.data, b"alive");
                    break;
                }
            }
            session.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn active_expired_close_retires_session_after_repeated_fin() {
        let (transport, mut peer, _) = gated_transport();
        let max_age = Duration::from_secs(1);
        let session = Session::new_client(
            1,
            transport,
            Arc::new(RwLock::new(PaddingFactory::new(b"stop=0").unwrap())),
            max_age,
        );
        let mut stream = session.open_stream().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        stream.shutdown_write_by_send_fin_to_remote().await.unwrap();
        stream.shutdown_write_by_send_fin_to_remote().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        tokio::time::sleep(max_age).await;
        stream.close().await.unwrap();
        assert!(session.is_closed());
        assert!(session.is_idle().await);
    }

    #[tokio::test(start_paused = true)]
    async fn old_close_timeout_preserves_replacement() {
        let (session, mut old, mut peer) = raw_stream().await;
        old.close().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        session.remove_stream_by_id(old.id()).await;
        let replacement = session.open_stream().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Syn);
        tokio::time::advance(STREAM_CLOSE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed());
        replacement.write(b"alive").await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().data, b"alive");
        session.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_close_keeps_existing_fin_handshake_timeout() {
        let (session, mut stream, mut peer) = raw_stream().await;
        stream.close().await.unwrap();
        assert_eq!(Frame::read_from(&mut peer).await.unwrap().command, Command::Fin);
        assert!(!session.is_closed());
        tokio::time::advance(STREAM_CLOSE_TIMEOUT).await;
        session.close_token.cancelled().await;
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn forced_transport_close_is_read_error() {
        let (session, stream, peer) = raw_stream().await;
        let mut io = crate::StreamIo::new(stream);
        drop(peer);
        let result = tokio::time::timeout(Duration::from_secs(1), io.read_to_end(&mut Vec::new()))
            .await
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::ConnectionReset);
        session.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_drains_streams_after_session_closed() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(1, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let client_stream = client.open_stream().await.unwrap();
        let _server_stream = server.accept_stream().await.unwrap();
        client.closed.store(true, std::sync::atomic::Ordering::Release);
        client.shutdown().await.unwrap();

        assert!(client.streams.lock().await.is_none());
        let mut data = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client_stream.read(&mut data))
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );

        let _ = server.shutdown().await;
    }

    #[tokio::test]
    async fn dropping_stream_releases_session_stream() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(1, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        let client_stream = client.open_stream().await.unwrap();
        client_stream.write(b"x").await.unwrap();
        let server_stream = server.accept_stream().await.unwrap();
        drop(client_stream);
        server_stream.shutdown_write_by_send_fin_to_remote().await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while client.streams.lock().await.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped stream should be released");

        let _ = server.shutdown().await;
        let _ = client.shutdown().await;
    }

    #[tokio::test]
    async fn open_stream_fails_after_shutdown() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let client = Session::new_client(1, Box::new(client_io), padding(), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(1, Box::new(server_io), padding(), DEFAULT_MAX_SESSION_AGE);
        client.run().await.unwrap();
        server.run().await.unwrap();

        client.shutdown().await.unwrap();
        let err = client.open_stream().await;
        assert!(err.is_err());
        if let Err(err) = &err {
            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        }
        assert!(client.streams.lock().await.is_none());

        let _ = server.shutdown().await;
    }
}
