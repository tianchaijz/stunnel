use std::{
    alloc::{GlobalAlloc, Layout, System},
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anytls::{DEFAULT_MAX_SESSION_AGE, DEFAULT_SCHEME, PaddingFactory, Session, StreamIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 8192;
const RESPONSE: &[u8] = b"receiver verified every payload byte";
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

fn record_allocation(size: usize) {
    if COUNTING.load(Ordering::Relaxed) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if !pointer.is_null() && COUNTING.load(Ordering::Relaxed) {
            REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug)]
enum Workload {
    Bulk,
    Cold,
}

impl Workload {
    fn bytes(self) -> usize {
        match self {
            Self::Bulk => 8 * 1024 * 1024,
            Self::Cold => 64 * 1024,
        }
    }
}

struct Pair {
    client: Arc<Session>,
    server: Arc<Session>,
    outgoing: StreamIo,
    incoming: StreamIo,
}

impl Pair {
    async fn new() -> io::Result<Self> {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let padding = Arc::new(tokio::sync::RwLock::new(PaddingFactory::new(DEFAULT_SCHEME).unwrap()));
        let client = Session::new_client(1, Box::new(client_io), Arc::clone(&padding), DEFAULT_MAX_SESSION_AGE);
        let server = Session::new_server(2, Box::new(server_io), padding, DEFAULT_MAX_SESSION_AGE);
        client.run().await?;
        server.run().await?;
        let outgoing = client.open_stream().await?;
        let incoming = server.accept_stream().await?;
        incoming.handshake_success().await?;
        Ok(Self {
            client,
            server,
            outgoing: StreamIo::new(outgoing),
            incoming: StreamIo::new(incoming),
        })
    }

    async fn warm_padding(&mut self) -> io::Result<()> {
        let expected = [7; CHUNK];
        let mut actual = [0; CHUNK];
        for _ in 0..8 {
            self.outgoing.write_all(&expected).await?;
            self.outgoing.flush().await?;
            self.incoming.read_exact(&mut actual).await?;
            assert_eq!(actual, expected);
            self.incoming.write_all(&expected).await?;
            self.incoming.flush().await?;
            self.outgoing.read_exact(&mut actual).await?;
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    async fn transfer(&mut self, expected: &[u8], actual: &mut [u8]) -> io::Result<()> {
        let sender = async {
            for chunk in expected.chunks(CHUNK) {
                self.outgoing.write_all(chunk).await?;
            }
            self.outgoing.shutdown().await?;
            let mut response = [0; RESPONSE.len()];
            self.outgoing.read_exact(&mut response).await?;
            assert_eq!(&response, RESPONSE);
            let mut extra = [0];
            assert_eq!(self.outgoing.read(&mut extra).await?, 0, "sender must receive EOF");
            Ok::<_, io::Error>(())
        };
        let receiver = async {
            self.incoming.read_exact(actual).await?;
            assert_eq!(actual, expected, "receiver must verify every byte");
            let mut extra = [0];
            assert_eq!(self.incoming.read(&mut extra).await?, 0, "receiver must receive EOF");
            self.incoming.write_all(RESPONSE).await?;
            self.incoming.shutdown().await?;
            Ok::<_, io::Error>(())
        };
        tokio::try_join!(sender, receiver)?;
        Ok(())
    }

    async fn close(self) -> io::Result<()> {
        self.client.shutdown().await?;
        self.server.shutdown().await?;
        drop(self);
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Measurement {
    wall: Duration,
    allocations: u64,
    reallocations: u64,
    allocated_bytes: u64,
}

async fn measure(workload: Workload, expected: &[u8], actual: &mut [u8], counting: bool) -> io::Result<Measurement> {
    let prepared = match workload {
        Workload::Bulk => {
            let mut pair = Pair::new().await?;
            pair.warm_padding().await?;
            Some(pair)
        }
        Workload::Cold => None,
    };
    ALLOCATIONS.store(0, Ordering::Relaxed);
    REALLOCATIONS.store(0, Ordering::Relaxed);
    ALLOCATED_BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(counting, Ordering::Relaxed);
    let start = Instant::now();
    let mut pair = match prepared {
        Some(pair) => pair,
        None => Pair::new().await?,
    };
    let result = pair.transfer(expected, actual).await;
    let wall = start.elapsed();
    COUNTING.store(false, Ordering::Relaxed);
    let measurement = Measurement {
        wall,
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        reallocations: REALLOCATIONS.load(Ordering::Relaxed),
        allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
    };
    result?;
    pair.close().await?;
    Ok(measurement)
}

fn positive_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .map(|value| value.parse::<usize>().expect("expected positive integer"))
        .unwrap_or(default)
        .max(1)
}

async fn run() -> io::Result<()> {
    let workload = match std::env::var("ANYTLS_BENCH_WORKLOAD").as_deref().unwrap_or("bulk") {
        "bulk" => Workload::Bulk,
        "cold" => Workload::Cold,
        _ => panic!("ANYTLS_BENCH_WORKLOAD must be bulk or cold"),
    };
    let counting = match std::env::var("ANYTLS_BENCH_MODE").as_deref().unwrap_or("timing") {
        "timing" => false,
        "allocations" => true,
        _ => panic!("ANYTLS_BENCH_MODE must be timing or allocations"),
    };
    let samples = positive_env("ANYTLS_BENCH_SAMPLES", 5);
    let iterations = positive_env(
        "ANYTLS_BENCH_ITERATIONS",
        match workload {
            Workload::Bulk => 16,
            Workload::Cold => 256,
        },
    );
    let expected: Vec<_> = (0..workload.bytes())
        .map(|index| ((index * 31 + index / CHUNK) % 251) as u8)
        .collect();
    let mut actual = vec![0; expected.len()];
    for _ in 0..2 {
        measure(workload, &expected, &mut actual, false).await?;
    }
    println!(
        "workload={workload:?} mode={} runtime=current_thread transport=duplex transport_capacity=262144 chunk_bytes={CHUNK} payload_bytes={} response_bytes={} iterations={iterations} samples={samples} warmup=2 padding=DEFAULT_SCHEME debug_assertions={}",
        if counting { "allocations" } else { "timing" },
        expected.len(),
        RESPONSE.len(),
        cfg!(debug_assertions)
    );
    for sample in 1..=samples {
        let mut total = Measurement::default();
        for _ in 0..iterations {
            let result = tokio::time::timeout(Duration::from_secs(30), measure(workload, &expected, &mut actual, counting)).await??;
            total.wall += result.wall;
            total.allocations += result.allocations;
            total.reallocations += result.reallocations;
            total.allocated_bytes += result.allocated_bytes;
        }
        let bytes = iterations * (expected.len() + RESPONSE.len());
        if counting {
            println!(
                "sample={sample} completed={iterations} verified_bytes={bytes} eof_checks={} errors=0 allocations={} reallocations={} allocated_bytes={}",
                iterations * 2,
                total.allocations,
                total.reallocations,
                total.allocated_bytes
            );
        } else {
            println!(
                "sample={sample} completed={iterations} verified_bytes={bytes} eof_checks={} errors=0 wall_ms={:.6} ns_per_transfer={:.0} mib_per_second={:.3}",
                iterations * 2,
                total.wall.as_secs_f64() * 1000.0,
                total.wall.as_nanos() as f64 / iterations as f64,
                bytes as f64 / 1048576.0 / total.wall.as_secs_f64()
            );
        }
    }
    Ok(())
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    if let Err(error) = runtime.block_on(run()) {
        eprintln!("errors=1 benchmark aborted: {error}");
        std::process::exit(1);
    }
}
