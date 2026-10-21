# AnyTLS optimization for STunnel

Clash Verge launches Mihomo as its proxy core. The comparison uses Mihomo's `transport/anytls` implementation and the original Rust library. It selects useful changes for internal STunnel use. It does not replace the original Rust implementation or add a Mihomo compatibility requirement.

## Source revisions

| Source | Revision |
| --- | --- |
| Rust upstream baseline | `c83e6dd44a7a6a5f318fda20bb8876fcf7f517de` |
| Reviewed Rust baseline before optimization | `a40691048555ed96a951a694c7f56c7f5f1871d6` |
| Mihomo | `88dcbf7f1614a67c3b36b848ee3592dfa92ada36` |
| Clash Verge | `c6b51171a1db9b75a4270d78944e132293dbdd83` |

Clash Verge's [prebuild script](https://github.com/clash-verge-rev/clash-verge-rev/blob/c6b51171a1db9b75a4270d78944e132293dbdd83/scripts/prebuild.mjs) fetches Mihomo release artifacts. The relevant implementation is [Mihomo's AnyTLS session package](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36/transport/anytls/session).

## Combined design

Codex measured the Rust write path. DS independently compared upstream session and pool behavior and reproduced refusal and reuse issues. An independent design review compared direct encoding and a stream-local failure state with buffer pooling and synchronous idle publication. The selected design keeps the current writer and ownership model.

| Candidate | Decision | Reason |
| --- | --- | --- |
| Direct contiguous frame encoding | Adopt separately | Removes a measured payload allocation and copy per accepted PUSH without changing queue ownership. |
| Stream-local nonempty SYNACK refusal | Adopt separately | One rejected stream should preserve its reason and leave its session usable. |
| Shared buffer pool or borrowed vectored transport writes | Defer | No measured need justifies retention, lifetime, and partial-write complexity. |
| Synchronous idle pool plus a close notification | Defer, issue remains open | The observed one-extra-dial case needs broader close and remote-FIN synchronization. |
| Newest-first idle selection | Keep Rust's oldest-ID selection | No workload evidence justifies replacing the original policy. |
| New pool policy knobs | Defer | Internal deployment has no demonstrated configuration need. |
| Padding cursor and Waste buffer changes | Defer | Padding is limited to the initial packet window; no isolated cold-path evidence justifies another change. |

The Laziness Protocol principle keeps the encoder crate-private and excludes pooled ownership. Model the Domain keeps refusal in the existing terminal-state enum. Sequence Work into Verifiable Units keeps the benchmark, encoder, refusal fix, and documentation in separate commits.

### Data-frame encoding

`Frame::encode_parts(command, stream_id, data)` creates one owned seven-byte header plus payload buffer. Public `Frame::encode()` delegates to the same implementation. `DataWritePermit::send` uses the borrowed input directly instead of constructing an intermediate payload Vec.

The writer retains one contiguous owned buffer. Queue capacity, control priority, current-buffer semantics after Pending, physical receipts, flush ordering, FIN ordering, and cancellation remain the same. Empty payloads, the maximum 65,535-byte payload, oversized public frames, and existing runtime regressions are tested.

### Refused streams

A nonempty SYNACK now records `Refused(reason)` in the stream's existing terminal-state enum. It cancels that stream's operations and removes only the matching stream ID. Read EOF and rejected writes return `BrokenPipe` with the remote reason. Ordinary FIN still yields clean EOF, while an unexpected transport failure keeps its reset behavior.

The reason and write cancellation are published under the active-stream lock, serializing against synchronous data acceptance. The stream retains its error even after the last Session owner disappears. Already accepted physical write receipts keep their existing meaning. No per-frame receipt state check is added.

Explicit close and Drop share one cleanup path. An already-removed stream is distinct from a failed FIN write, so closing an old refused handle cannot retire a reused session. Successful FIN cleanup and its timeout recheck the active stream under the session lock before retirement. A real FIN write failure still closes the transport, while a newer active stream can drain after the session reaches its maximum age.

Tests cover a refusal during a gated SYN write, cancellation while all 64 queue slots remain reserved, direct and adapted error reporting, late refusal of an old ID, error retention after Session destruction, and reuse after actual idle-pool publication. They also close refused handles before and after reuse, repeat close, verify stale cleanup after expiry, and retain genuine FIN failure and timeout behavior. The server readiness and client publication barriers are separate. STunnel acknowledges before its inner destination dial, so this is a library refusal fix, including internal stream-admission rejections, rather than its ordinary destination-connect failure path.

### Open reuse issue

DS's one-session probe completed 100 immediate close/open iterations with two physical dials in each of five runs. Only the first reuse missed. A 5 ms pause between close and open reduced the count to one. A warm spare session can mask this effect.

The read worker can publish EOF before it records read closure. Removal and idle publication follow, then another task inserts the session into the client pool. `close().await` can therefore return before the notification is enqueued. Replacing only the pool channel would not provide a reuse guarantee. Waiting for remote FIN also changes close behavior and cannot guarantee reuse when a peer never finishes. A reused SYN can additionally reach a server whose prior stream slot is still occupied. This issue needs its own narrower contract and tests before a lifecycle refactor.

## Measurements

These measurements precede the follow-up correction to refused-stream cleanup. They establish the encoding change's measured allocation reduction; the corrected lifecycle is verified by the regression tests below.

Release builds on Linux x86_64 used Rust 1.98.1, the existing default feature set, and the same ignored dependency lockfile for both native variants. The standalone runtime benchmark uses a current-thread Tokio runtime and a 256 KiB duplex transport. It measures actual Session and StreamIo paths. It has no TLS or external driver.

The bulk workload prewarms eight 8 KiB writes in each direction beyond the default padding window. It then transfers 8 MiB in 1,024 writes and receives a 36-byte verified reply. Every byte and EOF in both directions is checked. Setup and final cleanup are excluded. Cold measurements include session setup and 64 KiB plus the same response. Validation buffers are preallocated.

Five allocation-only samples per variant each produced the same bulk counts. Requested bytes count cumulative allocation requests, not live or peak memory.

| Bulk transfer | Baseline | Direct encoding |
| --- | ---: | ---: |
| Allocation calls | 6,160 | 5,135 |
| Reallocation calls | 0 | 0 |
| Requested allocation bytes | 25,845,417 | 17,456,773 |

Direct encoding removes exactly 1,025 allocations and 8,388,644 requested bytes per measured bulk transfer. That is one payload allocation per PUSH, including the reply. Cold allocation calls fell from 247 to 238. Cold reallocations and requested byte counts vary with randomized initial padding.

Timing used six alternating baseline/candidate pairs, reversing their order in each successive pair. Each bulk sample contains 64 transfers; each cold sample contains 1,024 sessions. Allocation counting is disabled during timing.

| Runtime workload | Baseline median (range) | Direct encoding median (range) |
| --- | --- | --- |
| Bulk transfer | 4.810 ms (4.670–4.883) | 4.597 ms (4.548–4.820) |
| Cold session | 75.622 µs (74.705–75.999) | 72.484 µs (69.030–74.021) |

Bulk ranges overlap on this shared 16-CPU host. Whole-process time uses roughly one core and includes work outside the transfer timer. A separate syscall profile shows frequent executor wakeups; it does not attribute dominant CPU cost to copying. The allocation reduction is established. These timings do not establish a production throughput gain or a comparison with Go.

STunnel release binaries were measured through the real HTTP CONNECT frontend with mutual TLS and the existing AnyTLS configuration. Each bulk flow receives 128 MiB after request half-close, checked for byte count, CRC32, and EOF. Each sequential sample contains 100 verified 1 KiB responses. Six alternating pairs tested the final combined code, with zero errors across 1,260 measured flows and 8,054,292,480 application bytes.

| Frontend workload | Baseline median (range) | Combined code median (range) |
| --- | --- | --- |
| One 128 MiB flow, total wall | 302.148 ms (248.019–359.657) | 248.496 ms (228.327–345.767) |
| Four parallel flows, total wall | 303.750 ms (299.130–418.513) | 301.426 ms (293.635–391.720) |
| Median short-flow latency per sample | 0.656 ms (0.633–0.694) | 0.665 ms (0.634–0.697) |

Bulk frontend wall time includes CONNECT and executor setup. Median client plus server CPU seconds per MiB were 0.004961 versus 0.004609 for one flow and 0.004385 versus 0.004229 for four. Driver/backend CPU was recorded separately. Process counters are coarse, the host is shared, and bulk ranges overlap. Short latency is similar. These are descriptive local results, not a production speed guarantee. Separate strace runs are excluded from all timing tables.

The baseline uses the same committed benchmark harness as the candidate. All native timed samples together verify 7,248,227,328 application bytes and 26,112 EOF events, with zero errors.

## Reproduce and verify

Build and run the native benchmark from this repository with the same feature set for both variants. Build each revision separately and preserve its executable before changing source. Run at least five alternating pairs, not all baseline samples followed by all candidate samples.

```sh
cargo bench --bench runtime --no-run
ANYTLS_BENCH_WORKLOAD=bulk ANYTLS_BENCH_MODE=timing ANYTLS_BENCH_SAMPLES=1 ANYTLS_BENCH_ITERATIONS=64 /path/to/variant/runtime-benchmark
ANYTLS_BENCH_WORKLOAD=bulk ANYTLS_BENCH_MODE=allocations ANYTLS_BENCH_SAMPLES=5 ANYTLS_BENCH_ITERATIONS=1 /path/to/variant/runtime-benchmark
ANYTLS_BENCH_WORKLOAD=cold ANYTLS_BENCH_MODE=timing ANYTLS_BENCH_SAMPLES=1 ANYTLS_BENCH_ITERATIONS=1024 /path/to/variant/runtime-benchmark
```

`debug_assertions=false` must appear in output. An I/O error, byte mismatch, missing EOF, or deadline aborts the run. Allocation counting uses a benchmark-only allocator, with counting and timing in separate invocations. The disabled counter still checks a flag, so compare only the identical harness. No production allocator or dependency was changed.

The corrected source passed 84 runtime-only library tests, 125 default library tests, six standalone server tests, no-default/core/async/runtime/client/server feature checks, default all-target checking, strict runtime all-target Clippy, default workspace Clippy, and formatting. Counts from overlapping feature selections must not be added.

STunnel passed 21 tests, strict all-target Clippy, formatting, and exact vendor-source verification. The real frontend sweep passed AnyTLS, TLS/TCP, Quinn, and s2n-quic. It checked HTTP CONNECT half-close, an 8 MiB paused-reader response, HTTP forwarding, SOCKS TCP and UDP, parallel AnyTLS flows, and wrong-password rejection.

DS independently reviewed the encoder and combined source. Another reviewer checked the refusal transition and regression coverage. Review corrected reason loss after Session destruction and replaced scheduling assumptions with explicit completion barriers. The source combination preserves each reviewed change exactly.

The branch-wide static scan reports seven gating groups of similar test setup, plus unresolved Rust test and allocator trait entry points. These findings were inspected and the fixtures retained. The runtime tests prove those entry points execute; this is not a claim that the static quality gate passes.

The original `docs/go-rust-improvements.md`, applications, feature defaults, FFI, panel synchronization, heartbeat policy, bounded queues, physical deadlines, idle cap, and STunnel's inner protocol are retained. Hosted macOS/Windows CI and production-duration stability were not measured locally.
