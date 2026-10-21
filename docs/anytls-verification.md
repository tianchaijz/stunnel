# Verify the original-based AnyTLS integration

The vendored dependency is the complete committed source from the sibling `anytls-rs` checkout. `vendor/anytls-rs/VENDORED.json` records its revision and source digest. STunnel enables only `runtime`. Cargo records local package versions and dependencies in its lockfile too.

## Run STunnel checks

Run these commands from STunnel:

```sh
python3 scripts/sync_anytls.py
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --bins
python3 scripts/verify_anytls.py
```

The source check must report `PASS AnyTLS source`. The tests cover half-close responses, session reuse, writes without an application flush, parallel flows, UDP forwarding, authentication, certificate trust, server name, ALPN, physical capacity, and configuration validation. Ownership regressions also abort and join public `tlstcp::server::serve`, drop owners outside an entered runtime, exercise consumed openers and either surviving split half, and check failed or cancelled open cleanup.

Shared-listener tests exercise legacy with and without ALPN, concurrent AnyTLS on the same port, legacy preference when both protocols are offered, and rejection of unknown or disabled ALPN. They fill the 64 AnyTLS slots during authentication and established sessions while proving legacy forwarding still works. Slow TLS admission tests check rejection and recovery, and slow TLS plus authentication must finish within one ten-second deadline. Configuration tests reject obsolete `anytls.listen` and empty passwords.

The binary verifier generates temporary certificates and starts the real client and server binaries against local TCP, UDP, and HTTP targets. Every transport must report a passing 8 MiB slow-reader response, HTTP CONNECT half-close, HTTP forwarding, SOCKS TCP, and SOCKS UDP. AnyTLS also runs eight parallel requests and rejects a wrong password through the HTTP frontend. AnyTLS and TLS/TCP use the same server TCP port. Quinn and s2n-quic use UDP at the same numeric address. `STUNNEL_BIN_DIR` selects another directory of already-built binaries.

## Measure the frontend

Build release binaries before measuring. On Linux, run the same benchmark against separately built baseline and candidate directories, alternating their order for at least five samples each.

```sh
python3 scripts/benchmark_anytls.py --bin-dir /path/to/baseline/release --variant baseline --samples 1
python3 scripts/benchmark_anytls.py --bin-dir /path/to/candidate/release --variant candidate --samples 1
```

The benchmark sends real HTTP CONNECT traffic through the AnyTLS client and server. Each bulk flow receives 128 MiB after a request half-close. It checks the byte count, CRC32, and EOF. It measures one flow and four parallel flows, then 100 sequential 1 KiB responses per sample. Any error aborts the run. Sequential flows are eligible for reuse; the benchmark does not count physical sessions.

Reverse the order in the next pair and repeat until each variant has at least five samples. JSON `wall_s` includes CONNECT and executor setup. Per-flow `flow_s` excludes CONNECT. Bulk samples use Linux `/proc` counters for client and server CPU, and Python's process clock for driver/backend CPU. Short sequential samples report latency only. Use `--trace-dir PATH` for a separate syscall profile; those instrumented timings must be excluded from performance comparisons, and application CPU fields are null. This workload includes TLS and frontend work, while the vendored library's `runtime` benchmark isolates paired sessions over an in-memory transport. Neither alone establishes which source function dominates CPU time.

## Run library checks

Run these commands from the separate library checkout:

```sh
cargo check --no-default-features
cargo check --no-default-features --features core
cargo check --no-default-features --features async
cargo check --no-default-features --features runtime
cargo check --no-default-features --features client
cargo check --no-default-features --features server
cargo test --no-default-features --features runtime
cargo clippy --no-default-features --features runtime --all-targets -- -D warnings
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --workspace -- -D warnings
```

The runtime suite includes exact-byte delivery beyond both inbound limits, prompt cancellation at saturation, idle heartbeat activation races, forced-close errors at both endpoints, cancelled write replacement, physical flush and FIN ordering, prompt write rejection after local FIN while capacity stays full, 65,535-byte boundaries and 128 KiB writes, and cancelled reads resumed with smaller or empty buffers. It also covers wire encoding boundaries, stream-local refusals during SYN and queue saturation, late old-stream replies, reason retention after Session destruction, and reuse after actual idle publication. Refused-stream cleanup is tested before and after reuse, including repeated close, stale Drop after expiry, FIN failure during replacement, and stream-specific close timeouts. These are committed tests, rather than external canaries that only fail on the original integration.

## Recorded results and limits

On Linux, the combined optimization code passes 21 STunnel tests, 84 runtime-only library tests, 125 default library tests, and six standalone server tests. Runtime and default feature selections overlap, so do not add those counts. Formatting, the listed strict Clippy commands, all listed feature checks, and default all-target checking pass. The preceding integration also passed a separate runtime-only consumer build. Hosted macOS and Windows CI has not run for these local commits.

The original frontend probe returned 3,072,000 of 8,388,608 bytes through AnyTLS with clean EOF. The same probe returned every byte through TLS/TCP. The fixed binary sweep returns every byte through all four transports. The paused reader waits one second. A physical writer stalled for 15 seconds still fails by the original deadline, and forced closure now produces an error. These checks establish the tested behavior, not production-duration stability or relative performance.

DS reviewed the design and every fix commit. Independent reviewers checked the library and adapter changes. A further local-FIN admission regression was reproduced during review, corrected, and retested before integration. The preserved `internal-stability` branches remain comparison references.

The subsequent [optimization comparison and recorded measurements](../vendor/anytls-rs/docs/stunnel-optimization.md) explain the separately committed encoding and refusal changes. Exact allocation counts establish the reduced allocation work. Timing ranges overlap, so the measurements do not establish a production throughput guarantee. The idle publication gap remains open for a focused follow-up.

Ripwire reports test-module size and fixture similarity, required Tokio IO delegation, and distinct owner shutdown bodies. Its static call graph also misses trait, macro, and test entry points. Those findings were inspected and retained where they reflect these structures. This is not a claim that its quality gate is clean. The complete upstream import retains an existing extra blank line at EOF in `scripts/smoke_test.py`.

The optimization branch adds seven gating fixture-similarity groups in the native branch-wide scan. Its protocol tests intentionally construct real sessions with the same setup as existing tests. The scanner also marks Rust test macros and the benchmark allocator's trait methods as dead; the executed suites and benchmark exercise them. These reports were reviewed without suppressing them.

To export a later reviewed library commit, commit the library change first, then run `python3 scripts/sync_anytls.py --write`. Repeat the checks above and commit the pinned vendor update separately. The source check compares every tracked library file byte-for-byte. The export also copies executable modes from the source checkout.
