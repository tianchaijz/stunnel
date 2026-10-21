# Original-based integration versus internal-stability

This document records the integration and stability phase. The subsequent optimization commits add direct frame encoding and stream-local refusal handling, including safe cleanup after reuse. These commits are included in both the optimization and stepwise branches. See the [optimization design and measured results](../vendor/anytls-rs/docs/stunnel-optimization.md). The preserved branches and their comparison below remain available.

The library branch `stunnel-stepwise` starts at original anytls-rs `c83e6dd`. The first library commit, `dcfebc3`, exposes the existing pool for embedding. STunnel's `anytls-stepwise` starts at `c2d77a5`, with the original-based integration in `03b4bae`. Later commits fix reproduced defects separately.

The comparison branches remain library `internal-stability` at `690745d` and STunnel `anytls-internal-stability` at `035e23b`. They provide reference material. Mihomo interoperability is not an acceptance requirement for this internal transport.

## Integration before runtime fixes

The integration prerequisite changes four library files, with 16 insertions and five deletions. It exports existing `Client` and `Dialer` under `runtime`, adds the Tokio macros that runtime already uses, widens two test helper gates, and adds runtime-only CI. The runtime-only build previously failed without those gates and macros. The export lets STunnel reuse the original idle pool without enabling the standalone applications.

The integration commit adds mutual TLS, ALPN, password authentication, physical connection admission on the shared TLS/TCP listener, and an adapter to STunnel's existing TCP and UDP forwarding protocol. The library supplies framing, padding, directional FIN, and pooling. No additional wire command, proxy translation, or production Go dependency is introduced.

## Reproduced defects and separate fixes

Each row corresponds to a focused fix commit and its regression tests. Library updates are exported into STunnel with separate pinned vendor commits.

| Fix | Evidence before the fix | Why the change is necessary |
| --- | --- | --- |
| Bounded lossless input and idle heartbeat validation | An 8 MiB HTTP CONNECT response with a paused reader returned only 3,072,000 bytes and clean EOF. TLS/TCP returned all 8,388,608 bytes. | A full inbound queue must wait for capacity. It must not discard bytes and manufacture successful FIN. Active receive backpressure must not trigger an idle probe failure. Cancellation must wake admission, and forced transport closure must surface as an error. |
| Server Session owner | After public `serve` was aborted and joined, its authenticated session still answered a fresh heartbeat. | A captured runtime handle schedules existing Session shutdown when the owner is cancelled, including cancellation during setup or normal cleanup. |
| Connector and flow ownership | The final Connector disappeared while its idle physical transport still occupied the server's capacity permit. | Shared ownership across Connector clones and returned flow IO schedules Client shutdown after the final owner disappears. Either split half keeps a consumed opener's client alive. |
| Cancellation-safe writes and physical receipts | A cancelled Pending write followed by a one-byte replacement returned the old length, 17, and retained the old bytes. | Pending reservations must own no caller payload. Acceptance uses the current slice, flush waits for physical completion, and shutdown waits for accepted PUSH before FIN. A regression found during review also requires pending and new writes to reject local FIN while the data queue stays full. |
| Large byte-stream writes | A direct 128 KiB `StreamIo::write_all` failed with `InvalidInput`, `frame data exceeds u16`. | A write accepts at most 65,535 bytes and returns a short count. `write_all` repeats until complete. Direct `Stream::write` retains physical-completion semantics. |
| Current caller read buffer | A Pending read using eight bytes, cancelled and resumed using two bytes, panicked when it copied the cached eight-byte result. | The adapter polls the existing reader into the current `ReadBuf`. Empty reads consume nothing, and forced EOF remains an error. |

The first three failures involve forwarding or transport ownership. The final three were reproduced through public library APIs. No additional CLI trigger is claimed for those API failures. STunnel's ordinary copying uses smaller buffers.

The fixes preserve the original session actors and pool. They add no per-stream output actor or unbounded queue. The original applications, FFI, panel sync, default features, workflows, scripts, and [upstream improvement document](../vendor/anytls-rs/docs/go-rust-improvements.md) remain. The package version remains `0.5.1` and its license remains MIT.

## Behavior and limits

| Behavior | Original-based branch after fixes | Preserved internal-stability |
| --- | --- | --- |
| Forwarding | Existing STunnel TCP and UDP framing. | Same application framing. |
| TLS | Mutual TLS 1.3, server name verification, explicit ALPN, password authentication. | Same application policy. |
| Half-close | Original directional FIN. | Additional negotiated carrier command. |
| Session use | One active flow per physical session; original pool retains up to four idle sessions. | Client reserves one flow per session; rewritten pool retains up to eight idle sessions. |
| Admission | 64 physical sessions per connector and server listener. Full connector returns `WouldBlock`. | Client library and STunnel server limits are 64. |
| Connection deadlines | Original 15-second client deadline; server TLS and authentication share 10 seconds. | Rewritten client defaults to 10 seconds, with separate server deadlines. |
| Inbound buffering | Existing 1 MiB byte budget, 65 message slots, 64 KiB duplex, and at most one parsed wire frame outside that budget. Admission awaits capacity with cancellation. | Rewritten bounded lossless buffering. |
| Heartbeat | Strictly idle probes; activation invalidates a probe even if the flow finishes before its timeout. | Idle probes with ACK-based timeout accounting. |
| Writer progress | Original 15-second physical write deadline. Adapter flush and shutdown wait for physical completion. | Buffered writes use physical receipts. |
| Session age | Original one-hour graceful retirement. | One-hour graceful retirement in rewritten state management. |
| Wire deployment | Both peers use the original-based STunnel transport. | Different negotiated carrier profile. Mixed-version deployment is unsupported. |

A physical write stalled for 15 seconds still fails the session. Bounded lossless admission preserves bytes when the reader resumes before that independent deadline. It does not promise indefinite tolerance of a stalled transport. Explicit flow abandonment retains the original FIN handshake and its 15-second client fallback. Unexpected delivery failure tears down the transport, so the peer receives an I/O error.

Drop schedules cleanup on the captured Tokio runtime. That runtime must remain alive for scheduled cleanup to complete. Runtime teardown itself drops its tasks. The write adapter allows one accepted frame awaiting physical completion. No benchmark establishes that either branch is faster, and these checks do not establish production-duration stability.

## Review commands

From the separate library checkout:

```sh
git log --reverse --oneline upstream-baseline..stunnel-stepwise
git diff upstream-baseline stunnel-stepwise
git diff --stat upstream-baseline internal-stability
git diff stunnel-stepwise internal-stability -- src Cargo.toml
```

From STunnel:

```sh
git log --reverse --oneline c2d77a5..anytls-stepwise
git diff c2d77a5 anytls-stepwise -- src Cargo.toml
git diff anytls-stepwise anytls-internal-stability -- src/anytls Cargo.toml
python3 scripts/sync_anytls.py
```

[Verification instructions](anytls-verification.md) cover the committed regressions and real frontend sweep. `vendor/anytls-rs/VENDORED.json` identifies the exact library revision and source digest.
