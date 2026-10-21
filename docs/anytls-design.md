# AnyTLS integration from the original Rust library

STunnel owns mutual TLS, listener admission, configuration, and its inner TCP and UDP forwarding protocol. The original Rust library owns authentication encoding, padding, framing, session lifetime, heartbeat, and its idle pool. This internal transport has no Mihomo interoperability requirement.

The client uses `Client::create_stream`, wraps the result in `StreamIo`, and splits it for `OpenTunnel`. Its dialer establishes TLS, checks `stunnel-anytls/1` ALPN, then calls `write_auth`. The server checks TLS and ALPN, calls `read_auth`, starts `Session::new_server`, and passes accepted streams to the existing forward handler. Original directional FIN supplies TCP half-close. No additional wire command or profile is introduced.

STunnel limits physical sessions to 64 per connector and 64 per server listener. A permit belongs to each physical transport until both halves disappear. A full connector returns `WouldBlock` immediately. Waiting for a transport permit inside a dial would prevent that call from noticing a session returned to the original idle pool.

Connector construction requires a running Tokio runtime, as does the underlying Client. Connector clones and returned flow IO share a Client owner. Either split flow half retains that owner. The final owner schedules existing Client shutdown on its captured runtime handle. A server Session guard similarly covers every cancellation point after construction, including `run` and normal awaited cleanup. Drop schedules cleanup while the runtime remains alive. Runtime teardown itself drops its tasks.

Inbound PUSH uses the original bounded queue and byte semaphore. It waits for capacity with both stream and Session cancellation. Ordered FIN reaches the pump after prior PUSH data. Clean EOF requires that ordered FIN. Unexpected delivery failure closes the transport so unfinished peer reads fail. Explicit full close or Drop retains the original FIN handshake, while write-half shutdown keeps response reads alive.

A blocked physical reader cannot consume heartbeat responses behind PUSH. Probes therefore run only while idle. An activation epoch invalidates an outstanding probe even if a complete flow starts and finishes before the timeout. Admission and retirement revalidate that epoch under the same lock as activation. The original 15-second physical writer deadline remains independent and fatal.

`StreamIo` reserves existing writer capacity without retaining caller bytes. It accepts the current slice synchronously and keeps one physical-completion receipt. Flush waits for that receipt. Shutdown completes accepted PUSH before submitting control-priority FIN. Large writes return a short count at the 65,535-byte frame limit. Reads poll the existing duplex reader with the current `ReadBuf`, so cancellation cannot retain an obsolete buffer size.

The integration prerequisite exposes existing `Client` and `Dialer` under `runtime`, enables the Tokio macros already used by that feature, and corrects two test helper gates. A runtime-only CI job covers embedding. Original applications, FFI, default features, workflows, and documentation remain.

Two integration designs were compared. Direct `Session` use would add per-flow lifecycle handling and lose idle-session reuse. Exposing the existing pool keeps those decisions in the library. Independent design review and DS selected that approach. Runtime fixes retain the same actors and queues, with a separate regression-backed commit for each fix.

Both STunnel peers must use this branch's transport implementation. The older `internal-stability` branch uses a different carrier profile. Switching only one peer is unsupported. [The comparison](anytls-comparison.md) explains the changes and limits. [Verification instructions](anytls-verification.md) reproduce the checks.

## Shared TCP listener

`tlstcp::server::serve(&ServerConfig)` binds the main TCP address once for legacy TLS and optional AnyTLS. QUIC uses UDP at the same numeric address. Server AnyTLS options contain only `password`; obsolete `anytls.listen` is rejected. Library callers of the former `anytls::serve` entrypoint should use `tlstcp::server::serve`.

Both TCP protocols use one TLS 1.3 configuration, the same certificate and private key, and the same mandatory client-certificate verifier rooted in that certificate. ALPN advertises `stunnel` first and `stunnel-anytls/1` second when enabled. Offering both selects legacy. Clients without ALPN use legacy forwarding; a broken AnyTLS client without ALPN therefore fails while parsing the tunnel header. Unknown protocols and AnyTLS when disabled fail TLS negotiation.

The listener admits at most 64 concurrent TLS handshakes. Excess sockets close immediately. Handshake permits release as soon as TLS completes. AnyTLS separately admits 64 physical transports, including password authentication, and retains each permit until both transport halves and protocol tasks release it. Legacy forwarding is independent of that session capacity. A single ten-second deadline from TCP acceptance covers TLS plus AnyTLS password authentication. The server owns accepted tasks and cancels them when its serving future is dropped.
