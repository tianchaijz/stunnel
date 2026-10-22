# Ordered forward failover

Clients accept an ordered `[[servers]]` list. Relays accept an ordered `[[upstreams]]` list. The legacy flat client fields and relay `[upstream]` table remain single-peer configurations. A server with neither upstream form forwards directly.

Each peer requires `server_addr`, `server_name`, `server_cert`, `private_key`, and `tunnel_type`. Supported transports are `tlstcp`, `anytls`, `quic`, and `s2n-quic`. An AnyTLS peer also requires its own nonempty password. Credentials and transport options do not inherit from another peer. Empty lists, mixed legacy and list forms, incomplete peers, and unknown peer fields are rejected. Every peer's configuration and credentials are loaded before traffic is accepted, including backups. Relay self-loop checks apply to every peer.

Examples are [client-failover.toml](../config/client-failover.toml) and [relay-failover.toml](../config/relay-failover.toml). These examples use a different transport and certificate for each peer.

## Setup and established traffic

Each new TCP or UDP flow tries eligible peers once in configured order. An attempt includes opening the transport, sending the STunnel request, and receiving a valid bind reply. Failed setup can try the next peer, including failures that arrive after AnyTLS stream creation. The relay preserves the exit's original valid bind reply bytes.

Application data stays local until a valid bind reply arrives. Setup retries may open destination TCP connections through multiple peers, but they do not replay application data. After a valid bind reply, downstream success delivery and data transfer cannot trigger another attempt. Established flows remain on the selected peer. Recovering a primary does not move or interrupt existing backup flows.

## Deadlines and recovery

Client forward setup has a ten-second total deadline, including legacy single-server configurations. Relays use their original ten-second admission deadline across the inbound header, all attempts, and downstream bind delivery. A relay holds one of its 64 shared flow permits through setup and data transfer. The client route has no corresponding 64-flow limit.

With multiple peers, an attempt receives the smaller of five seconds or the remaining time divided by the number of eligible untried peers. The last eligible attempt also remains capped at five seconds. Early failures leave more time for later attempts. A single peer receives the full remaining deadline and never enters cooldown, so subsequent flows can reconnect immediately.

For a multi-peer route, a proven remote transport-open failure puts that peer into a 30-second cooldown. New flows skip it. After cooldown expires, one new flow probes the peer while concurrent flows skip that probe. Successful setup or an inconclusive failure ends the probe. A cancelled probe lets another flow probe. Another proven remote failure starts a new cooldown. No background probes run. If every peer is cooling or already being probed, new flows fail immediately. Recovery can therefore take up to 30 seconds after a peer becomes reachable, followed by the next flow's setup time.

TLS certificate verification failures, capacity limits, opaque connector errors, cache-lock waits, and outer attempt timeouts do not prove a peer is down. Failures after transport opening, including destination refusal, malformed bind replies, and deferred AnyTLS authentication errors, also leave peer health unchanged. They still allow this flow to try the next peer. A wrong AnyTLS password can therefore consume an attempt on every flow.

## Reverse proxy compatibility

Multiple client peers cannot be combined with a nonempty `reverse_proxy`. Legacy singleton and single-entry list QUIC clients retain connection-owned reverse forwarding. AnyTLS reverse forwarding remains unsupported. TLS/TCP retains its existing behavior of ignoring reverse-proxy and QUIC transport settings. Relay mode rejects reverse control requests.
