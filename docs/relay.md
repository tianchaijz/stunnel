# Forward through an upstream server

Run a relay with the existing `stunnel_server` binary and an optional `[upstream]` table. The path is:

```text
app -> STunnel client A -> encrypted AB -> server B -> encrypted BC -> server C -> destination
```

A's normal client configuration points to B. B uses [config/relay.toml](../config/relay.toml) as its server configuration. C uses an ordinary server configuration without upstream configuration. Only C connects to TCP destinations and sends UDP datagrams to destinations.

Set B's inbound `listen`, `cert`, and `priv_key` for AB. Set its optional `[anytls].password` to enable AnyTLS on the same TCP address. The inbound password is independent of the upstream password. In `[upstream]`, set C's numeric `server_addr`, `server_name`, `server_cert`, `private_key`, and `tunnel_type`. The transport choices are `tlstcp`, `anytls`, `quic`, and `s2n-quic`. For AnyTLS, set `[upstream.anytls].password`. Optional `[upstream.quic]` settings use the same transport fields as the client configuration. Each hop can use a different transport and different credentials.

Start B with:

```sh
stunnel_server --config config/relay.toml
```

B terminates both encrypted hops and can read the forwarded traffic. C authenticates B. B has one upstream route for all its listeners and does not expose a local proxy frontend. C's actual bind reply reaches A before proxy success. With one upstream, failed authentication, destination connection, or malformed bind replies close the flow. With multiple upstreams, setup can try the next eligible peer. B never falls back to a direct destination connection and never replays a failed flow.

Reverse proxy registration is unsupported in relay mode and B rejects control streams before binding a reverse listener. Leave `reverse_proxy` empty on A. Servers without either upstream configuration retain direct forwarding and reverse proxy behavior.

B admits at most 64 relay flows across its listeners, including flows waiting for an AnyTLS stream acknowledgement or their first header byte. Excess flows close immediately. A single 10-second setup deadline starts at admission and covers the AnyTLS stream acknowledgement, inbound header, upstream connection and stream opening, request, C's bind reply, and its delivery to A. Once setup succeeds, TCP half-close and raw UDP framing pass through without an idle timeout. The flow limit is separate from transport session and preauthentication limits. It does not bound all inbound transport connections or handshakes. The shared TCP listener allows 64 concurrent TLS handshakes, independently of the 64 AnyTLS physical sessions and 64 relay flows. TLS plus AnyTLS password authentication share one ten-second deadline from TCP acceptance.

QUIC upstream connections are established lazily and shared across flows. Later flows reconnect after connection loss. Existing flows keep their connection generation until they finish. There is no background reconnect loop. Stopping B or losing an inbound multiplexed session cancels its relay tasks.

B rejects obvious self-loops to its own listener addresses, including wildcard listeners addressed through loopback. Remote servers can use the same port. Multi-node cycles are unsupported and are not detected. Configure an acyclic chain that ends at a server without upstream configuration.

## Ordered upstream failover

Replace `[upstream]` with complete `[[upstreams]]` entries to try multiple exits in order. Each entry owns its transport settings and credentials. See [the failover reference](failover.md) and [the relay failover example](../config/relay-failover.toml).

The relay keeps one 64-flow limit across all peers and inbound transports. All attempts and the downstream bind reply share the original ten-second setup deadline. Failed setup can open a destination connection on more than one exit, but no application bytes reach an exit until setup succeeds. Established flows remain pinned to their selected exit.

## Verify the route

Build the binaries and run the isolated three-machine checks on Linux:

```sh
cargo build --bins
python3 scripts/verify_relay.py
```

The verifier requires `ip`, `unshare`, `nsenter`, and enabled user namespaces. It checks all 16 transport pairs with A unable to reach C and the destination reachable only from C. It also checks upstream failures, reconnection, HTTP and SOCKS forwarding, and direct QUIC reverse forwarding. Set `STUNNEL_BIN_DIR` to test binaries from another build directory.
