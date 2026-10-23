# STunnel

Simple SOCKS5/HTTP tunnel. SOCKS5 on client side provides NO AUTHENTICATION TCP/UDP proxy. Version 3.0 based on QUIC and TLS-TCP.

```
                .                      |                     .
                .                      f                     .
                .                      i                     .
      HTTP -----|                      r                     |------ outbound1
                |                      e                     |
                |                      |                     |
             client---------------- tunnel ----------------server--- outbound2
                |                      |                     |
                |                      w                     |
    SOCKS5 -----|                      a                     |------ outbound3
                .                      l                     .
                .                      l                     .
                .                      |                     .
```

## Version 3.0 status

### Proxy type

- [x] HTTP proxy
- [x] SOCKS5 TCP proxy
- [x] SOCKS5 UDP proxy
- [x] Reverse proxy

### Tunnel type

- [x] QUIC
- [x] TLS-TCP(based on TLS on TCP)

## Usage

To create portable client, relay, and server bundles with certificates, use the [deployment config generator](docs/generate-configs.md).

1. `./certgen` generates cert and private key
2. modify `config/client.toml` and `config/server.toml`
3. start server(`./stunnel_server --config config/server.toml`) and client(`./stunnel_client --config config/client.toml`) with the same cert

Browser connect client address(`127.0.0.1:1080`) via SOCKS5 or connect client address(`127.0.0.1:8080`) via HTTP.

## AnyTLS

Set `tunnel_type = "anytls"` and point `server_addr` at the main server TCP address.

```toml
# client.toml
server_addr = "127.0.0.1:12345"
tunnel_type = "anytls"
anytls = { password = "replace-with-a-shared-secret" }
```

```toml
# server.toml
anytls = { password = "replace-with-a-shared-secret" }
```

Use the existing certificate and private key settings on both peers. AnyTLS uses mutual TLS and password authentication. HTTP, SOCKS TCP and SOCKS UDP use the existing client listeners. Reverse proxy configuration is rejected for this transport.

This integration uses the original Rust library and STunnel's inner forwarding protocol. See [the design](docs/anytls-design.md), [the comparison](docs/anytls-comparison.md) and [verification](docs/anytls-verification.md).

## Reverse proxy(`quic`/`s2n-quic`)

The client can register reverse TCP listeners on the server: the server listens
on the configured address, and every connection is forwarded through the tunnel
back to the client, which connects to the local `target`.

```toml
# client.toml
reverse_proxy = [
    { listen = "0.0.0.0:8081", target = "127.0.0.1:3000" },
    { listen = "0.0.0.0:8082", target = "127.0.0.1:22" },
]
```

Multiple entries are supported. The client registers the listeners on the
server when the tunnel connects and re-registers after reconnects. The server
opens streams on the same QUIC connection.

## Work with autoproxy and gatewaysocks

* [autoproxy](https://github.com/airtrack/autoproxy)
* [gatewaysocks](https://github.com/airtrack/gatewaysocks)

```
    ----------------                 -------------                        -------------
    |              |                 |           |                        |           |
    | gatewaysocks | --- TCP/UDP --> | autoproxy | ------- TCP/UDP -----> |  stunnel  |
    |              |                 |           |    |                   |           |
    ----------------                 -------------    |                   -------------
           ^                               ^          |
           |                               |          |                   -------------
           |                               |          |                   |           |
           |                               |          |--- TCP/UDP -----> |  direct   |
           |                               |                              |           |
           |                               |                              -------------
    -----------------             ------------------
    |    devices    |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```

### Relay through another server

A server can forward all TCP and UDP tunnels through another STunnel server using an optional `[upstream]` table. Both encrypted hops independently support TLS/TCP, AnyTLS, Quinn, and s2n-quic. See [the relay guide](docs/relay.md) and [sample relay configuration](config/relay.toml).

Ordered forward failover is available through client `[[servers]]` and relay `[[upstreams]]` lists. Peers can use different transports and credentials. See [the failover reference](docs/failover.md) for deadlines, recovery, and reverse-proxy restrictions.
