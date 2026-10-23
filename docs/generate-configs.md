# Generate deployment configs and certificates

Use Python 3.10 or later and the repository's Rust `certgen` binary. The generator uses only the Python standard library.

```sh
cargo build --release --bins
python3 scripts/generate_configs.py
```

This creates `deployment/` in the current working directory. It contains `server-1/`, `relay/`, and `client/`, each with `config.toml` and the credentials it needs. The default transport is AnyTLS. Use `--transport tlstcp`, `--transport quic` (Quinn), or `--transport s2n-quic` to select another transport for every hop.

The default relay address is `198.51.100.20:12345` and server address is `203.0.113.10:12345`. These are documentation placeholders for separate hosts. For a same-host setup, use distinct relay and server ports. Before deployment, edit `servers[].server_addr` in `client/config.toml` and `upstreams[].server_addr` in `relay/config.toml` to your hosts. Keep `server_name = "stunnel"`: it matches the fixed certificate SAN.

Use `--no-relay` to generate direct client-to-server bundles. Explicit `--server` values replace the default server list; repeat the flag for ordered backups. Explicit `--relay` replaces the default relay address and cannot be combined with `--no-relay`.

```sh
python3 scripts/generate_configs.py \
  --relay 198.51.100.20:443 \
  --server 203.0.113.10:443 \
  --server '[2001:db8::10]:8443' \
  --transport quic --output deployment-relay
```

The client connects to the relay, which tries `server-1`, then `server-2`. With `--no-relay` the client tries the servers directly. Failover applies to new flows; existing flows stay on their selected server. These documentation addresses must be replaced with your hosts' addresses.

`--server` and `--relay` require numeric IP addresses with ports from 1 to 65535. Bracket IPv6 addresses. Wildcard and multicast advertised addresses, IPv6 zone identifiers, duplicate endpoints, and obvious relay self-loops are rejected. Private and loopback addresses are allowed. Each server binds the wildcard address for its advertised address family and port. Configure your firewall and host networking to make that address reachable. Servers start both TCP and UDP listeners, including when the selected outbound transport uses only one of them. AnyTLS and TLS-over-TCP bundles omit the optional `[quic]` table; the server still starts its default UDP QUIC listener. QUIC bundles explicitly select the matching `quic` or `s2n-quic` backend.

The client defaults to SOCKS5 at `127.0.0.1:1080` and HTTP at `127.0.0.1:8080`. Override them with `--socks5-listen IP:PORT` and `--http-listen IP:PORT`. Conflicting listeners are rejected. Binding a proxy to a non-loopback address exposes it to other hosts that can reach that address. No telemetry destination is generated.

The generator looks for `target/release/certgen`, then `target/debug/certgen`, relative to the repository. Use `--certgen /path/to/certgen` or `--certgen executable-on-PATH` to override it. It invokes certgen separately for each receiving listener with a 30-second timeout. All peers use TLS name `stunnel`, matching certgen's fixed certificate SAN. The actual connection destination remains the numeric advertised address.

## Deploy the bundles

Copy each complete role directory to its host. Put the existing STunnel binaries on PATH and start the servers, then the relay if present, then the client. The generated `README.md` contains the commands for every role. For example, from the directory containing the copied `server-1/` bundle:

```sh
cd server-1
stunnel_server --config config.toml
```

On the client host, from the directory containing its copied bundle:

```sh
cd client
stunnel_client --config config.toml
```

Run from inside each bundle because credential paths resolve against the process working directory. Entire bundles can move to a different filesystem path without editing their configs.

Each receiving listener has its own certificate and private key. Current STunnel mutual TLS requires that same certificate **and private key** on both ends of a hop. Thus clients hold the credentials for their servers or relay, and a relay also holds the credentials for its servers. AnyTLS adds an independently generated password per listener, shared only with its dialers. Treat every bundle as secret material and transfer it securely. The generator does not print credentials. On Unix it creates directories with mode `0700` and files with mode `0600`.

## Output safety

`--output` defaults to `./deployment` in the current working directory. It must name a fresh directory under an existing parent. Existing directories, files, and symlinks, including dangling symlinks, are refused. There is no overwrite option. Generate a separate deployment when rotating credentials and distribute matching bundles together.

Generation finishes in a private temporary sibling directory before the generator exclusively creates the destination. Ordinary failures remove temporary files and any destination created by that invocation. Publication is not atomic. An interruption or process termination can leave partial output; a rerun refuses it. Inspect and remove an incomplete deployment yourself before reusing that path. Existing output created by another process is preserved.

Run the focused checks with a built certgen:

```sh
python3 scripts/test_generate_configs.py
```

Set `STUNNEL_CERTGEN=/path/to/certgen` to use another built binary for the tests. Checks requiring real certificate generation are skipped if no binary is available.
