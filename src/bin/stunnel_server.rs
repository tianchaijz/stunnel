use clap::Parser;
use log::{error, info};
use quinn::Connection;
use stunnel::tunnel::upstream::Forwarding;
use stunnel::{
    config::{self, QuicBackend, ServerConfig},
    metrics::TransportConnection,
    print_version, quic,
    telemetry::Telemetry,
    tlstcp,
    tunnel::server::handle_routed_tunnels,
    version,
};

async fn quinn_server(config: ServerConfig, route: Forwarding) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        transport: config.quic.transport,
    };
    let endpoint = quic::quinn::server::new(&quic_config)?;

    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let incoming = tokio::select! {
            accepted = endpoint.accept() => accepted.ok_or(std::io::Error::other("endpoint closed"))?,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };

        let route = route.clone();
        tasks.spawn(async move {
            if let Ok(conn) = incoming.await {
                let _connection = TransportConnection::established("quic");
                handle_quinn_conn(conn, route)
                    .await
                    .inspect_err(|error| {
                        error!("handle quic conn error: {error}");
                    })
                    .ok();
            }
        });
    }
}

async fn handle_quinn_conn(conn: Connection, route: Forwarding) -> std::io::Result<()> {
    handle_routed_tunnels(conn.clone(), conn, route).await
}

async fn s2n_server(config: ServerConfig, route: Forwarding) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        transport: config.quic.transport,
    };
    let mut endpoint = quic::s2n_quic::server::new(&quic_config)?;

    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let conn = tokio::select! {
            accepted = endpoint.accept() => accepted.ok_or(std::io::Error::other("endpoint closed"))?,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
        };

        let route = route.clone();
        tasks.spawn(async move {
            let _connection = TransportConnection::established("s2n-quic");
            handle_s2n_conn(conn, route)
                .await
                .inspect_err(|error| {
                    error!("handle quic conn error: {error}");
                })
                .ok();
        });
    }
}

async fn handle_s2n_conn(conn: s2n_quic::Connection, route: Forwarding) -> std::io::Result<()> {
    let (conn, acceptor) = conn.split();
    handle_routed_tunnels(conn, acceptor, route).await
}

#[derive(Parser)]
#[command(disable_version_flag = true)]
struct Args {
    #[arg(long, help = "Print version and build information")]
    version: bool,

    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "version",
        help = "Path to the server config file"
    )]
    config: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.version {
        print_version("stunnel_server");
        return;
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("starting up");

    let config_path = args.config.unwrap();
    let config = match config::load_server(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load server config: {error}");
            return;
        }
    };

    let _telemetry = match Telemetry::init(&config.otel, &version("stunnel_server")) {
        Ok(telemetry) => telemetry,
        Err(error) => {
            eprintln!("failed to start metrics: {error}");
            return;
        }
    };

    let route = match Forwarding::from_peers(&config.upstreams) {
        Ok(route) => route,
        Err(error) => {
            eprintln!("failed to configure upstream: {error}");
            return;
        }
    };
    let tcp = tlstcp::server::serve_routed(&config, route.clone());
    let quic = async {
        match config.quic.server_type {
            QuicBackend::S2nQuic => s2n_server(config.clone(), route).await,
            QuicBackend::Quinn => quinn_server(config.clone(), route).await,
        }
    };
    let result = futures::try_join!(tcp, quic);

    if let Err(error) = result {
        eprintln!("stunnel server error: {error}");
    }
}
