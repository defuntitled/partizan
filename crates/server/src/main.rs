//! `partizan-server`: the partizan VPN server.

use std::path::PathBuf;
use std::process::ExitCode;

use server::Server;
use server::config::Config;

const USAGE: &str = "usage: partizan-server run [--config PATH]\n       partizan-server version";
const DEFAULT_CONFIG: &str = "/etc/partizan/server.toml";

enum Command {
    Run { config: PathBuf },
    Version,
}

fn parse_args() -> Result<Command, lexopt::Error> {
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_env();
    let command = match parser.next()? {
        Some(Value(cmd)) => cmd.string()?,
        Some(Long("help") | Short('h')) | None => return Err(lexopt::Error::from(USAGE)),
        Some(arg) => return Err(arg.unexpected()),
    };
    match command.as_str() {
        "run" => {
            let mut config = PathBuf::from(DEFAULT_CONFIG);
            while let Some(arg) = parser.next()? {
                match arg {
                    Long("config") | Short('c') => config = parser.value()?.into(),
                    _ => return Err(arg.unexpected()),
                }
            }
            Ok(Command::Run { config })
        }
        "version" => Ok(Command::Version),
        other => Err(format!("unknown command {other:?}\n{USAGE}").into()),
    }
}

fn main() -> ExitCode {
    let command = match parse_args() {
        Ok(command) => command,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match command {
        Command::Version => {
            println!(
                "partizan-server {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                proto::auth::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Command::Run { config } => run(config),
    }
}

fn run(path: PathBuf) -> ExitCode {
    // Colours only on a terminal; journald and log files get plain text.
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let server = match Server::bind(config).await {
            Ok(server) => server,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::FAILURE;
            }
        };
        let addr = server
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let pin = proto::auth::format_pin(&server.pin());
        tracing::info!(listen = %addr, pin = %pin, "listening");
        let state = server.state();
        tokio::spawn(async move {
            let Ok(mut hup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while hup.recv().await.is_some() {
                match state.reload_registry() {
                    Ok(n) => tracing::info!(devices = n, "registry reloaded"),
                    Err(e) => tracing::error!("registry reload failed, keeping the old one: {e}"),
                }
            }
        });
        tokio::select! {
            () = server.run() => {}
            _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        }
        ExitCode::SUCCESS
    })
}
