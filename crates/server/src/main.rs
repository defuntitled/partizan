//! `partizan-server`: the partizan VPN server.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use server::Server;
use server::config::Config;

mod cli;

const USAGE: &str = "\
usage: partizan-server run [--config PATH]
       partizan-server device add NAME [--host HOST] [--config PATH]
       partizan-server device rotate ID|NAME [--host HOST] [--config PATH]
       partizan-server device revoke ID|NAME [--config PATH]
       partizan-server device list [--config PATH]
       partizan-server session list [--config PATH]
       partizan-server version";
const DEFAULT_CONFIG: &str = "/etc/partizan/server.toml";

enum Command {
    Run {
        config: PathBuf,
    },
    Admin {
        config: PathBuf,
        action: cli::Action,
    },
    Version,
}

fn parse_args() -> Result<Command, String> {
    use lexopt::prelude::*;
    let fail = |e: lexopt::Error| e.to_string();
    let mut parser = lexopt::Parser::from_env();
    let mut words = Vec::new();
    let (mut config, mut host) = (PathBuf::from(DEFAULT_CONFIG), None);
    while let Some(arg) = parser.next().map_err(fail)? {
        match arg {
            Long("config") | Short('c') => config = parser.value().map_err(fail)?.into(),
            Long("host") => host = Some(parser.value().map_err(fail)?.string().map_err(fail)?),
            Long("help") | Short('h') => return Err(USAGE.into()),
            Value(word) => words.push(word.string().map_err(fail)?),
            _ => return Err(format!("{}\n{USAGE}", fail(arg.unexpected()))),
        }
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let action = match words.as_slice() {
        ["run"] => return Ok(Command::Run { config }),
        ["version"] => return Ok(Command::Version),
        ["device", "add", name] => cli::Action::Add {
            name: (*name).into(),
            host,
        },
        ["device", "rotate", key] => cli::Action::Rotate {
            key: (*key).into(),
            host,
        },
        ["device", "revoke", key] => cli::Action::Revoke { key: (*key).into() },
        ["device", "list"] => cli::Action::List,
        ["session", "list"] => cli::Action::Sessions,
        _ => return Err(USAGE.into()),
    };
    Ok(Command::Admin { config, action })
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
        Command::Admin { config, action } => match cli::run(&config, action) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
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
                match state.certs.reload() {
                    Ok(true) => tracing::info!("certificate reloaded"),
                    Ok(false) => {}
                    Err(e) => {
                        tracing::error!("certificate reload failed, keeping the old one: {e}")
                    }
                }
            }
        });
        let shutdown = server.shutdown_handle();
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(e) => {
                    tracing::error!("signal handler: {e}");
                    return ExitCode::FAILURE;
                }
            };
        let run = tokio::spawn(server.run());
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        // Streams get 30 s to finish; clients come back in 5 s, to this or a new process.
        shutdown
            .run(Duration::from_secs(30), Duration::from_secs(5))
            .await;
        run.abort();
        tracing::info!("stopped");
        ExitCode::SUCCESS
    })
}
