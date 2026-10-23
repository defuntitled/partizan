//! `partizan`: OpenWrt client daemon wiring `socks5` into `client-core`.

mod admin;
mod logger;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use client_core::{Engine, EngineConfig};
use log::LevelFilter;
use proto::auth::{ClientInfo, ConnectionUri};
use transport::QuicConfig;

const USAGE: &str = "\
usage: partizan run (--uri URI | --uri-file PATH) [--socks ADDR] [--log-level LEVEL]
                    [--honest-connect] [--admin-sock PATH]
       partizan check (--uri URI | --uri-file PATH)
       partizan status [--admin-sock PATH]
       partizan version";
const DEFAULT_SOCKS: &str = "127.0.0.1:1080";

enum Command {
    Run {
        uri: ConnectionUri,
        socks: SocketAddr,
        level: LevelFilter,
        honest: bool,
        admin: PathBuf,
    },
    Status {
        admin: PathBuf,
    },
    Check {
        uri: ConnectionUri,
    },
    Version,
}

fn parse_args() -> Result<Command, String> {
    use lexopt::prelude::*;
    let fail = |e: lexopt::Error| e.to_string();
    let mut parser = lexopt::Parser::from_env();
    let command = match parser.next().map_err(fail)? {
        Some(Value(cmd)) => cmd.string().map_err(fail)?,
        _ => return Err(USAGE.into()),
    };
    if command == "version" {
        return Ok(Command::Version);
    }
    let (mut uri, mut socks, mut level, mut honest) =
        (None, DEFAULT_SOCKS.to_owned(), LevelFilter::Info, false);
    let mut admin = PathBuf::from(admin::DEFAULT_SOCKET);
    while let Some(arg) = parser.next().map_err(fail)? {
        match arg {
            // A URI on the command line is visible in `ps`; prefer --uri-file.
            Long("uri") => uri = Some(parser.value().map_err(fail)?.string().map_err(fail)?),
            Long("uri-file") => {
                let path: PathBuf = parser.value().map_err(fail)?.into();
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                uri = Some(text.trim().to_owned());
            }
            Long("socks") => socks = parser.value().map_err(fail)?.string().map_err(fail)?,
            Long("log-level") => {
                level = parser
                    .value()
                    .map_err(fail)?
                    .string()
                    .map_err(fail)?
                    .parse()
                    .map_err(|_| "bad --log-level")?;
            }
            Long("honest-connect") => honest = true,
            Long("admin-sock") => admin = parser.value().map_err(fail)?.into(),
            _ => return Err(format!("{}\n{USAGE}", fail(arg.unexpected()))),
        }
    }
    if command == "status" {
        return Ok(Command::Status { admin });
    }
    let uri = ConnectionUri::parse(&uri.ok_or("--uri or --uri-file is required")?)
        .map_err(|e| e.to_string())?;
    match command.as_str() {
        "run" => Ok(Command::Run {
            uri,
            socks: socks
                .parse()
                .map_err(|_| format!("bad --socks address {socks:?}"))?,
            level,
            honest,
            admin,
        }),
        "check" => Ok(Command::Check { uri }),
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    }
}

fn engine(uri: ConnectionUri) -> Engine {
    Engine::new(EngineConfig {
        uri,
        quic: QuicConfig::default(),
        info: ClientInfo::new("openwrt", env!("CARGO_PKG_VERSION")),
    })
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    // Two cores on the target router; more workers only cost memory.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
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
                "partizan {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                proto::auth::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Command::Check { uri } => {
            logger::init(LevelFilter::Warn);
            match runtime() {
                Ok(rt) => rt.block_on(check(uri)),
                Err(e) => {
                    eprintln!("runtime: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Status { admin } => match admin::query(&admin) {
            Ok(json) => {
                print!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("partizan is not running ({}: {e})", admin.display());
                ExitCode::FAILURE
            }
        },
        Command::Run {
            uri,
            socks,
            level,
            honest,
            admin,
        } => {
            logger::init(level);
            match runtime() {
                Ok(rt) => rt.block_on(run(uri, socks, honest, admin)),
                Err(e) => {
                    log::error!("runtime: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn check(uri: ConnectionUri) -> ExitCode {
    let server = format!("{}:{}", uri.host, uri.port);
    let started = Instant::now();
    match engine(uri).connect().await {
        Ok(session) => {
            println!(
                "ok: QUIC to {server}, authenticated in {} ms, caps {:x}, udp-max {}",
                started.elapsed().as_millis(),
                session.caps.0,
                session.udp_max
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("failed: QUIC to {server}: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(uri: ConnectionUri, socks: SocketAddr, honest: bool, admin: PathBuf) -> ExitCode {
    let options = socks5::Options {
        honest_connect: honest,
        credentials: None,
    };
    if !socks5::is_safe_listen(socks, &options) {
        log::error!("refusing to open SOCKS on {socks} without a password; use a loopback address");
        return ExitCode::FAILURE;
    }
    let listener = match tokio::net::TcpListener::bind(socks).await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("SOCKS listen on {socks}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let engine = engine(uri);
    tokio::spawn(admin::serve(admin, engine.clone()));
    // Warm the session so the first connection does not wait for the handshake.
    if let Err(e) = engine.connect().await {
        log::warn!("initial connection failed, will retry on demand: {e}");
    }
    let socks = listener.local_addr().unwrap_or(socks);
    log::info!("SOCKS5 on {socks}");
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(term) => term,
        Err(e) => {
            log::error!("signal handler: {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio::select! {
        () = socks5::serve(listener, engine, options) => {}
        _ = term.recv() => log::info!("terminated"),
        _ = tokio::signal::ctrl_c() => log::info!("interrupted"),
    }
    ExitCode::SUCCESS
}
