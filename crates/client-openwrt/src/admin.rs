//! Admin socket: one command line per connection (`status`, `rebind`), one answer, close.
//! A client that sends nothing gets the status.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use client_core::{Engine, Status};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// Default socket path on OpenWrt (tmpfs).
pub const DEFAULT_SOCKET: &str = "/var/run/partizan.sock";

/// Serves admin requests until the listener fails.
pub async fn serve(path: PathBuf, engine: Engine) {
    // A socket left by a crashed run would block the bind.
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            log::warn!("admin socket {}: {e}", path.display());
            return;
        }
    };
    // Status reveals traffic counters and rebind changes state: root only.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    while let Ok((stream, _)) = listener.accept().await {
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            let read =
                tokio::time::timeout(Duration::from_millis(500), stream.read_line(&mut line));
            let command = match read.await {
                Ok(Ok(_)) => line.trim().to_owned(),
                _ => String::new(),
            };
            let answer = match command.as_str() {
                "" | "status" => to_json(&engine.status().await),
                "rebind" => match engine.rebind() {
                    Ok(()) => "ok\n".into(),
                    Err(e) => format!("error: {e}\n"),
                },
                other => format!("error: unknown command {other:?}\n"),
            };
            let mut stream = stream.into_inner();
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Sends `command` to a running daemon and returns its answer.
pub fn query(path: &Path, command: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

/// One-line JSON; all values are numbers, booleans or fixed identifiers, so no escaping is
/// needed.
pub fn to_json(s: &Status) -> String {
    let state = match (s.connected, s.revoked) {
        (_, true) => "revoked",
        (true, false) => "connected",
        (false, false) => "connecting",
    };
    let session = match s.session {
        Some(info) => format!(
            "{{\"sid\":\"{:x}\",\"caps\":{},\"udp_max\":{}}}",
            info.sid, info.caps.0, info.udp_max
        ),
        None => "null".into(),
    };
    format!(
        concat!(
            "{{\"state\":\"{}\",\"transport\":{},\"session\":{},\"rtt_ms\":{},",
            "\"bytes_sent\":{},\"bytes_received\":{},\"mtu\":{},\"tcp_streams\":{},",
            "\"udp_flows\":{},\"udp_drops\":{},\"reconnects\":{}}}\n"
        ),
        state,
        s.transport.map_or("null".into(), |t| format!("\"{t}\"")),
        session,
        s.stats.rtt.as_millis(),
        s.stats.bytes_sent,
        s.stats.bytes_received,
        s.stats.mtu,
        s.tcp_streams,
        s.udp_flows,
        s.udp_drops,
        s.reconnects,
    )
}
