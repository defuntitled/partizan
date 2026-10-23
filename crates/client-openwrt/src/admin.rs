//! Admin socket: `partizan status` connects, the daemon answers one JSON object and closes.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use client_core::{Engine, Status};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

/// Default socket path on OpenWrt (tmpfs).
pub const DEFAULT_SOCKET: &str = "/var/run/partizan.sock";

/// Serves status requests until the listener fails.
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
    // Status reveals traffic counters: root only.
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    while let Ok((mut stream, _)) = listener.accept().await {
        let status = engine.status().await;
        let _ = stream.write_all(to_json(&status).as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

/// Asks a running daemon for its status.
pub fn query(path: &Path) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}

/// One-line JSON; all values are numbers, booleans or fixed identifiers, so no escaping is
/// needed.
pub fn to_json(s: &Status) -> String {
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
        if s.connected {
            "connected"
        } else {
            "disconnected"
        },
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
