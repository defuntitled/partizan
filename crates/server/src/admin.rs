//! Admin socket: line commands from `partizan-server device|session …` to the running server.
//!
//! `reload`, `revoke <device id>`, `sessions`, `info`; one command per connection, then the
//! answer and close. The socket is root-only.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use proto::ErrorCode;
use proto::auth::DeviceId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::State;

/// What `info` reports.
#[derive(Debug, Clone, Copy)]
pub struct Info {
    /// SPKI pin of the certificate in use.
    pub pin: [u8; 32],
    /// Listening port.
    pub port: u16,
}

/// Serves the admin socket until it fails.
pub async fn serve(path: PathBuf, state: Arc<State>, info: Info) {
    let _ = std::fs::remove_file(&path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "admin socket");
            return;
        }
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    while let Ok((stream, _)) = listener.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            if tokio::time::timeout(Duration::from_secs(2), stream.read_line(&mut line))
                .await
                .is_err()
            {
                return;
            }
            let answer = handle(line.trim(), &state, info);
            let mut stream = stream.into_inner();
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn handle(command: &str, state: &State, info: Info) -> String {
    let mut words = command.split_whitespace();
    match (words.next(), words.next()) {
        (Some("reload"), None) => match state.reload_registry() {
            Ok(n) => format!("ok {n} devices\n"),
            Err(e) => format!("error: {e}\n"),
        },
        (Some("revoke"), Some(id)) => {
            let Some(id) = DeviceId::from_hex(id) else {
                return "error: bad device id\n".into();
            };
            if let Err(e) = state.reload_registry() {
                return format!("error: {e}\n");
            }
            let kicked = state.sessions.go_away(Some(id), ErrorCode::REVOKED, 0);
            format!("ok {kicked} sessions closed\n")
        }
        (Some("sessions"), None) => sessions(state),
        (Some("info"), None) => format!(
            "pin={} port={}\n",
            proto::auth::format_pin(&info.pin),
            info.port
        ),
        _ => format!("error: unknown command {command:?}\n"),
    }
}

/// One line per session: id, device, platform, transport, RTT, traffic, age.
fn sessions(state: &State) -> String {
    let mut out = String::from(
        "SID              DEVICE                           NAME             PLATFORM  VERSION   TRANSPORT  RTT_MS  SENT        RECEIVED    AGE_S\n",
    );
    let mut list = state.sessions.list();
    list.sort_by_key(|(_, s)| s.started);
    for (sid, s) in list {
        let stats = s.connection.stats();
        let rtt = if stats.rtt.is_zero() {
            "-".to_owned()
        } else {
            stats.rtt.as_millis().to_string()
        };
        out.push_str(&format!(
            "{sid:016x} {} {:<16} {:<9} {:<9} {:<10} {rtt:<7} {:<11} {:<11} {}\n",
            s.device,
            s.name,
            s.platform,
            s.client_version,
            s.transport,
            stats.bytes_sent,
            stats.bytes_received,
            s.started.elapsed().as_secs()
        ));
    }
    out
}

/// Sends one command to the running server.
pub fn request(path: &Path, command: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    let mut out = String::new();
    stream.read_to_string(&mut out)?;
    Ok(out)
}
