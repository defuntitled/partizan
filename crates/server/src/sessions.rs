//! Live sessions: `sid → device`, for limits, `session list` and `GoAway`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use proto::auth::DeviceId;
use proto::{ControlFrame, ErrorCode};
use tokio::sync::mpsc;

/// One authenticated connection.
#[derive(Clone)]
pub struct Session {
    /// Device it belongs to.
    pub device: DeviceId,
    /// Device name from the registry.
    pub name: String,
    /// Client platform from `x-client`.
    pub platform: String,
    /// Client version from `x-client`.
    pub client_version: String,
    /// `quic` or `tls`.
    pub transport: &'static str,
    /// When it was established.
    pub started: Instant,
    /// Its control channel.
    pub control: mpsc::Sender<ControlFrame>,
    /// The connection, to close it.
    pub connection: std::sync::Arc<dyn transport::Transport>,
}

/// Session table.
#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<u64, Session>>,
}

impl Sessions {
    /// Records a session.
    pub fn insert(&self, sid: u64, session: Session) {
        self.lock().insert(sid, session);
    }

    /// Forgets a session.
    pub fn remove(&self, sid: u64) {
        self.lock().remove(&sid);
    }

    /// Number of live sessions.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True if there are none.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Snapshot of all sessions.
    pub fn list(&self) -> Vec<(u64, Session)> {
        self.lock()
            .iter()
            .map(|(&sid, s)| (sid, s.clone()))
            .collect()
    }

    /// Sends `GoAway` to every session of `device` (all sessions if `None`); with
    /// [`ErrorCode::REVOKED`] the connections are closed after a short grace so the frame
    /// arrives first. Returns how many sessions were told.
    pub fn go_away(&self, device: Option<DeviceId>, code: ErrorCode, retry_after_ms: u64) -> usize {
        let targets: Vec<Session> = self
            .lock()
            .values()
            .filter(|s| device.is_none_or(|d| d == s.device))
            .cloned()
            .collect();
        for session in &targets {
            let _ = session.control.try_send(ControlFrame::GoAway {
                code,
                retry_after_ms,
            });
            if code == ErrorCode::REVOKED {
                let connection = session.connection.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    connection.close(code, b"revoked");
                });
            }
        }
        targets.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Session>> {
        // A panic while holding the lock leaves the map consistent; keep serving.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}
