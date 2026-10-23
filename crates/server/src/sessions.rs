//! Live sessions: `sid → device`, for limits, `session list` and `GoAway`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use proto::auth::DeviceId;

/// One authenticated connection.
#[derive(Debug, Clone)]
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
}

/// Session table.
#[derive(Debug, Default)]
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Session>> {
        // A panic while holding the lock leaves the map consistent; keep serving.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}
