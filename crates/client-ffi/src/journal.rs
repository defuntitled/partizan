//! Only explicitly instrumented, address-free events can enter an export.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

static LOGGER: Journal = Journal;
static EVENTS: Mutex<VecDeque<(u64, String)>> = Mutex::new(VecDeque::new());
static LOST: AtomicU64 = AtomicU64::new(0);
struct Journal;

impl log::Log for Journal {
    fn enabled(&self, meta: &log::Metadata<'_>) -> bool {
        meta.target() == "partizan_diag" && meta.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        if let Ok(mut q) = EVENTS.try_lock()
            && q.len() < 256
        {
            let ms = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            q.push_back((ms, record.args().to_string()));
        } else {
            LOST.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn flush(&self) {}
}

pub(super) fn configure(on: bool, verbose: bool) {
    static OWNS_LOGGER: OnceLock<bool> = OnceLock::new();
    if *OWNS_LOGGER.get_or_init(|| log::set_logger(&LOGGER).is_ok()) {
        log::set_max_level(if !on {
            log::LevelFilter::Off
        } else if verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        });
    }
    if !on {
        let _ = drain();
    }
}

pub(super) fn drain() -> serde_json::Value {
    let events = std::mem::take(&mut *super::lock(&EVENTS));
    serde_json::json!({"lost":LOST.swap(0,Ordering::Relaxed),"events":events})
}
