//! Stack diagnostics: profiling counters and the verbose log, switched on the fly.
//!
//! With profiling off nothing is counted or timed: the stack checks one flag per iteration.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// Histogram buckets: bucket `i` holds times in `[2^i, 2^(i+1))` ns, the last one everything above.
const BUCKETS: usize = 32;

/// Switches and counters shared between the stack and whoever reads the metrics.
#[derive(Default)]
pub struct Diagnostics {
    profiling: AtomicBool,
    verbose: AtomicBool,
    /// When profiling was last switched on.
    since: Mutex<Option<Instant>>,
    pub(crate) counters: Counters,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) packets_in: AtomicU64,
    pub(crate) packets_out: AtomicU64,
    pub(crate) bytes_in: AtomicU64,
    pub(crate) bytes_out: AtomicU64,
    pub(crate) dropped: AtomicU64,
    pub(crate) stack_ns: AtomicU64,
    pub(crate) io_ns: AtomicU64,
    pub(crate) queue_depth: AtomicU64,
    pub(crate) queue_peak: AtomicU64,
    pub(crate) tcp_connections: AtomicU64,
    pub(crate) udp_flows: AtomicU64,
    packet_time: [AtomicU64; BUCKETS],
}

impl Counters {
    fn reset(&self) {
        let all = [
            &self.packets_in,
            &self.packets_out,
            &self.bytes_in,
            &self.bytes_out,
            &self.dropped,
            &self.stack_ns,
            &self.io_ns,
            &self.queue_depth,
            &self.queue_peak,
            &self.tcp_connections,
            &self.udp_flows,
        ];
        for counter in all.into_iter().chain(&self.packet_time) {
            counter.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn set(counter: &AtomicU64, n: u64) {
        counter.store(n, Ordering::Relaxed);
    }

    /// Records `packets` packets that took `total` together.
    pub(crate) fn record_packets(&self, total: Duration, packets: u64) {
        if packets == 0 {
            return;
        }
        let each = (total.as_nanos() / u128::from(packets)).max(1);
        let bucket = (each.ilog2() as usize).min(BUCKETS - 1);
        self.packet_time[bucket].fetch_add(packets, Ordering::Relaxed);
    }

    /// Upper bound of the bucket holding the `q` quantile.
    fn quantile(&self, q: f64) -> Duration {
        let counts: Vec<u64> = self
            .packet_time
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return Duration::ZERO;
        }
        let rank = ((total as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0;
        for (i, n) in counts.iter().enumerate() {
            seen += n;
            if seen >= rank {
                return Duration::from_nanos(1u64 << (i + 1));
            }
        }
        Duration::from_nanos(1u64 << BUCKETS)
    }
}

impl Diagnostics {
    /// Switches profiling and the verbose stack log; takes effect on the next packet. Turning
    /// profiling on starts the counters from zero.
    pub fn set(&self, profiling: bool, verbose: bool) {
        self.verbose.store(verbose, Ordering::Relaxed);
        let was = self.profiling.swap(profiling, Ordering::Relaxed);
        if profiling && !was {
            self.counters.reset();
            *self.since.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        }
    }

    /// Whether counters are collected.
    pub fn profiling(&self) -> bool {
        self.profiling.load(Ordering::Relaxed)
    }

    /// Whether packet and connection events are logged (at `debug`, with addresses).
    pub fn verbose(&self) -> bool {
        self.verbose.load(Ordering::Relaxed)
    }

    /// Current metrics; all zero while profiling is off.
    pub fn metrics(&self) -> StackMetrics {
        if !self.profiling() {
            return StackMetrics::default();
        }
        let since = *self.since.lock().unwrap_or_else(|e| e.into_inner());
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        StackMetrics {
            elapsed: since.map_or(Duration::ZERO, |t| t.elapsed()),
            packets_in: get(&c.packets_in),
            packets_out: get(&c.packets_out),
            bytes_in: get(&c.bytes_in),
            bytes_out: get(&c.bytes_out),
            dropped: get(&c.dropped),
            packet_time_p50: c.quantile(0.50),
            packet_time_p99: c.quantile(0.99),
            queue_depth: get(&c.queue_depth),
            queue_peak: get(&c.queue_peak),
            tcp_connections: get(&c.tcp_connections),
            udp_flows: get(&c.udp_flows),
            stack_time: Duration::from_nanos(get(&c.stack_ns)),
            io_time: Duration::from_nanos(get(&c.io_ns)),
        }
    }
}

/// Snapshot of the stack counters since profiling was switched on.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StackMetrics {
    /// Time since profiling was switched on.
    pub elapsed: Duration,
    /// Packets read from the interface.
    pub packets_in: u64,
    /// Packets written to the interface.
    pub packets_out: u64,
    /// Bytes read from the interface.
    pub bytes_in: u64,
    /// Bytes written to the interface.
    pub bytes_out: u64,
    /// Packets dropped: malformed, unsupported, over a limit, or a failed write.
    pub dropped: u64,
    /// Median stack time per packet read (upper bound of a power-of-two bucket).
    pub packet_time_p50: Duration,
    /// 99th percentile of the same.
    pub packet_time_p99: Duration,
    /// Packets waiting to be written to the interface.
    pub queue_depth: u64,
    /// Highest `queue_depth` seen.
    pub queue_peak: u64,
    /// Open TCP connections.
    pub tcp_connections: u64,
    /// Open UDP flows.
    pub udp_flows: u64,
    /// Time spent in the stack, outside interface reads and writes.
    pub stack_time: Duration,
    /// Time spent reading and writing the interface.
    pub io_time: Duration,
}

impl StackMetrics {
    /// Packets per second, both directions.
    pub fn packets_per_sec(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs == 0.0 {
            return 0.0;
        }
        (self.packets_in + self.packets_out) as f64 / secs
    }

    /// Share of busy time spent in the stack rather than in interface I/O, `0.0..=1.0`.
    pub fn stack_share(&self) -> f64 {
        let busy = (self.stack_time + self.io_time).as_secs_f64();
        if busy == 0.0 {
            return 0.0;
        }
        self.stack_time.as_secs_f64() / busy
    }
}

impl fmt::Display for StackMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.0} pps, in {} pkt/{} B, out {} pkt/{} B, dropped {}, per packet p50 {:?} p99 {:?}, \
             queue {} (peak {}), tcp {}, udp {}, stack {:.0}%",
            self.packets_per_sec(),
            self.packets_in,
            self.bytes_in,
            self.packets_out,
            self.bytes_out,
            self.dropped,
            self.packet_time_p50,
            self.packet_time_p99,
            self.queue_depth,
            self.queue_peak,
            self.tcp_connections,
            self.udp_flows,
            self.stack_share() * 100.0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantiles_come_from_buckets() {
        let d = Diagnostics::default();
        d.set(true, false);
        d.counters
            .record_packets(Duration::from_nanos(1000 * 99), 99);
        d.counters.record_packets(Duration::from_millis(1), 1);
        let m = d.metrics();
        // 1000 ns sits in [512, 1024), 1 ms in [2^19, 2^20).
        assert_eq!(m.packet_time_p50, Duration::from_nanos(1024));
        assert_eq!(m.packet_time_p99, Duration::from_nanos(1024));
        d.counters.record_packets(Duration::from_millis(1), 1);
        assert_eq!(d.metrics().packet_time_p99, Duration::from_nanos(1 << 20));
    }

    #[test]
    fn metrics_are_zero_while_off_and_reset_on_enable() {
        let d = Diagnostics::default();
        Counters::add(&d.counters.packets_in, 5);
        assert_eq!(d.metrics(), StackMetrics::default());
        d.set(true, false);
        assert_eq!(d.metrics().packets_in, 0, "enabling starts from zero");
    }
}
