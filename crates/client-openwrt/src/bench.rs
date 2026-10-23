//! `partizan bench`: throughput, latency and CPU through the tunnel, against the server's
//! benchmark endpoints (`[bench] enabled = true` on the server).

use std::time::{Duration, Instant};

use bytes::Bytes;
use client_core::Engine;
use proto::{Host, TargetAddr, bench};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn endpoint(port: u16) -> TargetAddr {
    TargetAddr {
        host: Host::Domain(bench::HOST.into()),
        port,
    }
}

/// Runs every measurement and prints a report; `Err` if the server does not serve them.
pub async fn run(engine: &Engine, seconds: u64, streams: usize) -> Result<(), String> {
    let info = engine.connect().await.map_err(|e| e.to_string())?;
    println!(
        "session: QUIC, caps {:x}, udp-max {}",
        info.caps.0, info.udp_max
    );
    let tcp = tcp_rtt(engine, 50).await?;
    // Read after traffic has flowed: the estimate starts pessimistic.
    let quic_rtt = engine.status().await.stats.rtt;
    println!("quic rtt:      {:.2} ms (transport estimate)", ms(quic_rtt));
    println!(
        "tcp echo rtt:  p50 {:.2} ms, p99 {:.2} ms",
        ms(percentile(&tcp, 50)),
        ms(percentile(&tcp, 99))
    );
    let (udp, lost) = udp_rtt(engine, 200).await?;
    if udp.is_empty() {
        return Err("no UDP echo answers".into());
    }
    let p50 = percentile(&udp, 50);
    println!(
        "udp echo rtt:  p50 {:.2} ms, p99 {:.2} ms, lost {lost}/200; added over QUIC rtt {:.2} ms (N2)",
        ms(p50),
        ms(percentile(&udp, 99)),
        ms(p50.saturating_sub(quic_rtt))
    );

    let duration = Duration::from_secs(seconds);
    let cpu = cpu_seconds();
    let started = Instant::now();
    let down = download(engine, streams, duration).await?;
    report("download", down, started.elapsed(), cpu);
    let cpu = cpu_seconds();
    let started = Instant::now();
    let up = upload(engine, streams, duration).await?;
    report("upload", up, started.elapsed(), cpu);
    Ok(())
}

fn report(what: &str, bytes: u64, elapsed: Duration, cpu_before: Option<f64>) {
    let mbit = bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1e6;
    let cpu = match (cpu_before, cpu_seconds()) {
        (Some(a), Some(b)) => format!(
            ", client CPU {:.0}% of one core",
            (b - a) / elapsed.as_secs_f64() * 100.0
        ),
        _ => String::new(),
    };
    println!(
        "{what:<13} {mbit:.1} Mbit/s ({bytes} bytes in {:.1} s{cpu})",
        elapsed.as_secs_f64()
    );
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn percentile(samples: &[Duration], p: usize) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[(sorted.len() - 1) * p / 100]
}

async fn tcp_rtt(engine: &Engine, rounds: usize) -> Result<Vec<Duration>, String> {
    let (mut send, mut recv) = engine
        .open_tcp(endpoint(bench::ECHO), true)
        .await
        .map_err(|e| e.to_string())?;
    let mut samples = Vec::with_capacity(rounds);
    let mut byte = [0u8; 1];
    for i in 0..rounds {
        let started = Instant::now();
        send.write_all(&[i as u8])
            .await
            .map_err(|e| e.to_string())?;
        recv.read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        samples.push(started.elapsed());
    }
    Ok(samples)
}

async fn udp_rtt(engine: &Engine, rounds: usize) -> Result<(Vec<Duration>, usize), String> {
    let mut flow = engine.open_udp();
    let mut samples = Vec::with_capacity(rounds);
    let mut lost = 0;
    let payload = Bytes::from(vec![0u8; 200]);
    for _ in 0..rounds {
        let started = Instant::now();
        flow.send(endpoint(bench::ECHO), payload.clone())
            .await
            .map_err(|e| e.to_string())?;
        match tokio::time::timeout(Duration::from_secs(1), flow.recv()).await {
            Ok(Some(_)) => samples.push(started.elapsed()),
            _ => lost += 1,
        }
    }
    Ok((samples, lost))
}

async fn download(engine: &Engine, streams: usize, duration: Duration) -> Result<u64, String> {
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let (_send, mut recv) = engine
            .open_tcp(endpoint(bench::DOWNLOAD), true)
            .await
            .map_err(|e| e.to_string())?;
        tasks.push(tokio::spawn(async move {
            let mut total = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            let deadline = tokio::time::Instant::now() + duration;
            while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, recv.read(&mut buf)).await {
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            total
        }));
    }
    let mut total = 0;
    for task in tasks {
        total += task.await.unwrap_or(0);
    }
    Ok(total)
}

async fn upload(engine: &Engine, streams: usize, duration: Duration) -> Result<u64, String> {
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let (mut send, mut recv) = engine
            .open_tcp(endpoint(bench::UPLOAD), true)
            .await
            .map_err(|e| e.to_string())?;
        tasks.push(tokio::spawn(async move {
            let chunk = vec![0u8; 64 * 1024];
            let deadline = tokio::time::Instant::now() + duration;
            while tokio::time::Instant::now() < deadline {
                if send.write_all(&chunk).await.is_err() {
                    return 0;
                }
            }
            let _ = send.shutdown().await;
            // The server's count is what actually arrived.
            let mut count = [0u8; 8];
            match recv.read_exact(&mut count).await {
                Ok(_) => u64::from_be_bytes(count),
                Err(_) => 0,
            }
        }));
    }
    let mut total = 0;
    for task in tasks {
        total += task.await.unwrap_or(0);
    }
    Ok(total)
}

/// User + system CPU time of this process from `/proc/self/stat` (Linux; 100 ticks/s).
fn cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the parenthesised command name; utime and stime are fields 14 and 15.
    let rest = &stat[stat.rfind(')')? + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ticks: u64 = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    Some(ticks as f64 / 100.0)
}
