//! Outgoing TCP: resolve, apply the egress policy, connect with Happy Eyeballs (RFC 8305).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use proto::{ErrorCode, Host, TargetAddr};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until};

use crate::egress::EgressPolicy;

/// Overall connect timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Stagger between connection attempts (RFC 8305 §5).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Why a target could not be reached; maps to a stream error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DialError {
    /// Every resolved address is denied by the egress policy.
    #[error("not allowed by egress policy")]
    NotAllowed,
    /// Name did not resolve or no route.
    #[error("unreachable")]
    Unreachable,
    /// Target refused the connection.
    #[error("refused")]
    Refused,
    /// No answer within [`CONNECT_TIMEOUT`].
    #[error("timed out")]
    Timeout,
}

impl DialError {
    /// Stream error code for `RESET_STREAM`.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::NotAllowed => ErrorCode::NOT_ALLOWED,
            Self::Unreachable => ErrorCode::TARGET_UNREACHABLE,
            Self::Refused => ErrorCode::TARGET_REFUSED,
            Self::Timeout => ErrorCode::TARGET_TIMEOUT,
        }
    }
}

/// Resolves `target` on the server and connects to the first address that answers.
pub async fn dial(
    target: &TargetAddr,
    resolver: &TokioResolver,
    egress: &EgressPolicy,
) -> Result<TcpStream, DialError> {
    let ips: Vec<IpAddr> = match &target.host {
        Host::V4(ip) => vec![IpAddr::V4(*ip)],
        Host::V6(ip) => vec![IpAddr::V6(*ip)],
        Host::Domain(name) => {
            // A trailing dot keeps resolv.conf search domains out of it.
            let fqdn = if name.ends_with('.') {
                name.clone()
            } else {
                format!("{name}.")
            };
            let lookup = resolver
                .lookup_ip(fqdn)
                .await
                .map_err(|_| DialError::Unreachable)?;
            lookup.iter().collect()
        }
    };
    let allowed: Vec<SocketAddr> = ips
        .iter()
        .filter(|ip| egress.allows(**ip))
        .map(|&ip| SocketAddr::new(ip, target.port))
        .collect();
    if allowed.is_empty() {
        return Err(if ips.is_empty() {
            DialError::Unreachable
        } else {
            DialError::NotAllowed
        });
    }
    let stream = happy_eyeballs(interleave(allowed), ATTEMPT_DELAY, CONNECT_TIMEOUT)
        .await
        .map_err(|e| match e.kind() {
            io::ErrorKind::ConnectionRefused => DialError::Refused,
            io::ErrorKind::TimedOut => DialError::Timeout,
            _ => DialError::Unreachable,
        })?;
    stream.set_nodelay(true).ok();
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    SockRef::from(&stream).set_tcp_keepalive(&keepalive).ok();
    Ok(stream)
}

/// IPv6 and IPv4 alternating, IPv6 first (RFC 8305 §4).
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addrs.into_iter().partition(SocketAddr::is_ipv6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Starts an attempt every `delay`, or right after one fails; the first success wins and
/// the rest are cancelled.
async fn happy_eyeballs(
    addrs: Vec<SocketAddr>,
    delay: Duration,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let mut pending = addrs.into_iter().peekable();
    let mut attempts = JoinSet::new();
    let mut last_error = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    loop {
        if let Some(addr) = pending.next() {
            attempts.spawn(TcpStream::connect(addr));
        }
        let more = pending.peek().is_some();
        tokio::select! {
            result = attempts.join_next(), if !attempts.is_empty() => match result {
                Some(Ok(Ok(stream))) => return Ok(stream),
                Some(Ok(Err(e))) => last_error = e,
                Some(Err(join)) => last_error = io::Error::other(join),
                None => {}
            },
            () = sleep(delay), if more => {}
            () = sleep_until(deadline) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
        }
        if attempts.is_empty() && pending.peek().is_none() {
            return Err(last_error);
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn addresses_alternate_v6_first() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let mixed = vec![a("1.1.1.1:1"), a("2.2.2.2:1"), a("[::1]:1"), a("3.3.3.3:1")];
        assert_eq!(
            interleave(mixed),
            [a("[::1]:1"), a("1.1.1.1:1"), a("2.2.2.2:1"), a("3.3.3.3:1")]
        );
    }

    #[tokio::test]
    async fn first_answer_wins_and_failures_move_on() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // A closed port first: refused at once, so the next attempt starts without waiting.
        let closed = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let start = std::time::Instant::now();
        let stream =
            happy_eyeballs(vec![closed, good], Duration::from_secs(5), CONNECT_TIMEOUT).await;
        assert_eq!(stream.unwrap().peer_addr().unwrap(), good);
        assert!(start.elapsed() < Duration::from_secs(2));

        let refused = happy_eyeballs(vec![closed], ATTEMPT_DELAY, CONNECT_TIMEOUT).await;
        assert_eq!(
            refused.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
    }
}
