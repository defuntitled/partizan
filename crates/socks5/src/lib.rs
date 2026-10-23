//! Traffic source: SOCKS5 (RFC 1928) `CONNECT` and `UDP ASSOCIATE`, feeding `client-core`.
//! Domain names are passed on unresolved.

mod udp;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use client_core::{ConnectError, Engine, relay};
use proto::{Host, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const VERSION: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// `REP` codes (RFC 1928 §6).
pub mod reply {
    /// Succeeded.
    pub const SUCCEEDED: u8 = 0x00;
    /// General SOCKS server failure.
    pub const GENERAL_FAILURE: u8 = 0x01;
    /// Command not supported.
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// Address type not supported.
    pub const ADDRESS_NOT_SUPPORTED: u8 = 0x08;
}

/// Time a client gets to finish the SOCKS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Proxy behaviour.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Reply to `CONNECT` only after the server reached the target, with the real `REP`.
    /// Off by default: reply at once and report a failed target by closing (fast open).
    pub honest_connect: bool,
    /// Require RFC 1929 login and password, for a proxy opened beyond loopback.
    pub credentials: Option<(String, String)>,
}

/// Protocol error from the SOCKS client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Not SOCKS5 or malformed.
    #[error("bad SOCKS request: {0}")]
    Protocol(&'static str),
    /// Socket error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Accepts SOCKS clients until the listener fails.
pub async fn serve(listener: TcpListener, engine: Engine, options: Options) {
    let options = Arc::new(options);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log::warn!("SOCKS accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        let (engine, options) = (engine.clone(), options.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(stream, &engine, &options).await {
                log::debug!("SOCKS client {peer}: {e}");
            }
        });
    }
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `CMD`.
    pub command: u8,
    /// Destination, unresolved.
    pub target: TargetAddr,
}

async fn handle(mut stream: TcpStream, engine: &Engine, options: &Options) -> Result<(), Error> {
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        negotiate(&mut stream, options).await?;
        read_request(&mut stream).await
    })
    .await
    .map_err(|_| Error::Protocol("handshake timed out"))?;
    let request = match request {
        Ok(request) => request,
        Err(RequestError::AddressType) => {
            write_reply(&mut stream, reply::ADDRESS_NOT_SUPPORTED).await?;
            return Ok(());
        }
        Err(RequestError::Other(e)) => return Err(e),
    };
    match request.command {
        CMD_CONNECT => {}
        CMD_UDP_ASSOCIATE => return udp::associate(stream, engine).await,
        // BIND is not supported.
        _ => {
            write_reply(&mut stream, reply::COMMAND_NOT_SUPPORTED).await?;
            return Ok(());
        }
    }
    match engine
        .open_tcp(request.target.clone(), options.honest_connect)
        .await
    {
        Ok((send, recv)) => {
            write_reply(&mut stream, reply::SUCCEEDED).await?;
            relay(Box::new(stream), send, recv, !options.honest_connect).await;
        }
        Err(e) => {
            log::debug!("CONNECT {:?}: {e}", request.target);
            let rep = match e {
                ConnectError::Session(_) => reply::GENERAL_FAILURE,
                other => other.socks_reply(),
            };
            write_reply(&mut stream, rep).await?;
        }
    }
    Ok(())
}

/// Method selection and, if configured, the RFC 1929 login.
async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    options: &Options,
) -> Result<(), Error> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Error::Protocol("not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    let wanted = if options.credentials.is_some() {
        METHOD_PASSWORD
    } else {
        METHOD_NONE
    };
    if !methods.contains(&wanted) {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
        return Err(Error::Protocol("no acceptable auth method"));
    }
    stream.write_all(&[VERSION, wanted]).await?;
    let Some((user, pass)) = &options.credentials else {
        return Ok(());
    };
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;
    if version[0] != 0x01 {
        return Err(Error::Protocol("bad login version"));
    }
    let mut got_user = vec![0u8; usize::from(version[1])];
    stream.read_exact(&mut got_user).await?;
    let mut len = [0u8; 1];
    stream.read_exact(&mut len).await?;
    let mut got_pass = vec![0u8; usize::from(len[0])];
    stream.read_exact(&mut got_pass).await?;
    let ok = got_user == user.as_bytes() && got_pass == pass.as_bytes();
    stream
        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
        .await?;
    if ok {
        Ok(())
    } else {
        Err(Error::Protocol("wrong login"))
    }
}

enum RequestError {
    AddressType,
    Other(Error),
}

impl From<Error> for RequestError {
    fn from(e: Error) -> Self {
        Self::Other(e)
    }
}

impl From<std::io::Error> for RequestError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.into())
    }
}

/// `VER CMD RSV ATYP DST.ADDR DST.PORT`.
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Request, RequestError> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(RequestError::Other(Error::Protocol("not SOCKS5")));
    }
    let host = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Host::V4(Ipv4Addr::from(ip))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Host::V6(Ipv6Addr::from(ip))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await?;
            match String::from_utf8(name) {
                Ok(name) if !name.is_empty() => Host::Domain(name),
                _ => return Err(RequestError::AddressType),
            }
        }
        _ => return Err(RequestError::AddressType),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Request {
        command: head[1],
        target: TargetAddr {
            host,
            port: u16::from_be_bytes(port),
        },
    })
}

/// Reply with `BND.ADDR` 0.0.0.0:0; clients of a CONNECT proxy ignore it.
async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, rep: u8) -> std::io::Result<()> {
    write_reply_bound(stream, rep, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

/// Reply naming the bound address (the relay socket for `UDP ASSOCIATE`).
async fn write_reply_bound<S: AsyncWrite + Unpin>(
    stream: &mut S,
    rep: u8,
    bound: SocketAddr,
) -> std::io::Result<()> {
    let mut out = vec![VERSION, rep, 0x00];
    match bound {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&out).await
}

/// Listen address helper for binaries: loopback unless credentials are set.
pub fn is_safe_listen(addr: SocketAddr, options: &Options) -> bool {
    addr.ip().is_loopback() || options.credentials.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> Result<Request, RequestError> {
        read_request(&mut &bytes[..]).await
    }

    #[tokio::test]
    async fn c09_t5_domain_is_passed_on_unresolved() {
        let mut wire = vec![VERSION, CMD_CONNECT, 0, 0x03, 11];
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&443u16.to_be_bytes());
        let request = parse(&wire).await.ok().unwrap();
        assert_eq!(
            request.target,
            TargetAddr {
                host: Host::Domain("example.com".into()),
                port: 443
            }
        );
    }

    #[tokio::test]
    async fn addresses_parse_and_bad_types_are_flagged() {
        let v4 = [VERSION, CMD_CONNECT, 0, 0x01, 1, 2, 3, 4, 0, 80];
        assert_eq!(
            parse(&v4).await.ok().unwrap().target.host,
            Host::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        let mut v6 = vec![VERSION, CMD_CONNECT, 0, 0x04];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 80]);
        assert_eq!(
            parse(&v6).await.ok().unwrap().target.host,
            Host::V6(Ipv6Addr::LOCALHOST)
        );
        let bad = [VERSION, CMD_CONNECT, 0, 0x02, 0, 0];
        assert!(matches!(parse(&bad).await, Err(RequestError::AddressType)));
        let empty_domain = [VERSION, CMD_CONNECT, 0, 0x03, 0, 0, 80];
        assert!(matches!(
            parse(&empty_domain).await,
            Err(RequestError::AddressType)
        ));
    }

    #[tokio::test]
    async fn login_is_checked_when_configured() {
        let options = Options {
            credentials: Some(("user".into(), "pass".into())),
            ..Options::default()
        };
        let (mut client, mut server) = tokio::io::duplex(256);
        let server = tokio::spawn(async move { negotiate(&mut server, &options).await.is_ok() });
        client
            .write_all(&[VERSION, 1, METHOD_PASSWORD, 0x01, 4])
            .await
            .unwrap();
        client.write_all(b"user\x04pass").await.unwrap();
        let mut answer = [0u8; 4];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, METHOD_PASSWORD, 0x01, 0x00]);
        assert!(server.await.unwrap());

        // Without credentials configured, a client offering only a password is refused.
        let (mut client, mut server) = tokio::io::duplex(64);
        let server =
            tokio::spawn(async move { negotiate(&mut server, &Options::default()).await.is_ok() });
        client
            .write_all(&[VERSION, 1, METHOD_PASSWORD])
            .await
            .unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [VERSION, METHOD_UNACCEPTABLE]);
        assert!(!server.await.unwrap());
    }
}
