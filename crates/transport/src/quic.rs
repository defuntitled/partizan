//! QUIC transport on quinn: one connection, one bidi stream per proxied TCP connection, UDP in
//! DATAGRAM frames (RFC 9221).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use proto::ErrorCode;
use quinn::congestion::{CubicConfig, NewRenoConfig};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ConnectionError, Endpoint, IdleTimeout, MtuDiscoveryConfig, SendDatagramError, TransportConfig,
    VarInt,
};

use crate::{
    Congestion, DatagramError, QuicConfig, RecvHalf, RecvStream, SendHalf, SendStream, Transport,
    TransportError, TransportStats,
};

impl QuicConfig {
    /// quinn transport parameters for these settings.
    pub fn transport_config(&self) -> TransportConfig {
        let varint = |v: u64| VarInt::from_u64(v).unwrap_or(VarInt::MAX);
        let mut t = TransportConfig::default();
        t.stream_receive_window(varint(self.stream_receive_window))
            .receive_window(varint(self.receive_window))
            .send_window(self.send_window)
            .max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_bidi_streams))
            .datagram_send_buffer_size(
                usize::try_from(self.datagram_send_buffer).unwrap_or(usize::MAX),
            )
            .keep_alive_interval(Some(self.keep_alive))
            .max_idle_timeout(IdleTimeout::try_from(self.idle_timeout).ok())
            .initial_mtu(self.initial_mtu)
            .enable_segmentation_offload(true);
        let mut mtu = MtuDiscoveryConfig::default();
        mtu.upper_bound(self.max_mtu);
        t.mtu_discovery_config(Some(mtu));
        match self.congestion {
            Congestion::Cubic => t.congestion_controller_factory(Arc::new(CubicConfig::default())),
            Congestion::NewReno => {
                t.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
        };
        t
    }
}

/// Client endpoint bound to `bind`, ready to connect with `tls`.
pub fn client_endpoint(
    bind: SocketAddr,
    tls: rustls::ClientConfig,
    config: &QuicConfig,
) -> io::Result<Endpoint> {
    let crypto = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(config.transport_config()));
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

/// Server endpoint on `bind`.
pub fn server_endpoint(
    bind: SocketAddr,
    tls: rustls::ServerConfig,
    config: &QuicConfig,
) -> io::Result<Endpoint> {
    let crypto = QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(config.transport_config()));
    Endpoint::server(server, bind)
}

/// Moves a client endpoint to a new local socket (WAN address change); live connections
/// migrate.
pub fn rebind(endpoint: &Endpoint, bind: SocketAddr) -> io::Result<()> {
    endpoint.rebind(UdpSocket::bind(bind)?)
}

/// Connects to `addr`, presenting `server_name` as SNI.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
) -> Result<QuicTransport, TransportError> {
    let connecting = endpoint
        .connect(addr, server_name)
        .map_err(|e| TransportError::Lost(e.to_string()))?;
    let conn = connecting.await.map_err(map_connection_error)?;
    Ok(QuicTransport::new(conn))
}

/// [`Transport`] over one QUIC connection.
#[derive(Debug, Clone)]
pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    /// Wraps an established connection.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// The underlying connection, for the auth exchange and ALPN checks.
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

fn map_connection_error(e: ConnectionError) -> TransportError {
    match e {
        ConnectionError::ApplicationClosed(close) => {
            TransportError::ClosedByPeer(ErrorCode(close.error_code.into_inner()))
        }
        ConnectionError::LocallyClosed => TransportError::ClosedLocally,
        other => TransportError::Lost(other.to_string()),
    }
}

/// Reset code inside an I/O error from a quinn stream.
pub(crate) fn reset_code(e: &io::Error) -> Option<ErrorCode> {
    let inner = e.get_ref()?;
    let code = if let Some(read) = inner.downcast_ref::<quinn::ReadError>() {
        match read {
            quinn::ReadError::Reset(code) => *code,
            _ => return None,
        }
    } else {
        match inner.downcast_ref::<quinn::WriteError>()? {
            quinn::WriteError::Stopped(code) => *code,
            _ => return None,
        }
    };
    Some(ErrorCode(code.into_inner()))
}

fn code(code: ErrorCode) -> VarInt {
    VarInt::from_u64(code.0).unwrap_or(VarInt::MAX)
}

impl SendStream for quinn::SendStream {
    fn reset(&mut self, error: ErrorCode) {
        // Already finished or reset: nothing left to abandon.
        let _ = quinn::SendStream::reset(self, code(error));
    }
}

impl RecvStream for quinn::RecvStream {
    fn stop(&mut self, error: ErrorCode) {
        let _ = quinn::RecvStream::stop(self, code(error));
    }
}

#[async_trait]
impl Transport for QuicTransport {
    async fn open_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let (send, recv) = self.conn.open_bi().await.map_err(map_connection_error)?;
        Ok((Box::new(send), Box::new(recv)))
    }

    async fn accept_stream(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let (send, recv) = self.conn.accept_bi().await.map_err(map_connection_error)?;
        Ok((Box::new(send), Box::new(recv)))
    }

    fn send_datagram(&self, data: Bytes) -> Result<(), DatagramError> {
        self.conn.send_datagram(data).map_err(|e| match e {
            SendDatagramError::TooLarge => DatagramError::TooLarge,
            SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
                DatagramError::Unsupported
            }
            SendDatagramError::ConnectionLost(_) => DatagramError::Closed,
        })
    }

    async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.conn
            .read_datagram()
            .await
            .map_err(map_connection_error)
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn stats(&self) -> TransportStats {
        let stats = self.conn.stats();
        TransportStats {
            rtt: self.conn.rtt(),
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            mtu: stats.path.current_mtu,
        }
    }

    fn close(&self, error: ErrorCode, reason: &[u8]) {
        self.conn.close(code(error), reason);
    }
}
