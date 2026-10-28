//! The packet interface under the stack: one read or write is one whole IP packet.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;

/// Packet-oriented I/O: a TUN fd, or anything with the same message boundaries.
pub trait PacketDevice: Send + 'static {
    /// Reads one packet into `buf`, returning its length.
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>;

    /// Writes one packet.
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>>;
}

/// A packet fd: the TUN fd from `VpnService`, or a `SOCK_DGRAM`/`SOCK_SEQPACKET` socket in
/// tests. The fd must be non-blocking (as `VpnService.Builder.establish()` returns it).
pub struct FdDevice {
    fd: AsyncFd<File>,
}

impl FdDevice {
    /// Takes ownership of `fd`; it is closed when the device is dropped.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: the `File` owns the fd, so it stays open and `as_raw_fd` returns the same fd
        // for as long as the `AsyncFd` holds the `File`.
        #[allow(unsafe_code)]
        let fd = unsafe { AsyncFd::register(File::from(fd)) }.map_err(io::Error::from)?;
        Ok(Self { fd })
    }
}

impl PacketDevice for FdDevice {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            match guard.try_io(|fd| fd.get_ref().read(buf)) {
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|fd| fd.get_ref().write(packet)) {
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(result) => return Poll::Ready(result.map(drop)),
                Err(_would_block) => {}
            }
        }
    }
}
