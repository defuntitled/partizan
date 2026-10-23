//! Names of the server's benchmark endpoints (`[bench] enabled = true` on the server).
//!
//! A `Connect` to [`HOST`] never leaves the server: the port picks the test.

/// Target host of every benchmark endpoint.
pub const HOST: &str = "partizan.bench";
/// TCP: the server sends data until the client closes.
pub const DOWNLOAD: u16 = 1;
/// TCP: the server reads to FIN, then answers the byte count as `u64` BE.
pub const UPLOAD: u16 = 2;
/// TCP and UDP: echo.
pub const ECHO: u16 = 3;
