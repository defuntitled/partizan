//! The server certificate, shared by the QUIC and TCP listeners and reloadable in place, so a
//! renewal (certbot rewriting the PEM files) needs no restart.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// Where the certificate comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// PEM files, reloaded when they change.
    Files {
        /// Certificate chain (PEM).
        cert: PathBuf,
        /// Private key (PEM).
        key: PathBuf,
    },
    /// Fixed for the process lifetime.
    Fixed,
}

/// Current certificate.
#[derive(Debug)]
pub struct CertStore {
    source: Source,
    current: RwLock<(Arc<CertifiedKey>, Option<SystemTime>)>,
}

impl CertStore {
    /// Store serving `chain` and `key`.
    pub fn new(
        source: Source,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, String> {
        let certified = certified(chain, key)?;
        let mtime = modified(&source);
        Ok(Self {
            source,
            current: RwLock::new((certified, mtime)),
        })
    }

    /// Loads PEM files.
    pub fn from_files(cert: PathBuf, key: PathBuf) -> Result<Self, String> {
        let (chain, key_der) = read_pem(&cert, &key)?;
        Self::new(Source::Files { cert, key }, chain, key_der)
    }

    /// SHA-256 of the current certificate's SPKI.
    pub fn pin(&self) -> Option<[u8; 32]> {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        current.0.cert.first().and_then(transport::tls::spki_pin)
    }

    /// Re-reads the files if they changed; returns whether the certificate was replaced. A bad
    /// new file keeps the old certificate.
    pub fn reload(&self) -> Result<bool, String> {
        let Source::Files { cert, key } = &self.source else {
            return Ok(false);
        };
        let mtime = modified(&self.source);
        if mtime == self.current.read().unwrap_or_else(|e| e.into_inner()).1 {
            return Ok(false);
        }
        let (chain, key_der) = read_pem(cert, key)?;
        let certified = certified(chain, key_der)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = (certified, mtime);
        Ok(true)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.current
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .clone(),
        )
    }
}

fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, String> {
    if chain.is_empty() {
        return Err("certificate file holds no certificate".into());
    }
    let signing =
        rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

fn read_pem(
    cert: &PathBuf,
    key: &PathBuf,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    Ok((chain, key))
}

/// Latest modification time of the files, to notice a renewal.
fn modified(source: &Source) -> Option<SystemTime> {
    let Source::Files { cert, key } = source else {
        return None;
    };
    let time = |p: &PathBuf| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    time(cert).max(time(key))
}
