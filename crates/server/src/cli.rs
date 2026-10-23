//! `partizan-server device|session …`: registry edits plus a nudge to the running server.

use std::path::Path;

use proto::auth::{ConnectionUri, DeviceId, Token, TransportMode};
use server::config::{Config, TlsMode};
use server::{admin, devices};

/// A management command.
pub enum Action {
    Add { name: String, host: Option<String> },
    Rotate { key: String, host: Option<String> },
    Revoke { key: String },
    List,
    Sessions,
}

pub fn run(config_path: &Path, action: Action) -> Result<(), String> {
    let config = Config::load(config_path)?;
    let registry = &config.server.devices;
    match action {
        Action::Add { name, host } => {
            let (id, token) = devices::add(registry, &name)?;
            notify(&config, "reload");
            print_link(&config, host.as_deref(), id, token)
        }
        Action::Rotate { key, host } => {
            let (entry, token) = devices::rotate(registry, &key)?;
            // Sessions on the old token end now; the device needs the new link.
            notify(&config, &format!("revoke {}", entry.id));
            print_link(&config, host.as_deref(), entry.id, token)
        }
        Action::Revoke { key } => {
            let entry = devices::revoke(registry, &key)?;
            match request(&config, &format!("revoke {}", entry.id)) {
                Some(answer) => print!("revoked {} ({}): {answer}", entry.name, entry.id),
                None => println!(
                    "revoked {} ({}); the server is not running",
                    entry.name, entry.id
                ),
            }
            Ok(())
        }
        Action::List => {
            let live = request(&config, "sessions").unwrap_or_default();
            println!("{:<32} {:<16} {:<8} SESSIONS", "ID", "NAME", "STATUS");
            for e in devices::load(registry)? {
                let id = e.id.to_string();
                let sessions = live.lines().filter(|l| l.contains(&id)).count();
                let status = if e.revoked { "revoked" } else { "active" };
                println!("{id:<32} {:<16} {status:<8} {sessions}", e.name);
            }
            Ok(())
        }
        Action::Sessions => {
            let answer = request(&config, "sessions").ok_or("the server is not running")?;
            print!("{answer}");
            Ok(())
        }
    }
}

/// Sends a command to the running server, if there is one.
fn request(config: &Config, command: &str) -> Option<String> {
    let path = config.server.admin_sock.as_ref()?;
    admin::request(path, command).ok()
}

fn notify(config: &Config, command: &str) {
    if let Some(answer) = request(config, command)
        && answer.starts_with("error")
    {
        eprintln!("server: {answer}");
    }
}

/// Prints the connection link (shown once; only its hash is stored) and its QR code.
fn print_link(
    config: &Config,
    host: Option<&str>,
    id: DeviceId,
    token: Token,
) -> Result<(), String> {
    let domain = config.server.domain.clone();
    let host = host
        .map(str::to_owned)
        .or_else(|| domain.clone())
        .ok_or("no [server] domain; pass --host with the server's public address")?;
    let info = request(config, "info");
    let port = info
        .as_deref()
        .and_then(|i| i.split_whitespace().find_map(|w| w.strip_prefix("port=")))
        .and_then(|p| p.parse().ok())
        .unwrap_or(config.server.listen.port());
    let uri = ConnectionUri {
        device_id: id,
        token,
        sni: domain.filter(|d| *d != host),
        host,
        port,
        path: config.server.auth_path.clone(),
        pin: pin(config, info.as_deref())?,
        transport: TransportMode::Auto,
        insecure: false,
        passthrough: None,
    };
    let link = uri.to_uri_string();
    println!("{}\n", link.as_str());
    match qrcode::QrCode::new(link.as_bytes()) {
        Ok(qr) => println!(
            "{}",
            qr.render::<qrcode::render::unicode::Dense1x2>().build()
        ),
        Err(e) => eprintln!("no QR code: {e}"),
    }
    println!("Shown once: the server keeps only a hash of this token.");
    Ok(())
}

/// Pin for the link: the running server's (self-signed), the certificate file's, or none when
/// a public CA vouches for the certificate (ACME).
fn pin(config: &Config, info: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    let from_server = info
        .and_then(|i| {
            i.split_whitespace()
                .find_map(|w| w.strip_prefix("pin=sha256/"))
        })
        .and_then(proto::auth::parse_pin_base64);
    match config.tls.mode {
        TlsMode::Acme | TlsMode::AcmeIp => Ok(None),
        TlsMode::SelfSigned => from_server.map(Some).ok_or_else(|| {
            "self-signed certificate: start the server first so its pin is known".into()
        }),
        TlsMode::Files => {
            let cert = config.tls.cert.as_ref().ok_or("tls.cert is required")?;
            use rustls::pki_types::CertificateDer;
            use rustls::pki_types::pem::PemObject;
            let der = CertificateDer::from_pem_file(cert)
                .map_err(|e| format!("{}: {e}", cert.display()))?;
            Ok(transport::tls::spki_pin(&der))
        }
    }
}
