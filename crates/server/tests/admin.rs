//! Device management: the partizan-server CLI against a running server with an admin socket.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use proto::auth::{ConnectionUri, HandshakeError};
use server::Server;
use server::config::Config;
use transport::Transport;

struct Running {
    config: PathBuf,
    dir: PathBuf,
    addr: std::net::SocketAddr,
    pin: [u8; 32],
    state: Arc<server::State>,
}

async fn start(sessions_per_device: u32) -> Running {
    let dir = temp_path("x").parent().unwrap().to_path_buf();
    let config = dir.join("server.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\ndomain = \"localhost\"\nlisten = \"127.0.0.1:0\"\nauth_path = \"/api/v2/sync\"\n\
             devices = \"{d}/devices.toml\"\nadmin_sock = \"{d}/admin.sock\"\n\
             [tls]\nmode = \"self-signed\"\n[limits]\nsessions_per_device = {sessions_per_device}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let server = Server::bind(Config::load(&config).unwrap()).await.unwrap();
    let (addr, pin, state) = (server.local_addr().unwrap(), server.pin(), server.state());
    tokio::spawn(server.run());
    // The admin socket comes up with run().
    for _ in 0..50 {
        if dir.join("admin.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Running {
        config,
        dir,
        addr,
        pin,
        state,
    }
}

async fn cli(config: &Path, args: &[&str]) -> (bool, String) {
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_partizan-server"))
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

/// Adds a device and returns its parsed link.
async fn add(r: &Running, name: &str) -> ConnectionUri {
    let (ok, out) = cli(&r.config, &["device", "add", name, "--host", "127.0.0.1"]).await;
    assert!(ok, "{out}");
    let link = out
        .lines()
        .find(|l| l.starts_with("partizan://"))
        .expect("link printed");
    ConnectionUri::parse(link).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn c18_t1_device_add_prints_link_and_qr_and_stores_only_the_hash() {
    let r = start(2).await;
    let (ok, out) = cli(
        &r.config,
        &["device", "add", "router", "--host", "127.0.0.1"],
    )
    .await;
    assert!(ok, "{out}");
    let link = out.lines().find(|l| l.starts_with("partizan://")).unwrap();
    assert!(out.contains('█') || out.contains('▀'), "no QR code:\n{out}");
    let uri = ConnectionUri::parse(link).unwrap();
    assert_eq!(uri.pin, Some(r.pin), "the running server's pin");
    assert_eq!(uri.sni.as_deref(), Some("localhost"));
    let registry = std::fs::read_to_string(r.dir.join("devices.toml")).unwrap();
    assert!(
        !registry.contains(uri.token.to_base64url().as_str()),
        "token stored in the registry"
    );
    assert!(registry.contains(&uri.token.hash().to_hex()));
    // The server picked the device up without a restart.
    assert!(connect_uri(r.addr, r.pin, &uri).await.is_ok());
    let (ok, list) = cli(&r.config, &["device", "list"]).await;
    assert!(
        ok && list.contains("router") && list.contains("active"),
        "{list}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c18_t2_revoke_closes_live_sessions_within_five_seconds() {
    let r = start(2).await;
    let uri = add(&r, "phone").await;
    let client = connect_uri(r.addr, r.pin, &uri).await.unwrap();
    let started = std::time::Instant::now();
    let (ok, out) = cli(&r.config, &["device", "revoke", "phone"]).await;
    assert!(ok && out.contains("1 sessions closed"), "{out}");
    tokio::time::timeout(Duration::from_secs(5), client.transport.closed())
        .await
        .expect("session still open after 5 s");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        connect_uri(r.addr, r.pin, &uri).await.err(),
        Some(HandshakeError::Rejected)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn c18_t3_rotate_issues_a_new_token_and_the_old_one_stops() {
    let r = start(2).await;
    let old = add(&r, "laptop").await;
    let client = connect_uri(r.addr, r.pin, &old).await.unwrap();
    let (ok, out) = cli(
        &r.config,
        &["device", "rotate", "laptop", "--host", "127.0.0.1"],
    )
    .await;
    assert!(ok, "{out}");
    let new =
        ConnectionUri::parse(out.lines().find(|l| l.starts_with("partizan://")).unwrap()).unwrap();
    assert_eq!(new.device_id, old.device_id);
    tokio::time::timeout(Duration::from_secs(5), client.transport.closed())
        .await
        .expect("old session survived");
    assert_eq!(
        connect_uri(r.addr, r.pin, &old).await.err(),
        Some(HandshakeError::Rejected)
    );
    assert!(connect_uri(r.addr, r.pin, &new).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn c18_t4_session_list_shows_platform_transport_rtt_and_traffic() {
    let r = start(2).await;
    let uri = add(&r, "tv").await;
    let _client = connect_uri(r.addr, r.pin, &uri).await.unwrap();
    let (ok, out) = cli(&r.config, &["session", "list"]).await;
    assert!(ok, "{out}");
    let header = out.lines().next().unwrap();
    for column in ["PLATFORM", "TRANSPORT", "RTT_MS", "SENT", "RECEIVED"] {
        assert!(header.contains(column), "{header}");
    }
    let row = out.lines().find(|l| l.contains("tv")).expect("session row");
    assert!(row.contains("test") && row.contains("quic"), "{row}");
}

#[tokio::test(flavor = "multi_thread")]
async fn c18_t5_over_the_limit_the_oldest_session_is_closed() {
    let r = start(2).await;
    let uri = add(&r, "router").await;
    let first = connect_uri(r.addr, r.pin, &uri).await.unwrap();
    let _second = connect_uri(r.addr, r.pin, &uri).await.unwrap();
    assert_eq!(r.state.sessions.len(), 2);
    let _third = connect_uri(r.addr, r.pin, &uri).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), first.transport.closed())
        .await
        .expect("oldest session kept");
    assert!(eventually_len(&r.state, 2).await);
}

async fn eventually_len(state: &server::State, n: usize) -> bool {
    for _ in 0..50 {
        if state.sessions.len() == n {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}
