//! Deploy files: the example config parses, the unit and sysctl file say what the spec asks.

use std::path::PathBuf;

fn file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/server")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn example_config_parses() {
    let config: server::config::Config = toml::from_str(&file("server.toml")).unwrap();
    assert_eq!(config.server.listen.port(), 443);
    assert!(
        config.metrics.listen.unwrap().ip().is_loopback(),
        "metrics must stay on loopback"
    );
}

#[test]
fn unit_runs_unprivileged_with_bind_capability_and_drain_time() {
    let unit = file("partizan-server.service");
    for line in [
        "User=partizan",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "KillSignal=SIGTERM",
        "RuntimeDirectory=partizan",
    ] {
        assert!(unit.contains(line), "{line}");
    }
    let stop: u64 = unit
        .lines()
        .find_map(|l| l.strip_prefix("TimeoutStopSec="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(stop > 30, "stop timeout must exceed the 30 s drain");
}

#[test]
fn sysctl_and_image() {
    let sysctl = file("99-partizan.conf");
    for key in [
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.ipv4.tcp_congestion_control = bbr",
        "net.core.default_qdisc = fq",
    ] {
        assert!(sysctl.contains(key), "{key}");
    }
    let dockerfile = file("Dockerfile");
    assert!(dockerfile.contains("FROM scratch") && dockerfile.contains("STOPSIGNAL SIGTERM"));
    assert!(file("docker-compose.yml").contains("network_mode: host"));
}
