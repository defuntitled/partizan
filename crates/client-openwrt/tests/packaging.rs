//! OpenWrt packaging: the init script, run with UCI and procd stubbed.

use std::path::PathBuf;
use std::process::Command;

fn packaging() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/openwrt")
}

#[test]
fn init_script_parses_and_hands_procd_the_right_command() {
    let init = packaging().join("partizan/files/partizan.init");
    let syntax = Command::new("sh").arg("-n").arg(&init).status().unwrap();
    assert!(syntax.success(), "init script has syntax errors");
    let output = Command::new("sh")
        .arg(packaging().join("test-init.sh"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn config_is_a_conffile_installed_root_only() {
    let makefile = std::fs::read_to_string(packaging().join("partizan/Makefile")).unwrap();
    assert!(makefile.contains("define Package/partizan/conffiles\n/etc/config/partizan\nendef"));
    assert!(makefile.contains("$(INSTALL_CONF) ./files/partizan.config $(1)/etc/config/partizan"));
}
