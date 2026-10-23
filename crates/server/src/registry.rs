//! Device registry (`devices.toml`): who may connect. Holds token hashes, never tokens.
//!
//! ```toml
//! [[device]]
//! id = "<32 hex>"
//! name = "home-router"
//! token_sha256 = "<64 hex>"
//! revoked = false
//! ```

use std::collections::HashMap;
use std::path::Path;

use proto::auth::{DeviceId, DeviceRecord, DeviceRegistry, TokenHash};
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    #[serde(default, rename = "device")]
    devices: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    name: String,
    token_sha256: String,
    #[serde(default)]
    revoked: bool,
}

/// A registered device.
#[derive(Debug, Clone)]
pub struct Device {
    /// Human name.
    pub name: String,
    /// Credentials and status.
    pub record: DeviceRecord,
}

/// Parsed registry.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    devices: HashMap<DeviceId, Device>,
}

impl Registry {
    /// Reads `path`; a missing file is an empty registry.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Parses registry text.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut devices = HashMap::new();
        for entry in file.devices {
            let id = DeviceId::from_hex(&entry.id)
                .ok_or_else(|| format!("bad device id {:?}", entry.id))?;
            let token_hash = TokenHash::from_hex(&entry.token_sha256)
                .ok_or_else(|| format!("bad token_sha256 for {}", entry.name))?;
            let device = Device {
                name: entry.name,
                record: DeviceRecord {
                    token_hash,
                    revoked: entry.revoked,
                },
            };
            if devices.insert(id, device).is_some() {
                return Err(format!("duplicate device id {id}"));
            }
        }
        Ok(Self { devices })
    }

    /// The device, if registered.
    pub fn get(&self, id: &DeviceId) -> Option<&Device> {
        self.devices.get(id)
    }

    /// Number of devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

impl DeviceRegistry for Registry {
    fn device(&self, id: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(id).map(|d| &d.record)
    }
}

#[cfg(test)]
mod tests {
    use proto::auth::Token;

    use super::*;

    #[test]
    fn registry_parses_and_rejects_bad_entries() {
        let hash = Token::from_bytes([1; 32]).hash().to_hex();
        let id = "ab".repeat(16);
        let text = format!(
            "[[device]]\nid = \"{id}\"\nname = \"router\"\ntoken_sha256 = \"{hash}\"\n\n\
             [[device]]\nid = \"{}\"\nname = \"phone\"\ntoken_sha256 = \"{hash}\"\nrevoked = true\n",
            "cd".repeat(16)
        );
        let registry = Registry::parse(&text).unwrap();
        assert_eq!(registry.len(), 2);
        let router = registry.get(&DeviceId::from_hex(&id).unwrap()).unwrap();
        assert_eq!(router.name, "router");
        assert!(!router.record.revoked);

        let duplicate =
            format!("{text}\n[[device]]\nid = \"{id}\"\nname = \"x\"\ntoken_sha256 = \"{hash}\"\n");
        assert!(Registry::parse(&duplicate).is_err());
        assert!(
            Registry::parse("[[device]]\nid = \"zz\"\nname = \"x\"\ntoken_sha256 = \"00\"\n")
                .is_err()
        );
        assert!(Registry::parse("").unwrap().is_empty());
    }
}
