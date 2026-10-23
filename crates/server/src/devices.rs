//! Registry edits for `partizan-server device …`: the file is rewritten atomically (temp file,
//! then rename) with mode 0600, and holds token hashes only.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use proto::auth::{DeviceId, Token, TokenHash};

/// One registry entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Device id.
    pub id: DeviceId,
    /// Human name, unique.
    pub name: String,
    /// SHA-256 of the token.
    pub token_hash: TokenHash,
    /// Revoked devices cannot connect.
    pub revoked: bool,
}

/// Longest device name.
const MAX_NAME: usize = 64;

fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Entries in file order; a missing file is empty.
pub fn load(path: &Path) -> Result<Vec<Entry>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let table: toml::Table =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let devices = match table.get("device") {
        None => return Ok(Vec::new()),
        Some(toml::Value::Array(devices)) => devices,
        Some(_) => return Err("device must be an array of tables".into()),
    };
    devices
        .iter()
        .map(|d| {
            let field = |key: &str| {
                d.get(key)
                    .and_then(toml::Value::as_str)
                    .ok_or(format!("device without {key}"))
            };
            Ok(Entry {
                id: DeviceId::from_hex(field("id")?).ok_or("bad device id")?,
                name: field("name")?.to_owned(),
                token_hash: TokenHash::from_hex(field("token_sha256")?)
                    .ok_or("bad token_sha256")?,
                revoked: d
                    .get("revoked")
                    .and_then(toml::Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

/// Writes `entries` atomically, readable by the owner only.
pub fn save(path: &Path, entries: &[Entry]) -> Result<(), String> {
    let mut text = String::from("# Managed by `partizan-server device`; token hashes only.\n");
    for e in entries {
        text.push_str(&format!(
            "\n[[device]]\nid = \"{}\"\nname = \"{}\"\ntoken_sha256 = \"{}\"\nrevoked = {}\n",
            e.id,
            e.name,
            e.token_hash.to_hex(),
            e.revoked
        ));
    }
    let tmp = path.with_extension("toml.tmp");
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        // Keep the owner of the existing file: the CLI often runs as root, the server does not.
        if let Ok(meta) = std::fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            let _ = std::os::unix::fs::chown(&tmp, Some(meta.uid()), Some(meta.gid()));
        }
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))
}

/// Index of the entry whose id or name is `key`.
pub fn find(entries: &[Entry], key: &str) -> Result<usize, String> {
    entries
        .iter()
        .position(|e| e.id.to_string() == key || e.name == key)
        .ok_or_else(|| format!("no device {key:?}"))
}

/// Registers a device; returns its id and the only copy of its token.
pub fn add(path: &Path, name: &str) -> Result<(DeviceId, Token), String> {
    if !valid_name(name) {
        return Err(format!(
            "device name must be 1-{MAX_NAME} of [A-Za-z0-9._-]"
        ));
    }
    let mut entries = load(path)?;
    if entries.iter().any(|e| e.name == name) {
        return Err(format!("device {name:?} already exists"));
    }
    let id = DeviceId::generate().map_err(|e| e.to_string())?;
    let token = Token::generate().map_err(|e| e.to_string())?;
    entries.push(Entry {
        id,
        name: name.to_owned(),
        token_hash: token.hash(),
        revoked: false,
    });
    save(path, &entries)?;
    Ok((id, token))
}

/// Issues a new token for a device; the old one stops working.
pub fn rotate(path: &Path, key: &str) -> Result<(Entry, Token), String> {
    let mut entries = load(path)?;
    let i = find(&entries, key)?;
    let token = Token::generate().map_err(|e| e.to_string())?;
    entries[i].token_hash = token.hash();
    entries[i].revoked = false;
    save(path, &entries)?;
    Ok((entries[i].clone(), token))
}

/// Marks a device revoked.
pub fn revoke(path: &Path, key: &str) -> Result<Entry, String> {
    let mut entries = load(path)?;
    let i = find(&entries, key)?;
    entries[i].revoked = true;
    save(path, &entries)?;
    Ok(entries[i].clone())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::registry::Registry;

    #[test]
    fn edits_roundtrip_through_the_registry_parser() {
        let dir = std::env::temp_dir().join(format!("partizan-devices-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.toml");
        let _ = std::fs::remove_file(&path);
        let (id, token) = add(&path, "router").unwrap();
        assert!(add(&path, "router").is_err(), "duplicate name");
        assert!(add(&path, "bad name").is_err());
        add(&path, "phone").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(token.to_base64url().as_str()),
            "token stored"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let registry = Registry::parse(&text).unwrap();
        assert!(
            registry
                .get(&id)
                .unwrap()
                .record
                .token_hash
                .matches(&token.hash())
        );

        let (entry, new_token) = rotate(&path, "router").unwrap();
        assert!(entry.token_hash.matches(&new_token.hash()));
        assert!(!entry.token_hash.matches(&token.hash()));
        revoke(&path, &id.to_string()).unwrap();
        let registry = Registry::load(&path).unwrap();
        assert!(registry.get(&id).unwrap().record.revoked);
        assert_eq!(registry.len(), 2);
        assert!(revoke(&path, "nobody").is_err());
    }
}
