#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_STRING_LEN: usize = 128;
const ASSET_DIGEST_DOMAIN: &str = "UCF:ASSET";
const DEFAULT_REGISTRY_PATH: &str = "assets/registry.json";

#[derive(Debug, Error)]
pub enum AssetError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("asset file not found at {0}")]
    MissingAsset(String),
    #[error("asset digest mismatch for {0}")]
    DigestMismatch(String),
    #[error("duplicate asset id {0}")]
    DuplicateAssetId(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetFormat {
    Safetensors,
    Pt,
    Onnx,
    Bin,
    Json,
    Protobuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetHandle {
    pub asset_id: String,
    pub asset_digest: [u8; 32],
    pub local_path: String,
    pub format: AssetFormat,
}

impl AssetHandle {
    pub fn new(
        asset_id: &str,
        asset_digest: [u8; 32],
        local_path: &str,
        format: AssetFormat,
    ) -> Self {
        Self {
            asset_id: bound_string(asset_id),
            asset_digest,
            local_path: bound_string(local_path),
            format,
        }
    }

    pub fn verify(&self) -> Result<(), AssetError> {
        let path = Path::new(&self.local_path);
        if !path.exists() {
            return Err(AssetError::MissingAsset(self.local_path.clone()));
        }
        let bytes = fs::read(path)?;
        let digest = asset_digest(&bytes);
        if digest != self.asset_digest {
            return Err(AssetError::DigestMismatch(self.asset_id.clone()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRegistry {
    pub handles: BTreeMap<String, AssetHandle>,
}

impl AssetRegistry {
    /// Loads registry JSON from the default path (`assets/registry.json`).
    ///
    /// Canonical ordering is lexicographic by `asset_id`, enforced by `BTreeMap`.
    pub fn load_default() -> Result<Self, AssetError> {
        Self::load_from_json(DEFAULT_REGISTRY_PATH)
    }

    /// Loads registry JSON deterministically into a `BTreeMap` keyed by `asset_id`.
    pub fn load_from_json(path: impl AsRef<Path>) -> Result<Self, AssetError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        let registry: RegistryFile = serde_json::from_slice(&bytes)?;
        let mut handles = BTreeMap::new();
        for handle in registry.handles {
            let handle = bound_handle(handle);
            if handles.contains_key(&handle.asset_id) {
                return Err(AssetError::DuplicateAssetId(handle.asset_id));
            }
            handles.insert(handle.asset_id.clone(), handle);
        }
        Ok(Self { handles })
    }

    pub fn get(&self, asset_id: &str) -> Option<&AssetHandle> {
        self.handles.get(asset_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegistryFile {
    pub handles: Vec<AssetHandle>,
}

fn bound_string(value: &str) -> String {
    let mut out = value.to_string();
    out.truncate(MAX_STRING_LEN);
    out
}

fn bound_handle(handle: AssetHandle) -> AssetHandle {
    AssetHandle {
        asset_id: bound_string(&handle.asset_id),
        asset_digest: handle.asset_digest,
        local_path: bound_string(&handle.local_path),
        format: handle.format,
    }
}

pub fn asset_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(ASSET_DIGEST_DOMAIN.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub fn asset_handle_digest(handle: &AssetHandle) -> [u8; 32] {
    let mut buf = Vec::new();
    write_string(&mut buf, &handle.asset_id);
    buf.extend_from_slice(&handle.asset_digest);
    write_string(&mut buf, &handle.local_path);
    buf.push(handle.format as u8);
    asset_digest(&buf)
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn verify_accepts_correct_digest() {
        let file = NamedTempFile::new().expect("tempfile");
        fs::write(file.path(), b"asset-bytes").expect("write");
        let digest = asset_digest(b"asset-bytes");
        let handle = AssetHandle::new(
            "asset-a",
            digest,
            file.path().to_string_lossy().as_ref(),
            AssetFormat::Bin,
        );
        handle.verify().expect("verification");
    }

    #[test]
    fn verify_rejects_wrong_digest() {
        let file = NamedTempFile::new().expect("tempfile");
        fs::write(file.path(), b"asset-bytes").expect("write");
        let handle = AssetHandle::new(
            "asset-b",
            [3; 32],
            file.path().to_string_lossy().as_ref(),
            AssetFormat::Bin,
        );
        let err = handle.verify().expect_err("expected mismatch");
        assert!(matches!(err, AssetError::DigestMismatch(_)));
    }
}
