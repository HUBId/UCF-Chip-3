#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration path missing: {0}")]
    MissingPath(String),
}

#[derive(Debug, Clone)]
struct ConfigPaths {
    deployment_map: PathBuf,
    tool_registry: PathBuf,
    receipt_gate_policy: PathBuf,
}

impl ConfigPaths {
    fn new(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        Self {
            deployment_map: base.join("deployment_map.yaml"),
            tool_registry: base.join("tool_registry.yaml"),
            receipt_gate_policy: base.join("receipt_gate_policy.yaml"),
        }
    }

    fn validate(&self) -> Result<(), AppError> {
        for (label, path) in [
            ("deployment_map", &self.deployment_map),
            ("tool_registry", &self.tool_registry),
            ("receipt_gate_policy", &self.receipt_gate_policy),
        ] {
            if !path.exists() {
                return Err(AppError::MissingPath(label.to_string()));
            }
        }

        Ok(())
    }
}

fn main() -> Result<(), AppError> {
    let config_paths = ConfigPaths::new("config");
    config_paths.validate()?;
    println!("boot ok");
    Ok(())
}
