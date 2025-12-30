#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use lnss_runtime::{LnssRuntimeError, MechIntRecord, MechIntWriter, DEFAULT_MAX_MECHINT_BYTES};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MechIntError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct JsonlMechIntWriter {
    path: PathBuf,
    max_line_bytes: usize,
}

impl JsonlMechIntWriter {
    pub fn new(
        path: impl AsRef<Path>,
        max_line_bytes: Option<usize>,
    ) -> Result<Self, MechIntError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            max_line_bytes: max_line_bytes.unwrap_or(DEFAULT_MAX_MECHINT_BYTES),
        })
    }

    fn append_json<T: Serialize>(&self, value: &T) -> Result<(), MechIntError> {
        let mut line = serde_json::to_vec(value)?;
        if line.len() > self.max_line_bytes {
            line.truncate(self.max_line_bytes);
        }
        line.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        Ok(())
    }
}

impl MechIntWriter for JsonlMechIntWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), LnssRuntimeError> {
        self.append_json(rec)
            .map_err(|err| LnssRuntimeError::MechInt(err.to_string()))
    }
}

#[cfg(feature = "lnss-arrow")]
pub struct ArrowMechIntWriter;

#[cfg(feature = "lnss-arrow")]
impl ArrowMechIntWriter {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "lnss-arrow")]
impl Default for ArrowMechIntWriter {
    fn default() -> Self {
        Self::new()
    }
}
