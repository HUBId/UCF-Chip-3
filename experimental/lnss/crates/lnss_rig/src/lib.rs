#![forbid(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use lnss_runtime::{BrainSpike, LnssRuntimeError, RigClient};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct LoggingRigClient {
    path: PathBuf,
    max_line_bytes: usize,
}

impl LoggingRigClient {
    pub fn new(path: impl AsRef<Path>, max_line_bytes: usize) -> Result<Self, RigError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            max_line_bytes,
        })
    }

    fn append_json<T: Serialize + ?Sized>(&self, value: &T) -> Result<(), RigError> {
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

impl RigClient for LoggingRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        self.append_json(spikes)
            .map_err(|err| LnssRuntimeError::Rig(err.to_string()))
    }
}

#[derive(Debug, Default)]
pub struct InMemoryRigClient {
    pub spikes: Vec<BrainSpike>,
}

impl RigClient for InMemoryRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        self.spikes.extend_from_slice(spikes);
        Ok(())
    }
}
