#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Link adapter contracts to ucf-protocol tool APIs.

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("adapter failed: {0}")]
    Failure(String),
}

pub trait ToolAdapter: Send + Sync {
    fn invoke(&self, command: &str) -> Result<AdapterResponse, AdapterError>;
}

#[derive(Debug, Clone)]
pub struct AdapterResponse {
    pub status: AdapterStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterStatus {
    Success,
    TemporaryFailure,
    PermanentFailure,
}

pub struct NoopAdapter;

impl ToolAdapter for NoopAdapter {
    fn invoke(&self, command: &str) -> Result<AdapterResponse, AdapterError> {
        Ok(AdapterResponse {
            status: AdapterStatus::Success,
            detail: Some(format!("noop executed {command}")),
        })
    }
}
