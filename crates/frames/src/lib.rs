#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Replace placeholders with ucf-protocol frame types.

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("aggregation failed: {0}")]
    Aggregation(String),
}

#[derive(Debug, Clone)]
pub struct SignalFrame {
    pub signals: Vec<String>,
}

pub trait FrameAggregator: Send + Sync {
    fn aggregate(&self, frames: Vec<SignalFrame>) -> Result<SignalFrame, FrameError>;
}

pub struct PassthroughAggregator;

impl FrameAggregator for PassthroughAggregator {
    fn aggregate(&self, frames: Vec<SignalFrame>) -> Result<SignalFrame, FrameError> {
        let merged = frames.into_iter().flat_map(|frame| frame.signals).collect();
        Ok(SignalFrame { signals: merged })
    }
}
