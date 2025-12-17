#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Wire ucf-protocol data models for curator decisions.

#[derive(Debug, Error)]
pub enum CuratorError {
    #[error("content inspection failed: {0}")]
    Inspection(String),
}

#[derive(Debug, Clone)]
pub struct ContentDescriptor {
    pub label: String,
    pub preview: String,
}

#[derive(Debug, Clone)]
pub enum InspectionOutcome {
    Clean,
    Redacted(String),
}

pub trait Curator: Send + Sync {
    fn inspect(&self, content: ContentDescriptor) -> Result<InspectionOutcome, CuratorError>;
}

pub struct NoopCurator;

impl Curator for NoopCurator {
    fn inspect(&self, content: ContentDescriptor) -> Result<InspectionOutcome, CuratorError> {
        let _ = content;
        Ok(InspectionOutcome::Clean)
    }
}
