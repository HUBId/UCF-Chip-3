#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Bind commit/receipt messages to ucf-protocol definitions.

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("receipt verification failed")]
    VerificationFailed,
    #[error("commit rejected: {0}")]
    CommitRejected(String),
}

#[derive(Debug, Clone)]
pub struct CommitRequest {
    pub payload_hint: String,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub receipt_id: String,
}

pub trait PvgsClient: Send + Sync {
    fn commit(&self, request: CommitRequest) -> Result<Receipt, ClientError>;
    fn verify(&self, receipt: &Receipt) -> Result<(), ClientError>;
}

pub struct NoopPvgsClient;

impl PvgsClient for NoopPvgsClient {
    fn commit(&self, request: CommitRequest) -> Result<Receipt, ClientError> {
        Ok(Receipt {
            receipt_id: format!("noop-{}", request.payload_hint),
        })
    }

    fn verify(&self, _receipt: &Receipt) -> Result<(), ClientError> {
        Ok(())
    }
}
