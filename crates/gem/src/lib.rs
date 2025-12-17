#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Bind to ucf-protocol request/response envelopes.

#[derive(Debug, Error)]
pub enum GateError {
    #[error("policy gate rejected request: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone)]
pub struct GateRequest {
    pub subject: String,
    pub intent: String,
}

#[derive(Debug, Clone)]
pub struct GateDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

pub trait PolicyGate: Send + Sync {
    fn evaluate(&self, request: GateRequest) -> Result<GateDecision, GateError>;
}

pub struct AllowAllGate;

impl PolicyGate for AllowAllGate {
    fn evaluate(&self, request: GateRequest) -> Result<GateDecision, GateError> {
        Ok(GateDecision {
            allowed: true,
            reason: Some(format!("allowed intent {}", request.intent)),
        })
    }
}
