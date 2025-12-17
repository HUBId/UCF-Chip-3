#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Integrate ucf-protocol types for policy inputs/outputs.

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy evaluation failed: {0}")]
    Evaluation(String),
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub subject: String,
    pub action: String,
    pub resource: String,
}

pub trait PolicyBrain: Send + Sync {
    fn evaluate(&self, context: PolicyContext) -> Result<PolicyDecision, PolicyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Permit,
    Deny,
    Indeterminate,
}

pub struct NoopPolicyBrain;

impl PolicyBrain for NoopPolicyBrain {
    fn evaluate(&self, _context: PolicyContext) -> Result<PolicyDecision, PolicyError> {
        Ok(PolicyDecision::Indeterminate)
    }
}
