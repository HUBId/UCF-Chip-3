#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Integrate ucf-protocol types once available.

#[derive(Debug, Error)]
pub enum WireError {
    #[error("signature missing")]
    MissingSignature,
    #[error("authentication failed")]
    AuthenticationFailed,
}

#[derive(Debug, Clone)]
pub struct EnvelopeDraft {
    pub payload_hint: String,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub nonce: String,
    pub epoch: u64,
    pub payload_hint: String,
}

impl EnvelopeDraft {
    pub fn seal(self, auth: &dyn Authenticator) -> Result<Envelope, WireError> {
        auth.authenticate(&self.payload_hint)?;
        Ok(Envelope {
            nonce: "pending-nonce".to_string(),
            epoch: 0,
            payload_hint: self.payload_hint,
        })
    }
}

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, token_hint: &str) -> Result<(), WireError>;
}

pub trait EpochSource: Send + Sync {
    fn current_epoch(&self) -> u64;
}
