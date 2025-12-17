#![forbid(unsafe_code)]

#[derive(Debug, Clone)]
pub struct ExecutionRequestLike {
    pub action_digest: [u8; 32],
    pub tool_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeStatus {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeLike {
    pub status: OutcomeStatus,
    pub payload: Vec<u8>,
}

pub trait ToolAdapter: Send + Sync {
    fn execute(&self, req: &ExecutionRequestLike) -> OutcomeLike;
}

pub struct MockAdapter;

impl ToolAdapter for MockAdapter {
    fn execute(&self, req: &ExecutionRequestLike) -> OutcomeLike {
        match req.tool_id.as_str() {
            "mock.read" => OutcomeLike {
                status: OutcomeStatus::Success,
                payload: b"ok:read".to_vec(),
            },
            "mock.fail" => OutcomeLike {
                status: OutcomeStatus::Failure,
                payload: b"fail".to_vec(),
            },
            _ => OutcomeLike {
                status: OutcomeStatus::Failure,
                payload: b"unknown tool".to_vec(),
            },
        }
    }
}
