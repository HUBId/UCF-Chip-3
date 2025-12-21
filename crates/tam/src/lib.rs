#![forbid(unsafe_code)]

use blake3::hash;
use ucf_protocol::ucf;

pub trait ToolAdapter: Send + Sync {
    fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket;
}

pub struct MockAdapter;

impl ToolAdapter for MockAdapter {
    fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket {
        let (status, payload, reason_codes) = match req.tool_id.as_str() {
            "mock.read" => (
                ucf::v1::OutcomeStatus::Success,
                b"ok:read".to_vec(),
                Vec::new(),
            ),
            "mock.fail" => (
                ucf::v1::OutcomeStatus::Failure,
                Vec::new(),
                vec!["RC.TAM.MOCK.FAIL".to_string()],
            ),
            _ => (
                ucf::v1::OutcomeStatus::Failure,
                Vec::new(),
                vec!["RC.TAM.UNKNOWN_TOOL".to_string()],
            ),
        };

        let payload_digest = hash(&payload);

        ucf::v1::OutcomePacket {
            outcome_id: format!("{}:outcome", req.request_id),
            request_id: req.request_id,
            status: status.into(),
            payload,
            payload_digest: Some(ucf::v1::Digest32 {
                value: payload_digest.as_bytes().to_vec(),
            }),
            data_class: ucf::v1::DataClass::Public.into(),
            reason_codes: if reason_codes.is_empty() {
                None
            } else {
                Some(ucf::v1::ReasonCodes {
                    codes: reason_codes,
                })
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_digest_matches_payload() {
        let adapter = MockAdapter;
        let request = ucf::v1::ExecutionRequest {
            request_id: "req-1".to_string(),
            action_digest: vec![1u8; 32],
            tool_id: "mock.read".to_string(),
            action_name: "read".to_string(),
            constraints: vec![],
            data_class_context: ucf::v1::DataClass::Public.into(),
            payload: Vec::new(),
        };

        let outcome = adapter.execute(request);
        assert_eq!(outcome.status, ucf::v1::OutcomeStatus::Success.into());
        assert_eq!(outcome.payload, b"ok:read".to_vec());

        let digest = outcome.payload_digest.unwrap();
        let expected = blake3::hash(&outcome.payload);
        assert_eq!(digest.value, expected.as_bytes());
    }
}
