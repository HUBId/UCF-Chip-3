#![forbid(unsafe_code)]

use pbm::{DecisionForm, PolicyDecisionRecord, PolicyEngine, PolicyEvaluationRequest};
use tam::{ExecutionRequestLike, OutcomeLike, OutcomeStatus, ToolAdapter};
use ucf_protocol::{canonical_bytes, digest32, ucf};

pub struct Gate {
    pub policy: PolicyEngine,
    pub adapter: Box<dyn ToolAdapter>,
}

#[derive(Debug, Clone)]
pub struct GateContext {
    pub integrity_state: String,
    pub charter_version_digest: String,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GateResult {
    ValidationError {
        code: String,
        message: String,
    },
    Denied {
        decision: PolicyDecisionRecord,
    },
    ApprovalRequired {
        decision: PolicyDecisionRecord,
    },
    SimulationRequired {
        decision: PolicyDecisionRecord,
    },
    Executed {
        decision: PolicyDecisionRecord,
        outcome: OutcomePacket,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomePacket {
    pub status: OutcomePacketStatus,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomePacketStatus {
    Success,
    Failure,
}

impl From<OutcomeLike> for OutcomePacket {
    fn from(value: OutcomeLike) -> Self {
        let status = match value.status {
            OutcomeStatus::Success => OutcomePacketStatus::Success,
            OutcomeStatus::Failure => OutcomePacketStatus::Failure,
        };
        Self {
            status,
            payload: value.payload,
        }
    }
}

impl Gate {
    pub fn handle_action_spec(
        &self,
        session_id: &str,
        step_id: &str,
        action: ucf::v1::ActionSpec,
        ctx: GateContext,
    ) -> GateResult {
        if action.verb.is_empty() {
            return GateResult::ValidationError {
                code: "RC.GE.VALIDATION.SCHEMA_INVALID".to_string(),
                message: "tool_id is required".to_string(),
            };
        }

        if action.resources.len() > 16 {
            return GateResult::ValidationError {
                code: "RC.GE.VALIDATION.SCOPE_UNBOUNDED".to_string(),
                message: "too many targets".to_string(),
            };
        }

        let tool_id = action.verb.clone();
        let canonical = canonical_bytes(&action);
        let action_digest = digest32("UCF:HASH:ACTION_SPEC", "ActionSpec", "v1", &canonical);

        let query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let decision = self.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: format!("{session_id}:{step_id}"),
            query,
            integrity_state: ctx.integrity_state,
            charter_version_digest: ctx.charter_version_digest,
            allowed_tools: ctx.allowed_tools,
        });

        // TODO: budget accounting hook.
        // TODO: PVGS receipts hook.
        // TODO: DLP enforcement hook.

        match decision.form {
            DecisionForm::Deny => GateResult::Denied { decision },
            DecisionForm::RequireApproval => GateResult::ApprovalRequired { decision },
            DecisionForm::RequireSimulationFirst => GateResult::SimulationRequired { decision },
            DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                let outcome = self.adapter.execute(&ExecutionRequestLike {
                    action_digest,
                    tool_id,
                    payload: Vec::new(),
                });
                GateResult::Executed {
                    decision,
                    outcome: outcome.into(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use tam::{MockAdapter, OutcomeStatus};

    #[derive(Clone, Default)]
    struct CountingAdapter {
        calls: Arc<Mutex<usize>>,
    }

    impl CountingAdapter {
        fn count(&self) -> usize {
            *self.calls.lock().expect("count lock")
        }
    }

    impl ToolAdapter for CountingAdapter {
        fn execute(&self, _req: &ExecutionRequestLike) -> OutcomeLike {
            let mut guard = self.calls.lock().expect("count lock");
            *guard += 1;
            OutcomeLike {
                status: OutcomeStatus::Success,
                payload: Vec::new(),
            }
        }
    }

    fn gate_with_adapter(adapter: Box<dyn ToolAdapter>) -> Gate {
        Gate {
            policy: PolicyEngine::new(),
            adapter,
        }
    }

    fn base_action(tool: &str) -> ucf::v1::ActionSpec {
        ucf::v1::ActionSpec {
            verb: tool.to_string(),
            resources: vec!["target".to_string()],
        }
    }

    fn ok_ctx() -> GateContext {
        GateContext {
            integrity_state: "OK".to_string(),
            charter_version_digest: "charter".to_string(),
            allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
        }
    }

    #[test]
    fn denies_without_invoking_adapter() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let mut ctx = ok_ctx();
        ctx.integrity_state = "FAIL".to_string();
        let result = gate.handle_action_spec("s", "step", base_action("mock.read"), ctx);

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.DENY.INTEGRITY_REQUIRED".to_string()]
                );
            }
            other => panic!("unexpected gate result: {other:?}"),
        }
        assert_eq!(counting.count(), 0, "adapter must not run on deny");
    }

    #[test]
    fn executes_mock_read() {
        let gate = gate_with_adapter(Box::new(MockAdapter));
        let result = gate.handle_action_spec("s", "step", base_action("mock.read"), ok_ctx());
        match result {
            GateResult::Executed { decision, outcome } => {
                let codes = decision.decision.reason_codes.unwrap().codes;
                assert_eq!(
                    codes,
                    vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()],
                    "expected constraint reason code"
                );
                assert_eq!(outcome.status, OutcomePacketStatus::Success);
                assert_eq!(outcome.payload, b"ok:read".to_vec());
            }
            other => panic!("expected execution result, got {other:?}"),
        }
    }
}
