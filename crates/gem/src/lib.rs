#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use frames::ShortWindowAggregator;
use pbm::{DecisionForm, PolicyDecisionRecord, PolicyEngine, PolicyEvaluationRequest};
use tam::ToolAdapter;
use ucf_protocol::{canonical_bytes, digest32, ucf};

pub struct Gate {
    pub policy: PolicyEngine,
    pub adapter: Box<dyn ToolAdapter>,
    pub aggregator: Arc<Mutex<ShortWindowAggregator>>,
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
        outcome: ucf::v1::OutcomePacket,
    },
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

        self.note_policy_decision(&decision);

        match decision.form {
            DecisionForm::Deny => GateResult::Denied { decision },
            DecisionForm::RequireApproval => GateResult::ApprovalRequired { decision },
            DecisionForm::RequireSimulationFirst => GateResult::SimulationRequired { decision },
            DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                let execution_request = self.build_execution_request(
                    action_digest,
                    tool_id,
                    action.verb,
                    &decision,
                    session_id,
                    step_id,
                );

                let outcome = self.adapter.execute(execution_request.clone());
                self.note_execution_outcome(&outcome);

                GateResult::Executed { decision, outcome }
            }
        }
    }

    fn build_execution_request(
        &self,
        action_digest: [u8; 32],
        tool_id: String,
        action_name: String,
        decision: &PolicyDecisionRecord,
        session_id: &str,
        step_id: &str,
    ) -> ucf::v1::ExecutionRequest {
        let request_id = format!("{session_id}:{step_id}");
        let constraints = decision
            .decision
            .constraints
            .as_ref()
            .map(|c| c.constraints_added.clone())
            .unwrap_or_default();

        let mut constraints_sorted = constraints;
        constraints_sorted.sort();

        ucf::v1::ExecutionRequest {
            request_id,
            action_digest: action_digest.to_vec(),
            tool_id,
            action_name,
            constraints: constraints_sorted,
            data_class_context: ucf::v1::DataClass::Unspecified.into(),
            payload: Vec::new(),
        }
    }

    fn note_policy_decision(&self, decision: &PolicyDecisionRecord) {
        let reason_codes = decision
            .decision
            .reason_codes
            .as_ref()
            .map(|rc| rc.codes.clone())
            .unwrap_or_default();

        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_policy_decision(decision.form.clone(), &reason_codes);
        }
    }

    fn note_execution_outcome(&self, outcome: &ucf::v1::OutcomePacket) {
        let reason_codes = outcome
            .reason_codes
            .as_ref()
            .map(|rc| rc.codes.clone())
            .unwrap_or_default();

        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_execution_outcome(
                ucf::v1::OutcomeStatus::try_from(outcome.status)
                    .unwrap_or(ucf::v1::OutcomeStatus::Unspecified),
                &reason_codes,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use tam::MockAdapter;

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
        fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket {
            let mut guard = self.calls.lock().expect("count lock");
            *guard += 1;
            ucf::v1::OutcomePacket {
                outcome_id: format!("{}:outcome", req.request_id),
                request_id: req.request_id,
                status: ucf::v1::OutcomeStatus::Success.into(),
                payload: Vec::new(),
                payload_digest: None,
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            }
        }
    }

    fn gate_with_adapter(adapter: Box<dyn ToolAdapter>) -> Gate {
        Gate {
            policy: PolicyEngine::new(),
            adapter,
            aggregator: Arc::new(Mutex::new(ShortWindowAggregator::new(32))),
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
                assert_eq!(
                    ucf::v1::OutcomeStatus::try_from(outcome.status),
                    Ok(ucf::v1::OutcomeStatus::Success)
                );
                assert_eq!(outcome.payload, b"ok:read".to_vec());
            }
            other => panic!("expected execution result, got {other:?}"),
        }
    }

    #[test]
    fn execution_request_is_deterministic() {
        let gate = gate_with_adapter(Box::new(MockAdapter));
        let action = base_action("mock.read");
        let ctx = ok_ctx();

        let canonical_action = canonical_bytes(&action);
        let action_digest = digest32(
            "UCF:HASH:ACTION_SPEC",
            "ActionSpec",
            "v1",
            &canonical_action,
        );
        let decision = gate.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: "sid:step".to_string(),
            query: ucf::v1::PolicyQuery {
                principal: "chip3".to_string(),
                action: Some(action.clone()),
                channel: ucf::v1::Channel::Unspecified.into(),
                risk_level: ucf::v1::RiskLevel::Unspecified.into(),
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            integrity_state: ctx.integrity_state,
            charter_version_digest: ctx.charter_version_digest,
            allowed_tools: ctx.allowed_tools,
        });

        let req_a = gate.build_execution_request(
            action_digest,
            action.verb.clone(),
            action.verb.clone(),
            &decision,
            "sid",
            "step",
        );
        let req_b = gate.build_execution_request(
            action_digest,
            action.verb.clone(),
            action.verb,
            &decision,
            "sid",
            "step",
        );

        assert_eq!(canonical_bytes(&req_a), canonical_bytes(&req_b));
    }
}
