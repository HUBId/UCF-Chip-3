#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use control::ControlFrameStore;
use frames::{ReceiptIssue, ShortWindowAggregator};
use pbm::{
    compute_decision_digest, DecisionForm, PolicyContext, PolicyDecisionRecord, PolicyEngine,
    PolicyEvaluationRequest,
};
use pvgs_verify::{verify_pvgs_receipt, PvgsKeyEpochStore, VerifyError};
use tam::ToolAdapter;
use ucf_protocol::{canonical_bytes, digest32, ucf};

const RECEIPT_BLOCKED_REASON: &str = "RC.GE.EXEC.DISPATCH_BLOCKED";

pub struct Gate {
    pub policy: PolicyEngine,
    pub adapter: Box<dyn ToolAdapter>,
    pub aggregator: Arc<Mutex<ShortWindowAggregator>>,
    pub control_store: Arc<Mutex<ControlFrameStore>>,
    pub receipt_store: Arc<PvgsKeyEpochStore>,
}

#[derive(Debug, Clone)]
pub struct GateContext {
    pub integrity_state: String,
    pub charter_version_digest: String,
    pub allowed_tools: Vec<String>,
    pub control_frame: Option<ucf::v1::ControlFrame>,
    pub pvgs_receipt: Option<ucf::v1::PvgsReceipt>,
    pub approval_grant_id: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolActionClass {
    Read,
    Write,
    Execute,
    Export,
    Persist,
    Other,
}

impl ToolActionClass {
    fn requires_receipt(&self) -> bool {
        matches!(
            self,
            ToolActionClass::Write
                | ToolActionClass::Execute
                | ToolActionClass::Export
                | ToolActionClass::Persist
        )
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
        let action_class = classify_tool_action(&tool_id);
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

        let control_frame = self.resolve_control_frame(&ctx);

        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame: control_frame.clone(),
        };

        let decision = self.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: format!("{session_id}:{step_id}"),
            query,
            context: policy_ctx,
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
                if let Err(result) =
                    self.enforce_receipt_gate(action_class, action_digest, &action, &decision, &ctx)
                {
                    return result;
                }

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

    #[allow(clippy::result_large_err)]
    fn enforce_receipt_gate(
        &self,
        action_class: ToolActionClass,
        action_digest: [u8; 32],
        action: &ucf::v1::ActionSpec,
        decision: &PolicyDecisionRecord,
        ctx: &GateContext,
    ) -> Result<(), GateResult> {
        if !action_class.requires_receipt() {
            return Ok(());
        }

        let receipt = match ctx.pvgs_receipt.clone() {
            Some(r) => r,
            None => {
                self.note_receipt_issue(ReceiptIssue::Missing);
                return Err(GateResult::Denied {
                    decision: self.receipt_blocked_decision(
                        decision,
                        &[RECEIPT_BLOCKED_REASON.to_string()],
                    ),
                });
            }
        };

        if let Err(err) = verify_pvgs_receipt(&receipt, &self.receipt_store) {
            self.note_receipt_issue(ReceiptIssue::Invalid);
            return Err(self.receipt_gate_error(decision, err, action));
        }

        if ucf::v1::ReceiptStatus::try_from(receipt.status) != Ok(ucf::v1::ReceiptStatus::Accepted)
        {
            self.note_receipt_issue(ReceiptIssue::Invalid);
            return Err(self.receipt_gate_error(
                decision,
                VerifyError::Schema("receipt must be accepted".to_string()),
                action,
            ));
        }

        if !digest_matches(receipt.action_digest.as_ref(), &action_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid);
            return Err(self.receipt_gate_error(
                decision,
                VerifyError::Schema("action digest mismatch".to_string()),
                action,
            ));
        }

        if !digest_matches(receipt.decision_digest.as_ref(), &decision.decision_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid);
            return Err(self.receipt_gate_error(
                decision,
                VerifyError::Schema("decision digest mismatch".to_string()),
                action,
            ));
        }

        if let Some(expected_grant) = ctx.approval_grant_id.as_deref() {
            if receipt.grant_id != expected_grant {
                self.note_receipt_issue(ReceiptIssue::Invalid);
                return Err(self.receipt_gate_error(
                    decision,
                    VerifyError::Schema("grant binding mismatch".to_string()),
                    action,
                ));
            }
        }

        Ok(())
    }

    fn note_receipt_issue(&self, issue: ReceiptIssue) {
        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_receipt_issue(issue, &[RECEIPT_BLOCKED_REASON.to_string()]);
        }
    }

    fn receipt_blocked_decision(
        &self,
        prior: &PolicyDecisionRecord,
        reason_codes: &[String],
    ) -> PolicyDecisionRecord {
        let mut rc = reason_codes.to_vec();
        rc.sort();
        let digest = compute_decision_digest(&prior.decision_id, &DecisionForm::Deny, &rc);

        PolicyDecisionRecord {
            form: DecisionForm::Deny,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Deny.into(),
                reason_codes: Some(ucf::v1::ReasonCodes { codes: rc.clone() }),
                constraints: None,
            },
            policy_version_digest: prior.policy_version_digest.clone(),
            decision_id: prior.decision_id.clone(),
            decision_digest: digest,
        }
    }

    fn receipt_gate_error(
        &self,
        prior: &PolicyDecisionRecord,
        _error: VerifyError,
        _action: &ucf::v1::ActionSpec,
    ) -> GateResult {
        GateResult::Denied {
            decision: self.receipt_blocked_decision(prior, &[RECEIPT_BLOCKED_REASON.to_string()]),
        }
    }

    fn resolve_control_frame(&self, ctx: &GateContext) -> ucf::v1::ControlFrame {
        if let Some(cf) = ctx.control_frame.clone() {
            return cf;
        }

        let guard = self.control_store.lock().expect("control frame store lock");

        guard
            .current()
            .cloned()
            .unwrap_or_else(|| guard.strict_fallback())
    }
}

fn classify_tool_action(tool_id: &str) -> ToolActionClass {
    if tool_id.starts_with("mock.write") {
        ToolActionClass::Write
    } else if tool_id.starts_with("mock.exec") {
        ToolActionClass::Execute
    } else if tool_id.starts_with("mock.export") {
        ToolActionClass::Export
    } else if tool_id.starts_with("mock.persist") {
        ToolActionClass::Persist
    } else if tool_id.starts_with("mock.read") {
        ToolActionClass::Read
    } else {
        ToolActionClass::Other
    }
}

fn digest_matches(opt: Option<&ucf::v1::Digest32>, expected: &[u8; 32]) -> bool {
    opt.map(|d| d.value.as_slice() == expected).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pvgs_verify::pvgs_receipt_signing_preimage;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
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
        let store = Arc::new(Mutex::new(ControlFrameStore::default()));
        {
            let mut guard = store.lock().expect("control frame store lock");
            guard
                .update(control_frame_open())
                .expect("valid control frame");
        }

        gate_with_components(
            adapter,
            store,
            Arc::new(PvgsKeyEpochStore::new()),
            Arc::new(Mutex::new(ShortWindowAggregator::new(32))),
        )
    }

    fn gate_with_components(
        adapter: Box<dyn ToolAdapter>,
        store: Arc<Mutex<ControlFrameStore>>,
        receipt_store: Arc<PvgsKeyEpochStore>,
        aggregator: Arc<Mutex<ShortWindowAggregator>>,
    ) -> Gate {
        Gate {
            policy: PolicyEngine::new(),
            adapter,
            aggregator,
            control_store: store,
            receipt_store,
        }
    }

    fn control_frame_open() -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "cf-open".to_string(),
            note: String::new(),
            active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            overlays: None,
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: true,
                enable_write: true,
                enable_execute: true,
            }),
            deescalation_lock: false,
            reason_codes: None,
        }
    }

    fn control_frame_locked_sim() -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "cf-locked".to_string(),
            note: String::new(),
            active_profile: ucf::v1::ControlFrameProfile::M1Restricted.into(),
            overlays: Some(ucf::v1::ControlFrameOverlays {
                ovl_simulate_first: true,
                ovl_export_lock: true,
                ovl_novelty_lock: false,
            }),
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: false,
                enable_write: false,
                enable_execute: false,
            }),
            deescalation_lock: true,
            reason_codes: None,
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
            allowed_tools: vec![
                "mock.read".to_string(),
                "mock.export".to_string(),
                "mock.write".to_string(),
                "mock.exec".to_string(),
                "mock.persist".to_string(),
            ],
            control_frame: None,
            pvgs_receipt: None,
            approval_grant_id: None,
        }
    }

    fn open_control_store() -> Arc<Mutex<ControlFrameStore>> {
        let store = Arc::new(Mutex::new(ControlFrameStore::default()));
        {
            let mut guard = store.lock().expect("control frame store lock");
            guard
                .update(control_frame_open())
                .expect("valid control frame");
        }
        store
    }

    fn sample_digest(byte: u8) -> ucf::v1::Digest32 {
        ucf::v1::Digest32 {
            value: vec![byte; 32],
        }
    }

    fn signing_material() -> (SigningKey, String) {
        let mut seed = [0u8; 32];
        StdRng::seed_from_u64(7).fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        (sk, "pvgs-test-key".to_string())
    }

    fn receipt_store_with_key() -> (Arc<PvgsKeyEpochStore>, SigningKey, String) {
        let (sk, key_id) = signing_material();
        let mut store = PvgsKeyEpochStore::new();
        store.insert_key(key_id.clone(), sk.verifying_key().to_bytes());
        (Arc::new(store), sk, key_id)
    }

    fn policy_decision_for(
        gate: &Gate,
        action: &ucf::v1::ActionSpec,
        ctx: &GateContext,
        session_id: &str,
        step_id: &str,
    ) -> PolicyDecisionRecord {
        let control_frame = gate.resolve_control_frame(ctx);
        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame,
        };

        gate.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: format!("{session_id}:{step_id}"),
            query: ucf::v1::PolicyQuery {
                principal: "chip3".to_string(),
                action: Some(action.clone()),
                channel: ucf::v1::Channel::Unspecified.into(),
                risk_level: ucf::v1::RiskLevel::Unspecified.into(),
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            context: policy_ctx,
        })
    }

    fn signed_receipt_for(
        action_digest: [u8; 32],
        decision_digest: [u8; 32],
        signer: &SigningKey,
        key_id: &str,
    ) -> ucf::v1::PvgsReceipt {
        let mut receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: "epoch-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            receipt_digest: Some(sample_digest(9)),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: Some(sample_digest(1)),
            decision_digest: Some(sample_digest(2)),
            grant_id: "grant-123".to_string(),
            charter_version_digest: Some(sample_digest(3)),
            policy_version_digest: Some(sample_digest(4)),
            prev_record_digest: Some(sample_digest(5)),
            profile_digest: Some(sample_digest(6)),
            tool_profile_digest: Some(sample_digest(7)),
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        receipt.action_digest = Some(ucf::v1::Digest32 {
            value: action_digest.to_vec(),
        });
        receipt.decision_digest = Some(ucf::v1::Digest32 {
            value: decision_digest.to_vec(),
        });

        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let sig = signer.sign(&preimage);
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });

        receipt
    }

    fn compute_action_digest(action: &ucf::v1::ActionSpec) -> [u8; 32] {
        let canonical = canonical_bytes(action);
        digest32("UCF:HASH:ACTION_SPEC", "ActionSpec", "v1", &canonical)
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

        let control_frame = gate.resolve_control_frame(&ctx);
        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame: control_frame.clone(),
        };

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
            context: policy_ctx,
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

    #[test]
    fn blocks_side_effect_without_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, _, _) = receipt_store_with_key();
        let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
        );

        let ctx = ok_ctx();
        let result = gate.handle_action_spec("s", "step", base_action("mock.write"), ctx.clone());

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![RECEIPT_BLOCKED_REASON.to_string()]
                );
            }
            other => panic!("expected receipt gate denial, got {other:?}"),
        }
        assert_eq!(counting.count(), 0, "adapter must not run without receipt");
    }

    #[test]
    fn blocks_side_effect_with_invalid_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
        );

        let mut ctx = ok_ctx();
        let action = base_action("mock.write");
        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        let mut receipt =
            signed_receipt_for(action_digest, decision.decision_digest, &signer, &key_id);
        receipt.charter_version_digest = Some(sample_digest(99));
        ctx.pvgs_receipt = Some(receipt);

        let result = gate.handle_action_spec("s", "step", action, ctx);
        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![RECEIPT_BLOCKED_REASON.to_string()]
                );
            }
            other => panic!("expected receipt gate denial, got {other:?}"),
        }
        assert_eq!(
            counting.count(),
            0,
            "adapter must not run with invalid receipt"
        );
    }

    #[test]
    fn allows_side_effect_with_valid_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
        );

        let mut ctx = ok_ctx();
        let action = base_action("mock.write");
        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        let receipt = signed_receipt_for(action_digest, decision.decision_digest, &signer, &key_id);
        ctx.pvgs_receipt = Some(receipt);

        let result = gate.handle_action_spec("s", "step", action.clone(), ctx);
        match result {
            GateResult::Executed { decision, outcome } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()]
                );
                assert_eq!(
                    ucf::v1::OutcomeStatus::try_from(outcome.status),
                    Ok(ucf::v1::OutcomeStatus::Success)
                );
            }
            other => panic!("expected execution, got {other:?}"),
        }
        assert_eq!(counting.count(), 1, "adapter should run with valid receipt");
    }

    #[test]
    fn fallback_store_enforces_fail_closed() {
        let counting = CountingAdapter::default();
        let store = Arc::new(Mutex::new(ControlFrameStore::default()));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            store,
            Arc::new(PvgsKeyEpochStore::new()),
            Arc::new(Mutex::new(ShortWindowAggregator::new(32))),
        );

        let ctx = ok_ctx();
        let sim_result =
            gate.handle_action_spec("s", "step1", base_action("mock.read"), ctx.clone());
        match sim_result {
            GateResult::SimulationRequired { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()]
                );
            }
            other => panic!("expected simulation-required, got {other:?}"),
        }

        let export_result = gate.handle_action_spec("s", "step2", base_action("mock.export"), ctx);
        match export_result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()]
                );
            }
            other => panic!("expected deny for export, got {other:?}"),
        }

        assert_eq!(
            counting.count(),
            0,
            "adapter must not run under fallback locks"
        );
    }

    #[test]
    fn simulate_first_overlay_blocks_execution() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let mut ctx = ok_ctx();
        ctx.control_frame = Some(control_frame_locked_sim());

        let result = gate.handle_action_spec("s", "step", base_action("mock.read"), ctx);
        match result {
            GateResult::SimulationRequired { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()]
                );
            }
            other => panic!("expected simulation required, got {other:?}"),
        }
        assert_eq!(
            counting.count(),
            0,
            "adapter blocked by simulate-first overlay"
        );
    }

    #[test]
    fn export_lock_blocks_execution() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let mut ctx = ok_ctx();
        ctx.control_frame = Some(control_frame_locked_sim());

        let result = gate.handle_action_spec("s", "step", base_action("mock.export"), ctx);
        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()]
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
        assert_eq!(counting.count(), 0, "adapter blocked by export lock");
    }

    #[test]
    fn receipt_stats_recorded_in_signal_frame() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store.clone(),
            aggregator.clone(),
        );

        let ctx = ok_ctx();
        let action = base_action("mock.write");

        for idx in 0..2 {
            let _ =
                gate.handle_action_spec("s", &format!("missing{idx}"), action.clone(), ctx.clone());
        }

        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "invalid");
        let mut receipt =
            signed_receipt_for(action_digest, decision.decision_digest, &signer, &key_id);
        receipt.policy_version_digest = Some(sample_digest(10));
        let mut ctx_with_receipt = ctx.clone();
        ctx_with_receipt.pvgs_receipt = Some(receipt);

        let _ = gate.handle_action_spec("s", "invalid", action, ctx_with_receipt);

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let receipt_stats = frames
            .first()
            .and_then(|f| f.receipt_stats.as_ref())
            .cloned()
            .expect("receipt stats present");

        assert_eq!(receipt_stats.receipt_missing_count, 2);
        assert_eq!(receipt_stats.receipt_invalid_count, 1);
        assert!(receipt_stats
            .top_reason_codes
            .iter()
            .any(|c| c.code == RECEIPT_BLOCKED_REASON && c.count == 3));
        assert_eq!(
            counting.count(),
            0,
            "adapter must not run when receipts invalid or missing"
        );
    }

    #[test]
    fn blocked_exports_show_in_signal_frame() {
        let counting = CountingAdapter::default();
        let store = Arc::new(Mutex::new(ControlFrameStore::default()));
        {
            let mut guard = store.lock().expect("control store lock");
            guard
                .update(control_frame_locked_sim())
                .expect("valid control frame");
        }
        let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
        let gate = Gate {
            policy: PolicyEngine::new(),
            adapter: Box::new(counting.clone()),
            aggregator: aggregator.clone(),
            control_store: store,
            receipt_store: Arc::new(PvgsKeyEpochStore::new()),
        };

        let mut ctx = ok_ctx();
        ctx.control_frame = None;

        for idx in 0..3 {
            let _ = gate.handle_action_spec(
                "s",
                &format!("step{idx}"),
                base_action("mock.export"),
                ctx.clone(),
            );
        }

        let frames = aggregator.lock().expect("agg lock").force_flush();
        assert_eq!(
            counting.count(),
            0,
            "adapter must not run when exports blocked"
        );
        let top_codes: Vec<_> = frames
            .first()
            .and_then(|f| f.policy_stats.as_ref())
            .map(|p| p.top_reason_codes.clone())
            .unwrap_or_default();

        assert!(
            top_codes
                .iter()
                .any(|c| c.code == "RC.CD.DLP.EXPORT_BLOCKED"),
            "export blocked reason should appear in signal frame"
        );
    }
}
