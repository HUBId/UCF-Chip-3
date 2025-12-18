#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use control::ControlFrameStore;
#[cfg(test)]
use frames::FramesConfig;
use frames::{ReceiptIssue, WindowEngine};
use pbm::{
    compute_decision_digest, DecisionForm, PolicyContext, PolicyDecisionRecord, PolicyEngine,
    PolicyEvaluationRequest,
};
use pvgs_client::PvgsClient;
use pvgs_verify::{verify_pvgs_receipt, PvgsKeyEpochStore, VerifyError};
use tam::ToolAdapter;
use trm::ToolRegistry;
use ucf_protocol::{canonical_bytes, digest32, digest_proto, ucf};

const RECEIPT_BLOCKED_REASON: &str = "RC.GE.EXEC.DISPATCH_BLOCKED";
const RECEIPT_UNKNOWN_KEY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";
const PVGS_INTEGRITY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";
const CORE_FRAME_DOMAIN: &str = "UCF:HASH:CORE_FRAME";
const METABOLIC_FRAME_DOMAIN: &str = "UCF:HASH:METABOLIC_FRAME";
const GOVERNANCE_FRAME_DOMAIN: &str = "UCF:HASH:GOVERNANCE_FRAME";
const BUDGET_SNAPSHOT_DOMAIN: &str = "UCF:HASH:BUDGET_SNAPSHOT";
const GRANT_REF_DOMAIN: &str = "UCF:HASH:GRANT_REF";

pub struct Gate {
    pub policy: PolicyEngine,
    pub adapter: Box<dyn ToolAdapter>,
    pub aggregator: Arc<Mutex<WindowEngine>>,
    pub control_store: Arc<Mutex<ControlFrameStore>>,
    pub receipt_store: Arc<PvgsKeyEpochStore>,
    pub registry: Arc<ToolRegistry>,
    pub pvgs_client: Arc<Mutex<Box<dyn PvgsClient>>>,
    pub integrity_issues: Arc<Mutex<u64>>,
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

        let (tool_id, action_id) = parse_tool_and_action(&action);
        let tool_profile = self.registry.get(&tool_id, &action_id);
        let action_type = tool_profile
            .and_then(|tap| ucf::v1::ToolActionType::try_from(tap.action_type).ok())
            .unwrap_or(ucf::v1::ToolActionType::Unspecified);
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
        let control_frame_digest = control::control_frame_digest(&control_frame);

        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame: control_frame.clone(),
            tool_action_type: action_type,
        };

        let mut decision = self.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: format!("{session_id}:{step_id}"),
            query,
            context: policy_ctx,
        });

        if tool_profile.is_none() {
            decision =
                self.deny_with_reasons(&decision, &["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()]);
        }

        // TODO: budget accounting hook.
        // TODO: PVGS receipts hook.
        // TODO: DLP enforcement hook.

        self.note_policy_decision(&decision);

        match decision.form {
            DecisionForm::Deny => GateResult::Denied { decision },
            DecisionForm::RequireApproval => GateResult::ApprovalRequired { decision },
            DecisionForm::RequireSimulationFirst => GateResult::SimulationRequired { decision },
            DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                if let Some(tap) = tool_profile {
                    if let Err(result) = self.enforce_receipt_gate(
                        tap,
                        action_type,
                        action_digest,
                        &action,
                        &decision,
                        &ctx,
                        &control_frame_digest,
                    ) {
                        return result;
                    }
                } else {
                    return GateResult::Denied { decision };
                }

                let execution_request = self.build_execution_request(
                    action_digest,
                    &tool_id,
                    &action_id,
                    &decision,
                    session_id,
                    step_id,
                );

                let outcome = self.adapter.execute(execution_request.clone());
                self.note_execution_outcome(&outcome);

                self.commit_action_exec_record(
                    session_id,
                    step_id,
                    &action,
                    action_digest,
                    &decision,
                    &outcome,
                    &control_frame,
                    &ctx,
                );

                GateResult::Executed { decision, outcome }
            }
        }
    }

    fn build_execution_request(
        &self,
        action_digest: [u8; 32],
        tool_id: &str,
        action_name: &str,
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
            tool_id: tool_id.to_string(),
            action_name: action_name.to_string(),
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

    #[allow(clippy::too_many_arguments)]
    fn commit_action_exec_record(
        &self,
        session_id: &str,
        step_id: &str,
        action: &ucf::v1::ActionSpec,
        action_digest: [u8; 32],
        decision: &PolicyDecisionRecord,
        outcome: &ucf::v1::OutcomePacket,
        control_frame: &ucf::v1::ControlFrame,
        ctx: &GateContext,
    ) {
        let record = build_action_exec_record(
            session_id,
            step_id,
            action,
            action_digest,
            decision,
            outcome,
            control_frame,
            ctx,
        );

        let receipt_result = self
            .pvgs_client
            .lock()
            .map(|mut client| client.commit_experience_record(record));

        match receipt_result {
            Ok(Ok(receipt)) => {
                if ucf::v1::ReceiptStatus::try_from(receipt.status)
                    != Ok(ucf::v1::ReceiptStatus::Accepted)
                {
                    let reasons = if receipt.reject_reason_codes.is_empty() {
                        vec![PVGS_INTEGRITY_REASON.to_string()]
                    } else {
                        receipt.reject_reason_codes.clone()
                    };
                    self.note_integrity_issue(&reasons);
                }
            }
            _ => self.note_integrity_issue(&[PVGS_INTEGRITY_REASON.to_string()]),
        }
    }

    fn note_integrity_issue(&self, reason_codes: &[String]) {
        let mut codes = reason_codes.to_vec();
        if codes.is_empty() {
            codes.push(PVGS_INTEGRITY_REASON.to_string());
        }
        codes.sort();
        codes.dedup();

        if let Ok(mut guard) = self.integrity_issues.lock() {
            *guard += 1;
        }

        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_integrity_issue(&codes);
            agg.on_integrity_state(ucf::v1::IntegrityState::Degraded);
        }
    }

    #[allow(clippy::result_large_err, clippy::too_many_arguments)]
    fn enforce_receipt_gate(
        &self,
        tap: &ucf::v1::ToolActionProfile,
        action_type: ucf::v1::ToolActionType,
        action_digest: [u8; 32],
        action: &ucf::v1::ActionSpec,
        decision: &PolicyDecisionRecord,
        ctx: &GateContext,
        control_frame_digest: &[u8; 32],
    ) -> Result<(), GateResult> {
        if !requires_receipt(action_type) {
            return Ok(());
        }

        let receipt = match ctx.pvgs_receipt.clone() {
            Some(r) => r,
            None => {
                self.note_receipt_issue(
                    ReceiptIssue::Missing,
                    &[RECEIPT_BLOCKED_REASON.to_string()],
                );
                return Err(GateResult::Denied {
                    decision: self
                        .receipt_blocked_decision(decision, &[RECEIPT_BLOCKED_REASON.to_string()]),
                });
            }
        };

        if let Err(err) = verify_pvgs_receipt(&receipt, &self.receipt_store) {
            let reason_codes = match err {
                VerifyError::UnknownKeyId(_) => vec![RECEIPT_UNKNOWN_KEY_REASON.to_string()],
                _ => vec![RECEIPT_BLOCKED_REASON.to_string()],
            };
            self.note_receipt_issue(ReceiptIssue::Invalid, &reason_codes);
            return Err(self.receipt_gate_error(decision, &reason_codes, action));
        }

        if ucf::v1::ReceiptStatus::try_from(receipt.status) != Ok(ucf::v1::ReceiptStatus::Accepted)
        {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(receipt.action_digest.as_ref(), &action_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(receipt.decision_digest.as_ref(), &decision.decision_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(receipt.profile_digest.as_ref(), control_frame_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest32_matches(
            tap.profile_digest.as_ref(),
            receipt.tool_profile_digest.as_ref(),
        ) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if let Some(expected_grant) = ctx.approval_grant_id.as_deref() {
            if receipt.grant_id != expected_grant {
                self.note_receipt_issue(
                    ReceiptIssue::Invalid,
                    &[RECEIPT_BLOCKED_REASON.to_string()],
                );
                return Err(self.receipt_gate_error(
                    decision,
                    &[RECEIPT_BLOCKED_REASON.to_string()],
                    action,
                ));
            }
        }

        Ok(())
    }

    fn note_receipt_issue(&self, issue: ReceiptIssue, reason_codes: &[String]) {
        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_receipt_issue(issue, reason_codes);
        }
    }

    fn deny_with_reasons(
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

    fn receipt_blocked_decision(
        &self,
        prior: &PolicyDecisionRecord,
        reason_codes: &[String],
    ) -> PolicyDecisionRecord {
        self.deny_with_reasons(prior, reason_codes)
    }

    fn receipt_gate_error(
        &self,
        prior: &PolicyDecisionRecord,
        reason_codes: &[String],
        _action: &ucf::v1::ActionSpec,
    ) -> GateResult {
        GateResult::Denied {
            decision: self.receipt_blocked_decision(prior, reason_codes),
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

fn digest_matches(opt: Option<&ucf::v1::Digest32>, expected: &[u8; 32]) -> bool {
    opt.map(|d| d.value.as_slice() == expected).unwrap_or(false)
}

fn digest32_matches(
    expected: Option<&ucf::v1::Digest32>,
    actual: Option<&ucf::v1::Digest32>,
) -> bool {
    match (expected, actual) {
        (Some(exp), Some(act)) => exp.value == act.value,
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_action_exec_record(
    session_id: &str,
    step_id: &str,
    _action: &ucf::v1::ActionSpec,
    action_digest: [u8; 32],
    decision: &PolicyDecisionRecord,
    outcome: &ucf::v1::OutcomePacket,
    control_frame: &ucf::v1::ControlFrame,
    ctx: &GateContext,
) -> ucf::v1::ExperienceRecord {
    let core_frame = build_core_frame(session_id, step_id, action_digest);
    let metabolic_frame = build_metabolic_frame(control_frame);
    let governance_frame = build_governance_frame(decision, outcome, ctx);

    let core_frame_ref = digest_proto(CORE_FRAME_DOMAIN, &canonical_bytes(&core_frame));
    let metabolic_frame_ref =
        digest_proto(METABOLIC_FRAME_DOMAIN, &canonical_bytes(&metabolic_frame));
    let governance_frame_ref =
        digest_proto(GOVERNANCE_FRAME_DOMAIN, &canonical_bytes(&governance_frame));

    ucf::v1::ExperienceRecord {
        record_type: ucf::v1::RecordType::ActionExec.into(),
        core_frame: Some(core_frame),
        metabolic_frame: Some(metabolic_frame),
        governance_frame: Some(governance_frame),
        core_frame_ref: Some(ucf::v1::Digest32 {
            value: core_frame_ref.to_vec(),
        }),
        metabolic_frame_ref: Some(ucf::v1::Digest32 {
            value: metabolic_frame_ref.to_vec(),
        }),
        governance_frame_ref: Some(ucf::v1::Digest32 {
            value: governance_frame_ref.to_vec(),
        }),
    }
}

fn build_core_frame(
    session_id: &str,
    step_id: &str,
    action_digest: [u8; 32],
) -> ucf::v1::CoreFrame {
    ucf::v1::CoreFrame {
        session_id: session_id.to_string(),
        step_id: step_id.to_string(),
        input_packet_refs: Vec::new(),
        intent_refs: Vec::new(),
        candidate_refs: vec![ucf::v1::Digest32 {
            value: action_digest.to_vec(),
        }],
        workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
    }
}

fn build_metabolic_frame(control_frame: &ucf::v1::ControlFrame) -> ucf::v1::MetabolicFrame {
    let control_frame_digest = control::control_frame_digest(control_frame);

    ucf::v1::MetabolicFrame {
        profile_state: control_frame.active_profile,
        control_frame_ref: Some(ucf::v1::Digest32 {
            value: control_frame_digest.to_vec(),
        }),
        hormone_classes: vec![ucf::v1::HormoneClass::Low.into()],
        noise_class: ucf::v1::NoiseClass::Medium.into(),
        priority_class: ucf::v1::PriorityClass::Medium.into(),
    }
}

fn build_governance_frame(
    decision: &PolicyDecisionRecord,
    outcome: &ucf::v1::OutcomePacket,
    ctx: &GateContext,
) -> ucf::v1::GovernanceFrame {
    let mut grant_refs = Vec::new();
    if let Some(grant_id) = ctx.approval_grant_id.as_ref() {
        grant_refs.push(ucf::v1::Digest32 {
            value: digest_proto(GRANT_REF_DOMAIN, grant_id.as_bytes()).to_vec(),
        });
    }

    let pvgs_receipt_ref = ctx
        .pvgs_receipt
        .as_ref()
        .and_then(|r| r.receipt_digest.clone());

    let mut reason_codes = aggregate_reason_codes(decision, outcome);
    if let Some(rc) = ctx.pvgs_receipt.as_ref() {
        reason_codes.extend(rc.reject_reason_codes.clone());
    }
    reason_codes.sort();
    reason_codes.dedup();

    ucf::v1::GovernanceFrame {
        policy_decision_refs: vec![ucf::v1::Digest32 {
            value: decision.decision_digest.to_vec(),
        }],
        grant_refs,
        dlp_refs: Vec::new(),
        budget_snapshot_ref: Some(ucf::v1::Digest32 {
            value: digest_proto(BUDGET_SNAPSHOT_DOMAIN, b"budget").to_vec(),
        }),
        pvgs_receipt_ref,
        reason_codes: if reason_codes.is_empty() {
            None
        } else {
            Some(ucf::v1::ReasonCodes {
                codes: reason_codes,
            })
        },
    }
}

fn aggregate_reason_codes(
    decision: &PolicyDecisionRecord,
    outcome: &ucf::v1::OutcomePacket,
) -> Vec<String> {
    let mut reason_codes = decision
        .decision
        .reason_codes
        .as_ref()
        .map(|rc| rc.codes.clone())
        .unwrap_or_default();

    reason_codes.extend(
        outcome
            .reason_codes
            .as_ref()
            .map(|rc| rc.codes.clone())
            .unwrap_or_default(),
    );

    reason_codes
}

fn parse_tool_and_action(action: &ucf::v1::ActionSpec) -> (String, String) {
    action
        .verb
        .split_once('/')
        .map(|(tool, action_name)| (tool.to_string(), action_name.to_string()))
        .unwrap_or_else(|| (action.verb.clone(), action.verb.clone()))
}

fn requires_receipt(action_type: ucf::v1::ToolActionType) -> bool {
    matches!(
        action_type,
        ucf::v1::ToolActionType::Write
            | ucf::v1::ToolActionType::Execute
            | ucf::v1::ToolActionType::Export
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pvgs_client::MockPvgsClient;
    use pvgs_verify::{
        pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
    };
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use tam::MockAdapter;

    type LocalClientHandle = Arc<Mutex<pvgs_client::LocalPvgsClient>>;
    type PvgsClientHandle = Arc<Mutex<Box<dyn PvgsClient>>>;

    #[derive(Clone, Default)]
    struct CountingAdapter {
        calls: Arc<Mutex<usize>>,
    }

    impl CountingAdapter {
        fn count(&self) -> usize {
            *self.calls.lock().expect("count lock")
        }
    }

    #[derive(Clone, Default)]
    struct SharedLocalClient {
        inner: Arc<Mutex<pvgs_client::LocalPvgsClient>>,
    }

    impl SharedLocalClient {
        fn new(inner: Arc<Mutex<pvgs_client::LocalPvgsClient>>) -> Self {
            Self { inner }
        }
    }

    impl PvgsClient for SharedLocalClient {
        fn commit_experience_record(
            &mut self,
            record: ucf::v1::ExperienceRecord,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_experience_record(record)
        }
    }

    fn default_aggregator() -> Arc<Mutex<WindowEngine>> {
        Arc::new(Mutex::new(
            WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
        ))
    }

    fn default_pvgs_client() -> PvgsClientHandle {
        Arc::new(Mutex::new(
            Box::new(MockPvgsClient::default()) as Box<dyn PvgsClient>
        ))
    }

    fn integrity_counter() -> Arc<Mutex<u64>> {
        Arc::new(Mutex::new(0))
    }

    fn boxed_client(client: impl PvgsClient + 'static) -> PvgsClientHandle {
        Arc::new(Mutex::new(Box::new(client) as Box<dyn PvgsClient>))
    }

    #[allow(clippy::type_complexity)]
    fn shared_local_client() -> (LocalClientHandle, PvgsClientHandle) {
        let inner: LocalClientHandle =
            Arc::new(Mutex::new(pvgs_client::LocalPvgsClient::default()));
        let client = SharedLocalClient::new(inner.clone());
        (inner, boxed_client(client))
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
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        )
    }

    fn gate_with_components(
        adapter: Box<dyn ToolAdapter>,
        store: Arc<Mutex<ControlFrameStore>>,
        receipt_store: Arc<PvgsKeyEpochStore>,
        aggregator: Arc<Mutex<WindowEngine>>,
        registry: Arc<ToolRegistry>,
        pvgs_client: PvgsClientHandle,
        integrity_issues: Arc<Mutex<u64>>,
    ) -> Gate {
        Gate {
            policy: PolicyEngine::new(),
            adapter,
            aggregator,
            control_store: store,
            receipt_store,
            registry,
            pvgs_client,
            integrity_issues,
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

    fn control_frame_digest(frame: &ucf::v1::ControlFrame) -> ucf::v1::Digest32 {
        ucf::v1::Digest32 {
            value: control::control_frame_digest(frame).to_vec(),
        }
    }

    fn open_control_frame_digest() -> ucf::v1::Digest32 {
        control_frame_digest(&control_frame_open())
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

    fn control_frame_export_masked() -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "cf-export-mask".to_string(),
            note: String::new(),
            active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            overlays: Some(ucf::v1::ControlFrameOverlays {
                ovl_simulate_first: false,
                ovl_export_lock: false,
                ovl_novelty_lock: false,
            }),
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: false,
                enable_write: true,
                enable_execute: true,
            }),
            deescalation_lock: false,
            reason_codes: None,
        }
    }

    fn base_action(tool: &str, action_id: &str) -> ucf::v1::ActionSpec {
        ucf::v1::ActionSpec {
            verb: format!("{tool}/{action_id}"),
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

    fn signed_key_epoch(
        signing_key: &SigningKey,
        key_id: &str,
        epoch_id: u64,
    ) -> ucf::v1::PvgsKeyEpoch {
        let mut key_epoch = ucf::v1::PvgsKeyEpoch {
            epoch_id,
            attestation_key_id: key_id.to_string(),
            attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            announcement_digest: None,
            signature: None,
            timestamp_ms: 1_700_000_000_000,
            vrf_key_id: None,
        };

        let digest = pvgs_key_epoch_digest(&key_epoch);
        key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
        key_epoch.signature = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });

        key_epoch
    }

    fn receipt_store_with_key() -> (Arc<PvgsKeyEpochStore>, SigningKey, String) {
        let (sk, key_id) = signing_material();
        let mut store = PvgsKeyEpochStore::new();
        let key_epoch = signed_key_epoch(&sk, &key_id, 1);
        store.ingest_key_epoch(key_epoch).expect("valid key epoch");
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
        let (tool_id, action_id) = parse_tool_and_action(action);
        let action_type = gate
            .registry
            .get(&tool_id, &action_id)
            .and_then(|tap| ucf::v1::ToolActionType::try_from(tap.action_type).ok())
            .unwrap_or(ucf::v1::ToolActionType::Unspecified);
        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame,
            tool_action_type: action_type,
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
        profile_digest: &ucf::v1::Digest32,
        tool_profile_digest: &ucf::v1::Digest32,
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
            profile_digest: Some(profile_digest.clone()),
            tool_profile_digest: Some(tool_profile_digest.clone()),
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
        let result = gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ctx);

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
        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
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
        let action = base_action("mock.read", "get");
        let ctx = ok_ctx();

        let control_frame = gate.resolve_control_frame(&ctx);
        let (tool_id, action_id) = parse_tool_and_action(&action);
        let action_type = gate
            .registry
            .get(&tool_id, &action_id)
            .and_then(|tap| ucf::v1::ToolActionType::try_from(tap.action_type).ok())
            .unwrap_or(ucf::v1::ToolActionType::Unspecified);
        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame: control_frame.clone(),
            tool_action_type: action_type,
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
            &tool_id,
            &action_id,
            &decision,
            "sid",
            "step",
        );
        let req_b = gate.build_execution_request(
            action_digest,
            &tool_id,
            &action_id,
            &decision,
            "sid",
            "step",
        );

        assert_eq!(canonical_bytes(&req_a), canonical_bytes(&req_b));
    }

    #[test]
    fn commits_experience_record_for_action_exec() {
        let counting = CountingAdapter::default();
        let (inner_client, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
        assert!(matches!(result, GateResult::Executed { .. }));

        let guard = inner_client.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_records.len(), 1);
        let record = guard.committed_records.first().expect("record committed");
        assert_eq!(
            ucf::v1::RecordType::try_from(record.record_type),
            Ok(ucf::v1::RecordType::ActionExec)
        );
        assert!(record.governance_frame_ref.is_some());
    }

    #[test]
    fn experience_record_bytes_are_deterministic() {
        let counting = CountingAdapter::default();
        let (inner_client, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
        );

        let ctx = ok_ctx();
        let action = base_action("mock.read", "get");
        let _ = gate.handle_action_spec("s", "step", action.clone(), ctx.clone());
        let _ = gate.handle_action_spec("s", "step", action, ctx);

        let guard = inner_client.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_bytes.len(), 2);
        assert_eq!(guard.committed_bytes[0], guard.committed_bytes[1]);
    }

    #[test]
    fn blocks_side_effect_without_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, _, _) = receipt_store_with_key();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let ctx = ok_ctx();
        let result =
            gate.handle_action_spec("s", "step", base_action("mock.write", "apply"), ctx.clone());

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
    fn export_requires_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, _, _) = receipt_store_with_key();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let ctx = ok_ctx();
        let result =
            gate.handle_action_spec("s", "step", base_action("mock.export", "render"), ctx);

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
            "export adapter must not run without receipt"
        );
    }

    #[test]
    fn blocks_side_effect_with_invalid_receipt() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let mut ctx = ok_ctx();
        let action = base_action("mock.write", "apply");
        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        let mismatched_profile = sample_digest(200);
        let receipt = signed_receipt_for(
            action_digest,
            decision.decision_digest,
            &signer,
            &key_id,
            &open_control_frame_digest(),
            &mismatched_profile,
        );
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
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            aggregator,
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let mut ctx = ok_ctx();
        let action = base_action("mock.write", "apply");
        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        let receipt = signed_receipt_for(
            action_digest,
            decision.decision_digest,
            &signer,
            &key_id,
            &open_control_frame_digest(),
            &gate
                .registry
                .tool_profile_digest("mock.write", "apply")
                .expect("fixture digest"),
        );
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
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let ctx = ok_ctx();
        let sim_result =
            gate.handle_action_spec("s", "step1", base_action("mock.read", "get"), ctx.clone());
        match sim_result {
            GateResult::SimulationRequired { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()]
                );
            }
            other => panic!("expected simulation-required, got {other:?}"),
        }

        let export_result =
            gate.handle_action_spec("s", "step2", base_action("mock.export", "render"), ctx);
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
    fn unknown_tool_fails_closed_and_counts_policy_deny() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let mut ctx = ok_ctx();
        ctx.allowed_tools.push("unknown.tool".to_string());
        let result = gate.handle_action_spec("s", "step", base_action("unknown.tool", "do"), ctx);

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()]
                );
            }
            other => panic!("expected deny for unknown tool, got {other:?}"),
        }
        assert_eq!(counting.count(), 0, "unknown tools must not run");

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let top_policy_codes = frames
            .first()
            .and_then(|f| f.policy_stats.as_ref())
            .map(|p| p.top_reason_codes.clone())
            .unwrap_or_default();
        assert!(top_policy_codes
            .iter()
            .any(|rc| rc.code == "RC.PB.DENY.TOOL_NOT_ALLOWED"));
    }

    #[test]
    fn simulate_first_overlay_blocks_execution() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let mut ctx = ok_ctx();
        ctx.control_frame = Some(control_frame_locked_sim());

        let result = gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ctx);
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

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.export", "render"), ctx);
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
    fn toolclass_mask_blocks_export() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let mut ctx = ok_ctx();
        ctx.control_frame = Some(control_frame_export_masked());

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.export", "render"), ctx);
        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()]
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
        assert_eq!(counting.count(), 0, "adapter blocked by toolclass mask");
    }

    #[test]
    fn receipt_stats_recorded_in_signal_frame() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store.clone(),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let ctx = ok_ctx();
        let action = base_action("mock.write", "apply");

        for idx in 0..2 {
            let _ =
                gate.handle_action_spec("s", &format!("missing{idx}"), action.clone(), ctx.clone());
        }

        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "invalid");
        let mut receipt = signed_receipt_for(
            action_digest,
            decision.decision_digest,
            &signer,
            &key_id,
            &open_control_frame_digest(),
            &gate
                .registry
                .tool_profile_digest("mock.write", "apply")
                .expect("fixture digest"),
        );
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
    fn pvgs_rejection_triggers_integrity_signal() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let integrity = integrity_counter();
        let rejecting_client = boxed_client(SharedLocalClient::new(Arc::new(Mutex::new(
            pvgs_client::LocalPvgsClient::rejecting(vec![PVGS_INTEGRITY_REASON.to_string()]),
        ))));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            rejecting_client,
            integrity.clone(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
        assert!(matches!(result, GateResult::Executed { .. }));
        assert_eq!(*integrity.lock().expect("integrity counter lock"), 1);

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let integrity_stats = frames
            .first()
            .and_then(|f| f.integrity_stats.as_ref())
            .cloned()
            .expect("integrity stats present");
        assert_eq!(integrity_stats.integrity_issue_count, 1);
        assert!(integrity_stats
            .top_reason_codes
            .iter()
            .any(|rc| rc.code == PVGS_INTEGRITY_REASON));
    }

    #[test]
    fn denies_when_receipt_uses_unknown_key() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
        );

        let mut ctx = ok_ctx();
        let action = base_action("mock.write", "apply");
        let action_digest = compute_action_digest(&action);
        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        let (signer, key_id) = signing_material();
        let receipt = signed_receipt_for(
            action_digest,
            decision.decision_digest,
            &signer,
            &key_id,
            &open_control_frame_digest(),
            &gate
                .registry
                .tool_profile_digest("mock.write", "apply")
                .expect("fixture digest"),
        );
        ctx.pvgs_receipt = Some(receipt);

        let result = gate.handle_action_spec("s", "step", action, ctx);
        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![RECEIPT_UNKNOWN_KEY_REASON.to_string()]
                );
            }
            other => panic!("expected deny for unknown key, got {other:?}"),
        }
        assert_eq!(
            counting.count(),
            0,
            "adapter must not run when receipt key is unknown"
        );

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let receipt_stats = frames
            .first()
            .and_then(|f| f.receipt_stats.as_ref())
            .cloned()
            .expect("receipt stats present");
        assert_eq!(receipt_stats.receipt_invalid_count, 1);
        assert!(receipt_stats
            .top_reason_codes
            .iter()
            .any(|rc| rc.code == RECEIPT_UNKNOWN_KEY_REASON && rc.count >= 1));
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
        let aggregator = default_aggregator();
        let gate = Gate {
            policy: PolicyEngine::new(),
            adapter: Box::new(counting.clone()),
            aggregator: aggregator.clone(),
            control_store: store,
            receipt_store: Arc::new(PvgsKeyEpochStore::new()),
            registry: Arc::new(trm::registry_fixture()),
            pvgs_client: default_pvgs_client(),
            integrity_issues: integrity_counter(),
        };

        let mut ctx = ok_ctx();
        ctx.control_frame = None;

        for idx in 0..3 {
            let _ = gate.handle_action_spec(
                "s",
                &format!("step{idx}"),
                base_action("mock.export", "render"),
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
