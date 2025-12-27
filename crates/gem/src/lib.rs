#![forbid(unsafe_code)]

pub mod inflight;

use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use cdm::{dlp_check_output, dlp_decision_digest, output_artifact_digest};
use ckm_orchestrator::CkmOrchestrator;
use control::ControlFrameStore;
#[cfg(test)]
use frames::FramesConfig;
use frames::{DlpDecision as FramesDlpDecision, ReceiptIssue, WindowEngine};
use pbm::{
    compute_decision_digest, policy_query_digest, DecisionForm, PolicyContext,
    PolicyDecisionRecord, PolicyEngine, PolicyEvaluationRequest,
};
use pvgs_client::{PvgsClientReader, RppHeadMeta};
use pvgs_verify::{verify_pvgs_receipt, PvgsKeyEpochStore, VerifyError};
use rpp_checker::{verify_accumulator, RppCheckInputs};
use tam::ToolAdapter;
use trm::{ToolLookup, ToolRegistry};
use ucf_protocol::{canonical_bytes, digest32, digest_proto, ucf};

const RECEIPT_BLOCKED_REASON: &str = "RC.GE.EXEC.DISPATCH_BLOCKED";
const RECEIPT_UNKNOWN_KEY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";
const PVGS_INTEGRITY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";
const RPP_VERIFY_FAIL_REASON: &str = "RC.GV.RPP.VERIFY_FAIL";
const REPLAY_MISMATCH_REASON: &str = "RC.RE.REPLAY.MISMATCH";
const FORENSIC_ACTION_REASON: &str = "RC.RX.ACTION.FORENSIC";
const INTEGRITY_FAIL_REASON: &str = "RC.RE.INTEGRITY.FAIL";
const RECOVERY_UNLOCK_GRANTED_REASON: &str = "RC.GV.RECOVERY.UNLOCK_GRANTED";
const RECOVERY_READONLY_REASON: &str = "RC.GV.RECOVERY.READONLY_MODE";
const TOOL_SUSPENDED_REASON: &str = "RC.GV.TOOL.SUSPENDED";
const CORE_FRAME_DOMAIN: &str = "UCF:HASH:CORE_FRAME";
const METABOLIC_FRAME_DOMAIN: &str = "UCF:HASH:METABOLIC_FRAME";
const GOVERNANCE_FRAME_DOMAIN: &str = "UCF:HASH:GOVERNANCE_FRAME";
const BUDGET_SNAPSHOT_DOMAIN: &str = "UCF:HASH:BUDGET_SNAPSHOT";
const GRANT_REF_DOMAIN: &str = "UCF:HASH:GRANT_REF";
const RPP_META_CACHE_TTL: Duration = Duration::from_millis(250);
const POLICY_DECISION_REF: &str = "policy_decision";
const MAX_RELATED_REFS: usize = 8;

/// Maps policy query digests to their corresponding decision digests to detect replay mismatches.
#[derive(Debug, Default, Clone)]
pub struct QueryDecisionMap {
    entries: HashMap<[u8; 32], [u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayMismatch {
    pub existing: [u8; 32],
    pub attempted: [u8; 32],
}

impl QueryDecisionMap {
    pub fn insert(
        &mut self,
        policy_query_digest: [u8; 32],
        decision_digest: [u8; 32],
    ) -> Result<(), ReplayMismatch> {
        match self.entries.get(&policy_query_digest) {
            Some(existing) if existing != &decision_digest => Err(ReplayMismatch {
                existing: *existing,
                attempted: decision_digest,
            }),
            _ => {
                self.entries.insert(policy_query_digest, decision_digest);
                Ok(())
            }
        }
    }

    pub fn lookup(&self, policy_query_digest: [u8; 32]) -> Option<[u8; 32]> {
        self.entries.get(&policy_query_digest).copied()
    }
}

/// Tracks PVGS commit attempts for decisions to enable idempotent retry on restarts.
///
/// The store records the commit lifecycle for each decision digest so that callers can safely
/// retry pending or failed commits without re-issuing successful ones. This strategy preserves
/// integrity on restart: a decision observed as `Committed` is skipped, while `Pending` or
/// `Failed` entries are retried and updated based on the latest commit outcome.
#[derive(Debug, Default, Clone)]
pub struct DecisionLogStore {
    entries: std::collections::HashMap<[u8; 32], DecisionLogEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCommitState {
    Pending,
    Committed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionCommitDisposition {
    CommitRequired,
    AlreadyCommitted,
}

#[derive(Debug, Clone, Copy)]
pub struct DecisionLogEntry {
    pub state: DecisionCommitState,
    pub receipt_digest: Option<[u8; 32]>,
}

impl Default for DecisionLogEntry {
    fn default() -> Self {
        Self {
            state: DecisionCommitState::Pending,
            receipt_digest: None,
        }
    }
}

impl DecisionLogStore {
    pub fn observe_or_register(
        &mut self,
        decision_digest: [u8; 32],
    ) -> (DecisionCommitDisposition, Option<[u8; 32]>) {
        let (disposition, receipt_digest) = match self.entries.get(&decision_digest) {
            Some(entry) if entry.state == DecisionCommitState::Committed => (
                DecisionCommitDisposition::AlreadyCommitted,
                entry.receipt_digest,
            ),
            Some(entry) => (
                DecisionCommitDisposition::CommitRequired,
                entry.receipt_digest,
            ),
            None => (DecisionCommitDisposition::CommitRequired, None),
        };

        let entry = self.entries.entry(decision_digest).or_default();

        if entry.state != DecisionCommitState::Committed {
            entry.state = DecisionCommitState::Pending;
        }

        (disposition, receipt_digest)
    }

    pub fn mark_committed(&mut self, decision_digest: [u8; 32], receipt_digest: Option<[u8; 32]>) {
        self.entries.insert(
            decision_digest,
            DecisionLogEntry {
                state: DecisionCommitState::Committed,
                receipt_digest,
            },
        );
    }

    pub fn mark_failed(&mut self, decision_digest: [u8; 32], receipt_digest: Option<[u8; 32]>) {
        self.entries.insert(
            decision_digest,
            DecisionLogEntry {
                state: DecisionCommitState::Failed,
                receipt_digest,
            },
        );
    }

    pub fn status(&self, decision_digest: [u8; 32]) -> Option<DecisionCommitState> {
        self.entries.get(&decision_digest).map(|entry| entry.state)
    }
}

pub struct Gate {
    pub policy: PolicyEngine,
    pub adapter: Box<dyn ToolAdapter>,
    pub aggregator: Arc<Mutex<WindowEngine>>,
    pub orchestrator: Arc<Mutex<CkmOrchestrator>>,
    pub control_store: Arc<Mutex<ControlFrameStore>>,
    pub receipt_store: Arc<PvgsKeyEpochStore>,
    pub registry: Arc<ToolRegistry>,
    pub pvgs_client: Arc<Mutex<Box<dyn PvgsClientReader>>>,
    pub integrity_issues: Arc<Mutex<u64>>,
    pub decision_log: Arc<Mutex<DecisionLogStore>>,
    pub query_decisions: Arc<Mutex<QueryDecisionMap>>,
    pub rpp_cache: Arc<Mutex<RppMetaCache>>,
}

#[derive(Debug, Clone)]
pub struct GateContext {
    pub integrity_state: String,
    pub charter_version_digest: String,
    pub allowed_tools: Vec<String>,
    pub control_frame: Option<ucf::v1::ControlFrame>,
    pub pvgs_receipt: Option<ucf::v1::PvgsReceipt>,
    pub approval_grant_id: Option<String>,
    pub pev: Option<ucf::v1::PolicyEcologyVector>,
    pub pev_digest: Option<[u8; 32]>,
    pub ruleset_digest: Option<[u8; 32]>,
    pub session_sealed: bool,
    pub session_unlock_permit: bool,
}

#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub session_id: String,
    pub step_id: String,
    pub policy_query: ucf::v1::PolicyQuery,
    pub policy_query_digest: [u8; 32],
    pub policy_decision: ucf::v1::PolicyDecision,
    pub decision_digest: [u8; 32],
    pub ruleset_digest: Option<[u8; 32]>,
    pub control_frame_digest: [u8; 32],
    pub tool_profile_digest: Option<[u8; 32]>,
    pub commit_disposition: DecisionCommitDisposition,
    pub receipt_digest: Option<[u8; 32]>,
    pub(crate) rpp_head_meta: Option<RppHeadMeta>,
    pub(crate) rpp_refs: RppEvidenceRefs,
    pub(crate) micro_evidence: MicroEvidence,
    pub(crate) microcircuit_config_refs: MicrocircuitConfigRefs,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MicroEvidence {
    lc_digest: Option<[u8; 32]>,
    sn_digest: Option<[u8; 32]>,
    plasticity_digest: Option<[u8; 32]>,
}

impl MicroEvidence {
    fn is_empty(&self) -> bool {
        self.lc_digest.is_none() && self.sn_digest.is_none() && self.plasticity_digest.is_none()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MicrocircuitConfigRefs {
    lc_digest: Option<[u8; 32]>,
    sn_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RppEvidenceRefs {
    prev_acc_digest: Option<[u8; 32]>,
    acc_digest: Option<[u8; 32]>,
    new_root_digest: Option<[u8; 32]>,
}

impl RppEvidenceRefs {
    fn from_meta(meta: Option<RppHeadMeta>) -> Self {
        if let Some(meta) = meta {
            Self {
                prev_acc_digest: Some(meta.prev_acc_digest),
                acc_digest: Some(meta.acc_digest),
                new_root_digest: Some(meta.state_root),
            }
        } else {
            Self::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RppMetaCache {
    fetched_at: Option<Instant>,
    meta: Option<RppHeadMeta>,
}

#[derive(Clone, Copy)]
struct SealStatus {
    sealed: bool,
    unlock_present: bool,
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

#[derive(Debug, Clone, PartialEq)]
pub enum OutputDisposition {
    Delivered,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputResult {
    pub disposition: OutputDisposition,
    pub artifact_digest: [u8; 32],
    pub dlp_decision_digest: [u8; 32],
    pub record_digest: Option<[u8; 32]>,
    pub reason_codes: Vec<String>,
    pub delivered: bool,
}

impl Gate {
    pub fn handle_action_spec(
        &self,
        session_id: &str,
        step_id: &str,
        action: ucf::v1::ActionSpec,
        ctx: GateContext,
    ) -> GateResult {
        let mut ctx = ctx;
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
        let tool_lookup = self.registry.lookup(&tool_id, &action_id);
        let tool_profile = match tool_lookup {
            ToolLookup::Profile(profile) => Some(profile),
            _ => None,
        };
        let action_type = tool_profile
            .and_then(|tap| ucf::v1::ToolActionType::try_from(tap.action_type).ok())
            .unwrap_or(ucf::v1::ToolActionType::Unspecified);
        let canonical = canonical_bytes(&action);
        let action_digest = digest32("UCF:HASH:ACTION_SPEC", "ActionSpec", "v1", &canonical);

        let seal_status = self.session_seal_status(session_id);
        ctx.session_sealed = seal_status.sealed;
        ctx.session_unlock_permit = seal_status.unlock_present;

        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);

        let control_frame = self.resolve_control_frame(&ctx);
        let control_frame_digest = control::control_frame_digest(&control_frame);

        let policy_ctx = PolicyContext {
            integrity_state: ctx.integrity_state.clone(),
            charter_version_digest: ctx.charter_version_digest.clone(),
            allowed_tools: ctx.allowed_tools.clone(),
            control_frame: control_frame.clone(),
            tool_action_type: action_type,
            pev: ctx.pev.clone(),
            pev_digest: ctx.pev_digest,
            ruleset_digest: ctx.ruleset_digest,
            session_sealed: seal_status.sealed,
            unlock_present: seal_status.unlock_present,
        };

        let mut decision = self.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: format!("{session_id}:{step_id}"),
            query: policy_query.clone(),
            context: policy_ctx,
        });

        decision.policy_query_digest = policy_query_digest;
        let rpp_head_meta = self.load_rpp_head_meta();

        let mut decision_context = DecisionContext {
            session_id: session_id.to_string(),
            step_id: step_id.to_string(),
            policy_query,
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest: decision.decision_digest,
            ruleset_digest: decision.ruleset_digest,
            control_frame_digest,
            tool_profile_digest: tool_profile
                .as_ref()
                .and_then(|tap| tap.profile_digest.as_ref())
                .and_then(digest32_to_array),
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta,
            rpp_refs: RppEvidenceRefs::from_meta(rpp_head_meta),
            micro_evidence: micro_evidence_from_control_frame(&control_frame),
            microcircuit_config_refs: microcircuit_config_refs_from_pvgs(&self.pvgs_client),
        };

        if let Err(result) =
            self.enforce_query_decision_consistency(&mut decision, &mut decision_context)
        {
            return result;
        }

        if matches!(tool_lookup, ToolLookup::Suspended) {
            self.deny_with_reasons(
                &mut decision,
                &mut decision_context,
                &[TOOL_SUSPENDED_REASON.to_string()],
            );
        } else if tool_profile.is_none() {
            self.deny_with_reasons(
                &mut decision,
                &mut decision_context,
                &["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()],
            );
        }

        if let Some(result) = self.enforce_seal_policy(
            action_type,
            &mut ctx,
            &mut decision,
            &mut decision_context,
            seal_status,
        ) {
            return result;
        }

        // TODO: budget accounting hook.
        // TODO: PVGS receipts hook.
        // TODO: DLP enforcement hook.

        self.note_policy_decision(&decision);
        self.refresh_commit_disposition(&mut decision_context);
        self.commit_policy_decision_record(&decision, &decision_context);

        match decision.form {
            DecisionForm::Deny => GateResult::Denied { decision },
            DecisionForm::RequireApproval => GateResult::ApprovalRequired { decision },
            DecisionForm::RequireSimulationFirst => GateResult::SimulationRequired { decision },
            DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                if tool_profile.is_some() {
                    if let Err(result) = self.enforce_decision_commit_success(
                        action_type,
                        &mut decision,
                        &mut decision_context,
                    ) {
                        return result;
                    }

                    if let Err(result) = self.enforce_receipt_gate(
                        action_type,
                        action_digest,
                        &action,
                        &mut decision,
                        &ctx,
                        &mut decision_context,
                    ) {
                        return result;
                    }

                    if let Err(result) = self.enforce_rpp_second_check(
                        action_type,
                        &mut decision,
                        &mut decision_context,
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
                    &decision_context,
                );

                let outcome = self.adapter.execute(execution_request.clone());
                self.note_execution_outcome(&outcome);

                self.commit_action_exec_record(
                    &action,
                    action_digest,
                    &decision,
                    &outcome,
                    &control_frame,
                    &ctx,
                    &decision_context,
                );

                GateResult::Executed { decision, outcome }
            }
        }
    }

    pub fn handle_output_artifact(
        &self,
        session_id: &str,
        step_id: &str,
        mut artifact: ucf::v1::OutputArtifact,
        ctx: GateContext,
    ) -> OutputResult {
        let artifact_digest = output_artifact_digest(&artifact);
        artifact.artifact_digest = Some(ucf::v1::Digest32 {
            value: artifact_digest.to_vec(),
        });

        let mut dlp_decision = dlp_check_output(&artifact);
        ensure_dlp_decision_digest(&mut dlp_decision);
        let mut reason_codes = dlp_decision
            .reason_codes
            .as_ref()
            .map(|rc| rc.codes.clone())
            .unwrap_or_default();
        reason_codes.sort();
        reason_codes.dedup();

        if let Ok(mut agg) = self.aggregator.lock() {
            let frames_decision = match ucf::v1::DlpDecisionForm::try_from(dlp_decision.form) {
                Ok(ucf::v1::DlpDecisionForm::Block) => FramesDlpDecision::Block,
                Ok(ucf::v1::DlpDecisionForm::Redact) => FramesDlpDecision::Redact,
                Ok(ucf::v1::DlpDecisionForm::ClassifyUpgrade) => FramesDlpDecision::ClassifyUpgrade,
                _ => FramesDlpDecision::Allow,
            };
            agg.on_dlp_decision(frames_decision, &reason_codes);
        }

        let control_frame = self.resolve_control_frame(&ctx);
        let control_frame_digest = control::control_frame_digest(&control_frame);

        let dlp_receipt = self
            .pvgs_client
            .lock()
            .map(|mut client| client.commit_dlp_decision(dlp_decision.clone()));

        let dlp_decision_digest = dlp_decision
            .dlp_decision_digest
            .as_ref()
            .and_then(digest32_to_array)
            .expect("dlp decision digest present");

        let (dlp_committed, dlp_reasons) = match dlp_receipt {
            Ok(Ok(receipt))
                if ucf::v1::ReceiptStatus::try_from(receipt.status)
                    == Ok(ucf::v1::ReceiptStatus::Accepted) =>
            {
                (true, reason_codes.clone())
            }
            Ok(Ok(receipt)) => {
                let mut reasons = receipt.reject_reason_codes.clone();
                if reasons.is_empty() {
                    reasons.push(PVGS_INTEGRITY_REASON.to_string());
                }
                (false, reasons)
            }
            _ => (false, vec![PVGS_INTEGRITY_REASON.to_string()]),
        };

        if !dlp_committed {
            let mut reasons = dlp_reasons;
            reasons.sort();
            reasons.dedup();
            self.note_integrity_issue(&reasons);
            return OutputResult {
                disposition: OutputDisposition::Failed,
                artifact_digest,
                dlp_decision_digest,
                record_digest: None,
                reason_codes: reasons,
                delivered: false,
            };
        }

        let record = build_output_record(
            session_id,
            step_id,
            artifact_digest,
            &dlp_decision,
            &control_frame,
            &control_frame_digest,
            None,
            None,
            ctx.ruleset_digest,
        );

        let record_receipt = self
            .pvgs_client
            .lock()
            .map(|mut client| client.commit_experience_record(record.clone()));

        let (_record_committed, record_reasons) = match record_receipt {
            Ok(Ok(receipt))
                if ucf::v1::ReceiptStatus::try_from(receipt.status)
                    == Ok(ucf::v1::ReceiptStatus::Accepted) =>
            {
                let digest = receipt.receipt_digest.as_ref().and_then(digest32_to_array);
                return self.finalize_output_result(
                    &dlp_decision,
                    artifact_digest,
                    dlp_decision_digest,
                    digest,
                    reason_codes,
                    &control_frame,
                );
            }
            Ok(Ok(receipt)) => {
                let mut reasons = receipt.reject_reason_codes.clone();
                if reasons.is_empty() {
                    reasons.push(PVGS_INTEGRITY_REASON.to_string());
                }
                (false, reasons)
            }
            _ => (false, vec![PVGS_INTEGRITY_REASON.to_string()]),
        };

        let mut reasons = record_reasons;
        reasons.sort();
        reasons.dedup();
        self.note_integrity_issue(&reasons);

        OutputResult {
            disposition: OutputDisposition::Failed,
            artifact_digest,
            dlp_decision_digest,
            record_digest: None,
            reason_codes: reasons,
            delivered: false,
        }
    }

    fn finalize_output_result(
        &self,
        dlp_decision: &ucf::v1::DlpDecision,
        artifact_digest: [u8; 32],
        dlp_decision_digest: [u8; 32],
        record_digest: Option<[u8; 32]>,
        mut reason_codes: Vec<String>,
        control_frame: &ucf::v1::ControlFrame,
    ) -> OutputResult {
        reason_codes.sort();
        reason_codes.dedup();

        let form = ucf::v1::DlpDecisionForm::try_from(dlp_decision.form)
            .unwrap_or(ucf::v1::DlpDecisionForm::Unspecified);
        let delivery_allowed = matches!(
            form,
            ucf::v1::DlpDecisionForm::Allow | ucf::v1::DlpDecisionForm::Redact
        ) && !control_frame
            .overlays
            .as_ref()
            .map(|o| o.ovl_export_lock)
            .unwrap_or(false)
            && control_frame
                .toolclass_mask
                .as_ref()
                .map(|m| m.enable_export)
                .unwrap_or(false);

        let disposition = match form {
            ucf::v1::DlpDecisionForm::Block => OutputDisposition::Blocked,
            _ if delivery_allowed => OutputDisposition::Delivered,
            _ => OutputDisposition::Blocked,
        };

        OutputResult {
            disposition,
            artifact_digest,
            dlp_decision_digest,
            record_digest,
            reason_codes,
            delivered: delivery_allowed,
        }
    }

    fn build_execution_request(
        &self,
        action_digest: [u8; 32],
        tool_id: &str,
        action_name: &str,
        decision: &PolicyDecisionRecord,
        decision_ctx: &DecisionContext,
    ) -> ucf::v1::ExecutionRequest {
        let request_id = format!("{}:{}", decision_ctx.session_id, decision_ctx.step_id);
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

    fn commit_policy_decision_record(
        &self,
        decision: &PolicyDecisionRecord,
        decision_ctx: &DecisionContext,
    ) {
        let record = build_decision_record(decision, decision_ctx);
        self.commit_record(record, decision_ctx);
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
        action: &ucf::v1::ActionSpec,
        action_digest: [u8; 32],
        decision: &PolicyDecisionRecord,
        outcome: &ucf::v1::OutcomePacket,
        control_frame: &ucf::v1::ControlFrame,
        ctx: &GateContext,
        decision_ctx: &DecisionContext,
    ) {
        let record = build_action_exec_record(
            action,
            action_digest,
            decision,
            outcome,
            control_frame,
            ctx,
            decision_ctx,
        );

        self.commit_record(record, decision_ctx);
    }

    fn refresh_commit_disposition(&self, decision_ctx: &mut DecisionContext) {
        if let Ok(mut log) = self.decision_log.lock() {
            let (disposition, receipt_digest) =
                log.observe_or_register(decision_ctx.decision_digest);
            decision_ctx.commit_disposition = disposition;
            decision_ctx.receipt_digest = receipt_digest;
        } else {
            decision_ctx.commit_disposition = DecisionCommitDisposition::CommitRequired;
            decision_ctx.receipt_digest = None;
        }
    }

    #[allow(clippy::result_large_err)]
    fn enforce_query_decision_consistency(
        &self,
        decision: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
    ) -> Result<(), GateResult> {
        let reason_codes = [REPLAY_MISMATCH_REASON.to_string()];
        let map_digest = map_decision_digest(decision, decision_ctx);

        let mut map = match self.query_decisions.lock() {
            Ok(map) => map,
            Err(_) => {
                self.note_integrity_issue(&reason_codes);
                self.deny_with_reasons(decision, decision_ctx, &reason_codes);
                return Err(GateResult::Denied {
                    decision: decision.clone(),
                });
            }
        };

        if map
            .insert(decision_ctx.policy_query_digest, map_digest)
            .is_err()
        {
            self.note_integrity_issue(&reason_codes);
            self.deny_with_reasons(decision, decision_ctx, &reason_codes);
            return Err(GateResult::Denied {
                decision: decision.clone(),
            });
        }

        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn enforce_decision_commit_success(
        &self,
        action_type: ucf::v1::ToolActionType,
        decision: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
    ) -> Result<(), GateResult> {
        if !requires_receipt(action_type) {
            return Ok(());
        }

        let status = self
            .decision_log
            .lock()
            .ok()
            .and_then(|log| log.status(decision_ctx.decision_digest));

        if matches!(status, Some(DecisionCommitState::Committed)) {
            return Ok(());
        }

        let reason_codes = [PVGS_INTEGRITY_REASON.to_string()];
        self.note_integrity_issue(&reason_codes);
        self.deny_with_reasons(decision, decision_ctx, &reason_codes);

        Err(GateResult::Denied {
            decision: decision.clone(),
        })
    }

    fn commit_record(&self, record: ucf::v1::ExperienceRecord, decision_ctx: &DecisionContext) {
        if decision_ctx.commit_disposition == DecisionCommitDisposition::AlreadyCommitted {
            return;
        }

        let receipt_result = self
            .pvgs_client
            .lock()
            .map(|mut client| client.commit_experience_record(record));

        match receipt_result {
            Ok(Ok(receipt)) => {
                let receipt_digest = receipt.receipt_digest.as_ref().and_then(digest32_to_array);
                let receipt_status = ucf::v1::ReceiptStatus::try_from(receipt.status);
                if let Ok(mut log) = self.decision_log.lock() {
                    if receipt_status == Ok(ucf::v1::ReceiptStatus::Accepted) {
                        log.mark_committed(decision_ctx.decision_digest, receipt_digest);
                    } else {
                        log.mark_failed(decision_ctx.decision_digest, receipt_digest);
                    }
                }

                if receipt_status == Ok(ucf::v1::ReceiptStatus::Accepted) {
                    if let (Ok(mut orchestrator), Ok(mut pvgs)) =
                        (self.orchestrator.lock(), self.pvgs_client.lock())
                    {
                        orchestrator.on_record_committed(pvgs.as_mut(), &decision_ctx.session_id);
                    }
                } else {
                    let reasons = if receipt.reject_reason_codes.is_empty() {
                        vec![PVGS_INTEGRITY_REASON.to_string()]
                    } else {
                        receipt.reject_reason_codes.clone()
                    };
                    self.note_integrity_issue(&reasons);
                }
            }
            _ => {
                if let Ok(mut log) = self.decision_log.lock() {
                    log.mark_failed(decision_ctx.decision_digest, None);
                }
                self.note_integrity_issue(&[PVGS_INTEGRITY_REASON.to_string()]);
            }
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

    fn note_forensic_seal(&self, reason_codes: &[String]) {
        let mut codes = reason_codes.to_vec();
        codes.sort();
        codes.dedup();

        if let Ok(mut guard) = self.integrity_issues.lock() {
            *guard += 1;
        }

        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_integrity_issue(&codes);
            agg.on_integrity_state(ucf::v1::IntegrityState::Fail);
        }
    }

    fn note_recovery_unlock(&self, reason_codes: &[String]) {
        let mut codes = reason_codes.to_vec();
        codes.sort();
        codes.dedup();

        if let Ok(mut guard) = self.integrity_issues.lock() {
            *guard += 1;
        }

        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_integrity_issue(&codes);
            agg.on_integrity_state(ucf::v1::IntegrityState::Fail);
        }
    }

    fn enforce_seal_policy(
        &self,
        action_type: ucf::v1::ToolActionType,
        _ctx: &mut GateContext,
        decision: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
        seal_status: SealStatus,
    ) -> Option<GateResult> {
        let SealStatus {
            sealed,
            unlock_present,
        } = seal_status;

        if !sealed {
            return None;
        }

        let integrity_reasons = if unlock_present {
            self.recovery_reason_codes()
        } else {
            self.forensic_reason_codes()
        };

        if unlock_present {
            decision
                .metadata
                .insert("recovery_readonly".to_string(), "true".to_string());
            self.note_recovery_unlock(&integrity_reasons);
        } else {
            self.note_forensic_seal(&integrity_reasons);
        }

        if is_side_effect_action(action_type) {
            let reason_codes = if unlock_present {
                self.recovery_enforcement_reason_codes()
            } else {
                integrity_reasons.clone()
            };
            self.deny_with_reasons(decision, decision_ctx, &reason_codes);
            return Some(GateResult::Denied {
                decision: decision.clone(),
            });
        }

        None
    }

    fn session_seal_status(&self, session_id: &str) -> SealStatus {
        match self.pvgs_client.lock() {
            Ok(client) => {
                let sealed = client.is_session_sealed(session_id).unwrap_or(true);
                let unlock_present = if sealed {
                    client.has_unlock_permit(session_id).unwrap_or(false)
                } else {
                    false
                };
                SealStatus {
                    sealed,
                    unlock_present,
                }
            }
            Err(_) => SealStatus {
                sealed: true,
                unlock_present: false,
            },
        }
    }

    fn forensic_reason_codes(&self) -> Vec<String> {
        let mut codes = vec![
            FORENSIC_ACTION_REASON.to_string(),
            INTEGRITY_FAIL_REASON.to_string(),
        ];
        codes.sort();
        codes
    }

    fn recovery_reason_codes(&self) -> Vec<String> {
        let mut codes = vec![
            INTEGRITY_FAIL_REASON.to_string(),
            RECOVERY_UNLOCK_GRANTED_REASON.to_string(),
        ];
        codes.sort();
        codes
    }

    fn recovery_enforcement_reason_codes(&self) -> Vec<String> {
        let mut codes = vec![
            FORENSIC_ACTION_REASON.to_string(),
            INTEGRITY_FAIL_REASON.to_string(),
            RECOVERY_READONLY_REASON.to_string(),
            RECOVERY_UNLOCK_GRANTED_REASON.to_string(),
        ];
        codes.sort();
        codes
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::result_large_err)]
    fn enforce_receipt_gate(
        &self,
        action_type: ucf::v1::ToolActionType,
        action_digest: [u8; 32],
        action: &ucf::v1::ActionSpec,
        decision: &mut PolicyDecisionRecord,
        ctx: &GateContext,
        decision_ctx: &mut DecisionContext,
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
                self.receipt_blocked_decision(
                    decision,
                    decision_ctx,
                    &[RECEIPT_BLOCKED_REASON.to_string()],
                );
                return Err(GateResult::Denied {
                    decision: decision.clone(),
                });
            }
        };

        if let Err(err) = verify_pvgs_receipt(&receipt, &self.receipt_store) {
            let reason_codes = match err {
                VerifyError::UnknownKeyId(_) => vec![RECEIPT_UNKNOWN_KEY_REASON.to_string()],
                _ => vec![RECEIPT_BLOCKED_REASON.to_string()],
            };
            self.note_receipt_issue(ReceiptIssue::Invalid, &reason_codes);
            return Err(self.receipt_gate_error(decision, decision_ctx, &reason_codes, action));
        }

        if ucf::v1::ReceiptStatus::try_from(receipt.status) != Ok(ucf::v1::ReceiptStatus::Accepted)
        {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                decision_ctx,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(receipt.action_digest.as_ref(), &action_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                decision_ctx,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(receipt.decision_digest.as_ref(), &decision.decision_digest) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                decision_ctx,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_matches(
            receipt.profile_digest.as_ref(),
            &decision_ctx.control_frame_digest,
        ) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                decision_ctx,
                &[RECEIPT_BLOCKED_REASON.to_string()],
                action,
            ));
        }

        if !digest_array_matches(
            receipt.tool_profile_digest.as_ref(),
            decision_ctx.tool_profile_digest,
        ) {
            self.note_receipt_issue(ReceiptIssue::Invalid, &[RECEIPT_BLOCKED_REASON.to_string()]);
            return Err(self.receipt_gate_error(
                decision,
                decision_ctx,
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
                    decision_ctx,
                    &[RECEIPT_BLOCKED_REASON.to_string()],
                    action,
                ));
            }
        }

        Ok(())
    }

    fn load_rpp_head_meta(&self) -> Option<RppHeadMeta> {
        let now = Instant::now();
        if let Ok(cache) = self.rpp_cache.lock() {
            if let Some(fetched_at) = cache.fetched_at {
                if now.duration_since(fetched_at) <= RPP_META_CACHE_TTL {
                    return cache.meta;
                }
            }
        }

        let meta = self
            .pvgs_client
            .lock()
            .ok()
            .and_then(|mut client| client.get_latest_rpp_head_meta().ok().flatten());

        if let Ok(mut cache) = self.rpp_cache.lock() {
            cache.fetched_at = Some(now);
            cache.meta = meta;
        }

        meta
    }

    #[allow(clippy::result_large_err)]
    fn enforce_rpp_second_check(
        &self,
        action_type: ucf::v1::ToolActionType,
        decision: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
    ) -> Result<(), GateResult> {
        if !is_side_effect_action(action_type) {
            return Ok(());
        }

        let Some(meta) = decision_ctx.rpp_head_meta else {
            return Err(self.rpp_verification_denied(decision, decision_ctx));
        };

        let Some(payload_digest) = meta.payload_digest else {
            return Err(self.rpp_verification_denied(decision, decision_ctx));
        };

        let inputs = RppCheckInputs {
            prev_acc: meta.prev_acc_digest,
            prev_root: meta.prev_state_root,
            new_root: meta.state_root,
            payload_digest,
            ruleset_digest: meta.ruleset_digest,
            asset_manifest_digest: meta.asset_manifest_digest,
        };

        let result = verify_accumulator(meta.acc_digest, &inputs);
        if result.ok {
            return Ok(());
        }

        self.note_integrity_issue(&result.reason_codes);
        self.deny_with_reasons(decision, decision_ctx, &result.reason_codes);
        Err(GateResult::Denied {
            decision: decision.clone(),
        })
    }

    fn rpp_verification_denied(
        &self,
        decision: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
    ) -> GateResult {
        let reason_codes = rpp_verification_reason_codes();
        self.note_integrity_issue(&reason_codes);
        self.deny_with_reasons(decision, decision_ctx, &reason_codes);
        GateResult::Denied {
            decision: decision.clone(),
        }
    }

    fn note_receipt_issue(&self, issue: ReceiptIssue, reason_codes: &[String]) {
        if let Ok(mut agg) = self.aggregator.lock() {
            agg.on_receipt_issue(issue, reason_codes);
        }
    }

    fn deny_with_reasons(
        &self,
        prior: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
        reason_codes: &[String],
    ) {
        let mut rc = reason_codes.to_vec();
        rc.sort();
        let digest = compute_decision_digest(
            &prior.decision_id,
            &DecisionForm::Deny,
            &rc,
            prior.pev_digest,
            prior.ruleset_digest,
            &decision_ctx.policy_query_digest,
        );

        prior.form = DecisionForm::Deny;
        prior.decision = ucf::v1::PolicyDecision {
            decision: ucf::v1::DecisionForm::Deny.into(),
            reason_codes: Some(ucf::v1::ReasonCodes { codes: rc.clone() }),
            constraints: None,
        };
        prior.policy_query_digest = decision_ctx.policy_query_digest;
        prior.decision_digest = digest;

        update_decision_context(prior, decision_ctx);
    }

    fn receipt_blocked_decision(
        &self,
        prior: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
        reason_codes: &[String],
    ) {
        self.deny_with_reasons(prior, decision_ctx, reason_codes)
    }

    fn receipt_gate_error(
        &self,
        prior: &mut PolicyDecisionRecord,
        decision_ctx: &mut DecisionContext,
        reason_codes: &[String],
        _action: &ucf::v1::ActionSpec,
    ) -> GateResult {
        self.receipt_blocked_decision(prior, decision_ctx, reason_codes);
        GateResult::Denied {
            decision: prior.clone(),
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

fn digest32_to_array(d: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    if d.value.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&d.value);
        Some(arr)
    } else {
        None
    }
}

fn micro_evidence_from_control_frame(control_frame: &ucf::v1::ControlFrame) -> MicroEvidence {
    let mut evidence = MicroEvidence::default();
    for related in &control_frame.evidence_refs {
        match related.id.as_str() {
            "mc:lc" if evidence.lc_digest.is_none() => {
                evidence.lc_digest = related.digest.as_ref().and_then(digest32_to_array);
            }
            "mc:sn" if evidence.sn_digest.is_none() => {
                evidence.sn_digest = related.digest.as_ref().and_then(digest32_to_array);
            }
            "mc_snap:plasticity" if evidence.plasticity_digest.is_none() => {
                evidence.plasticity_digest = related.digest.as_ref().and_then(digest32_to_array);
            }
            _ => {}
        }
    }

    if evidence.is_empty() {
        if let Some(fallback) = test_only_micro_evidence_fallback() {
            evidence = fallback;
        }
    }

    evidence
}

fn microcircuit_config_refs_from_pvgs(
    pvgs_client: &Arc<Mutex<Box<dyn PvgsClientReader>>>,
) -> MicrocircuitConfigRefs {
    let Ok(pvgs) = pvgs_client.lock() else {
        return MicrocircuitConfigRefs::default();
    };

    let lc = pvgs
        .get_microcircuit_config(ucf::v1::MicroModule::Lc)
        .ok()
        .flatten()
        .and_then(|config| config.config_digest.as_ref().and_then(digest32_to_array));
    let sn = pvgs
        .get_microcircuit_config(ucf::v1::MicroModule::Sn)
        .ok()
        .flatten()
        .and_then(|config| config.config_digest.as_ref().and_then(digest32_to_array));

    MicrocircuitConfigRefs {
        lc_digest: lc,
        sn_digest: sn,
    }
}

fn test_only_micro_evidence_fallback() -> Option<MicroEvidence> {
    #[cfg(test)]
    {
        micro_evidence_fallback::read_micro_evidence()
    }
    #[cfg(not(test))]
    {
        // TODO: prefer ControlFrame evidence_refs in production; add EngineSnapshot reader fallback.
        None
    }
}

fn push_related_ref(related_refs: &mut Vec<ucf::v1::RelatedRef>, related_ref: ucf::v1::RelatedRef) {
    if related_refs.len() < MAX_RELATED_REFS {
        related_refs.push(related_ref);
    }
}

fn micro_related_ref(id: &str, digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: id.to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
    }
}

fn append_micro_evidence_refs(related_refs: &mut Vec<ucf::v1::RelatedRef>, micro: MicroEvidence) {
    if let Some(digest) = micro.lc_digest {
        push_related_ref(related_refs, micro_related_ref("mc:lc", digest));
    }
    if let Some(digest) = micro.sn_digest {
        push_related_ref(related_refs, micro_related_ref("mc:sn", digest));
    }
    if let Some(digest) = micro.plasticity_digest {
        push_related_ref(
            related_refs,
            micro_related_ref("mc_snap:plasticity", digest),
        );
    }
}

fn append_microcircuit_config_refs(
    related_refs: &mut Vec<ucf::v1::RelatedRef>,
    micro_configs: MicrocircuitConfigRefs,
) {
    if let Some(digest) = micro_configs.lc_digest {
        push_related_ref(related_refs, micro_related_ref("mc_cfg:lc", digest));
    }
    if let Some(digest) = micro_configs.sn_digest {
        push_related_ref(related_refs, micro_related_ref("mc_cfg:sn", digest));
    }
}

fn append_rpp_refs(related_refs: &mut Vec<ucf::v1::RelatedRef>, rpp_refs: RppEvidenceRefs) {
    if let Some(digest) = rpp_refs.prev_acc_digest {
        push_related_ref(related_refs, rpp_related_ref("rpp:prev_acc", digest));
    }
    if let Some(digest) = rpp_refs.acc_digest {
        push_related_ref(related_refs, rpp_related_ref("rpp:acc", digest));
    }
    if let Some(digest) = rpp_refs.new_root_digest {
        push_related_ref(related_refs, rpp_related_ref("rpp:new_root", digest));
    }
}

fn rpp_related_ref(id: &str, digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: id.to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
    }
}

fn ensure_dlp_decision_digest(decision: &mut ucf::v1::DlpDecision) {
    if let Some(rc) = decision.reason_codes.as_mut() {
        rc.codes.sort();
        rc.codes.dedup();
    }

    if decision.dlp_decision_digest.is_none() {
        let digest = dlp_decision_digest(decision);
        decision.dlp_decision_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
    }
}

fn digest_array_matches(actual: Option<&ucf::v1::Digest32>, expected: Option<[u8; 32]>) -> bool {
    match (actual, expected) {
        (Some(act), Some(exp)) => act.value.as_slice() == exp,
        _ => false,
    }
}

fn update_decision_context(decision: &PolicyDecisionRecord, decision_ctx: &mut DecisionContext) {
    decision_ctx.policy_decision = decision.decision.clone();
    decision_ctx.decision_digest = decision.decision_digest;
    decision_ctx.ruleset_digest = decision.ruleset_digest;
    decision_ctx.commit_disposition = DecisionCommitDisposition::CommitRequired;
    decision_ctx.receipt_digest = None;
}

#[allow(clippy::too_many_arguments)]
fn build_decision_record(
    decision: &PolicyDecisionRecord,
    decision_ctx: &DecisionContext,
) -> ucf::v1::ExperienceRecord {
    let mut reason_codes = decision
        .decision
        .reason_codes
        .as_ref()
        .map(|rc| rc.codes.clone())
        .unwrap_or_default();
    reason_codes.sort();
    reason_codes.dedup();

    let governance_frame = ucf::v1::GovernanceFrame {
        policy_decision_refs: vec![ucf::v1::Digest32 {
            value: decision_ctx.decision_digest.to_vec(),
        }],
        grant_refs: Vec::new(),
        dlp_refs: Vec::new(),
        budget_snapshot_ref: None,
        pvgs_receipt_ref: None,
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: reason_codes,
        }),
    };

    let governance_frame_ref =
        digest_proto(GOVERNANCE_FRAME_DOMAIN, &canonical_bytes(&governance_frame));

    let mut related_refs = vec![policy_query_related_ref(decision_ctx.policy_query_digest)];
    push_related_ref(
        &mut related_refs,
        ucf::v1::RelatedRef {
            id: POLICY_DECISION_REF.to_string(),
            digest: Some(ucf::v1::Digest32 {
                value: decision_ctx.decision_digest.to_vec(),
            }),
        },
    );
    if let Some(ruleset_digest) = decision.ruleset_digest {
        push_related_ref(
            &mut related_refs,
            ucf::v1::RelatedRef {
                id: "ruleset".to_string(),
                digest: Some(ucf::v1::Digest32 {
                    value: ruleset_digest.to_vec(),
                }),
            },
        );
    }
    append_rpp_refs(&mut related_refs, decision_ctx.rpp_refs);
    append_micro_evidence_refs(&mut related_refs, decision_ctx.micro_evidence);
    append_microcircuit_config_refs(&mut related_refs, decision_ctx.microcircuit_config_refs);

    ucf::v1::ExperienceRecord {
        record_type: ucf::v1::RecordType::Decision.into(),
        core_frame: None,
        metabolic_frame: None,
        governance_frame: Some(governance_frame),
        core_frame_ref: None,
        metabolic_frame_ref: None,
        governance_frame_ref: Some(ucf::v1::Digest32 {
            value: governance_frame_ref.to_vec(),
        }),
        related_refs,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_action_exec_record(
    _action: &ucf::v1::ActionSpec,
    action_digest: [u8; 32],
    decision: &PolicyDecisionRecord,
    outcome: &ucf::v1::OutcomePacket,
    control_frame: &ucf::v1::ControlFrame,
    ctx: &GateContext,
    decision_ctx: &DecisionContext,
) -> ucf::v1::ExperienceRecord {
    let core_frame = build_core_frame(decision_ctx, action_digest);
    let metabolic_frame = build_metabolic_frame(control_frame, &decision_ctx.control_frame_digest);
    let governance_frame = build_governance_frame(decision, decision_ctx, outcome, ctx);

    let core_frame_ref = digest_proto(CORE_FRAME_DOMAIN, &canonical_bytes(&core_frame));
    let metabolic_frame_ref =
        digest_proto(METABOLIC_FRAME_DOMAIN, &canonical_bytes(&metabolic_frame));
    let governance_frame_ref =
        digest_proto(GOVERNANCE_FRAME_DOMAIN, &canonical_bytes(&governance_frame));
    let mut related_refs = vec![policy_query_related_ref(decision_ctx.policy_query_digest)];
    push_related_ref(
        &mut related_refs,
        decision_related_ref(decision_ctx.decision_digest),
    );
    if let Some(ruleset_digest) = decision_ctx.ruleset_digest {
        push_related_ref(&mut related_refs, ruleset_related_ref(ruleset_digest));
    }
    append_rpp_refs(&mut related_refs, decision_ctx.rpp_refs);
    append_micro_evidence_refs(&mut related_refs, decision_ctx.micro_evidence);
    append_microcircuit_config_refs(&mut related_refs, decision_ctx.microcircuit_config_refs);
    if let Some(receipt_digest) = decision_ctx.receipt_digest {
        push_related_ref(
            &mut related_refs,
            decision_receipt_related_ref(receipt_digest),
        );
    }

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
        related_refs,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_output_record(
    session_id: &str,
    step_id: &str,
    artifact_digest: [u8; 32],
    dlp_decision: &ucf::v1::DlpDecision,
    control_frame: &ucf::v1::ControlFrame,
    control_frame_digest: &[u8; 32],
    policy_query_digest: Option<[u8; 32]>,
    decision_digest: Option<[u8; 32]>,
    ruleset_digest: Option<[u8; 32]>,
) -> ucf::v1::ExperienceRecord {
    let core_frame = ucf::v1::CoreFrame {
        session_id: session_id.to_string(),
        step_id: step_id.to_string(),
        input_packet_refs: Vec::new(),
        intent_refs: Vec::new(),
        candidate_refs: vec![ucf::v1::Digest32 {
            value: artifact_digest.to_vec(),
        }],
        workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
    };

    let metabolic_frame = build_metabolic_frame(control_frame, control_frame_digest);
    let governance_frame = build_output_governance_frame(dlp_decision);

    let core_frame_ref = digest_proto(CORE_FRAME_DOMAIN, &canonical_bytes(&core_frame));
    let metabolic_frame_ref =
        digest_proto(METABOLIC_FRAME_DOMAIN, &canonical_bytes(&metabolic_frame));
    let governance_frame_ref =
        digest_proto(GOVERNANCE_FRAME_DOMAIN, &canonical_bytes(&governance_frame));

    let mut related_refs = Vec::new();
    related_refs.push(output_artifact_related_ref(artifact_digest));

    if let Some(dlp_digest) = dlp_decision
        .dlp_decision_digest
        .as_ref()
        .and_then(digest32_to_array)
    {
        related_refs.push(dlp_decision_related_ref(dlp_digest));
    }

    if let Some(digest) = policy_query_digest {
        related_refs.push(policy_query_related_ref(digest));
    }

    if let Some(digest) = decision_digest {
        related_refs.push(decision_related_ref(digest));
    }

    if let Some(digest) = ruleset_digest {
        related_refs.push(ruleset_related_ref(digest));
    }

    ucf::v1::ExperienceRecord {
        record_type: ucf::v1::RecordType::Output.into(),
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
        related_refs,
    }
}

fn build_core_frame(decision_ctx: &DecisionContext, action_digest: [u8; 32]) -> ucf::v1::CoreFrame {
    ucf::v1::CoreFrame {
        session_id: decision_ctx.session_id.to_string(),
        step_id: decision_ctx.step_id.to_string(),
        input_packet_refs: Vec::new(),
        intent_refs: Vec::new(),
        candidate_refs: vec![ucf::v1::Digest32 {
            value: action_digest.to_vec(),
        }],
        workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
    }
}

fn build_metabolic_frame(
    control_frame: &ucf::v1::ControlFrame,
    control_frame_digest: &[u8; 32],
) -> ucf::v1::MetabolicFrame {
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
    decision_ctx: &DecisionContext,
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
            value: decision_ctx.decision_digest.to_vec(),
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

fn build_output_governance_frame(dlp_decision: &ucf::v1::DlpDecision) -> ucf::v1::GovernanceFrame {
    let mut dlp_refs = Vec::new();
    if let Some(digest) = dlp_decision
        .dlp_decision_digest
        .as_ref()
        .and_then(digest32_to_array)
    {
        dlp_refs.push(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
    }

    let mut reason_codes = dlp_decision
        .reason_codes
        .as_ref()
        .map(|rc| rc.codes.clone())
        .unwrap_or_default();
    reason_codes.sort();
    reason_codes.dedup();

    ucf::v1::GovernanceFrame {
        policy_decision_refs: Vec::new(),
        grant_refs: Vec::new(),
        dlp_refs,
        budget_snapshot_ref: None,
        pvgs_receipt_ref: None,
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

fn decision_related_ref(decision_digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "decision".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: decision_digest.to_vec(),
        }),
    }
}

fn ruleset_related_ref(ruleset_digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "ruleset".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: ruleset_digest.to_vec(),
        }),
    }
}

fn policy_query_related_ref(policy_query_digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "policy_query".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: policy_query_digest.to_vec(),
        }),
    }
}

fn output_artifact_related_ref(digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "output_artifact".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
    }
}

fn dlp_decision_related_ref(digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "dlp_decision".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
    }
}

fn decision_receipt_related_ref(receipt_digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: "decision_record_receipt".to_string(),
        digest: Some(ucf::v1::Digest32 {
            value: receipt_digest.to_vec(),
        }),
    }
}

fn map_decision_digest(
    decision: &PolicyDecisionRecord,
    decision_ctx: &DecisionContext,
) -> [u8; 32] {
    let mut reason_codes = decision
        .decision
        .reason_codes
        .as_ref()
        .map(|rc| rc.codes.clone())
        .unwrap_or_default();
    reason_codes.sort();

    compute_decision_digest(
        &hex::encode(decision_ctx.policy_query_digest),
        &decision.form,
        &reason_codes,
        decision.pev_digest,
        decision.ruleset_digest,
        &decision_ctx.policy_query_digest,
    )
}

fn requires_receipt(action_type: ucf::v1::ToolActionType) -> bool {
    matches!(
        action_type,
        ucf::v1::ToolActionType::Write
            | ucf::v1::ToolActionType::Execute
            | ucf::v1::ToolActionType::Export
    )
}

fn is_side_effect_action(action_type: ucf::v1::ToolActionType) -> bool {
    matches!(
        action_type,
        ucf::v1::ToolActionType::Write
            | ucf::v1::ToolActionType::Execute
            | ucf::v1::ToolActionType::Export
    )
}

fn rpp_verification_reason_codes() -> Vec<String> {
    let mut codes = vec![
        PVGS_INTEGRITY_REASON.to_string(),
        RPP_VERIFY_FAIL_REASON.to_string(),
    ];
    codes.sort();
    codes
}

#[cfg(test)]
mod micro_evidence_fallback {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    pub struct EngineSnapshot {
        pub lc_digest: Option<[u8; 32]>,
        pub sn_digest: Option<[u8; 32]>,
        pub plasticity_digest: Option<[u8; 32]>,
    }

    pub trait Chip2Reader: Send + Sync {
        fn get_engine_snapshot(&self) -> Option<EngineSnapshot>;
    }

    #[derive(Default)]
    pub struct TestChip2Reader;

    static SNAPSHOT: Mutex<Option<EngineSnapshot>> = Mutex::new(None);

    impl TestChip2Reader {
        pub fn set_snapshot(snapshot: Option<EngineSnapshot>) {
            *SNAPSHOT.lock().expect("engine snapshot lock") = snapshot;
        }
    }

    impl Chip2Reader for TestChip2Reader {
        fn get_engine_snapshot(&self) -> Option<EngineSnapshot> {
            SNAPSHOT.lock().expect("engine snapshot lock").clone()
        }
    }

    pub fn read_micro_evidence() -> Option<MicroEvidence> {
        let reader = TestChip2Reader;
        let snapshot = reader.get_engine_snapshot()?;
        Some(MicroEvidence {
            lc_digest: snapshot.lc_digest,
            sn_digest: snapshot.sn_digest,
            plasticity_digest: snapshot.plasticity_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pbm::policy_query_digest;
    use pvgs_client::{MockPvgsClient, PvgsClient, PvgsReader};
    use pvgs_verify::{
        pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
    };
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use tam::MockAdapter;

    type LocalClientHandle = Arc<Mutex<pvgs_client::LocalPvgsClient>>;
    type PvgsClientHandle = Arc<Mutex<Box<dyn PvgsClientReader>>>;

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
    struct CountingPvgsClient {
        inner: Arc<Mutex<pvgs_client::LocalPvgsClient>>,
        decision_counts: Arc<Mutex<HashMap<[u8; 32], usize>>>,
        call_order: Arc<Mutex<Vec<&'static str>>>,
        rpp_head_calls: Arc<Mutex<u64>>,
    }

    impl CountingPvgsClient {
        fn new(inner: pvgs_client::LocalPvgsClient) -> Self {
            Self {
                inner: Arc::new(Mutex::new(inner)),
                decision_counts: Arc::new(Mutex::new(HashMap::new())),
                call_order: Arc::new(Mutex::new(Vec::new())),
                rpp_head_calls: Arc::new(Mutex::new(0)),
            }
        }

        fn decision_commits(&self, digest: [u8; 32]) -> usize {
            *self
                .decision_counts
                .lock()
                .expect("decision count lock")
                .get(&digest)
                .unwrap_or(&0)
        }

        fn calls(&self) -> Vec<String> {
            self.call_order
                .lock()
                .expect("call order lock")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }

        fn rpp_head_query_count(&self) -> u64 {
            *self.rpp_head_calls.lock().expect("rpp head count lock")
        }
    }

    impl PvgsClient for CountingPvgsClient {
        fn commit_experience_record(
            &mut self,
            record: ucf::v1::ExperienceRecord,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.call_order
                .lock()
                .expect("call order lock")
                .push("commit_experience_record");

            if ucf::v1::RecordType::try_from(record.record_type)
                == Ok(ucf::v1::RecordType::Decision)
            {
                if let Some(digest) = record
                    .governance_frame
                    .as_ref()
                    .and_then(|g| g.policy_decision_refs.first())
                    .and_then(digest32_to_array)
                {
                    let mut guard = self.decision_counts.lock().expect("decision count lock");
                    *guard.entry(digest).or_insert(0) += 1;
                }
            }

            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_experience_record(record)
        }

        fn commit_dlp_decision(
            &mut self,
            dlp: ucf::v1::DlpDecision,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.call_order
                .lock()
                .expect("call order lock")
                .push("commit_dlp_decision");

            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_dlp_decision(dlp)
        }

        fn commit_tool_registry(
            &mut self,
            trc: ucf::v1::ToolRegistryContainer,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_registry(trc)
        }

        fn commit_tool_onboarding_event(
            &mut self,
            event: ucf::v1::ToolOnboardingEvent,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_onboarding_event(event)
        }

        fn commit_micro_milestone(
            &mut self,
            micro: ucf::v1::MicroMilestone,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.call_order
                .lock()
                .expect("call order lock")
                .push("commit_micro_milestone");

            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_micro_milestone(micro)
        }

        fn commit_consistency_feedback(
            &mut self,
            feedback: ucf::v1::ConsistencyFeedback,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.call_order
                .lock()
                .expect("call order lock")
                .push("commit_consistency_feedback");

            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_consistency_feedback(feedback)
        }

        fn try_commit_next_micro(
            &mut self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_macro(
            &mut self,
            _consistency_digest: Option<[u8; 32]>,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn get_pending_replay_plans(
            &mut self,
            _session_id: &str,
        ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
            Ok(Vec::new())
        }

        fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
            self.inner.lock().expect("pvgs client lock").get_pvgs_head()
        }
    }

    impl PvgsReader for CountingPvgsClient {
        fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev()
        }

        fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev_digest()
        }

        fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_current_ruleset_digest()
        }

        fn get_recovery_state(
            &self,
            session_id: &str,
        ) -> Result<Option<String>, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_recovery_state(session_id)
        }

        fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_cbv_digest()
        }

        fn get_latest_rpp_head_meta(
            &mut self,
        ) -> Result<Option<pvgs_client::RppHeadMeta>, pvgs_client::PvgsClientError> {
            let mut guard = self.rpp_head_calls.lock().expect("rpp head count lock");
            *guard += 1;
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_rpp_head_meta()
        }

        fn get_rpp_head_meta(
            &mut self,
            head_id: u64,
        ) -> Result<Option<pvgs_client::RppHeadMeta>, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_rpp_head_meta(head_id)
        }

        fn is_session_sealed(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .is_session_sealed(session_id)
        }

        fn has_unlock_permit(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .has_unlock_permit(session_id)
        }

        fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_session_seal_digest(session_id)
        }
    }

    #[derive(Clone, Default)]
    struct RecordRejectingPvgsClient {
        inner: Arc<Mutex<pvgs_client::LocalPvgsClient>>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl RecordRejectingPvgsClient {
        fn new(inner: pvgs_client::LocalPvgsClient) -> Self {
            Self {
                inner: Arc::new(Mutex::new(inner)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .expect("call order lock")
                .iter()
                .map(|c| c.to_string())
                .collect()
        }
    }

    impl PvgsClient for RecordRejectingPvgsClient {
        fn commit_experience_record(
            &mut self,
            _record: ucf::v1::ExperienceRecord,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.calls
                .lock()
                .expect("call order lock")
                .push("commit_experience_record");
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "record rejected".to_string(),
            ))
        }

        fn commit_dlp_decision(
            &mut self,
            dlp: ucf::v1::DlpDecision,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.calls
                .lock()
                .expect("call order lock")
                .push("commit_dlp_decision");
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_dlp_decision(dlp)
        }

        fn commit_tool_registry(
            &mut self,
            trc: ucf::v1::ToolRegistryContainer,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_registry(trc)
        }

        fn commit_tool_onboarding_event(
            &mut self,
            event: ucf::v1::ToolOnboardingEvent,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_onboarding_event(event)
        }

        fn commit_micro_milestone(
            &mut self,
            _micro: ucf::v1::MicroMilestone,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.calls
                .lock()
                .expect("call order lock")
                .push("commit_micro_milestone");
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "record rejected".to_string(),
            ))
        }

        fn commit_consistency_feedback(
            &mut self,
            feedback: ucf::v1::ConsistencyFeedback,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.calls
                .lock()
                .expect("call order lock")
                .push("commit_consistency_feedback");
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_consistency_feedback(feedback)
        }

        fn try_commit_next_micro(
            &mut self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_macro(
            &mut self,
            _consistency_digest: Option<[u8; 32]>,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn get_pending_replay_plans(
            &mut self,
            _session_id: &str,
        ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
            Ok(Vec::new())
        }

        fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
            self.inner.lock().expect("pvgs client lock").get_pvgs_head()
        }
    }

    impl PvgsReader for RecordRejectingPvgsClient {
        fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev()
        }

        fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev_digest()
        }

        fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_current_ruleset_digest()
        }

        fn get_recovery_state(
            &self,
            session_id: &str,
        ) -> Result<Option<String>, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_recovery_state(session_id)
        }

        fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_cbv_digest()
        }

        fn is_session_sealed(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .is_session_sealed(session_id)
        }

        fn has_unlock_permit(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .has_unlock_permit(session_id)
        }

        fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_session_seal_digest(session_id)
        }
    }

    #[derive(Clone, Default)]
    struct FailingPvgsClient;

    impl PvgsClient for FailingPvgsClient {
        fn commit_experience_record(
            &mut self,
            _record: ucf::v1::ExperienceRecord,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn commit_dlp_decision(
            &mut self,
            _dlp: ucf::v1::DlpDecision,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn commit_tool_registry(
            &mut self,
            _trc: ucf::v1::ToolRegistryContainer,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn commit_tool_onboarding_event(
            &mut self,
            _event: ucf::v1::ToolOnboardingEvent,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn commit_micro_milestone(
            &mut self,
            _micro: ucf::v1::MicroMilestone,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn commit_consistency_feedback(
            &mut self,
            _feedback: ucf::v1::ConsistencyFeedback,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn try_commit_next_micro(
            &mut self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn try_commit_next_macro(
            &mut self,
            _consistency_digest: Option<[u8; 32]>,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "forced failure".to_string(),
            ))
        }

        fn get_pending_replay_plans(
            &mut self,
            _session_id: &str,
        ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
            Ok(Vec::new())
        }

        fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
            pvgs_client::PvgsHead {
                head_experience_id: 0,
                head_record_digest: [0u8; 32],
            }
        }
    }

    impl PvgsReader for FailingPvgsClient {
        fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
            None
        }

        fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
            None
        }

        fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
            None
        }

        fn get_recovery_state(
            &self,
            _session_id: &str,
        ) -> Result<Option<String>, pvgs_client::PvgsClientError> {
            Ok(None)
        }

        fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
            None
        }

        fn is_session_sealed(
            &self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn has_unlock_permit(
            &self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
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

        fn commit_dlp_decision(
            &mut self,
            dlp: ucf::v1::DlpDecision,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_dlp_decision(dlp)
        }

        fn commit_tool_registry(
            &mut self,
            trc: ucf::v1::ToolRegistryContainer,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_registry(trc)
        }

        fn commit_tool_onboarding_event(
            &mut self,
            event: ucf::v1::ToolOnboardingEvent,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_tool_onboarding_event(event)
        }

        fn commit_micro_milestone(
            &mut self,
            micro: ucf::v1::MicroMilestone,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_micro_milestone(micro)
        }

        fn commit_consistency_feedback(
            &mut self,
            feedback: ucf::v1::ConsistencyFeedback,
        ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .commit_consistency_feedback(feedback)
        }

        fn try_commit_next_micro(
            &mut self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_macro(
            &mut self,
            _consistency_digest: Option<[u8; 32]>,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn get_pending_replay_plans(
            &mut self,
            _session_id: &str,
        ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
            Ok(Vec::new())
        }

        fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
            self.inner.lock().expect("pvgs client lock").get_pvgs_head()
        }
    }

    impl PvgsReader for SharedLocalClient {
        fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev()
        }

        fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_pev_digest()
        }

        fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_current_ruleset_digest()
        }

        fn get_recovery_state(
            &self,
            session_id: &str,
        ) -> Result<Option<String>, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_recovery_state(session_id)
        }

        fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_latest_cbv_digest()
        }

        fn is_session_sealed(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .is_session_sealed(session_id)
        }

        fn has_unlock_permit(
            &self,
            session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .has_unlock_permit(session_id)
        }

        fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
            self.inner
                .lock()
                .expect("pvgs client lock")
                .get_session_seal_digest(session_id)
        }
    }

    fn default_aggregator() -> Arc<Mutex<WindowEngine>> {
        Arc::new(Mutex::new(
            WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
        ))
    }

    fn default_decision_log() -> Arc<Mutex<DecisionLogStore>> {
        Arc::new(Mutex::new(DecisionLogStore::default()))
    }

    fn default_query_map() -> Arc<Mutex<QueryDecisionMap>> {
        Arc::new(Mutex::new(QueryDecisionMap::default()))
    }

    #[test]
    fn query_decision_map_allows_matching_inserts() {
        let mut map = QueryDecisionMap::default();
        let policy_query_digest = [1u8; 32];
        let decision_digest = [2u8; 32];

        assert!(map.insert(policy_query_digest, decision_digest).is_ok());
        assert!(map.insert(policy_query_digest, decision_digest).is_ok());
        assert_eq!(map.lookup(policy_query_digest), Some(decision_digest));
    }

    fn default_pvgs_client() -> PvgsClientHandle {
        Arc::new(Mutex::new(
            Box::new(MockPvgsClient::default()) as Box<dyn PvgsClientReader>
        ))
    }

    fn integrity_counter() -> Arc<Mutex<u64>> {
        Arc::new(Mutex::new(0))
    }

    fn boxed_client(client: impl PvgsClientReader + 'static) -> PvgsClientHandle {
        Arc::new(Mutex::new(Box::new(client) as Box<dyn PvgsClientReader>))
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
            default_decision_log(),
            default_query_map(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn gate_with_components(
        adapter: Box<dyn ToolAdapter>,
        store: Arc<Mutex<ControlFrameStore>>,
        receipt_store: Arc<PvgsKeyEpochStore>,
        aggregator: Arc<Mutex<WindowEngine>>,
        registry: Arc<ToolRegistry>,
        pvgs_client: PvgsClientHandle,
        integrity_issues: Arc<Mutex<u64>>,
        decision_log: Arc<Mutex<DecisionLogStore>>,
        query_decisions: Arc<Mutex<QueryDecisionMap>>,
    ) -> Gate {
        let orchestrator = Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
            aggregator.clone(),
        )));
        Gate {
            policy: PolicyEngine::new(),
            adapter,
            aggregator,
            orchestrator,
            control_store: store,
            receipt_store,
            registry,
            pvgs_client,
            integrity_issues,
            decision_log,
            query_decisions,
            rpp_cache: Arc::new(Mutex::new(RppMetaCache::default())),
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
            evidence_refs: Vec::new(),
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
            evidence_refs: Vec::new(),
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
            evidence_refs: Vec::new(),
        }
    }

    fn control_frame_with_micro_evidence(
        lc_digest: Option<[u8; 32]>,
        sn_digest: Option<[u8; 32]>,
        plasticity_digest: Option<[u8; 32]>,
    ) -> ucf::v1::ControlFrame {
        let mut frame = control_frame_open();
        let mut refs = Vec::new();
        if let Some(digest) = lc_digest {
            refs.push(micro_related_ref("mc:lc", digest));
        }
        if let Some(digest) = sn_digest {
            refs.push(micro_related_ref("mc:sn", digest));
        }
        if let Some(digest) = plasticity_digest {
            refs.push(micro_related_ref("mc_snap:plasticity", digest));
        }
        frame.evidence_refs = refs;
        frame
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
            pev: None,
            pev_digest: None,
            ruleset_digest: None,
            session_sealed: false,
            session_unlock_permit: false,
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
            pev: ctx.pev.clone(),
            pev_digest: ctx.pev_digest,
            ruleset_digest: ctx.ruleset_digest,
            session_sealed: ctx.session_sealed,
            unlock_present: ctx.session_unlock_permit,
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

    fn rpp_meta_fixture() -> pvgs_client::RppHeadMeta {
        let inputs = RppCheckInputs {
            prev_acc: [1u8; 32],
            prev_root: [2u8; 32],
            new_root: [3u8; 32],
            payload_digest: [4u8; 32],
            ruleset_digest: [5u8; 32],
            asset_manifest_digest: None,
        };
        let acc_digest = rpp_checker::compute_accumulator_digest(&inputs);
        pvgs_client::RppHeadMeta {
            head_id: 7,
            head_record_digest: [9u8; 32],
            prev_state_root: inputs.prev_root,
            state_root: inputs.new_root,
            prev_acc_digest: inputs.prev_acc,
            acc_digest,
            ruleset_digest: inputs.ruleset_digest,
            asset_manifest_digest: inputs.asset_manifest_digest,
            payload_digest: Some(inputs.payload_digest),
        }
    }

    fn signed_receipt_for_action(
        gate: &Gate,
        action: &ucf::v1::ActionSpec,
        ctx: &GateContext,
        session_id: &str,
        step_id: &str,
        signer: &SigningKey,
        key_id: &str,
    ) -> ucf::v1::PvgsReceipt {
        let decision = policy_decision_for(gate, action, ctx, session_id, step_id);
        let action_digest = compute_action_digest(action);
        let (tool_id, action_id) = parse_tool_and_action(action);
        let tool_profile_digest = gate
            .registry
            .get(&tool_id, &action_id)
            .and_then(|tap| tap.profile_digest.as_ref())
            .expect("tool profile digest");

        signed_receipt_for(
            action_digest,
            decision.decision_digest,
            signer,
            key_id,
            &open_control_frame_digest(),
            tool_profile_digest,
        )
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
    fn suspended_tools_are_denied_before_execution() {
        let counting = CountingAdapter::default();
        let mut registry = trm::registry_fixture();
        registry.suspend("mock.read", "get");
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(registry),
            default_pvgs_client(),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![TOOL_SUSPENDED_REASON.to_string()]
                );
            }
            other => panic!("unexpected gate result: {other:?}"),
        }

        assert_eq!(
            counting.count(),
            0,
            "adapter must not run for suspended tools"
        );
    }

    #[test]
    fn suspended_denials_surface_in_signal_frames() {
        let counting = CountingAdapter::default();
        let mut registry = trm::registry_fixture();
        registry.suspend("mock.read", "get");
        let aggregator = default_aggregator();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(registry),
            default_pvgs_client(),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![TOOL_SUSPENDED_REASON.to_string()]
                );
            }
            other => panic!("unexpected gate result: {other:?}"),
        }

        assert_eq!(
            counting.count(),
            0,
            "adapter must not run for suspended tools"
        );

        let top_codes: Vec<_> = aggregator
            .lock()
            .expect("agg lock")
            .force_flush()
            .first()
            .and_then(|f| f.policy_stats.as_ref())
            .map(|stats| stats.top_reason_codes.clone())
            .unwrap_or_default();

        assert!(top_codes
            .iter()
            .any(|code| code.code == TOOL_SUSPENDED_REASON));
    }

    #[test]
    fn replay_mismatch_blocks_execution_and_degrades_integrity() {
        let counting = CountingAdapter::default();
        let gate = gate_with_adapter(Box::new(counting.clone()));
        let ctx = ok_ctx();
        let action = base_action("mock.read", "get");

        let decision = policy_decision_for(&gate, &action, &ctx, "s", "step");
        {
            let mut map = gate.query_decisions.lock().expect("query map lock");
            map.insert(decision.policy_query_digest, [99u8; 32])
                .expect("initial insert");
        }

        let result = gate.handle_action_spec("s", "step", action, ctx);

        match result {
            GateResult::Denied { decision } => {
                let reason_codes = decision.decision.reason_codes.expect("reason codes").codes;
                assert_eq!(reason_codes, vec![REPLAY_MISMATCH_REASON.to_string()]);
            }
            other => panic!("unexpected gate result: {other:?}"),
        }

        assert_eq!(counting.count(), 0, "adapter must not run on mismatch");
        assert_eq!(*gate.integrity_issues.lock().expect("integrity counter"), 1);
    }

    #[test]
    fn decision_record_committed_on_deny() {
        let counting = CountingAdapter::default();
        let (local, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let mut ctx = ok_ctx();
        ctx.integrity_state = "FAIL".to_string();
        let result = gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ctx);

        assert!(matches!(result, GateResult::Denied { .. }));
        assert_eq!(counting.count(), 0);

        let records = local
            .lock()
            .expect("pvgs local client")
            .committed_records
            .clone();
        assert_eq!(records.len(), 1);

        let record = &records[0];
        assert_eq!(
            ucf::v1::RecordType::try_from(record.record_type),
            Ok(ucf::v1::RecordType::Decision)
        );
        let related_ids: Vec<_> = record.related_refs.iter().map(|r| r.id.clone()).collect();
        assert_eq!(related_ids[0], "policy_query");
        assert_eq!(related_ids[1], POLICY_DECISION_REF);
        let rpp_ids: Vec<_> = record
            .related_refs
            .iter()
            .filter(|r| r.id.starts_with("rpp:"))
            .map(|r| r.id.as_str())
            .collect();
        if !rpp_ids.is_empty() {
            assert_eq!(rpp_ids, vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]);
        }

        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };
        let expected_digest = policy_query_digest(&policy_query);
        let policy_query_ref = record
            .related_refs
            .iter()
            .find(|r| r.id == "policy_query")
            .and_then(|r| r.digest.as_ref())
            .expect("policy query ref present");

        assert_eq!(policy_query_ref.value, expected_digest.to_vec());
    }

    #[test]
    fn related_refs_are_deterministic() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);
        let decision_digest = [2u8; 32];
        let ruleset_digest = Some([3u8; 32]);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest,
            pev_digest: None,
            ruleset_digest,
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest,
            ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: Some([4u8; 32]),
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: MicroEvidence::default(),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let decision_record = build_decision_record(&decision, &decision_ctx);
        let decision_ids: Vec<_> = decision_record
            .related_refs
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(
            decision_ids,
            vec![
                "policy_query".to_string(),
                POLICY_DECISION_REF.to_string(),
                "ruleset".to_string(),
            ]
        );

        let action_record = build_action_exec_record(
            &base_action("mock.read", "get"),
            [7u8; 32],
            &decision,
            &ucf::v1::OutcomePacket {
                outcome_id: "oid".to_string(),
                request_id: "sid:step".to_string(),
                status: ucf::v1::OutcomeStatus::Success.into(),
                payload: Vec::new(),
                payload_digest: None,
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            &control_frame_open(),
            &ok_ctx(),
            &decision_ctx,
        );

        let action_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(
            action_ids,
            vec![
                "policy_query".to_string(),
                "decision".to_string(),
                "ruleset".to_string(),
                "decision_record_receipt".to_string(),
            ]
        );
    }

    #[test]
    fn decision_record_includes_micro_refs() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };
        let policy_query_digest = policy_query_digest(&policy_query);
        let decision_digest = [2u8; 32];
        let ruleset_digest = Some([3u8; 32]);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest,
            pev_digest: None,
            ruleset_digest,
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let control_frame =
            control_frame_with_micro_evidence(Some([11u8; 32]), Some([12u8; 32]), Some([13u8; 32]));
        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest,
            ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: micro_evidence_from_control_frame(&control_frame),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let decision_record = build_decision_record(&decision, &decision_ctx);
        let decision_ids: Vec<_> = decision_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            decision_ids,
            vec![
                "policy_query",
                POLICY_DECISION_REF,
                "ruleset",
                "mc:lc",
                "mc:sn",
                "mc_snap:plasticity",
            ]
        );

        let lc_ref = decision_record
            .related_refs
            .iter()
            .find(|r| r.id == "mc:lc")
            .and_then(|r| r.digest.as_ref())
            .expect("mc:lc related ref");
        assert_eq!(lc_ref.value, vec![11u8; 32]);

        let sn_ref = decision_record
            .related_refs
            .iter()
            .find(|r| r.id == "mc:sn")
            .and_then(|r| r.digest.as_ref())
            .expect("mc:sn related ref");
        assert_eq!(sn_ref.value, vec![12u8; 32]);

        let plasticity_ref = decision_record
            .related_refs
            .iter()
            .find(|r| r.id == "mc_snap:plasticity")
            .and_then(|r| r.digest.as_ref())
            .expect("mc_snap:plasticity related ref");
        assert_eq!(plasticity_ref.value, vec![13u8; 32]);
    }

    #[test]
    fn decision_record_includes_microcircuit_config_refs_in_order() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };
        let policy_query_digest = policy_query_digest(&policy_query);
        let decision_digest = [2u8; 32];
        let ruleset_digest = Some([3u8; 32]);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest,
            pev_digest: None,
            ruleset_digest,
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest,
            ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: MicroEvidence {
                lc_digest: Some([11u8; 32]),
                sn_digest: Some([12u8; 32]),
                plasticity_digest: Some([13u8; 32]),
            },
            microcircuit_config_refs: MicrocircuitConfigRefs {
                lc_digest: Some([21u8; 32]),
                sn_digest: Some([22u8; 32]),
            },
        };

        let decision_record = build_decision_record(&decision, &decision_ctx);
        let decision_ids: Vec<_> = decision_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            decision_ids,
            vec![
                "policy_query",
                POLICY_DECISION_REF,
                "ruleset",
                "mc:lc",
                "mc:sn",
                "mc_snap:plasticity",
                "mc_cfg:lc",
                "mc_cfg:sn",
            ]
        );

        let action_record = build_action_exec_record(
            &base_action("mock.read", "get"),
            [7u8; 32],
            &decision,
            &ucf::v1::OutcomePacket {
                outcome_id: "oid".to_string(),
                request_id: "sid:step".to_string(),
                status: ucf::v1::OutcomeStatus::Success.into(),
                payload: Vec::new(),
                payload_digest: None,
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            &control_frame_open(),
            &ok_ctx(),
            &decision_ctx,
        );

        let action_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            action_ids,
            vec![
                "policy_query",
                "decision",
                "ruleset",
                "mc:lc",
                "mc:sn",
                "mc_snap:plasticity",
                "mc_cfg:lc",
                "mc_cfg:sn",
            ]
        );
    }

    #[test]
    fn action_exec_record_includes_micro_refs() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);
        let decision_digest = [2u8; 32];
        let ruleset_digest = Some([3u8; 32]);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest,
            pev_digest: None,
            ruleset_digest,
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let control_frame =
            control_frame_with_micro_evidence(Some([11u8; 32]), Some([12u8; 32]), Some([13u8; 32]));
        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest,
            ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: Some([4u8; 32]),
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: micro_evidence_from_control_frame(&control_frame),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let action_record = build_action_exec_record(
            &base_action("mock.read", "get"),
            [7u8; 32],
            &decision,
            &ucf::v1::OutcomePacket {
                outcome_id: "oid".to_string(),
                request_id: "sid:step".to_string(),
                status: ucf::v1::OutcomeStatus::Success.into(),
                payload: Vec::new(),
                payload_digest: None,
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            &control_frame_open(),
            &ok_ctx(),
            &decision_ctx,
        );

        let action_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            action_ids,
            vec![
                "policy_query",
                "decision",
                "ruleset",
                "mc:lc",
                "mc:sn",
                "mc_snap:plasticity",
                "decision_record_receipt",
            ]
        );
    }

    #[test]
    fn action_exec_record_caps_related_refs_after_micro_config() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);
        let decision_digest = [2u8; 32];
        let ruleset_digest = Some([3u8; 32]);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest,
            pev_digest: None,
            ruleset_digest,
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest,
            ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: Some([4u8; 32]),
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: MicroEvidence {
                lc_digest: Some([11u8; 32]),
                sn_digest: Some([12u8; 32]),
                plasticity_digest: Some([13u8; 32]),
            },
            microcircuit_config_refs: MicrocircuitConfigRefs {
                lc_digest: Some([21u8; 32]),
                sn_digest: Some([22u8; 32]),
            },
        };

        let action_record = build_action_exec_record(
            &base_action("mock.read", "get"),
            [7u8; 32],
            &decision,
            &ucf::v1::OutcomePacket {
                outcome_id: "oid".to_string(),
                request_id: "sid:step".to_string(),
                status: ucf::v1::OutcomeStatus::Success.into(),
                payload: Vec::new(),
                payload_digest: None,
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            &control_frame_open(),
            &ok_ctx(),
            &decision_ctx,
        );

        let action_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();

        assert_eq!(action_record.related_refs.len(), MAX_RELATED_REFS);
        assert_eq!(
            action_ids,
            vec![
                "policy_query",
                "decision",
                "ruleset",
                "mc:lc",
                "mc:sn",
                "mc_snap:plasticity",
                "mc_cfg:lc",
                "mc_cfg:sn",
            ]
        );
    }

    #[test]
    fn micro_refs_omitted_when_absent() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest: [2u8; 32],
            pev_digest: None,
            ruleset_digest: Some([3u8; 32]),
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest: decision.decision_digest,
            ruleset_digest: decision.ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: micro_evidence_from_control_frame(&control_frame_open()),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let decision_record = build_decision_record(&decision, &decision_ctx);
        assert!(decision_record
            .related_refs
            .iter()
            .all(|r| r.id != "mc:lc" && r.id != "mc:sn" && r.id != "mc_snap:plasticity"));
    }

    #[test]
    fn micro_refs_are_deterministic() {
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let policy_query_digest = policy_query_digest(&policy_query);
        let decision = PolicyDecisionRecord {
            decision_id: "sid:step".to_string(),
            form: DecisionForm::Allow,
            decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            policy_query_digest,
            decision_digest: [2u8; 32],
            pev_digest: None,
            ruleset_digest: Some([3u8; 32]),
            policy_version_digest: String::new(),
            metadata: std::collections::HashMap::new(),
        };

        let control_frame =
            control_frame_with_micro_evidence(Some([11u8; 32]), Some([12u8; 32]), Some([13u8; 32]));
        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest: decision.decision_digest,
            ruleset_digest: decision.ruleset_digest,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: micro_evidence_from_control_frame(&control_frame),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let record_a = build_decision_record(&decision, &decision_ctx);
        let record_b = build_decision_record(&decision, &decision_ctx);

        assert_eq!(canonical_bytes(&record_a), canonical_bytes(&record_b));
    }

    #[test]
    fn micro_refs_use_snapshot_fallback_in_tests() {
        micro_evidence_fallback::TestChip2Reader::set_snapshot(Some(
            micro_evidence_fallback::EngineSnapshot {
                lc_digest: Some([21u8; 32]),
                sn_digest: Some([22u8; 32]),
                plasticity_digest: Some([23u8; 32]),
            },
        ));

        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: ucf::v1::PolicyQuery {
                principal: "chip3".to_string(),
                action: Some(base_action("mock.read", "get")),
                channel: ucf::v1::Channel::Unspecified.into(),
                risk_level: ucf::v1::RiskLevel::Unspecified.into(),
                data_class: ucf::v1::DataClass::Unspecified.into(),
                reason_codes: None,
            },
            policy_query_digest: [1u8; 32],
            policy_decision: ucf::v1::PolicyDecision {
                decision: ucf::v1::DecisionForm::Allow.into(),
                reason_codes: None,
                constraints: None,
            },
            decision_digest: [2u8; 32],
            ruleset_digest: None,
            control_frame_digest: [9u8; 32],
            tool_profile_digest: None,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: micro_evidence_from_control_frame(&control_frame_open()),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        assert_eq!(decision_ctx.micro_evidence.lc_digest, Some([21u8; 32]));
        assert_eq!(decision_ctx.micro_evidence.sn_digest, Some([22u8; 32]));
        assert_eq!(
            decision_ctx.micro_evidence.plasticity_digest,
            Some([23u8; 32])
        );

        micro_evidence_fallback::TestChip2Reader::set_snapshot(None);
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
            pev: ctx.pev.clone(),
            pev_digest: ctx.pev_digest,
            ruleset_digest: ctx.ruleset_digest,
            session_sealed: ctx.session_sealed,
            unlock_present: ctx.session_unlock_permit,
        };

        let canonical_action = canonical_bytes(&action);
        let action_digest = digest32(
            "UCF:HASH:ACTION_SPEC",
            "ActionSpec",
            "v1",
            &canonical_action,
        );
        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let decision = gate.policy.decide_with_context(PolicyEvaluationRequest {
            decision_id: "sid:step".to_string(),
            query: policy_query.clone(),
            context: policy_ctx,
        });

        let control_frame_digest = control::control_frame_digest(&control_frame);
        let tool_profile_digest = gate
            .registry
            .get(&tool_id, &action_id)
            .and_then(|tap| tap.profile_digest.as_ref())
            .and_then(digest32_to_array);
        let decision_ctx = DecisionContext {
            session_id: "sid".to_string(),
            step_id: "step".to_string(),
            policy_query: policy_query.clone(),
            policy_query_digest: decision.policy_query_digest,
            policy_decision: decision.decision.clone(),
            decision_digest: decision.decision_digest,
            ruleset_digest: decision.ruleset_digest,
            control_frame_digest,
            tool_profile_digest,
            commit_disposition: DecisionCommitDisposition::CommitRequired,
            receipt_digest: None,
            rpp_head_meta: None,
            rpp_refs: RppEvidenceRefs::default(),
            micro_evidence: MicroEvidence::default(),
            microcircuit_config_refs: MicrocircuitConfigRefs::default(),
        };

        let req_a = gate.build_execution_request(
            action_digest,
            &tool_id,
            &action_id,
            &decision,
            &decision_ctx,
        );
        let req_b = gate.build_execution_request(
            action_digest,
            &tool_id,
            &action_id,
            &decision,
            &decision_ctx,
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
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
        assert!(matches!(result, GateResult::Executed { .. }));

        let guard = inner_client.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_records.len(), 2);
        let decision_record = guard
            .committed_records
            .iter()
            .find(|r| {
                ucf::v1::RecordType::try_from(r.record_type) == Ok(ucf::v1::RecordType::Decision)
            })
            .expect("decision record committed");
        let action_record = guard
            .committed_records
            .iter()
            .find(|r| {
                ucf::v1::RecordType::try_from(r.record_type) == Ok(ucf::v1::RecordType::ActionExec)
            })
            .expect("action record committed");

        assert!(decision_record.governance_frame_ref.is_some());
        assert!(action_record.governance_frame_ref.is_some());

        let policy_query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };
        let expected_digest = policy_query_digest(&policy_query);
        let policy_query_ref = decision_record
            .related_refs
            .iter()
            .find(|r| r.id == "policy_query")
            .and_then(|r| r.digest.as_ref());

        assert_eq!(
            policy_query_ref.map(|d| d.value.clone()),
            Some(expected_digest.to_vec())
        );

        let related_ids: Vec<_> = decision_record
            .related_refs
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(related_ids[0], "policy_query");
        assert_eq!(related_ids[1], POLICY_DECISION_REF);
        let rpp_ids: Vec<_> = decision_record
            .related_refs
            .iter()
            .filter(|r| r.id.starts_with("rpp:"))
            .map(|r| r.id.as_str())
            .collect();
        if !rpp_ids.is_empty() {
            assert_eq!(rpp_ids, vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]);
        }
    }

    #[test]
    fn action_exec_references_decision_context_digest() {
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
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
        let decision_digest = match result {
            GateResult::Executed { decision, .. } => decision.decision_digest,
            other => panic!("expected execution, got {other:?}"),
        };

        let action_record = inner_client
            .lock()
            .expect("pvgs client lock")
            .committed_records
            .iter()
            .find(|r| {
                ucf::v1::RecordType::try_from(r.record_type) == Ok(ucf::v1::RecordType::ActionExec)
            })
            .cloned()
            .expect("action record committed");

        let decision_ref = action_record
            .related_refs
            .iter()
            .find(|r| r.id == "decision")
            .and_then(|r| r.digest.as_ref())
            .expect("decision related ref present");

        assert_eq!(decision_ref.value, decision_digest);
        assert_eq!(counting.count(), 1, "adapter executes once for success");
    }

    #[test]
    fn rpp_verification_allows_side_effect_action() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let mut local = pvgs_client::LocalPvgsClient::default();
        local.set_latest_rpp_head_meta(rpp_meta_fixture());
        let pvgs = CountingPvgsClient::new(local);
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            boxed_client(pvgs),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let action = base_action("mock.export", "render");
        let base_ctx = ok_ctx();
        let mut ctx = base_ctx.clone();
        ctx.pvgs_receipt = Some(signed_receipt_for_action(
            &gate, &action, &base_ctx, "s", "step", &signer, &key_id,
        ));

        let result = gate.handle_action_spec("s", "step", action, ctx);
        assert!(matches!(result, GateResult::Executed { .. }));
        assert_eq!(counting.count(), 1);
    }

    #[test]
    fn rpp_verification_blocks_side_effect_on_mismatch() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let mut meta = rpp_meta_fixture();
        meta.acc_digest = [0u8; 32];
        let mut local = pvgs_client::LocalPvgsClient::default();
        local.set_latest_rpp_head_meta(meta);
        let pvgs = CountingPvgsClient::new(local);
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            boxed_client(pvgs),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let action = base_action("mock.export", "render");
        let base_ctx = ok_ctx();
        let mut ctx = base_ctx.clone();
        ctx.pvgs_receipt = Some(signed_receipt_for_action(
            &gate, &action, &base_ctx, "s", "step", &signer, &key_id,
        ));

        let result = gate.handle_action_spec("s", "step", action, ctx);
        match result {
            GateResult::Denied { decision } => {
                let reason_codes = decision.decision.reason_codes.expect("reason codes").codes;
                assert!(reason_codes.contains(&RPP_VERIFY_FAIL_REASON.to_string()));
            }
            other => panic!("expected denial, got {other:?}"),
        }
        assert_eq!(counting.count(), 0);
        assert_eq!(
            *gate.integrity_issues.lock().expect("integrity count lock"),
            1
        );
    }

    #[test]
    fn rpp_meta_cache_reuses_latest_head() {
        let counting = CountingAdapter::default();
        let (receipt_store, signer, key_id) = receipt_store_with_key();
        let mut local = pvgs_client::LocalPvgsClient::default();
        local.set_latest_rpp_head_meta(rpp_meta_fixture());
        let pvgs = CountingPvgsClient::new(local);
        let pvgs_handle = boxed_client(pvgs.clone());
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            receipt_store,
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_handle,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let action = base_action("mock.export", "render");
        let base_ctx = ok_ctx();
        let mut ctx = base_ctx.clone();
        ctx.pvgs_receipt = Some(signed_receipt_for_action(
            &gate, &action, &base_ctx, "s", "step1", &signer, &key_id,
        ));
        let _ = gate.handle_action_spec("s", "step1", action.clone(), ctx);

        let mut ctx = base_ctx.clone();
        ctx.pvgs_receipt = Some(signed_receipt_for_action(
            &gate, &action, &base_ctx, "s", "step2", &signer, &key_id,
        ));
        let _ = gate.handle_action_spec("s", "step2", action, ctx);

        assert_eq!(pvgs.rpp_head_query_count(), 1);
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
            default_decision_log(),
            default_query_map(),
        );

        let ctx = ok_ctx();
        let action = base_action("mock.read", "get");
        let _ = gate.handle_action_spec("s", "step", action.clone(), ctx.clone());

        let first_bytes = {
            let guard = inner_client.lock().expect("pvgs client lock");
            assert_eq!(guard.committed_bytes.len(), 2);
            guard.committed_bytes.clone()
        };

        let _ = gate.handle_action_spec("s", "step", action, ctx);

        let guard = inner_client.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_bytes.len(), 2);
        assert_eq!(guard.committed_bytes, first_bytes);
    }

    #[test]
    fn identical_queries_share_decision_digest() {
        let gate = gate_with_adapter(Box::new(MockAdapter));
        let action = base_action("mock.read", "get");
        let ctx = ok_ctx();

        let first = gate.handle_action_spec("s", "step", action.clone(), ctx.clone());
        let second = gate.handle_action_spec("s", "step", action, ctx);

        let (first_digest, second_digest) = match (first, second) {
            (
                GateResult::Executed { decision: a, .. },
                GateResult::Executed { decision: b, .. },
            ) => (a.decision_digest, b.decision_digest),
            other => panic!("expected both executions to succeed, got {other:?}"),
        };

        assert_eq!(first_digest, second_digest);
    }

    #[test]
    fn experience_record_carries_ruleset_ref() {
        let (local, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(MockAdapter),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let mut ctx = ok_ctx();
        ctx.ruleset_digest = Some([9u8; 32]);
        let action = base_action("mock.read", "get");

        let result = gate.handle_action_spec("s", "step", action, ctx);
        assert!(matches!(result, GateResult::Executed { .. }));

        let records = local
            .lock()
            .expect("pvgs local client")
            .committed_records
            .clone();
        assert_eq!(records.len(), 2);

        let action_record = records
            .iter()
            .find(|r| {
                ucf::v1::RecordType::try_from(r.record_type) == Ok(ucf::v1::RecordType::ActionExec)
            })
            .expect("action record present");

        let related_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(related_ids[0..3], ["policy_query", "decision", "ruleset"]);
        let rpp_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .filter(|r| r.id.starts_with("rpp:"))
            .map(|r| r.id.as_str())
            .collect();
        if !rpp_ids.is_empty() {
            assert_eq!(rpp_ids, vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]);
        }

        let decision_digest = action_record
            .governance_frame
            .as_ref()
            .and_then(|g| g.policy_decision_refs.first())
            .expect("decision ref in governance frame")
            .value
            .clone();

        let decision_ref = action_record
            .related_refs
            .iter()
            .find(|r| r.id == "decision")
            .expect("decision related ref present");
        assert_eq!(decision_ref.digest.as_ref().unwrap().value, decision_digest);

        let ruleset_ref = action_record
            .related_refs
            .iter()
            .find(|r| r.id == "ruleset")
            .expect("ruleset ref present");
        assert_eq!(ruleset_ref.digest.as_ref().unwrap().value, vec![9u8; 32]);
    }

    #[test]
    fn experience_record_unmodified_without_ruleset() {
        let (local, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(MockAdapter),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let ctx = ok_ctx();
        let action = base_action("mock.read", "get");
        let result = gate.handle_action_spec("s", "step", action, ctx);
        assert!(matches!(result, GateResult::Executed { .. }));

        let records = local
            .lock()
            .expect("pvgs local client")
            .committed_records
            .clone();
        assert_eq!(records.len(), 2);
        let action_record = records
            .iter()
            .find(|r| {
                ucf::v1::RecordType::try_from(r.record_type) == Ok(ucf::v1::RecordType::ActionExec)
            })
            .expect("action record present");
        assert!(
            action_record.related_refs.len() == 2 || action_record.related_refs.len() == 5,
            "unexpected related refs length: {}",
            action_record.related_refs.len()
        );
        assert_eq!(action_record.related_refs[0].id, "policy_query");
        assert_eq!(action_record.related_refs[1].id, "decision");
        let rpp_ids: Vec<_> = action_record
            .related_refs
            .iter()
            .filter(|r| r.id.starts_with("rpp:"))
            .map(|r| r.id.as_str())
            .collect();
        if !rpp_ids.is_empty() {
            assert_eq!(rpp_ids, vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]);
        }

        let decision_digest = action_record
            .governance_frame
            .as_ref()
            .and_then(|g| g.policy_decision_refs.first())
            .expect("decision ref in governance frame")
            .value
            .clone();
        assert_eq!(
            action_record.related_refs[1]
                .digest
                .as_ref()
                .expect("decision ref digest present")
                .value,
            decision_digest
        );
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
            default_decision_log(),
            default_query_map(),
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
            default_decision_log(),
            default_query_map(),
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
            default_decision_log(),
            default_query_map(),
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
            default_decision_log(),
            default_query_map(),
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
            default_decision_log(),
            default_query_map(),
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
            default_decision_log(),
            default_query_map(),
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
    fn decision_log_prevents_duplicate_commits_after_success() {
        let counting = CountingAdapter::default();
        let (local, pvgs_client) = shared_local_client();
        let decision_log = default_decision_log();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            decision_log.clone(),
            default_query_map(),
        );

        let action = base_action("unknown.tool", "do");
        let ctx = ok_ctx();
        let first = gate.handle_action_spec("s", "step", action.clone(), ctx.clone());
        let first_digest = match first {
            GateResult::Denied { decision } => decision.decision_digest,
            other => panic!("expected deny for unknown tool, got {other:?}"),
        };

        assert_eq!(
            local
                .lock()
                .expect("pvgs client lock")
                .committed_records
                .len(),
            1
        );
        assert_eq!(
            decision_log
                .lock()
                .expect("decision log lock")
                .status(first_digest),
            Some(DecisionCommitState::Committed)
        );

        let second = gate.handle_action_spec("s", "step", action, ctx);
        assert!(matches!(second, GateResult::Denied { .. }));
        assert_eq!(
            local
                .lock()
                .expect("pvgs client lock")
                .committed_records
                .len(),
            1,
            "duplicate commits should be skipped",
        );
    }

    #[test]
    fn single_rt_decision_commit_per_digest() {
        let pvgs = CountingPvgsClient::new(pvgs_client::LocalPvgsClient::default());
        let pvgs_handle = boxed_client(pvgs.clone());
        let gate = gate_with_components(
            Box::new(MockAdapter),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_handle,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let action = base_action("mock.read", "get");
        let ctx = ok_ctx();
        let first = gate.handle_action_spec("s", "step", action.clone(), ctx.clone());
        let second = gate.handle_action_spec("s", "step", action, ctx);

        let digest = match (first, second) {
            (GateResult::Executed { decision, .. }, GateResult::Executed { .. }) => {
                decision.decision_digest
            }
            other => panic!("expected both executions, got {other:?}"),
        };

        assert_eq!(pvgs.decision_commits(digest), 1);
        assert_eq!(
            pvgs.inner
                .lock()
                .expect("pvgs client lock")
                .committed_records
                .len(),
            2,
            "only the first attempt should commit decision and action records",
        );
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
            default_decision_log(),
            default_query_map(),
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
        let decision_log = default_decision_log();
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
            decision_log.clone(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());
        assert!(matches!(result, GateResult::Executed { .. }));
        assert_eq!(*integrity.lock().expect("integrity counter lock"), 2);

        if let GateResult::Executed { decision, .. } = result {
            assert_eq!(
                decision_log
                    .lock()
                    .expect("decision log lock")
                    .status(decision.decision_digest),
                Some(DecisionCommitState::Failed)
            );
        }

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let integrity_stats = frames
            .first()
            .and_then(|f| f.integrity_stats.as_ref())
            .cloned()
            .expect("integrity stats present");
        assert_eq!(integrity_stats.integrity_issue_count, 2);
        assert!(integrity_stats
            .top_reason_codes
            .iter()
            .any(|rc| rc.code == PVGS_INTEGRITY_REASON));
    }

    #[test]
    fn pvgs_rejection_on_decision_only_records_integrity_issue() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let integrity = integrity_counter();
        let decision_log = default_decision_log();
        let rejecting_client = boxed_client(MockPvgsClient::rejecting(vec![
            PVGS_INTEGRITY_REASON.to_string()
        ]));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            rejecting_client,
            integrity.clone(),
            decision_log.clone(),
            default_query_map(),
        );

        let mut ctx = ok_ctx();
        ctx.integrity_state = "FAIL".to_string();
        let result = gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ctx);

        assert!(matches!(result, GateResult::Denied { .. }));
        assert_eq!(counting.count(), 0);
        assert_eq!(*integrity.lock().expect("integrity counter lock"), 1);

        if let GateResult::Denied { decision } = result {
            assert_eq!(
                decision_log
                    .lock()
                    .expect("decision log lock")
                    .status(decision.decision_digest),
                Some(DecisionCommitState::Failed)
            );
        }

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
    fn side_effect_execution_blocked_when_decision_commit_fails() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let integrity = integrity_counter();
        let decision_log = default_decision_log();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator,
            Arc::new(trm::registry_fixture()),
            boxed_client(FailingPvgsClient),
            integrity.clone(),
            decision_log.clone(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.write", "apply"), ok_ctx());

        let _decision_digest = match result {
            GateResult::Denied { ref decision } => {
                assert!(decision
                    .decision
                    .reason_codes
                    .as_ref()
                    .expect("reason codes present")
                    .codes
                    .contains(&PVGS_INTEGRITY_REASON.to_string()));
                decision.decision_digest
            }
            other => panic!("expected denial due to decision commit failure, got {other:?}"),
        };

        assert_eq!(
            counting.count(),
            0,
            "adapter must not run when decision commit fails"
        );
        let log_guard = decision_log.lock().expect("decision log lock");
        let states: Vec<_> = log_guard.entries.values().map(|e| e.state).collect();
        assert!(
            states.contains(&DecisionCommitState::Failed),
            "decision log should record failed commit"
        );
        assert_eq!(
            *integrity.lock().expect("integrity counter lock"),
            2,
            "integrity issues should be signaled for commit failure"
        );
    }

    #[test]
    fn sealed_session_blocks_side_effects() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let client = MockPvgsClient {
            session_sealed: true,
            ..Default::default()
        };
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator,
            Arc::new(trm::registry_fixture()),
            boxed_client(client),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.export", "render"), ok_ctx());

        match result {
            GateResult::Denied { decision } => {
                let reason_codes = decision.decision.reason_codes.expect("reason codes").codes;
                assert_eq!(
                    reason_codes,
                    vec![
                        INTEGRITY_FAIL_REASON.to_string(),
                        FORENSIC_ACTION_REASON.to_string()
                    ]
                );
            }
            other => panic!("expected denial for sealed session, got {other:?}"),
        }

        assert_eq!(counting.count(), 0, "adapter must not run when sealed");
    }

    #[test]
    fn sealed_session_allows_read_actions() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let client = MockPvgsClient {
            session_sealed: true,
            ..Default::default()
        };
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            boxed_client(client),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());

        assert!(matches!(result, GateResult::Executed { .. }));
        assert_eq!(counting.count(), 1, "read should execute when sealed");

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let frame = frames.first().expect("frame emitted");
        assert_eq!(
            frame.integrity_state,
            ucf::v1::IntegrityState::Fail as i32,
            "seal should mark integrity as FAIL",
        );

        let integrity_stats = frame
            .integrity_stats
            .as_ref()
            .expect("integrity stats present");
        let reason_codes: Vec<_> = integrity_stats
            .top_reason_codes
            .iter()
            .map(|rc| rc.code.clone())
            .collect();
        assert!(reason_codes.contains(&INTEGRITY_FAIL_REASON.to_string()));
        assert!(reason_codes.contains(&FORENSIC_ACTION_REASON.to_string()));
    }

    #[test]
    fn sealed_session_with_unlock_blocks_side_effects() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let client = MockPvgsClient {
            session_sealed: true,
            unlock_permit: true,
            ..Default::default()
        };
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator,
            Arc::new(trm::registry_fixture()),
            boxed_client(client),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.export", "render"), ok_ctx());

        match result {
            GateResult::Denied { decision } => {
                let reason_codes = decision.decision.reason_codes.expect("reason codes").codes;
                assert!(reason_codes.contains(&RECOVERY_UNLOCK_GRANTED_REASON.to_string()));
                assert!(reason_codes.contains(&RECOVERY_READONLY_REASON.to_string()));
            }
            other => panic!("expected denial for sealed session with unlock, got {other:?}"),
        }

        assert_eq!(counting.count(), 0, "adapter must not run when sealed");
    }

    #[test]
    fn sealed_session_with_unlock_allows_read_actions_and_marks_metadata() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let client = MockPvgsClient {
            session_sealed: true,
            unlock_permit: true,
            ..Default::default()
        };
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator.clone(),
            Arc::new(trm::registry_fixture()),
            boxed_client(client),
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.read", "get"), ok_ctx());

        match result {
            GateResult::Executed { decision, .. } => {
                assert_eq!(counting.count(), 1, "read should execute when unlocked");
                assert_eq!(
                    decision
                        .metadata
                        .get("recovery_readonly")
                        .map(String::as_str),
                    Some("true")
                );
            }
            other => panic!("expected execution when sealed with unlock, got {other:?}"),
        }

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let integrity_stats = frames
            .first()
            .and_then(|f| f.integrity_stats.as_ref())
            .expect("integrity stats present");
        let reason_codes: Vec<_> = integrity_stats
            .top_reason_codes
            .iter()
            .map(|rc| rc.code.clone())
            .collect();
        assert!(reason_codes.contains(&RECOVERY_UNLOCK_GRANTED_REASON.to_string()));
        assert!(reason_codes.contains(&INTEGRITY_FAIL_REASON.to_string()));
    }

    #[test]
    fn write_actions_block_when_decision_commit_fails() {
        let counting = CountingAdapter::default();
        let integrity = integrity_counter();
        let decision_log = default_decision_log();
        let inner = Arc::new(Mutex::new(pvgs_client::LocalPvgsClient::rejecting(vec![
            PVGS_INTEGRITY_REASON.to_string(),
        ])));
        let rejecting_client = boxed_client(SharedLocalClient::new(inner.clone()));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            rejecting_client,
            integrity,
            decision_log,
            default_query_map(),
        );

        let result =
            gate.handle_action_spec("s", "step", base_action("mock.write", "apply"), ok_ctx());

        match result {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![PVGS_INTEGRITY_REASON.to_string()]
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }

        assert_eq!(
            counting.count(),
            0,
            "adapter should not execute on failed commit"
        );
        assert_eq!(
            inner
                .lock()
                .expect("pvgs client lock")
                .committed_records
                .len(),
            1,
            "action exec commit should be skipped",
        );
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
            default_decision_log(),
            default_query_map(),
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
            orchestrator: Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
                aggregator.clone(),
            ))),
            control_store: store,
            receipt_store: Arc::new(PvgsKeyEpochStore::new()),
            registry: Arc::new(trm::registry_fixture()),
            pvgs_client: default_pvgs_client(),
            integrity_issues: integrity_counter(),
            decision_log: default_decision_log(),
            query_decisions: Arc::new(Mutex::new(QueryDecisionMap::default())),
            rpp_cache: Arc::new(Mutex::new(RppMetaCache::default())),
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

    #[test]
    fn query_decision_conflict_blocks_execution() {
        let counting = CountingAdapter::default();
        let aggregator = default_aggregator();
        let decision_log = default_decision_log();
        let query_map = default_query_map();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            aggregator,
            Arc::new(trm::registry_fixture()),
            default_pvgs_client(),
            integrity_counter(),
            decision_log,
            query_map.clone(),
        );

        let mut deny_ctx = ok_ctx();
        deny_ctx.allowed_tools = vec!["mock.export".to_string()];
        let action = base_action("mock.read", "get");
        let first = gate.handle_action_spec("s", "step", action.clone(), deny_ctx);
        assert!(matches!(first, GateResult::Denied { .. }));

        let policy_query_digest = policy_query_digest(&ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(base_action("mock.read", "get")),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        });
        let before_conflict = query_map
            .lock()
            .expect("query map lock")
            .lookup(policy_query_digest)
            .expect("initial mapping stored");

        let second = gate.handle_action_spec("s", "step", action, ok_ctx());
        match second {
            GateResult::Denied { decision } => {
                assert_eq!(
                    decision.decision.reason_codes.unwrap().codes,
                    vec![REPLAY_MISMATCH_REASON.to_string()]
                );
            }
            other => panic!("expected denial from replay mismatch, got {other:?}"),
        }

        assert_eq!(
            counting.count(),
            0,
            "adapter suppressed on conflicting decisions"
        );
        assert_eq!(
            query_map
                .lock()
                .expect("query map lock")
                .lookup(policy_query_digest),
            Some(before_conflict),
            "conflict should not overwrite existing mapping",
        );
    }

    #[test]
    fn output_record_related_refs_are_ordered() {
        let counting = CountingAdapter::default();
        let (inner, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-1".to_string(),
            content: "ok".to_string(),
            artifact_digest: None,
        };

        let mut ctx = ok_ctx();
        ctx.ruleset_digest = Some([9u8; 32]);

        let result = gate.handle_output_artifact("s", "step", artifact, ctx);
        assert_eq!(result.disposition, OutputDisposition::Delivered);
        assert!(result.delivered);

        let guard = inner.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_records.len(), 1);
        let record = guard.committed_records.first().expect("output record");

        let ids: Vec<_> = record.related_refs.iter().map(|r| r.id.clone()).collect();
        assert_eq!(ids, vec!["output_artifact", "dlp_decision", "ruleset"]);

        let governance_frame = record
            .governance_frame
            .as_ref()
            .expect("governance frame present");
        assert_eq!(governance_frame.dlp_refs.len(), 1);
    }

    #[test]
    fn dlp_commit_precedes_output_record_append() {
        let counting = CountingAdapter::default();
        let pvgs = CountingPvgsClient::new(pvgs_client::LocalPvgsClient::default());
        let pvgs_handle: PvgsClientHandle = Arc::new(Mutex::new(
            Box::new(pvgs.clone()) as Box<dyn PvgsClientReader>
        ));

        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_handle,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-commit".to_string(),
            content: "ok".to_string(),
            artifact_digest: None,
        };

        let result = gate.handle_output_artifact("s", "step", artifact, ok_ctx());
        assert_eq!(result.disposition, OutputDisposition::Delivered);

        let calls = pvgs.calls();
        assert_eq!(
            calls,
            vec!["commit_dlp_decision", "commit_experience_record"]
        );

        let guard = pvgs.inner.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_dlp_decisions.len(), 1);
        assert_eq!(guard.committed_records.len(), 1);
    }

    #[test]
    fn rejecting_dlp_commit_blocks_output_record() {
        let counting = CountingAdapter::default();
        let inner = Arc::new(Mutex::new(pvgs_client::LocalPvgsClient::rejecting(vec![
            PVGS_INTEGRITY_REASON.to_string(),
        ])));
        let pvgs_client = Arc::new(Mutex::new(
            Box::new(SharedLocalClient::new(inner.clone())) as Box<dyn PvgsClientReader>
        ));
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-reject".to_string(),
            content: "clean".to_string(),
            artifact_digest: None,
        };

        let result = gate.handle_output_artifact("s", "step", artifact, ok_ctx());
        assert_eq!(result.disposition, OutputDisposition::Failed);
        assert!(result
            .reason_codes
            .contains(&PVGS_INTEGRITY_REASON.to_string()));
        assert!(!result.delivered);

        let guard = inner.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_dlp_decisions.len(), 1);
        assert!(guard.committed_records.is_empty());
    }

    #[test]
    fn blocked_output_still_commits_record() {
        let counting = CountingAdapter::default();
        let (inner, pvgs_client) = shared_local_client();
        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_client,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-2".to_string(),
            content: "SECRET plan".to_string(),
            artifact_digest: None,
        };

        let result = gate.handle_output_artifact("s", "step", artifact, ok_ctx());
        assert_eq!(result.disposition, OutputDisposition::Blocked);
        assert!(!result.delivered);
        assert_eq!(
            result.reason_codes,
            vec!["RC.CD.DLP.SECRET_PATTERN".to_string()]
        );

        let guard = inner.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_records.len(), 1);
        let record = guard.committed_records.first().expect("output record");
        let ids: Vec<_> = record.related_refs.iter().map(|r| r.id.clone()).collect();
        assert_eq!(ids, vec!["output_artifact", "dlp_decision"]);
    }

    #[test]
    fn allowed_output_commits_and_delivers_when_export_enabled() {
        let counting = CountingAdapter::default();
        let pvgs = CountingPvgsClient::new(pvgs_client::LocalPvgsClient::default());
        let pvgs_handle: PvgsClientHandle = Arc::new(Mutex::new(
            Box::new(pvgs.clone()) as Box<dyn PvgsClientReader>
        ));

        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_handle,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-allow".to_string(),
            content: "clean".to_string(),
            artifact_digest: None,
        };

        let result = gate.handle_output_artifact("s", "step", artifact, ok_ctx());
        assert_eq!(result.disposition, OutputDisposition::Delivered);
        assert!(result.delivered);

        let calls = pvgs.calls();
        assert_eq!(
            calls,
            vec!["commit_dlp_decision", "commit_experience_record"]
        );
        let guard = pvgs.inner.lock().expect("pvgs client lock");
        assert_eq!(guard.committed_dlp_decisions.len(), 1);
        assert_eq!(guard.committed_records.len(), 1);
    }

    #[test]
    fn record_commit_failure_results_in_failed_disposition() {
        let counting = CountingAdapter::default();
        let client = RecordRejectingPvgsClient::new(pvgs_client::LocalPvgsClient::default());
        let pvgs_handle: PvgsClientHandle = Arc::new(Mutex::new(
            Box::new(client.clone()) as Box<dyn PvgsClientReader>
        ));

        let gate = gate_with_components(
            Box::new(counting.clone()),
            open_control_store(),
            Arc::new(PvgsKeyEpochStore::new()),
            default_aggregator(),
            Arc::new(trm::registry_fixture()),
            pvgs_handle,
            integrity_counter(),
            default_decision_log(),
            default_query_map(),
        );

        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-record-reject".to_string(),
            content: "clean".to_string(),
            artifact_digest: None,
        };

        let result = gate.handle_output_artifact("s", "step", artifact, ok_ctx());
        assert_eq!(result.disposition, OutputDisposition::Failed);
        assert!(!result.delivered);
        assert!(result
            .reason_codes
            .contains(&PVGS_INTEGRITY_REASON.to_string()));

        assert_eq!(
            client.calls(),
            vec!["commit_dlp_decision", "commit_experience_record"]
        );
    }

    #[test]
    fn signal_frame_tracks_dlp_counts_and_reasons() {
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
            default_decision_log(),
            default_query_map(),
        );

        let blocked = ucf::v1::OutputArtifact {
            artifact_id: "art-block".to_string(),
            content: "SECRET".to_string(),
            artifact_digest: None,
        };
        let allowed = ucf::v1::OutputArtifact {
            artifact_id: "art-allow".to_string(),
            content: "ok".to_string(),
            artifact_digest: None,
        };

        let _ = gate.handle_output_artifact("s", "step", blocked.clone(), ok_ctx());
        let _ = gate.handle_output_artifact("s", "step2", blocked, ok_ctx());
        let _ = gate.handle_output_artifact("s", "step3", allowed, ok_ctx());

        let frames = aggregator.lock().expect("agg lock").force_flush();
        let stats = frames
            .first()
            .and_then(|f| f.dlp_stats.clone())
            .expect("dlp stats present");

        assert_eq!(stats.block_count, 2);
        assert_eq!(stats.allow_count, 1);
        assert!(stats
            .top_reason_codes
            .iter()
            .any(|rc| rc.code == "RC.CD.DLP.SECRET_PATTERN"));
    }

    #[test]
    fn output_record_bytes_are_deterministic() {
        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "art-3".to_string(),
            content: "deterministic".to_string(),
            artifact_digest: None,
        };
        let artifact_digest = output_artifact_digest(&artifact);

        let mut decision = dlp_check_output(&artifact);
        ensure_dlp_decision_digest(&mut decision);

        let control_store = control::ControlFrameStore::default();
        let control_frame = control_store
            .current()
            .cloned()
            .unwrap_or_else(|| control_store.strict_fallback());
        let control_frame_digest = control::control_frame_digest(&control_frame);

        let record_a = build_output_record(
            "s",
            "step",
            artifact_digest,
            &decision,
            &control_frame,
            &control_frame_digest,
            None,
            None,
            None,
        );
        let record_b = build_output_record(
            "s",
            "step",
            artifact_digest,
            &decision,
            &control_frame,
            &control_frame_digest,
            None,
            None,
            None,
        );

        assert_eq!(canonical_bytes(&record_a), canonical_bytes(&record_b));
    }
}
