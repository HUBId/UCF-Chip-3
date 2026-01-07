#![forbid(unsafe_code)]

use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

use lnss_approval::{
    approval_artifact_package_digest, build_aap_for_proposal, build_activation_evidence_pb,
    load_approval_decisions, ActivationInjectionLimits, ActivationStatus, ApprovalContext,
    ProposalActivationEvidenceLocal,
};
pub use lnss_core::BiophysFeedbackSnapshot;
use lnss_core::TapKind;
use lnss_core::{
    digest, wm_pred_error_bucket, BrainTarget, CfgRootDigestPack, CognitiveCore, ContextBundle,
    ControlIntentClass, CoreContextDigestPack, CoreOrchestrator, CoreStepOutput,
    DeliberationBudget, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap,
    FeedbackAnomalyFlags, PolicyMode, PolicyView, RecursionPolicy, RlmCfgSnapshot, RlmCore,
    RlmDirective, RlmInput, TapFrame, TapSpec, WorldModelCfgSnapshot, WorldModelCore,
    WorldModelInput, MAX_ACTIVATION_BYTES, MAX_MAPPING_ENTRIES, MAX_REASON_CODES,
    MAX_RLM_DIRECTIVES, MAX_RLM_REASON_CODES, MAX_STRING_LEN, MAX_TOP_FEATURES,
};
use lnss_evolve::{
    build_proposal_evidence_pb, evaluate, load_proposals, proposal_payload_digest,
    trace_encoding::{build_trace_run_evidence_pb, TraceRunEvidenceLocal},
    EvalContext, EvalVerdict, Proposal, ProposalEvidence, ProposalKind, ProposalPayload,
    TraceVerdict,
};
use lnss_hooks::TapRegistry;
use lnss_lifecycle::{
    EvidenceQueryClient, LifecycleIndex, LifecycleKey, ACTIVATION_STATUS_APPLIED,
    ACTIVATION_STATUS_REJECTED, TRACE_VERDICT_NEUTRAL, TRACE_VERDICT_PROMISING,
    TRACE_VERDICT_RISKY,
};
#[cfg(feature = "lnss-liquid-ode")]
use lnss_triggers::liquid_params_update_payload;
use lnss_triggers::{
    extract_triggers, mapping_update_plan, proposal_is_duplicate, propose_from_triggers, ActiveCfg,
    ActiveConstraints, LiquidParamsSnapshot,
};
use lnss_worldmodulation::{
    compute_world_modulation, BaseLimits, WorldModulationPlan, RC_WM_MODULATION_ACTIVE,
    RC_WM_PRED_ERROR_CRITICAL, RC_WM_PRED_ERROR_HIGH,
};
use pvgs_client::PvgsClientReader;
use ucf_protocol::canonical_bytes;
use ucf_protocol::ucf;

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 4096;
pub const DEFAULT_MAX_SPIKES: usize = 2048;
pub const DEFAULT_MAX_TAPS: usize = 128;
pub const DEFAULT_MAX_MECHINT_BYTES: usize = 8192;
pub const MAX_TAP_SAMPLE_BYTES: usize = 4096;
pub const DEFAULT_MAX_TARGETS_PER_SPIKE: u32 = 64;
pub const DEFAULT_AMPLITUDE_CAP_Q: u16 = 1000;
pub const DEFAULT_PROPOSAL_SCAN_TICKS: u64 = 50;
pub const DEFAULT_PROPOSAL_MAX_PER_TICK: usize = 5;
pub const DEFAULT_APPROVAL_SCAN_TICKS: u64 = 10;
pub const DEFAULT_APPROVAL_MAX_PER_TICK: usize = 1;
pub const FILE_DIGEST_DOMAIN: &str = "lnss.file.bytes.v1";
pub const LIQUID_PARAMS_DOMAIN: &str = "lnss.liquid.params.v1";
const LANG_CFG_DOMAIN: &str = "UCF:LNSS:LANG_CFG";
const WM_CFG_DOMAIN: &str = "UCF:LNSS:WM_CFG";
const RLM_CFG_DOMAIN: &str = "UCF:LNSS:RLM_CFG";
const SAE_CFG_DOMAIN: &str = "UCF:LNSS:SAE_CFG";
const MAP_CFG_DOMAIN: &str = "UCF:LNSS:MAP_CFG";
const LIMITS_CFG_DOMAIN: &str = "UCF:LNSS:LIMITS_CFG";
const HOOK_CFG_DOMAIN: &str = "UCF:LNSS:HOOK_CFG";
const ACTIVATION_ID_PREFIX_LEN: usize = 8;
const TRACE_ID_PREFIX_LEN: usize = 8;
const FIXED_MS_PER_TICK: u64 = 10;
const RC_PROPOSAL_ACTIVATED: &str = "RC.GV.PROPOSAL.ACTIVATED";
const RC_PROPOSAL_REJECTED: &str = "RC.GV.PROPOSAL.REJECTED";
const RC_SHADOW_BETTER: &str = "RC.GV.SHADOW.BETTER";
const RC_SHADOW_WORSE: &str = "RC.GV.SHADOW.WORSE";
const RC_SHADOW_EQUAL: &str = "RC.GV.SHADOW.EQUAL";
const RC_TRACE_PROMISING: &str = "RC.GV.TRACE.PROMISING";
const RC_TRACE_NEUTRAL: &str = "RC.GV.TRACE.NEUTRAL";
const RC_TRACE_RISKY: &str = "RC.GV.TRACE.RISKY";
const RC_TRACE_DUPLICATE_SKIPPED: &str = "RC.GV.TRACE.DUPLICATE_SKIPPED";
const RC_AAP_BLOCKED_BY_TRACE: &str = "RC.GV.AAP.BLOCKED_BY_TRACE";
const RC_AAP_BLOCKED_ALREADY_ACTIVATED: &str = "RC.GV.AAP.BLOCKED_ALREADY_ACTIVATED";
const RC_AAP_MISSING_CONTEXT_BINDING: &str = "RC.GV.AAP.MISSING_CONTEXT_BINDING";
const RC_PROPOSAL_ACTIVATION_PRECONDITION_FAILED: &str =
    "RC.GV.PROPOSAL.ACTIVATION_PRECONDITION_FAILED";
const RC_RLM_RECURSION_STEP: &str = "RC.GV.RLM.RECURSION_STEP";
const RC_RLM_RECURSION_BLOCKED_BY_POLICY: &str = "RC.GV.RLM.RECURSION_BLOCKED_BY_POLICY";
const RC_RLM_RECURSION_BLOCKED_BY_OVERLOAD: &str = "RC.GV.RLM.RECURSION_BLOCKED_BY_OVERLOAD";
const RC_RLM_RECURSION_BLOCKED_BY_WM: &str = "RC.GV.RLM.RECURSION_BLOCKED_BY_WM";

#[derive(Debug, Error)]
pub enum LnssRuntimeError {
    #[error("mechint writer error: {0}")]
    MechInt(String),
    #[error("rig client error: {0}")]
    Rig(String),
    #[error("proposal inbox error: {0}")]
    Proposal(String),
    #[error("approval inbox error: {0}")]
    Approval(String),
    #[error("shadow config error: {0}")]
    Shadow(String),
}

pub trait LlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8>;
    fn supports_hooks(&self) -> bool;
    fn backend_identifier(&self) -> &'static str;
    fn model_revision(&self) -> String;
}

pub trait HookProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame>;
}

pub struct LanguageCore<'a> {
    llm: &'a mut dyn LlmBackend,
    hooks: &'a mut dyn HookProvider,
    mods: &'a EmotionFieldSnapshot,
    tap_specs: &'a [TapSpec],
    limits: Limits,
}

impl<'a> LanguageCore<'a> {
    pub fn new(
        llm: &'a mut dyn LlmBackend,
        hooks: &'a mut dyn HookProvider,
        mods: &'a EmotionFieldSnapshot,
        tap_specs: &'a [TapSpec],
        limits: Limits,
    ) -> Self {
        Self {
            llm,
            hooks,
            mods,
            tap_specs,
            limits,
        }
    }
}

impl<'a> CognitiveCore for LanguageCore<'a> {
    fn step(&mut self, input: &[u8], _context: &ContextBundle) -> CoreStepOutput {
        let mut output_bytes = self.llm.infer_step(input, self.mods);
        output_bytes.truncate(self.limits.max_output_bytes);
        let taps = if self.llm.supports_hooks() {
            let mut frames = self.hooks.collect_taps(self.tap_specs);
            frames.truncate(self.limits.max_taps);
            frames
        } else {
            Vec::new()
        };
        CoreStepOutput { output_bytes, taps }
    }
}

pub trait SaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent;
}

pub trait MechIntWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), LnssRuntimeError>;
}

pub trait RigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError>;
    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        None
    }
}

pub trait ProposalApplier {
    fn apply_mapping_update(
        &mut self,
        path: &Path,
        digest: [u8; 32],
    ) -> Result<(), LnssRuntimeError>;
    fn apply_sae_pack_update(
        &mut self,
        path: &Path,
        digest: [u8; 32],
    ) -> Result<(), LnssRuntimeError>;
    fn apply_liquid_params_update(
        &mut self,
        params_digest: [u8; 32],
        kv_pairs: &[(String, String)],
    ) -> Result<(), LnssRuntimeError>;
    fn apply_injection_limits_update(
        &mut self,
        max_spikes: u32,
        max_targets: u32,
    ) -> Result<(), LnssRuntimeError>;
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_output_bytes: usize,
    pub max_taps: usize,
    pub max_spikes: usize,
    pub max_mechint_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_taps: DEFAULT_MAX_TAPS,
            max_spikes: DEFAULT_MAX_SPIKES,
            max_mechint_bytes: DEFAULT_MAX_MECHINT_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ShadowConfig {
    pub enabled: bool,
    pub shadow_mapping: Option<FeatureToBrainMap>,
    #[cfg(feature = "lnss-liquid-ode")]
    pub shadow_liquid_params: Option<LiquidOdeConfig>,
    pub shadow_injection_limits: Option<InjectionLimits>,
}

impl ShadowConfig {
    pub fn validate(
        &self,
        active_mapping: &FeatureToBrainMap,
        #[cfg(feature = "lnss-liquid-ode")] active_liquid_params: Option<&LiquidOdeConfig>,
        active_injection_limits: &InjectionLimits,
    ) -> Result<(), LnssRuntimeError> {
        if let Some(shadow_mapping) = &self.shadow_mapping {
            validate_shadow_mapping(active_mapping, shadow_mapping)?;
        }
        if let Some(shadow_limits) = &self.shadow_injection_limits {
            if shadow_limits.max_spikes_per_tick > active_injection_limits.max_spikes_per_tick {
                return Err(LnssRuntimeError::Shadow(
                    "shadow max_spikes_per_tick must tighten limits".to_string(),
                ));
            }
            if shadow_limits.max_targets_per_spike > active_injection_limits.max_targets_per_spike {
                return Err(LnssRuntimeError::Shadow(
                    "shadow max_targets_per_spike must tighten limits".to_string(),
                ));
            }
        }
        #[cfg(feature = "lnss-liquid-ode")]
        if let Some(shadow_params) = &self.shadow_liquid_params {
            let active = active_liquid_params.ok_or_else(|| {
                LnssRuntimeError::Shadow(
                    "shadow liquid params require active liquid params".to_string(),
                )
            })?;
            validate_shadow_liquid_params(active, shadow_params)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectionLimits {
    pub max_spikes_per_tick: u32,
    pub max_targets_per_spike: u32,
}

impl Default for InjectionLimits {
    fn default() -> Self {
        Self {
            max_spikes_per_tick: DEFAULT_MAX_SPIKES as u32,
            max_targets_per_spike: DEFAULT_MAX_TARGETS_PER_SPIKE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveWorldLimits {
    pub max_spikes_per_tick: u32,
    pub amplitude_cap_q: u16,
    pub fanout_cap: u32,
}

#[derive(Debug, Clone)]
pub struct ProposalInbox {
    pub dir: PathBuf,
    pub aap_dir: PathBuf,
    pub ticks_per_scan: u64,
    pub max_per_tick: usize,
    tick_counter: u64,
    committed: BTreeSet<[u8; 32]>,
}

impl ProposalInbox {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let aap_dir = dir.join("aap");
        Self {
            dir,
            aap_dir,
            ticks_per_scan: DEFAULT_PROPOSAL_SCAN_TICKS,
            max_per_tick: DEFAULT_PROPOSAL_MAX_PER_TICK,
            tick_counter: 0,
            committed: BTreeSet::new(),
        }
    }

    pub fn with_limits(dir: impl AsRef<Path>, ticks_per_scan: u64, max_per_tick: usize) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let aap_dir = dir.join("aap");
        Self {
            dir,
            aap_dir,
            ticks_per_scan: ticks_per_scan.max(1),
            max_per_tick: max_per_tick.max(1),
            tick_counter: 0,
            committed: BTreeSet::new(),
        }
    }

    fn should_scan(&mut self) -> bool {
        self.tick_counter = self.tick_counter.saturating_add(1);
        self.tick_counter.is_multiple_of(self.ticks_per_scan)
    }

    pub fn ingest(
        &mut self,
        eval_ctx: &EvalContext,
        base_parts: &MechIntRecordParts,
        mechint: &mut dyn MechIntWriter,
        mut pvgs: Option<&mut (dyn PvgsClientReader + '_)>,
        trace_state: Option<&TraceRunState>,
        lifecycle: LifecycleInputs<'_>,
    ) -> Result<usize, LnssRuntimeError> {
        if !self.should_scan() {
            return Ok(0);
        }
        let proposals =
            load_proposals(&self.dir).map_err(|err| LnssRuntimeError::Proposal(err.to_string()))?;

        let mut processed = 0usize;
        for proposal in proposals {
            if proposal.core_context_digest == [0u8; 32] {
                eprintln!("{RC_AAP_MISSING_CONTEXT_BINDING}: proposal missing core context digest");
                return Err(LnssRuntimeError::Proposal(
                    "proposal missing core context digest".to_string(),
                ));
            }
            let key = LifecycleKey {
                proposal_digest: proposal.proposal_digest,
                context_digest: proposal.core_context_digest,
                active_cfg_root_digest: proposal.base_active_cfg_digest,
            };
            lifecycle.index.note_proposal(key, lifecycle.tick);
            hydrate_lifecycle_from_query(
                lifecycle.index,
                lifecycle.evidence_query,
                key,
                lifecycle.tick,
            );
            if let Some(trace_state) = trace_state.filter(|state| state.committed) {
                let verdict = trace_verdict_code(&trace_state.verdict);
                lifecycle
                    .index
                    .note_trace(key, trace_state.trace_digest, verdict, lifecycle.tick);
            }
            let lifecycle_state = lifecycle.index.state_for(&key).cloned().unwrap_or_default();
            let lifecycle_trace_digest = lifecycle_state.latest_trace_digest;
            let lifecycle_trace_verdict = lifecycle_state.latest_trace_verdict;
            let activation_applied =
                lifecycle_state.latest_activation_status == Some(ACTIVATION_STATUS_APPLIED);
            let pending_approval =
                lifecycle_state.latest_approval_digest.is_some() && !activation_applied;
            eprintln!(
                "lifecycle: proposal={} context={} trace_verdict={:?} trace_digest={} activation={:?}",
                hex::encode(&key.proposal_digest[..4]),
                hex::encode(&key.context_digest[..4]),
                lifecycle_trace_verdict,
                lifecycle_trace_digest
                    .map(|digest| hex::encode(&digest[..4]))
                    .unwrap_or_else(|| "none".to_string()),
                lifecycle_state.latest_activation_status
            );
            let eval = evaluate(&proposal, eval_ctx);
            let base_evidence_digest = eval_ctx.latest_feedback_digest.unwrap_or([0u8; 32]);
            let mut reason_codes = eval.reason_codes.clone();
            let mut gating_codes = Vec::new();
            if base_evidence_digest == [0u8; 32] {
                reason_codes.push("RC.GV.PROPOSAL.MISSING_BASE_EVIDENCE".to_string());
            }
            let trace_allowed = match trace_state
                .filter(|state| state.committed && state.verdict == TraceVerdict::Promising)
            {
                Some(state) => {
                    lifecycle_trace_verdict == Some(TRACE_VERDICT_PROMISING)
                        && lifecycle_trace_digest == Some(state.trace_digest)
                }
                None => false,
            };
            if eval.verdict == EvalVerdict::Promising && !trace_allowed {
                reason_codes.push(RC_AAP_BLOCKED_BY_TRACE.to_string());
                gating_codes.push(RC_AAP_BLOCKED_BY_TRACE.to_string());
            }
            if activation_applied {
                reason_codes.push(RC_AAP_BLOCKED_ALREADY_ACTIVATED.to_string());
                gating_codes.push(RC_AAP_BLOCKED_ALREADY_ACTIVATED.to_string());
            }
            let payload_digest = proposal_payload_digest(&proposal.payload)
                .map_err(|err| LnssRuntimeError::Proposal(err.to_string()))?;

            let mut parts = base_parts.clone();
            parts.proposal_digest = Some(proposal.proposal_digest);
            parts.proposal_kind = Some(proposal.kind.clone());
            parts.proposal_eval_score = Some(eval.score);
            parts.proposal_verdict = Some(eval.verdict.clone());
            parts.proposal_base_evidence_digest = Some(proposal.base_evidence_digest);
            if !gating_codes.is_empty() {
                parts.reason_codes.extend(gating_codes.clone());
            }
            let active_cfg_root_digest = proposal
                .base_active_cfg_digest
                .or(trace_state.map(|state| state.active_cfg_digest));
            let shadow_cfg_root_digest = trace_state.map(|state| state.shadow_cfg_digest);
            if eval.verdict == EvalVerdict::Promising
                && trace_allowed
                && !activation_applied
                && !pending_approval
                && active_cfg_root_digest.is_some()
            {
                let trace_state = trace_state
                    .filter(|state| state.committed && state.verdict == TraceVerdict::Promising)
                    .expect("trace state");
                let ruleset_digest = pvgs
                    .as_deref()
                    .and_then(|client| client.get_current_ruleset_digest());
                let ctx = ApprovalContext {
                    session_id: parts.session_id.clone(),
                    ruleset_digest,
                    current_mapping_digest: Some(parts.mapping_digest),
                    current_sae_pack_digest: None,
                    current_liquid_params_digest: None,
                    latest_scorecard_digest: None,
                    trace_digest: Some(trace_state.trace_digest),
                    active_cfg_root_digest,
                    shadow_cfg_root_digest,
                    requested_operation: ucf::v1::OperationCategory::OpException,
                };
                let aap = match build_aap_for_proposal(&proposal, &ctx) {
                    Ok(aap) => aap,
                    Err(_) => {
                        eprintln!(
                            "{RC_AAP_MISSING_CONTEXT_BINDING}: proposal missing core context digest"
                        );
                        return Err(LnssRuntimeError::Proposal(
                            "missing core context digest".to_string(),
                        ));
                    }
                };
                let aap_digest = approval_artifact_package_digest(&aap);
                parts.aap_digest = Some(aap_digest);
                lifecycle.index.note_aap(key, aap_digest, lifecycle.tick);
                if let Err(err) = fs::create_dir_all(&self.aap_dir) {
                    return Err(LnssRuntimeError::Proposal(err.to_string()));
                }
                let filename = format!("aap_{}.bin", hex::encode(aap_digest));
                let path = self.aap_dir.join(filename);
                if let Err(err) = fs::write(path, lnss_approval::encode_aap(&aap)) {
                    return Err(LnssRuntimeError::Proposal(err.to_string()));
                }
            } else if eval.verdict == EvalVerdict::Promising
                && trace_allowed
                && !activation_applied
                && !pending_approval
            {
                eprintln!(
                    "cfg root digest missing: aap disabled for step {}",
                    parts.step_id
                );
            }
            let evidence = ProposalEvidence {
                proposal_id: proposal.proposal_id.clone(),
                proposal_digest: proposal.proposal_digest,
                kind: proposal.kind.clone(),
                base_evidence_digest,
                core_context_digest: proposal.core_context_digest,
                payload_digest,
                created_at_ms: proposal.created_at_ms,
                score: eval.score,
                verdict: eval.verdict.clone(),
                reason_codes,
            };
            let evidence_pb = build_proposal_evidence_pb(&evidence);
            let evidence_digest = evidence_pb
                .proposal_digest
                .as_ref()
                .and_then(digest_bytes)
                .unwrap_or([0u8; 32]);
            let payload_bytes = canonical_bytes(&evidence_pb);

            if self.committed.contains(&evidence_digest) {
                continue;
            }
            let record = MechIntRecord::new(parts);
            mechint.write_step(&record)?;

            let accepted = match pvgs.as_deref_mut() {
                Some(client) => match client.commit_proposal_evidence(payload_bytes) {
                    Ok(receipt) => receipt.status == ucf::v1::ReceiptStatus::Accepted as i32,
                    Err(_) => false,
                },
                None => true,
            };

            if accepted {
                self.committed.insert(evidence_digest);
            }

            processed += 1;
            if processed >= self.max_per_tick {
                break;
            }
        }
        Ok(processed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActivationState {
    pub active_mapping_digest: Option<[u8; 32]>,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_injection_limits: Option<InjectionLimits>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivationResult {
    Applied,
    Rejected,
}

pub trait LnssEventSink {
    fn on_activation_event(&mut self, activation_digest: [u8; 32], result: ActivationResult);
}

#[derive(Debug, Clone)]
pub struct ApprovalInbox {
    pub dir: PathBuf,
    pub ticks_per_scan: u64,
    pub max_per_tick: usize,
    tick_counter: u64,
    seen_approval_digests: BTreeSet<[u8; 32]>,
    seen_activation_digests: BTreeSet<[u8; 32]>,
    state_path: PathBuf,
    state: ActivationState,
}

#[derive(Debug, Clone)]
struct PendingAap {
    aap_digest: [u8; 32],
    proposal_digest: [u8; 32],
    trace_digest: Option<[u8; 32]>,
    context_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct ActivationPlan {
    approval_digest: [u8; 32],
    approval: ucf::v1::ApprovalDecision,
    proposal: Proposal,
    aap_digest: [u8; 32],
    aap_trace_digest: Option<[u8; 32]>,
    aap_context_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct ActivationOutcome {
    result: ActivationResult,
    state: ActivationState,
}

impl ActivationOutcome {
    fn applied(state: ActivationState) -> Self {
        Self {
            result: ActivationResult::Applied,
            state,
        }
    }

    fn rejected(state: ActivationState) -> Self {
        Self {
            result: ActivationResult::Rejected,
            state,
        }
    }
}

impl ApprovalInbox {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self, LnssRuntimeError> {
        Self::with_state_path(dir, default_state_path(), DEFAULT_APPROVAL_SCAN_TICKS)
    }

    pub fn with_state_path(
        dir: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
        ticks_per_scan: u64,
    ) -> Result<Self, LnssRuntimeError> {
        let dir = dir.as_ref().to_path_buf();
        let state_path = state_path.as_ref().to_path_buf();
        let state = load_activation_state(&state_path)?;
        Ok(Self {
            dir,
            ticks_per_scan: ticks_per_scan.max(1),
            max_per_tick: DEFAULT_APPROVAL_MAX_PER_TICK,
            tick_counter: 0,
            seen_approval_digests: BTreeSet::new(),
            seen_activation_digests: BTreeSet::new(),
            state_path,
            state,
        })
    }

    pub fn state(&self) -> &ActivationState {
        &self.state
    }

    fn should_scan(&mut self) -> bool {
        self.tick_counter = self.tick_counter.saturating_add(1);
        self.tick_counter.is_multiple_of(self.ticks_per_scan)
    }

    fn set_state(&mut self, state: ActivationState) -> Result<(), LnssRuntimeError> {
        self.state = state;
        persist_activation_state(&self.state_path, &self.state)?;
        Ok(())
    }

    fn has_seen_activation(&self, digest: &[u8; 32]) -> bool {
        self.seen_activation_digests.contains(digest)
    }

    fn mark_activation_seen(&mut self, digest: [u8; 32]) {
        self.seen_activation_digests.insert(digest);
    }

    fn next_activation(&mut self) -> Result<Option<ActivationPlan>, LnssRuntimeError> {
        if !self.should_scan() {
            return Ok(None);
        }
        let approvals = load_approval_decisions(&self.dir)
            .map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        if approvals.is_empty() {
            return Ok(None);
        }

        let proposals =
            load_proposals(&self.dir).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        let proposal_map = proposals
            .into_iter()
            .map(|proposal| (proposal.proposal_digest, proposal))
            .collect::<std::collections::BTreeMap<_, _>>();

        let pending_aaps = load_pending_aaps(self.dir.join("aap"))?;

        let mut candidates = Vec::new();
        for approval in approvals {
            let approval_digest = match approval
                .approval_decision_digest
                .as_ref()
                .and_then(digest_bytes)
            {
                Some(digest) => digest,
                None => continue,
            };
            if self.seen_approval_digests.contains(&approval_digest) {
                continue;
            }
            let pending = match pending_aaps.get(&approval.aap_id) {
                Some(pending) => pending,
                None => continue,
            };
            let proposal = match proposal_map.get(&pending.proposal_digest) {
                Some(proposal) => proposal.clone(),
                None => continue,
            };
            candidates.push(ActivationPlan {
                approval_digest,
                approval,
                proposal,
                aap_digest: pending.aap_digest,
                aap_trace_digest: pending.trace_digest,
                aap_context_digest: pending.context_digest,
            });
        }

        candidates.sort_by(|a, b| a.approval_digest.cmp(&b.approval_digest));
        let plan = candidates.into_iter().next();
        if let Some(ref plan) = plan {
            self.seen_approval_digests.insert(plan.approval_digest);
        }
        Ok(plan)
    }
}

pub struct LnssRuntime {
    pub llm: Box<dyn LlmBackend>,
    pub hooks: Box<dyn HookProvider>,
    pub worldmodel: Box<dyn WorldModelCore>,
    pub rlm: Box<dyn RlmCore>,
    pub orchestrator: CoreOrchestrator,
    pub sae: Box<dyn SaeBackend>,
    pub mechint: Box<dyn MechIntWriter>,
    pub pvgs: Option<Box<dyn PvgsClientReader>>,
    pub rig: Box<dyn RigClient>,
    pub mapper: FeatureToBrainMap,
    pub limits: Limits,
    pub injection_limits: InjectionLimits,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_cfg_root_digest: Option<[u8; 32]>,
    pub shadow_cfg_root_digest: Option<[u8; 32]>,
    #[cfg(feature = "lnss-liquid-ode")]
    pub active_liquid_params: Option<LiquidOdeConfig>,
    pub feedback: FeedbackConsumer,
    pub adaptation: MappingAdaptationConfig,
    pub proposal_inbox: Option<ProposalInbox>,
    pub approval_inbox: Option<ApprovalInbox>,
    pub activation_now_ms: Option<u64>,
    pub event_sink: Option<Box<dyn LnssEventSink>>,
    pub shadow: ShadowConfig,
    pub shadow_rig: Option<Box<dyn RigClient>>,
    pub trace_state: Option<TraceRunState>,
    pub seen_trace_digests: BTreeSet<[u8; 32]>,
    pub lifecycle_index: LifecycleIndex,
    pub evidence_query_client: Option<Box<dyn EvidenceQueryClient>>,
    pub lifecycle_tick: u64,
    pub policy_mode: PolicyMode,
    pub control_intent_class: ControlIntentClass,
    pub recursion_policy: RecursionPolicy,
    pub world_state_digest: [u8; 32],
    pub last_action_digest: [u8; 32],
    pub last_self_state_digest: [u8; 32],
    pub pred_error_threshold: i32,
    pub trigger_proposals_enabled: bool,
}

pub struct LifecycleInputs<'a> {
    pub index: &'a mut LifecycleIndex,
    pub evidence_query: Option<&'a dyn EvidenceQueryClient>,
    pub tick: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrainSpike {
    pub target: BrainTarget,
    pub tick: u64,
    pub amplitude_q: u16,
}

impl BrainSpike {
    pub fn new(target: BrainTarget, tick: u64, amplitude_q: u16) -> Self {
        Self {
            target,
            tick,
            amplitude_q: amplitude_q.min(1000),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechIntRecord {
    pub session_id: String,
    pub step_id: String,
    pub token_digest: [u8; 32],
    pub tap_digests: Vec<[u8; 32]>,
    pub tap_summaries: Vec<TapSummary>,
    pub feature_event_digests: Vec<[u8; 32]>,
    pub mapping_digest: [u8; 32],
    pub world_state_digest: [u8; 32],
    pub prediction_error_score: i32,
    pub wm_prediction_error_score: i32,
    pub wm_modulation_plan: WorldModulationPlan,
    pub wm_modulation_reason_codes: Vec<String>,
    pub max_spikes_eff: u32,
    pub top_k_eff: u16,
    pub amp_cap_eff: u16,
    pub fanout_eff: u32,
    pub rlm_directives: Vec<RlmDirective>,
    pub deliberation_budget: DeliberationBudget,
    pub followup_executed: bool,
    pub followup_control_frame_digest: Option<[u8; 32]>,
    pub followup_language_step_digest: Option<[u8; 32]>,
    pub self_state_digest: [u8; 32],
    pub reason_codes: Vec<String>,
    pub feedback: Option<FeedbackSummary>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
    pub proposal_digest: Option<[u8; 32]>,
    pub proposal_kind: Option<ProposalKind>,
    pub proposal_eval_score: Option<i32>,
    pub proposal_verdict: Option<EvalVerdict>,
    pub proposal_base_evidence_digest: Option<[u8; 32]>,
    pub aap_digest: Option<[u8; 32]>,
    pub approval_digest: Option<[u8; 32]>,
    pub activation_result: Option<ActivationResult>,
    pub active_mapping_digest: Option<[u8; 32]>,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_injection_limits: Option<InjectionLimits>,
    pub activation_digest: Option<[u8; 32]>,
    pub committed_to_pvgs: Option<bool>,
    pub shadow_evidence: Option<ShadowEvidence>,
    pub record_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechIntRecordParts {
    pub session_id: String,
    pub step_id: String,
    pub token_digest: [u8; 32],
    pub tap_summaries: Vec<TapSummary>,
    pub feature_event_digests: Vec<[u8; 32]>,
    pub mapping_digest: [u8; 32],
    pub world_state_digest: [u8; 32],
    pub prediction_error_score: i32,
    pub wm_prediction_error_score: i32,
    pub wm_modulation_plan: WorldModulationPlan,
    pub wm_modulation_reason_codes: Vec<String>,
    pub max_spikes_eff: u32,
    pub top_k_eff: u16,
    pub amp_cap_eff: u16,
    pub fanout_eff: u32,
    pub rlm_directives: Vec<RlmDirective>,
    pub deliberation_budget: DeliberationBudget,
    pub followup_executed: bool,
    pub followup_control_frame_digest: Option<[u8; 32]>,
    pub followup_language_step_digest: Option<[u8; 32]>,
    pub self_state_digest: [u8; 32],
    pub reason_codes: Vec<String>,
    pub feedback: Option<FeedbackSummary>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
    pub proposal_digest: Option<[u8; 32]>,
    pub proposal_kind: Option<ProposalKind>,
    pub proposal_eval_score: Option<i32>,
    pub proposal_verdict: Option<EvalVerdict>,
    pub proposal_base_evidence_digest: Option<[u8; 32]>,
    pub aap_digest: Option<[u8; 32]>,
    pub approval_digest: Option<[u8; 32]>,
    pub activation_result: Option<ActivationResult>,
    pub active_mapping_digest: Option<[u8; 32]>,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_injection_limits: Option<InjectionLimits>,
    pub activation_digest: Option<[u8; 32]>,
    pub committed_to_pvgs: Option<bool>,
    pub shadow_evidence: Option<ShadowEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapSummary {
    pub hook_id: String,
    pub activation_digest: [u8; 32],
    pub sample_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackSummary {
    pub tick: u64,
    pub snapshot_digest: [u8; 32],
    pub event_queue_overflowed: bool,
    pub events_dropped: u64,
    pub events_injected: u32,
    pub injected_total: u64,
}

impl FeedbackSummary {
    pub fn from_snapshot(snapshot: &BiophysFeedbackSnapshot) -> Self {
        Self {
            tick: snapshot.tick,
            snapshot_digest: snapshot.snapshot_digest,
            event_queue_overflowed: snapshot.event_queue_overflowed,
            events_dropped: snapshot.events_dropped,
            events_injected: snapshot.events_injected,
            injected_total: snapshot.injected_total,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingAdaptationSuggestion {
    pub amplitude_q_factor: u16,
    pub max_targets_per_feature: u16,
}

#[derive(Debug, Clone)]
pub struct MappingAdaptationConfig {
    pub enabled: bool,
    pub events_dropped_threshold: u64,
    pub amplitude_q_factor: u16,
    pub max_targets_per_feature: u16,
}

impl Default for MappingAdaptationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            events_dropped_threshold: 1,
            amplitude_q_factor: 900,
            max_targets_per_feature: 8,
        }
    }
}

impl MappingAdaptationConfig {
    pub fn suggest(
        &self,
        feedback: Option<&BiophysFeedbackSnapshot>,
    ) -> Option<MappingAdaptationSuggestion> {
        if !self.enabled {
            return None;
        }
        let feedback = feedback?;
        let dropped_high = feedback.events_dropped >= self.events_dropped_threshold;
        if !(feedback.event_queue_overflowed || dropped_high) {
            return None;
        }
        Some(MappingAdaptationSuggestion {
            amplitude_q_factor: self.amplitude_q_factor.clamp(1, 1000),
            max_targets_per_feature: self.max_targets_per_feature.max(1),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct FeedbackConsumer {
    pub last: Option<BiophysFeedbackSnapshot>,
}

impl FeedbackConsumer {
    pub fn ingest(&mut self, snap: BiophysFeedbackSnapshot) {
        self.last = Some(snap);
    }
}

impl TapSummary {
    pub fn from_tap(tap: &TapFrame) -> Self {
        Self {
            hook_id: tap.hook_id.clone(),
            activation_digest: tap.activation_digest,
            sample_len: tap.activation_bytes.len() as u32,
        }
    }
}

impl MechIntRecord {
    pub fn new(mut parts: MechIntRecordParts) -> Self {
        parts.tap_summaries.sort_by(|a, b| {
            a.hook_id
                .cmp(&b.hook_id)
                .then_with(|| a.activation_digest.cmp(&b.activation_digest))
        });
        parts.reason_codes.iter_mut().for_each(|code| {
            *code = bound_string(code);
        });
        parts.reason_codes.sort();
        parts.reason_codes.dedup();
        parts.reason_codes.truncate(MAX_REASON_CODES);
        parts
            .deliberation_budget
            .reason_codes
            .iter_mut()
            .for_each(|code| {
                *code = bound_string(code);
            });
        parts.deliberation_budget.reason_codes.sort();
        parts.deliberation_budget.reason_codes.dedup();
        parts
            .deliberation_budget
            .reason_codes
            .truncate(MAX_RLM_REASON_CODES);
        parts
            .wm_modulation_reason_codes
            .iter_mut()
            .for_each(|code| {
                *code = bound_string(code);
            });
        parts.wm_modulation_reason_codes.sort();
        parts.wm_modulation_reason_codes.dedup();
        parts.wm_modulation_reason_codes.truncate(MAX_REASON_CODES);
        if parts.rlm_directives.len() > MAX_RLM_DIRECTIVES {
            parts.rlm_directives.truncate(MAX_RLM_DIRECTIVES);
        }
        let mut tap_digests: Vec<[u8; 32]> = parts
            .tap_summaries
            .iter()
            .map(|summary| summary.activation_digest)
            .collect();
        tap_digests.sort();
        parts.feature_event_digests.sort();
        let record_digest = record_digest(&parts);
        Self {
            session_id: parts.session_id,
            step_id: parts.step_id,
            token_digest: parts.token_digest,
            tap_digests,
            tap_summaries: parts.tap_summaries,
            feature_event_digests: parts.feature_event_digests,
            mapping_digest: parts.mapping_digest,
            world_state_digest: parts.world_state_digest,
            prediction_error_score: parts.prediction_error_score,
            wm_prediction_error_score: parts.wm_prediction_error_score,
            wm_modulation_plan: parts.wm_modulation_plan,
            wm_modulation_reason_codes: parts.wm_modulation_reason_codes,
            max_spikes_eff: parts.max_spikes_eff,
            top_k_eff: parts.top_k_eff,
            amp_cap_eff: parts.amp_cap_eff,
            fanout_eff: parts.fanout_eff,
            rlm_directives: parts.rlm_directives,
            deliberation_budget: parts.deliberation_budget,
            followup_executed: parts.followup_executed,
            followup_control_frame_digest: parts.followup_control_frame_digest,
            followup_language_step_digest: parts.followup_language_step_digest,
            self_state_digest: parts.self_state_digest,
            reason_codes: parts.reason_codes,
            feedback: parts.feedback,
            mapping_suggestion: parts.mapping_suggestion,
            proposal_digest: parts.proposal_digest,
            proposal_kind: parts.proposal_kind,
            proposal_eval_score: parts.proposal_eval_score,
            proposal_verdict: parts.proposal_verdict,
            proposal_base_evidence_digest: parts.proposal_base_evidence_digest,
            aap_digest: parts.aap_digest,
            approval_digest: parts.approval_digest,
            activation_result: parts.activation_result,
            active_mapping_digest: parts.active_mapping_digest,
            active_sae_pack_digest: parts.active_sae_pack_digest,
            active_liquid_params_digest: parts.active_liquid_params_digest,
            active_injection_limits: parts.active_injection_limits,
            activation_digest: parts.activation_digest,
            committed_to_pvgs: parts.committed_to_pvgs,
            shadow_evidence: parts.shadow_evidence,
            record_digest,
        }
    }
}

fn record_digest(parts: &MechIntRecordParts) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(parts.session_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(parts.step_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&parts.token_digest);
    buf.extend_from_slice(&parts.mapping_digest);
    buf.extend_from_slice(&parts.world_state_digest);
    write_i32(&mut buf, parts.prediction_error_score);
    write_i32(&mut buf, parts.wm_prediction_error_score);
    write_u16(&mut buf, parts.wm_modulation_plan.feature_top_k_scale_q);
    write_u16(&mut buf, parts.wm_modulation_plan.spike_budget_scale_q);
    write_u16(&mut buf, parts.wm_modulation_plan.amplitude_cap_scale_q);
    write_u16(&mut buf, parts.wm_modulation_plan.fanout_cap_scale_q);
    buf.extend_from_slice(&(parts.wm_modulation_reason_codes.len() as u32).to_le_bytes());
    for code in &parts.wm_modulation_reason_codes {
        write_string(&mut buf, code);
    }
    write_u32(&mut buf, parts.max_spikes_eff);
    write_u16(&mut buf, parts.top_k_eff);
    write_u16(&mut buf, parts.amp_cap_eff);
    write_u32(&mut buf, parts.fanout_eff);
    buf.extend_from_slice(&parts.self_state_digest);
    buf.extend_from_slice(&(parts.rlm_directives.len() as u32).to_le_bytes());
    for directive in &parts.rlm_directives {
        buf.push(*directive as u8);
    }
    buf.push(u8::from(parts.deliberation_budget.allow_followup));
    buf.push(parts.deliberation_budget.max_followup_steps);
    buf.push(
        parts
            .deliberation_budget
            .selected_directive
            .map(|directive| directive as u8)
            .unwrap_or(0),
    );
    buf.extend_from_slice(&(parts.deliberation_budget.reason_codes.len() as u32).to_le_bytes());
    for code in &parts.deliberation_budget.reason_codes {
        write_string(&mut buf, code);
    }
    buf.push(u8::from(parts.followup_executed));
    match parts.followup_control_frame_digest {
        Some(digest_bytes) => {
            buf.push(1);
            buf.extend_from_slice(&digest_bytes);
        }
        None => buf.push(0),
    }
    match parts.followup_language_step_digest {
        Some(digest_bytes) => {
            buf.push(1);
            buf.extend_from_slice(&digest_bytes);
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&(parts.reason_codes.len() as u32).to_le_bytes());
    for code in &parts.reason_codes {
        write_string(&mut buf, code);
    }
    buf.extend_from_slice(&(parts.tap_summaries.len() as u32).to_le_bytes());
    for summary in &parts.tap_summaries {
        write_string(&mut buf, &summary.hook_id);
        buf.extend_from_slice(&summary.activation_digest);
        buf.extend_from_slice(&summary.sample_len.to_le_bytes());
    }
    buf.extend_from_slice(&(parts.feature_event_digests.len() as u32).to_le_bytes());
    for digest_bytes in &parts.feature_event_digests {
        buf.extend_from_slice(digest_bytes);
    }
    write_optional_feedback(&mut buf, parts.feedback.as_ref());
    write_optional_suggestion(&mut buf, parts.mapping_suggestion.as_ref());
    write_optional_proposal(&mut buf, parts);
    write_optional_activation(&mut buf, parts);
    write_optional_shadow(&mut buf, parts.shadow_evidence.as_ref());
    digest("lnss.mechint.record.v1", &buf)
}

#[derive(Debug, Clone)]
pub struct RuntimeOutput {
    pub output_bytes: Vec<u8>,
    pub taps: Vec<TapFrame>,
    pub feature_events: Vec<FeatureEvent>,
    pub spikes: Vec<BrainSpike>,
    pub feedback_snapshot: Option<BiophysFeedbackSnapshot>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
    pub mechint_record: MechIntRecord,
    pub shadow: Option<ShadowRunOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowScore {
    pub active: i32,
    pub shadow: i32,
    pub delta: i32,
}

#[derive(Debug, Clone, Copy)]
struct TraceContext {
    active_tick: u64,
    active_feedback_digest: [u8; 32],
    shadow_feedback_digest: [u8; 32],
    active_context_digest: [u8; 32],
    shadow_context_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvidence {
    pub shadow_mapping_digest: [u8; 32],
    pub shadow_liquid_params_digest: Option<[u8; 32]>,
    pub active_feedback_digest: [u8; 32],
    pub shadow_feedback_digest: [u8; 32],
    pub score: ShadowScore,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ShadowRunOutput {
    pub spikes: Vec<BrainSpike>,
    pub feedback_snapshot: BiophysFeedbackSnapshot,
    pub score: ShadowScore,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TraceRunState {
    pub trace_digest: [u8; 32],
    pub verdict: TraceVerdict,
    pub committed: bool,
    pub duplicate_skipped: bool,
    pub active_cfg_digest: [u8; 32],
    pub shadow_cfg_digest: [u8; 32],
    pub created_at_ms: u64,
}

impl LnssRuntime {
    pub fn run_step(
        &mut self,
        session_id: &str,
        step_id: &str,
        input: &[u8],
        mods: &EmotionFieldSnapshot,
        tap_specs: &[TapSpec],
    ) -> Result<RuntimeOutput, LnssRuntimeError> {
        let control_frame_digest = digest("lnss.control_frame.v1", input);
        let emotion_snapshot_digest = Some(emotion_snapshot_digest(mods));
        let prior_feedback_digest = self.feedback.last.as_ref().map(|snap| snap.snapshot_digest);
        let world_input = WorldModelInput {
            input_digest: control_frame_digest,
            prev_world_digest: self.world_state_digest,
            action_digest: self.last_action_digest,
        };
        let feedback_flags = feedback_anomaly_flags(self.feedback.last.as_ref());
        let rlm_input = RlmInput {
            control_frame_digest,
            policy_mode: self.policy_mode,
            control_intent: self.control_intent_class,
            feedback_flags,
            current_depth: 0,
        };
        let context = ContextBundle::new(
            control_frame_digest,
            None,
            None,
            self.world_state_digest,
            self.last_self_state_digest,
            emotion_snapshot_digest,
        );
        let mut language = LanguageCore::new(
            self.llm.as_mut(),
            self.hooks.as_mut(),
            mods,
            tap_specs,
            self.limits.clone(),
        );
        let policy_view = PolicyView {
            allow_internal_reflection: self.recursion_policy.allow_followup,
            feedback_drop_threshold: self.adaptation.events_dropped_threshold,
            worldmodel_pred_error_critical: false,
        };
        let orchestration = self.orchestrator.run_tick(
            self.worldmodel.as_mut(),
            &mut language,
            self.rlm.as_mut(),
            input,
            context,
            &world_input,
            &rlm_input,
            policy_view,
            self.feedback.last.as_ref(),
        );

        let CoreStepOutput {
            output_bytes: primary_output_bytes,
            taps: primary_taps,
        } = orchestration.language_output;
        let followup_output_bytes = orchestration
            .followup_output
            .as_ref()
            .map(|output| output.output_bytes.clone());
        let mut taps = primary_taps;
        if let Some(followup) = orchestration.followup_output.as_ref() {
            // Deterministic combine: concat first-pass taps with follow-up taps, then cap.
            taps.extend(followup.taps.clone());
        }
        taps.truncate(self.limits.max_taps);
        let output_bytes = followup_output_bytes
            .clone()
            .unwrap_or_else(|| primary_output_bytes.clone());
        let token_digest = digest("lnss.token_bytes.v1", &output_bytes);
        self.world_state_digest = orchestration.world_output.world_state_digest;
        self.last_self_state_digest = orchestration.rlm_output.self_state_digest;
        let action_bytes = followup_output_bytes.unwrap_or(primary_output_bytes.clone());
        self.last_action_digest = digest("lnss.action_bytes.v1", &action_bytes);
        let prediction_error_score = orchestration.world_output.prediction_error_score;
        let core_context_pack = CoreContextDigestPack {
            world_state_digest: orchestration.world_output.world_state_digest,
            self_state_digest: orchestration.rlm_output.self_state_digest,
            control_frame_digest,
            policy_digest: None,
            last_feedback_digest: prior_feedback_digest,
            wm_pred_error_bucket: wm_pred_error_bucket(prediction_error_score),
            rlm_followup_executed: orchestration.followup_output.is_some(),
        };
        let worldmodel_cfg = self.worldmodel.cfg_snapshot();
        let rlm_cfg = self.rlm.cfg_snapshot();
        let active_cfg_pack = cfg_root_digest_pack(CfgRootDigestInputs {
            llm: self.llm.as_ref(),
            tap_specs,
            worldmodel_cfg: &worldmodel_cfg,
            rlm_cfg: &rlm_cfg,
            sae_pack_digest: self.active_sae_pack_digest,
            mapping: &self.mapper,
            limits: &self.limits,
            injection_limits: &self.injection_limits,
            amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
            policy_digest: core_context_pack.policy_digest,
            liquid_params_digest: self.active_liquid_params_digest,
        });
        let active_cfg_root_digest = active_cfg_pack.as_ref().map(|pack| pack.root_cfg_digest);
        self.active_cfg_root_digest = active_cfg_root_digest;
        let shadow_cfg_root_digest = if self.shadow.enabled {
            let shadow_mapping = self.shadow.shadow_mapping.as_ref().unwrap_or(&self.mapper);
            let shadow_limits = self
                .shadow
                .shadow_injection_limits
                .as_ref()
                .unwrap_or(&self.injection_limits);
            #[cfg(feature = "lnss-liquid-ode")]
            let shadow_liquid_digest =
                shadow_liquid_params_digest(self.shadow.shadow_liquid_params.as_ref());
            #[cfg(not(feature = "lnss-liquid-ode"))]
            let shadow_liquid_digest = None;
            cfg_root_digest_pack(CfgRootDigestInputs {
                llm: self.llm.as_ref(),
                tap_specs,
                worldmodel_cfg: &worldmodel_cfg,
                rlm_cfg: &rlm_cfg,
                sae_pack_digest: self.active_sae_pack_digest,
                mapping: shadow_mapping,
                limits: &self.limits,
                injection_limits: shadow_limits,
                amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
                policy_digest: core_context_pack.policy_digest,
                liquid_params_digest: shadow_liquid_digest.or(self.active_liquid_params_digest),
            })
            .map(|pack| pack.root_cfg_digest)
        } else {
            None
        };
        self.shadow_cfg_root_digest = shadow_cfg_root_digest;
        let core_context_digest = core_context_pack.digest();
        let rlm_directives = orchestration.rlm_output.recursion_directives;
        let base_limits_for_plan = BaseLimits {
            top_k_base: MAX_TOP_FEATURES,
            max_spikes_per_tick: self.injection_limits.max_spikes_per_tick,
            amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
            fanout_cap: self.injection_limits.max_targets_per_spike,
        };
        let world_modulation_plan =
            compute_world_modulation(prediction_error_score, &base_limits_for_plan);
        let wm_modulation_reason_codes = world_modulation_plan.reason_codes.clone();
        let mut reason_codes = Vec::new();
        if prediction_error_score > self.pred_error_threshold {
            reason_codes.push(RC_WM_PRED_ERROR_HIGH.to_string());
        }
        if orchestration.recursion_used {
            reason_codes.push(RC_RLM_RECURSION_STEP.to_string());
        }
        if orchestration.recursion_blocked {
            if orchestration
                .deliberation_budget
                .reason_codes
                .iter()
                .any(|code| code == RC_RLM_RECURSION_BLOCKED_BY_POLICY)
            {
                reason_codes.push(RC_RLM_RECURSION_BLOCKED_BY_POLICY.to_string());
            }
            if orchestration
                .deliberation_budget
                .reason_codes
                .iter()
                .any(|code| code == RC_RLM_RECURSION_BLOCKED_BY_OVERLOAD)
            {
                reason_codes.push(RC_RLM_RECURSION_BLOCKED_BY_OVERLOAD.to_string());
            }
            if orchestration
                .deliberation_budget
                .reason_codes
                .iter()
                .any(|code| code == RC_RLM_RECURSION_BLOCKED_BY_WM)
            {
                reason_codes.push(RC_RLM_RECURSION_BLOCKED_BY_WM.to_string());
            }
        }
        if wm_modulation_reason_codes
            .iter()
            .any(|code| code == RC_WM_MODULATION_ACTIVE)
        {
            reason_codes.push(RC_WM_MODULATION_ACTIVE.to_string());
        }
        if wm_modulation_reason_codes
            .iter()
            .any(|code| code == RC_WM_PRED_ERROR_CRITICAL)
        {
            reason_codes.push(RC_WM_PRED_ERROR_CRITICAL.to_string());
        }

        let mut feature_events = Vec::new();
        let mut top_k_eff = 1usize;
        for tap in &taps {
            let mut event = self.sae.infer_features(tap);
            let event_top_k_base = event.top_features.len().max(1);
            let event_top_k_eff = effective_top_k(
                event_top_k_base,
                world_modulation_plan.feature_top_k_scale_q,
            );
            top_k_eff = top_k_eff.max(event_top_k_eff);
            event.top_features.truncate(event_top_k_eff);
            feature_events.push(event);
        }

        let effective_limits = apply_world_modulation_limits(
            &self.injection_limits,
            DEFAULT_AMPLITUDE_CAP_Q,
            &world_modulation_plan,
        );
        let max_spikes_eff = effective_limits
            .max_spikes_per_tick
            .min(self.limits.max_spikes as u32);
        let spike_result = map_features_to_spikes_with_limits(
            &self.mapper,
            &feature_events,
            &effective_limits,
            max_spikes_eff as usize,
        );
        let spikes = spike_result.spikes;
        self.rig.send_spikes(&spikes)?;
        if let Some(snapshot) = self.rig.poll_feedback() {
            self.feedback.ingest(snapshot);
        }
        let feedback_snapshot = self.feedback.last.clone();
        let lifecycle_tick = feedback_snapshot
            .as_ref()
            .map(|snap| snap.tick)
            .unwrap_or(0);
        self.lifecycle_tick = lifecycle_tick;
        let feedback_summary = feedback_snapshot
            .as_ref()
            .map(FeedbackSummary::from_snapshot);
        let mapping_suggestion = self.adaptation.suggest(feedback_snapshot.as_ref());

        let tap_summaries = taps.iter().map(TapSummary::from_tap).collect();
        let feature_event_digests = feature_events
            .iter()
            .map(|event| event.event_digest)
            .collect();
        let mut mechint_parts = MechIntRecordParts {
            session_id: session_id.to_string(),
            step_id: step_id.to_string(),
            token_digest,
            tap_summaries,
            feature_event_digests,
            mapping_digest: self.mapper.map_digest,
            world_state_digest: orchestration.world_output.world_state_digest,
            prediction_error_score,
            wm_prediction_error_score: prediction_error_score,
            wm_modulation_plan: world_modulation_plan.clone(),
            wm_modulation_reason_codes: wm_modulation_reason_codes.clone(),
            max_spikes_eff,
            top_k_eff: top_k_eff as u16,
            amp_cap_eff: effective_limits.amplitude_cap_q,
            fanout_eff: effective_limits.fanout_cap,
            rlm_directives: rlm_directives.clone(),
            deliberation_budget: orchestration.deliberation_budget.clone(),
            followup_executed: orchestration.followup_output.is_some(),
            followup_control_frame_digest: orchestration.followup_control_frame_digest,
            followup_language_step_digest: orchestration.followup_language_step_digest,
            self_state_digest: orchestration.rlm_output.self_state_digest,
            reason_codes,
            feedback: feedback_summary,
            mapping_suggestion: mapping_suggestion.clone(),
            proposal_digest: None,
            proposal_kind: None,
            proposal_eval_score: None,
            proposal_verdict: None,
            proposal_base_evidence_digest: None,
            aap_digest: None,
            approval_digest: None,
            activation_result: None,
            active_mapping_digest: None,
            active_sae_pack_digest: None,
            active_liquid_params_digest: None,
            active_injection_limits: None,
            activation_digest: None,
            committed_to_pvgs: None,
            shadow_evidence: None,
        };

        let effective_injection_limits = InjectionLimits {
            max_spikes_per_tick: max_spikes_eff,
            max_targets_per_spike: effective_limits.fanout_cap,
        };
        let shadow_output = if self.shadow.enabled {
            self.shadow.validate(
                &self.mapper,
                #[cfg(feature = "lnss-liquid-ode")]
                self.active_liquid_params.as_ref(),
                &self.injection_limits,
            )?;
            let shadow_mapping = self.shadow.shadow_mapping.as_ref().unwrap_or(&self.mapper);
            let shadow_limits = self
                .shadow
                .shadow_injection_limits
                .as_ref()
                .unwrap_or(&self.injection_limits);
            let shadow_effective_limits = apply_world_modulation_limits(
                shadow_limits,
                DEFAULT_AMPLITUDE_CAP_Q,
                &world_modulation_plan,
            );
            let shadow_max_spikes_eff = shadow_effective_limits
                .max_spikes_per_tick
                .min(self.limits.max_spikes as u32);
            let shadow_spike_result = map_features_to_spikes_with_limits(
                shadow_mapping,
                &feature_events,
                &shadow_effective_limits,
                shadow_max_spikes_eff as usize,
            );
            let shadow_spikes = shadow_spike_result.spikes;

            let shadow_feedback_snapshot = if let Some(shadow_rig) = self.shadow_rig.as_mut() {
                shadow_rig.send_spikes(&shadow_spikes)?;
                shadow_rig.poll_feedback()
            } else {
                let shadow_injection_limits = InjectionLimits {
                    max_spikes_per_tick: shadow_max_spikes_eff,
                    max_targets_per_spike: shadow_effective_limits.fanout_cap,
                };
                Some(predict_feedback_snapshot(
                    &shadow_spikes,
                    &shadow_injection_limits,
                ))
            };

            let active_feedback_snapshot = feedback_snapshot.clone().or_else(|| {
                Some(predict_feedback_snapshot(
                    &spikes,
                    &effective_injection_limits,
                ))
            });

            if let (Some(active_feedback), Some(shadow_feedback)) = (
                active_feedback_snapshot.as_ref(),
                shadow_feedback_snapshot.as_ref(),
            ) {
                let (score, reason_codes) = score_shadow(active_feedback, shadow_feedback);
                let shadow_mapping_digest = shadow_mapping.map_digest;
                #[cfg(feature = "lnss-liquid-ode")]
                let shadow_params_digest =
                    shadow_liquid_params_digest(self.shadow.shadow_liquid_params.as_ref());
                #[cfg(not(feature = "lnss-liquid-ode"))]
                let shadow_params_digest = None;
                let shadow_evidence = ShadowEvidence {
                    shadow_mapping_digest,
                    shadow_liquid_params_digest: shadow_params_digest,
                    active_feedback_digest: active_feedback.snapshot_digest,
                    shadow_feedback_digest: shadow_feedback.snapshot_digest,
                    score: score.clone(),
                    reason_codes: reason_codes.clone(),
                };
                let mut shadow_parts = mechint_parts.clone();
                shadow_parts.step_id = format!("{step_id}:shadow");
                shadow_parts.shadow_evidence = Some(shadow_evidence);
                let shadow_record = MechIntRecord::new(shadow_parts);
                self.mechint.write_step(&shadow_record)?;

                let trace_context = TraceContext {
                    active_tick: active_feedback.tick,
                    active_feedback_digest: active_feedback.snapshot_digest,
                    shadow_feedback_digest: shadow_feedback.snapshot_digest,
                    active_context_digest: core_context_digest,
                    shadow_context_digest: core_context_digest,
                };
                if let (Some(active_cfg_root_digest), Some(shadow_cfg_root_digest)) =
                    (active_cfg_root_digest, shadow_cfg_root_digest)
                {
                    let trace_state = self.commit_trace_run_evidence(
                        step_id,
                        &score,
                        &reason_codes,
                        active_cfg_root_digest,
                        shadow_cfg_root_digest,
                        trace_context,
                    );
                    self.trace_state = Some(trace_state);
                } else {
                    self.trace_state = None;
                }
                if let Some(state) = self.trace_state.as_ref() {
                    if state.duplicate_skipped {
                        mechint_parts
                            .reason_codes
                            .push(RC_TRACE_DUPLICATE_SKIPPED.to_string());
                    }
                }

                Some(ShadowRunOutput {
                    spikes: shadow_spikes,
                    feedback_snapshot: shadow_feedback.clone(),
                    score,
                    reason_codes,
                })
            } else {
                None
            }
        } else {
            None
        };

        let eval_ctx = EvalContext {
            latest_feedback_digest: feedback_snapshot.as_ref().map(|snap| snap.snapshot_digest),
            trace_run_digest: self
                .trace_state
                .as_ref()
                .filter(|state| state.committed)
                .map(|state| state.trace_digest),
            metrics: feedback_snapshot
                .as_ref()
                .map(|snap| {
                    vec![
                        (
                            "event_queue_overflowed".to_string(),
                            i64::from(snap.event_queue_overflowed),
                        ),
                        ("events_dropped".to_string(), snap.events_dropped as i64),
                        ("events_injected".to_string(), snap.events_injected as i64),
                        ("injected_total".to_string(), snap.injected_total as i64),
                    ]
                })
                .unwrap_or_default(),
        };
        let constraints = ActiveConstraints {
            cooldown_active: !orchestration.deliberation_budget.allow_followup
                && orchestration
                    .deliberation_budget
                    .selected_directive
                    .is_some(),
            modulation_active: wm_modulation_reason_codes
                .iter()
                .any(|code| code == RC_WM_MODULATION_ACTIVE),
        };
        let artifacts_dir = self
            .proposal_inbox
            .as_ref()
            .map(|inbox| inbox.dir.join("generated"));
        let liquid_params = {
            #[cfg(feature = "lnss-liquid-ode")]
            {
                self.active_liquid_params
                    .as_ref()
                    .map(|params| LiquidParamsSnapshot {
                        dt_ms_q: params.dt_ms_q,
                        steps_per_call: params.steps_per_call,
                    })
                    .unwrap_or_default()
            }
            #[cfg(not(feature = "lnss-liquid-ode"))]
            {
                LiquidParamsSnapshot::default()
            }
        };
        let active_cfg = ActiveCfg {
            created_at_ms: feedback_snapshot
                .as_ref()
                .map(|snap| snap.tick.saturating_mul(FIXED_MS_PER_TICK))
                .unwrap_or(0),
            base_evidence_digest: feedback_snapshot
                .as_ref()
                .map(|snap| snap.snapshot_digest)
                .unwrap_or([0u8; 32]),
            active_cfg_root_digest: active_cfg_root_digest.unwrap_or([0u8; 32]),
            core_context_digest_pack: core_context_pack.clone(),
            mapping: self.mapper.clone(),
            max_spikes_per_tick: self.injection_limits.max_spikes_per_tick,
            max_targets_per_spike: self.injection_limits.max_targets_per_spike,
            liquid_params,
            rlm_directives: rlm_directives.clone(),
            allow_followup: orchestration.deliberation_budget.allow_followup,
            artifacts_dir,
        };
        let trigger_set =
            extract_triggers(&core_context_pack, feedback_snapshot.as_ref(), &constraints);
        if self.trigger_proposals_enabled && active_cfg_root_digest.is_some() {
            if let Some(proposal) =
                propose_from_triggers(&trigger_set, &active_cfg, core_context_digest)
            {
                let key = LifecycleKey {
                    proposal_digest: proposal.proposal_digest,
                    context_digest: proposal.core_context_digest,
                    active_cfg_root_digest: proposal.base_active_cfg_digest,
                };
                hydrate_lifecycle_from_query(
                    &mut self.lifecycle_index,
                    self.evidence_query_client.as_deref(),
                    key,
                    lifecycle_tick,
                );
                if !proposal_is_duplicate(&self.lifecycle_index, &proposal) {
                    self.lifecycle_index.note_proposal(key, lifecycle_tick);
                    let eval = evaluate(&proposal, &eval_ctx);
                    let payload_digest = proposal_payload_digest(&proposal.payload)
                        .map_err(|err| LnssRuntimeError::Proposal(err.to_string()))?;
                    let evidence = ProposalEvidence {
                        proposal_id: proposal.proposal_id.clone(),
                        proposal_digest: proposal.proposal_digest,
                        kind: proposal.kind.clone(),
                        base_evidence_digest: proposal.base_evidence_digest,
                        core_context_digest: proposal.core_context_digest,
                        payload_digest,
                        created_at_ms: proposal.created_at_ms,
                        score: eval.score,
                        verdict: eval.verdict.clone(),
                        reason_codes: eval.reason_codes.clone(),
                    };
                    let evidence_pb = build_proposal_evidence_pb(&evidence);
                    let payload_bytes = canonical_bytes(&evidence_pb);
                    let committed = match self.pvgs.as_deref_mut() {
                        Some(client) => match client.commit_proposal_evidence(payload_bytes) {
                            Ok(receipt) => {
                                receipt.status == ucf::v1::ReceiptStatus::Accepted as i32
                            }
                            Err(_) => false,
                        },
                        None => true,
                    };
                    if committed {
                        if self.shadow.enabled {
                            self.schedule_shadow_for_proposal(&proposal, &active_cfg);
                        } else {
                            eprintln!(
                                "pending simulation: proposal={} context={}",
                                hex::encode(&proposal.proposal_digest[..4]),
                                hex::encode(&proposal.core_context_digest[..4])
                            );
                        }
                    }
                }
            }
        } else if self.trigger_proposals_enabled {
            eprintln!("cfg root digest missing: proposals disabled for step {step_id}");
        }

        let mechint_record = MechIntRecord::new(mechint_parts.clone());
        self.mechint.write_step(&mechint_record)?;

        if let Some(inbox) = self.proposal_inbox.as_mut() {
            inbox.ingest(
                &eval_ctx,
                &mechint_parts,
                self.mechint.as_mut(),
                self.pvgs.as_deref_mut(),
                self.trace_state.as_ref(),
                LifecycleInputs {
                    index: &mut self.lifecycle_index,
                    evidence_query: self.evidence_query_client.as_deref(),
                    tick: lifecycle_tick,
                },
            )?;
        }

        self.handle_approval_activation(&mechint_parts, lifecycle_tick)?;

        Ok(RuntimeOutput {
            output_bytes,
            taps,
            feature_events,
            spikes,
            feedback_snapshot,
            mapping_suggestion,
            mechint_record,
            shadow: shadow_output,
        })
    }

    fn schedule_shadow_for_proposal(&mut self, proposal: &Proposal, active_cfg: &ActiveCfg) {
        if !self.shadow.enabled {
            return;
        }
        match &proposal.payload {
            ProposalPayload::InjectionLimitsUpdate {
                max_spikes_per_tick,
                max_targets_per_spike,
            } => {
                self.shadow.shadow_injection_limits = Some(InjectionLimits {
                    max_spikes_per_tick: *max_spikes_per_tick,
                    max_targets_per_spike: *max_targets_per_spike,
                });
            }
            ProposalPayload::MappingUpdate { .. } => {
                let plan = mapping_update_plan(active_cfg);
                self.shadow.shadow_mapping = Some(plan.map);
            }
            ProposalPayload::LiquidParamsUpdate { .. } => {
                #[cfg(feature = "lnss-liquid-ode")]
                {
                    let Some(active) = self.active_liquid_params.as_ref() else {
                        eprintln!("pending simulation: liquid params update missing active params");
                        return;
                    };
                    let (_payload, snapshot) = liquid_params_update_payload(active_cfg);
                    let mut next = active.clone();
                    next.dt_ms_q = snapshot.dt_ms_q;
                    next.steps_per_call = snapshot.steps_per_call;
                    self.shadow.shadow_liquid_params = Some(next);
                }
                #[cfg(not(feature = "lnss-liquid-ode"))]
                {
                    eprintln!("pending simulation: liquid params update requires lnss-liquid-ode");
                }
            }
            ProposalPayload::SaePackUpdate { .. } => {}
        }
    }

    fn handle_approval_activation(
        &mut self,
        base_parts: &MechIntRecordParts,
        lifecycle_tick: u64,
    ) -> Result<(), LnssRuntimeError> {
        let (plan, current_state) = match self.approval_inbox.as_mut() {
            Some(inbox) => {
                let plan = inbox.next_activation()?;
                let mut state = inbox.state().clone();
                if state.active_mapping_digest.is_none() {
                    state.active_mapping_digest = Some(self.mapper.map_digest);
                }
                if state.active_sae_pack_digest.is_none() {
                    state.active_sae_pack_digest = self.active_sae_pack_digest;
                }
                if state.active_liquid_params_digest.is_none() {
                    state.active_liquid_params_digest = self.active_liquid_params_digest;
                }
                if state.active_injection_limits.is_none() {
                    state.active_injection_limits = Some(self.injection_limits.clone());
                }
                (plan, state)
            }
            None => return Ok(()),
        };

        let Some(plan) = plan else {
            return Ok(());
        };

        let key = LifecycleKey {
            proposal_digest: plan.proposal.proposal_digest,
            context_digest: plan.proposal.core_context_digest,
            active_cfg_root_digest: plan.proposal.base_active_cfg_digest,
        };
        hydrate_lifecycle_from_query(
            &mut self.lifecycle_index,
            self.evidence_query_client.as_deref(),
            key,
            lifecycle_tick,
        );
        self.lifecycle_index
            .note_approval(key, plan.approval_digest, lifecycle_tick);
        let lifecycle_state = self
            .lifecycle_index
            .state_for(&key)
            .cloned()
            .unwrap_or_default();
        let activation_applied =
            lifecycle_state.latest_activation_status == Some(ACTIVATION_STATUS_APPLIED);
        let trace_verdict_ok =
            lifecycle_state.latest_trace_verdict == Some(TRACE_VERDICT_PROMISING);
        let trace_digest_ok = plan
            .aap_trace_digest
            .map(|digest| Some(digest) == lifecycle_state.latest_trace_digest)
            .unwrap_or(false);
        let context_ok = plan
            .aap_context_digest
            .map(|digest| digest == plan.proposal.core_context_digest)
            .unwrap_or(true);
        let preconditions_ok =
            trace_verdict_ok && trace_digest_ok && context_ok && !activation_applied;
        if !preconditions_ok {
            eprintln!(
                "{RC_PROPOSAL_ACTIVATION_PRECONDITION_FAILED}: proposal={} context={} trace_ok={} activation_applied={}",
                hex::encode(&key.proposal_digest[..4]),
                hex::encode(&key.context_digest[..4]),
                trace_verdict_ok && trace_digest_ok && context_ok,
                activation_applied
            );
        }

        let outcome = if preconditions_ok {
            self.apply_activation_plan(&plan, &current_state)
        } else {
            ActivationOutcome::rejected(current_state.clone())
        };
        let activation_status = match outcome.result {
            ActivationResult::Applied => ActivationStatus::Applied,
            ActivationResult::Rejected => ActivationStatus::Rejected,
        };
        let activation_id = activation_id_for(plan.proposal.proposal_digest, plan.approval_digest);
        let created_at_ms = self.activation_now_ms.unwrap_or_else(|| {
            base_parts
                .feedback
                .as_ref()
                .map(|feedback| feedback.tick.saturating_mul(FIXED_MS_PER_TICK))
                .unwrap_or(0)
        });
        let activation_reason_code = if preconditions_ok {
            match outcome.result {
                ActivationResult::Applied => RC_PROPOSAL_ACTIVATED.to_string(),
                ActivationResult::Rejected => RC_PROPOSAL_REJECTED.to_string(),
            }
        } else {
            RC_PROPOSAL_ACTIVATION_PRECONDITION_FAILED.to_string()
        };
        let mut activation =
            ProposalActivationEvidenceLocal {
                activation_id,
                proposal_digest: plan.proposal.proposal_digest,
                approval_digest: plan.approval_digest,
                core_context_digest: plan.proposal.core_context_digest,
                status: activation_status.clone(),
                active_mapping_digest: outcome.state.active_mapping_digest,
                active_sae_pack_digest: outcome.state.active_sae_pack_digest,
                active_liquid_params_digest: outcome.state.active_liquid_params_digest,
                active_injection_limits: outcome.state.active_injection_limits.as_ref().map(
                    |limits| ActivationInjectionLimits {
                        max_spikes_per_tick: limits.max_spikes_per_tick,
                        max_targets_per_spike: limits.max_targets_per_spike,
                    },
                ),
                created_at_ms,
                reason_codes: vec![activation_reason_code.clone()],
                activation_digest: [0u8; 32],
            };
        let activation_pb = build_activation_evidence_pb(&activation);
        activation.activation_digest = activation_pb
            .activation_digest
            .as_ref()
            .and_then(digest_bytes)
            .unwrap_or([0u8; 32]);
        let activation_payload = canonical_bytes(&activation_pb);
        let mut committed_to_pvgs = None;
        let mut activation_digest = None;
        if let Some(inbox) = self.approval_inbox.as_mut() {
            activation_digest = Some(activation.activation_digest);
            if inbox.has_seen_activation(&activation.activation_digest) {
                committed_to_pvgs = Some(false);
            } else {
                let committed = match self.pvgs.as_deref_mut() {
                    Some(client) => match client.commit_proposal_activation(activation_payload) {
                        Ok(receipt) => receipt.status == ucf::v1::ReceiptStatus::Accepted as i32,
                        Err(_) => false,
                    },
                    None => false,
                };
                committed_to_pvgs = Some(committed);
                inbox.mark_activation_seen(activation.activation_digest);
            }
        }

        if let Some(sink) = self.event_sink.as_mut() {
            sink.on_activation_event(activation.activation_digest, outcome.result.clone());
        }

        let mut activation_parts = base_parts.clone();
        if !preconditions_ok {
            activation_parts
                .reason_codes
                .push(RC_PROPOSAL_ACTIVATION_PRECONDITION_FAILED.to_string());
        }
        activation_parts.proposal_digest = Some(plan.proposal.proposal_digest);
        activation_parts.proposal_kind = Some(plan.proposal.kind.clone());
        activation_parts.aap_digest = Some(plan.aap_digest);
        activation_parts.approval_digest = Some(plan.approval_digest);
        activation_parts.activation_result = Some(outcome.result.clone());
        activation_parts.active_mapping_digest = outcome.state.active_mapping_digest;
        activation_parts.active_sae_pack_digest = outcome.state.active_sae_pack_digest;
        activation_parts.active_liquid_params_digest = outcome.state.active_liquid_params_digest;
        activation_parts.active_injection_limits = outcome.state.active_injection_limits.clone();
        activation_parts.activation_digest = activation_digest;
        activation_parts.committed_to_pvgs = committed_to_pvgs;
        let activation_record = MechIntRecord::new(activation_parts);
        self.mechint.write_step(&activation_record)?;

        if let Some(inbox) = self.approval_inbox.as_mut() {
            inbox.set_state(outcome.state)?;
        }

        if let Some(activation_digest) = activation_digest {
            let status = match activation_status {
                ActivationStatus::Applied => ACTIVATION_STATUS_APPLIED,
                ActivationStatus::Rejected => ACTIVATION_STATUS_REJECTED,
            };
            self.lifecycle_index
                .note_activation(key, activation_digest, status, lifecycle_tick);
        }

        Ok(())
    }

    fn commit_trace_run_evidence(
        &mut self,
        step_id: &str,
        score: &ShadowScore,
        reason_codes: &[String],
        active_cfg_root_digest: [u8; 32],
        shadow_cfg_root_digest: [u8; 32],
        trace_context: TraceContext,
    ) -> TraceRunState {
        let verdict = trace_verdict_from_delta(score.delta);
        let created_at_ms = trace_context.active_tick.saturating_mul(FIXED_MS_PER_TICK);
        let trace_id = trace_id_for(
            active_cfg_root_digest,
            shadow_cfg_root_digest,
            trace_context.active_tick,
        );
        let mut trace_reason_codes = reason_codes.to_vec();
        trace_reason_codes.push(trace_verdict_reason_code(&verdict).to_string());

        let mut trace_evidence = TraceRunEvidenceLocal {
            trace_id,
            active_cfg_digest: active_cfg_root_digest,
            shadow_cfg_digest: shadow_cfg_root_digest,
            active_feedback_digest: trace_context.active_feedback_digest,
            shadow_feedback_digest: trace_context.shadow_feedback_digest,
            active_context_digest: trace_context.active_context_digest,
            shadow_context_digest: trace_context.shadow_context_digest,
            score_active: score.active,
            score_shadow: score.shadow,
            delta: score.delta,
            verdict: verdict.clone(),
            created_at_ms,
            reason_codes: trace_reason_codes,
            trace_digest: [0u8; 32],
        };
        let trace_pb = build_trace_run_evidence_pb(&trace_evidence);
        let trace_digest = trace_pb
            .trace_digest
            .as_ref()
            .and_then(digest_bytes)
            .unwrap_or([0u8; 32]);
        trace_evidence.trace_digest = trace_digest;
        let payload_bytes = canonical_bytes(&trace_pb);

        let duplicate_skipped = self.seen_trace_digests.contains(&trace_digest);
        let committed = if duplicate_skipped {
            true
        } else {
            let committed = match self.pvgs.as_deref_mut() {
                Some(client) => match client.commit_trace_run_evidence(payload_bytes) {
                    Ok(receipt) => receipt.status == ucf::v1::ReceiptStatus::Accepted as i32,
                    Err(err) => {
                        eprintln!("trace run commit failed for {step_id}: {err}");
                        false
                    }
                },
                None => true,
            };
            if committed {
                self.seen_trace_digests.insert(trace_digest);
            }
            committed
        };

        TraceRunState {
            trace_digest,
            verdict,
            committed,
            duplicate_skipped,
            active_cfg_digest: active_cfg_root_digest,
            shadow_cfg_digest: shadow_cfg_root_digest,
            created_at_ms,
        }
    }

    fn apply_activation_plan(
        &mut self,
        plan: &ActivationPlan,
        current_state: &ActivationState,
    ) -> ActivationOutcome {
        let approved = decision_allows_application(&plan.approval);
        if !approved {
            return ActivationOutcome::rejected(current_state.clone());
        }

        let result = match plan.proposal.payload.clone() {
            lnss_evolve::ProposalPayload::MappingUpdate {
                new_map_path,
                map_digest,
                ..
            } => self
                .apply_mapping_update(Path::new(&new_map_path), map_digest)
                .map(|_| {
                    let mut next = current_state.clone();
                    next.active_mapping_digest = Some(self.mapper.map_digest);
                    next
                }),
            lnss_evolve::ProposalPayload::SaePackUpdate {
                pack_path,
                pack_digest,
            } => self
                .apply_sae_pack_update(Path::new(&pack_path), pack_digest)
                .map(|_| {
                    let mut next = current_state.clone();
                    next.active_sae_pack_digest = Some(pack_digest);
                    next
                }),
            lnss_evolve::ProposalPayload::LiquidParamsUpdate {
                param_set,
                params_digest,
            } => self
                .apply_liquid_params_update(params_digest, &param_set)
                .map(|_| {
                    let mut next = current_state.clone();
                    next.active_liquid_params_digest = Some(params_digest);
                    next
                }),
            lnss_evolve::ProposalPayload::InjectionLimitsUpdate {
                max_spikes_per_tick,
                max_targets_per_spike,
            } => self
                .apply_injection_limits_update(max_spikes_per_tick, max_targets_per_spike)
                .map(|_| {
                    let mut next = current_state.clone();
                    next.active_injection_limits = Some(InjectionLimits {
                        max_spikes_per_tick,
                        max_targets_per_spike,
                    });
                    next
                }),
        };

        match result {
            Ok(state) => ActivationOutcome::applied(state),
            Err(_) => ActivationOutcome::rejected(current_state.clone()),
        }
    }
}

impl ProposalApplier for LnssRuntime {
    fn apply_mapping_update(
        &mut self,
        path: &Path,
        digest: [u8; 32],
    ) -> Result<(), LnssRuntimeError> {
        let bytes = fs::read(path).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        let computed = digest_file_bytes(&bytes);
        if computed != digest {
            return Err(LnssRuntimeError::Approval(
                "mapping digest mismatch".to_string(),
            ));
        }
        let map: FeatureToBrainMap = serde_json::from_slice(&bytes)
            .map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        self.mapper = map;
        Ok(())
    }

    fn apply_sae_pack_update(
        &mut self,
        path: &Path,
        digest: [u8; 32],
    ) -> Result<(), LnssRuntimeError> {
        let bytes = fs::read(path).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        let computed = digest_file_bytes(&bytes);
        if computed != digest {
            return Err(LnssRuntimeError::Approval(
                "sae pack digest mismatch".to_string(),
            ));
        }
        self.active_sae_pack_digest = Some(digest);
        Ok(())
    }

    fn apply_liquid_params_update(
        &mut self,
        params_digest: [u8; 32],
        kv_pairs: &[(String, String)],
    ) -> Result<(), LnssRuntimeError> {
        let computed = liquid_params_digest(kv_pairs);
        if computed != params_digest {
            return Err(LnssRuntimeError::Approval(
                "liquid params digest mismatch".to_string(),
            ));
        }
        self.active_liquid_params_digest = Some(params_digest);
        Ok(())
    }

    fn apply_injection_limits_update(
        &mut self,
        max_spikes: u32,
        max_targets: u32,
    ) -> Result<(), LnssRuntimeError> {
        self.limits.max_spikes = max_spikes as usize;
        self.injection_limits = InjectionLimits {
            max_spikes_per_tick: max_spikes,
            max_targets_per_spike: max_targets,
        };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpikeBudgetResult {
    pub spikes: Vec<BrainSpike>,
    pub dropped: usize,
}

pub fn effective_top_k(base_top_k: usize, scale_q: u16) -> usize {
    let base_top_k = base_top_k.max(1);
    let scaled = ((base_top_k as u32) * (scale_q as u32) / 1000) as usize;
    scaled.clamp(1, base_top_k)
}

pub fn apply_world_modulation_limits(
    base_limits: &InjectionLimits,
    amplitude_cap_q: u16,
    plan: &WorldModulationPlan,
) -> EffectiveWorldLimits {
    EffectiveWorldLimits {
        max_spikes_per_tick: scaled_u32(base_limits.max_spikes_per_tick, plan.spike_budget_scale_q)
            .max(1)
            .min(base_limits.max_spikes_per_tick),
        amplitude_cap_q: scaled_u16(amplitude_cap_q, plan.amplitude_cap_scale_q)
            .max(1)
            .min(amplitude_cap_q),
        fanout_cap: scaled_u32(base_limits.max_targets_per_spike, plan.fanout_cap_scale_q)
            .max(1)
            .min(base_limits.max_targets_per_spike),
    }
}

pub fn map_features_to_spikes_with_limits(
    mapper: &FeatureToBrainMap,
    feature_events: &[FeatureEvent],
    limits: &EffectiveWorldLimits,
    max_spikes_cap: usize,
) -> SpikeBudgetResult {
    let mut candidates = Vec::new();
    let mut entries = mapper.entries.clone();
    entries.sort_by(|(feature_a, target_a), (feature_b, target_b)| {
        feature_a
            .cmp(feature_b)
            .then_with(|| target_a.region.cmp(&target_b.region))
            .then_with(|| target_a.population.cmp(&target_b.population))
            .then_with(|| target_a.neuron_group.cmp(&target_b.neuron_group))
            .then_with(|| target_a.syn_kind.cmp(&target_b.syn_kind))
            .then_with(|| target_a.amplitude_q.cmp(&target_b.amplitude_q))
    });
    entries.truncate(MAX_MAPPING_ENTRIES);

    for event in feature_events {
        for (feature_id, strength_q) in event.top_features.iter().take(MAX_TOP_FEATURES) {
            let mut fanout = 0u32;
            for (_, target) in entries.iter().filter(|(id, _)| id == feature_id) {
                if fanout >= limits.fanout_cap {
                    break;
                }
                let scaled = ((*strength_q as u32) * (target.amplitude_q as u32) / 1000) as u16;
                let capped = scaled.min(limits.amplitude_cap_q);
                if capped > 0 {
                    candidates.push(SpikeCandidate {
                        spike: BrainSpike::new(target.clone(), 0, capped),
                        priority_q: *strength_q,
                        feature_id: *feature_id,
                    });
                    fanout = fanout.saturating_add(1);
                }
            }
        }
    }

    candidates.sort_by(|a, b| {
        b.priority_q
            .cmp(&a.priority_q)
            .then_with(|| b.spike.amplitude_q.cmp(&a.spike.amplitude_q))
            .then_with(|| a.feature_id.cmp(&b.feature_id))
            .then_with(|| a.spike.target.region.cmp(&b.spike.target.region))
            .then_with(|| a.spike.target.population.cmp(&b.spike.target.population))
            .then_with(|| {
                a.spike
                    .target
                    .neuron_group
                    .cmp(&b.spike.target.neuron_group)
            })
            .then_with(|| a.spike.target.syn_kind.cmp(&b.spike.target.syn_kind))
            .then_with(|| a.spike.target.amplitude_q.cmp(&b.spike.target.amplitude_q))
    });

    let max_spikes_eff = limits.max_spikes_per_tick.max(1).min(max_spikes_cap as u32) as usize;
    let dropped = candidates.len().saturating_sub(max_spikes_eff);
    let spikes = candidates
        .into_iter()
        .take(max_spikes_eff)
        .map(|candidate| candidate.spike)
        .collect();
    SpikeBudgetResult { spikes, dropped }
}

pub fn map_features_to_spikes(
    mapper: &FeatureToBrainMap,
    feature_events: &[FeatureEvent],
) -> Vec<BrainSpike> {
    let limits = EffectiveWorldLimits {
        max_spikes_per_tick: u32::MAX,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        fanout_cap: u32::MAX,
    };
    map_features_to_spikes_with_limits(mapper, feature_events, &limits, usize::MAX).spikes
}

pub fn apply_injection_limits(spikes: &mut Vec<BrainSpike>, limits: &InjectionLimits) {
    let max_spikes = limits.max_spikes_per_tick as usize;
    if spikes.len() > max_spikes {
        spikes.truncate(max_spikes);
    }
}

#[derive(Debug, Clone)]
struct SpikeCandidate {
    spike: BrainSpike,
    priority_q: u16,
    feature_id: u32,
}

fn scaled_u32(base: u32, scale_q: u16) -> u32 {
    ((base as u64) * (scale_q as u64) / 1000) as u32
}

fn scaled_u16(base: u16, scale_q: u16) -> u16 {
    ((base as u32) * (scale_q as u32) / 1000) as u16
}

fn score_shadow(
    active: &BiophysFeedbackSnapshot,
    shadow: &BiophysFeedbackSnapshot,
) -> (ShadowScore, Vec<String>) {
    let active_score = score_feedback_snapshot(active);
    let shadow_score = score_feedback_snapshot(shadow);
    let delta = shadow_score - active_score;
    let reason_codes = if delta > 0 {
        vec![RC_SHADOW_BETTER.to_string()]
    } else if delta < 0 {
        vec![RC_SHADOW_WORSE.to_string()]
    } else {
        vec![RC_SHADOW_EQUAL.to_string()]
    };
    (
        ShadowScore {
            active: active_score,
            shadow: shadow_score,
            delta,
        },
        reason_codes,
    )
}

fn trace_verdict_from_delta(delta: i32) -> TraceVerdict {
    if delta >= 5 {
        TraceVerdict::Promising
    } else if delta <= -5 {
        TraceVerdict::Risky
    } else {
        TraceVerdict::Neutral
    }
}

fn trace_verdict_reason_code(verdict: &TraceVerdict) -> &'static str {
    match verdict {
        TraceVerdict::Promising => RC_TRACE_PROMISING,
        TraceVerdict::Neutral => RC_TRACE_NEUTRAL,
        TraceVerdict::Risky => RC_TRACE_RISKY,
    }
}

fn trace_verdict_code(verdict: &TraceVerdict) -> u8 {
    match verdict {
        TraceVerdict::Promising => TRACE_VERDICT_PROMISING,
        TraceVerdict::Neutral => TRACE_VERDICT_NEUTRAL,
        TraceVerdict::Risky => TRACE_VERDICT_RISKY,
    }
}

fn hydrate_lifecycle_from_query(
    index: &mut LifecycleIndex,
    evidence_query: Option<&dyn EvidenceQueryClient>,
    key: LifecycleKey,
    tick: u64,
) {
    let Some(client) = evidence_query else {
        return;
    };
    if let Some((trace_digest, verdict)) =
        client.latest_trace_for(key.proposal_digest, key.context_digest)
    {
        index.note_trace(key, trace_digest, verdict, tick);
    }
    if let Some((activation_digest, status)) =
        client.latest_activation_for(key.proposal_digest, key.context_digest)
    {
        index.note_activation(key, activation_digest, status, tick);
    }
}

fn score_feedback_snapshot(snapshot: &BiophysFeedbackSnapshot) -> i32 {
    if !snapshot.event_queue_overflowed && snapshot.events_dropped == 0 {
        return 10;
    }
    let mut score = 0i32;
    if snapshot.event_queue_overflowed {
        score -= 5;
    }
    let drop_penalty = (snapshot.events_dropped / 10).min(10) as i32;
    score -= drop_penalty;
    score
}

fn predict_feedback_snapshot(
    spikes: &[BrainSpike],
    limits: &InjectionLimits,
) -> BiophysFeedbackSnapshot {
    let max_spikes = limits.max_spikes_per_tick as usize;
    let dropped = spikes.len().saturating_sub(max_spikes);
    let injected = spikes.len().saturating_sub(dropped);
    let mut buf = Vec::new();
    write_u32(&mut buf, spikes.len() as u32);
    write_u32(&mut buf, limits.max_spikes_per_tick);
    write_u32(&mut buf, limits.max_targets_per_spike);
    for spike in spikes {
        write_string(&mut buf, &spike.target.region);
        write_string(&mut buf, &spike.target.population);
        write_u32(&mut buf, spike.target.neuron_group);
        write_string(&mut buf, &spike.target.syn_kind);
        write_u16(&mut buf, spike.amplitude_q);
    }
    let snapshot_digest = digest("lnss.shadow.feedback.predicted.v1", &buf);
    BiophysFeedbackSnapshot {
        tick: 0,
        snapshot_digest,
        event_queue_overflowed: dropped > 0,
        events_dropped: dropped as u64,
        events_injected: injected.min(u32::MAX as usize) as u32,
        injected_total: injected as u64,
    }
}

fn validate_shadow_mapping(
    active: &FeatureToBrainMap,
    shadow: &FeatureToBrainMap,
) -> Result<(), LnssRuntimeError> {
    let mut active_targets: std::collections::BTreeMap<u32, Vec<BrainTarget>> =
        std::collections::BTreeMap::new();
    let mut active_counts: std::collections::BTreeMap<u32, usize> =
        std::collections::BTreeMap::new();
    for (feature_id, target) in &active.entries {
        active_targets
            .entry(*feature_id)
            .or_default()
            .push(target.clone());
        *active_counts.entry(*feature_id).or_default() += 1;
    }

    let mut shadow_counts: std::collections::BTreeMap<u32, usize> =
        std::collections::BTreeMap::new();
    for (feature_id, shadow_target) in &shadow.entries {
        *shadow_counts.entry(*feature_id).or_default() += 1;
        let targets = active_targets.get_mut(feature_id).ok_or_else(|| {
            LnssRuntimeError::Shadow(format!(
                "shadow mapping introduces new feature {feature_id}"
            ))
        })?;
        let idx = targets.iter().position(|active_target| {
            active_target.region == shadow_target.region
                && active_target.population == shadow_target.population
                && active_target.neuron_group == shadow_target.neuron_group
                && active_target.syn_kind == shadow_target.syn_kind
        });
        let Some(active_target) = idx.and_then(|index| targets.get(index)) else {
            return Err(LnssRuntimeError::Shadow(format!(
                "shadow mapping introduces new target for feature {feature_id}"
            )));
        };
        if shadow_target.amplitude_q > active_target.amplitude_q {
            return Err(LnssRuntimeError::Shadow(format!(
                "shadow amplitude exceeds active for feature {feature_id}"
            )));
        }
    }

    for (feature_id, count) in shadow_counts {
        let active_count = active_counts.get(&feature_id).copied().unwrap_or(0);
        if count > active_count {
            return Err(LnssRuntimeError::Shadow(format!(
                "shadow mapping increases fan-out for feature {feature_id}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "lnss-liquid-ode")]
fn validate_shadow_liquid_params(
    active: &LiquidOdeConfig,
    shadow: &LiquidOdeConfig,
) -> Result<(), LnssRuntimeError> {
    if shadow.state_dim != active.state_dim
        || shadow.input_proj_dim != active.input_proj_dim
        || shadow.mods_gain_q != active.mods_gain_q
        || shadow.seed != active.seed
    {
        return Err(LnssRuntimeError::Shadow(
            "shadow liquid params must match active non-step fields".to_string(),
        ));
    }
    if shadow.dt_ms_q > active.dt_ms_q || shadow.steps_per_call > active.steps_per_call {
        return Err(LnssRuntimeError::Shadow(
            "shadow liquid params must tighten dt/steps".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "lnss-liquid-ode")]
fn shadow_liquid_params_digest(params: Option<&LiquidOdeConfig>) -> Option<[u8; 32]> {
    let params = params?;
    let mut buf = Vec::new();
    write_u32(&mut buf, params.state_dim);
    write_u16(&mut buf, params.dt_ms_q);
    write_u16(&mut buf, params.steps_per_call);
    write_u64(&mut buf, params.seed);
    write_u32(&mut buf, params.input_proj_dim);
    write_u16(&mut buf, params.mods_gain_q);
    Some(digest("lnss.shadow.liquid_ode.v1", &buf))
}

pub struct StubLlmBackend;

impl LlmBackend for StubLlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(input);
        buf.extend_from_slice(mods.noise.as_bytes());
        buf.extend_from_slice(mods.priority.as_bytes());
        let digest_bytes = digest("lnss.stub.llm.v1", &buf);
        digest_bytes.to_vec()
    }

    fn supports_hooks(&self) -> bool {
        true
    }

    fn backend_identifier(&self) -> &'static str {
        "stub-llm"
    }

    fn model_revision(&self) -> String {
        "stub".to_string()
    }
}

pub struct StubHookProvider {
    pub taps: Vec<TapFrame>,
}

impl HookProvider for StubHookProvider {
    fn collect_taps(&mut self, _specs: &[TapSpec]) -> Vec<TapFrame> {
        let mut taps = self.taps.clone();
        taps.truncate(DEFAULT_MAX_TAPS);
        taps
    }
}

pub struct StubRigClient {
    pub sent: Vec<BrainSpike>,
}

impl StubRigClient {
    pub fn new() -> Self {
        Self { sent: Vec::new() }
    }
}

impl Default for StubRigClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RigClient for StubRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        self.sent.extend_from_slice(spikes);
        Ok(())
    }
}

pub fn ensure_bounded_bytes(bytes: &mut Vec<u8>, limit: usize) {
    bytes.truncate(limit.min(MAX_ACTIVATION_BYTES));
}

fn default_state_path() -> PathBuf {
    PathBuf::from("experimental/lnss/state/approval_state.json")
}

fn load_activation_state(path: &Path) -> Result<ActivationState, LnssRuntimeError> {
    if !path.exists() {
        return Ok(ActivationState::default());
    }
    let bytes = fs::read(path).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|err| LnssRuntimeError::Approval(err.to_string()))
}

fn persist_activation_state(path: &Path, state: &ActivationState) -> Result<(), LnssRuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
    }
    let bytes =
        serde_json::to_vec(state).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
    fs::write(path, bytes).map_err(|err| LnssRuntimeError::Approval(err.to_string()))
}

fn digest_file_bytes(bytes: &[u8]) -> [u8; 32] {
    digest(FILE_DIGEST_DOMAIN, bytes)
}

fn liquid_params_digest(kv_pairs: &[(String, String)]) -> [u8; 32] {
    let mut pairs = kv_pairs.to_vec();
    pairs.sort_by(|(a_key, a_val), (b_key, b_val)| a_key.cmp(b_key).then_with(|| a_val.cmp(b_val)));
    let mut buf = Vec::new();
    write_u32(&mut buf, pairs.len() as u32);
    for (key, value) in pairs {
        write_string(&mut buf, &key);
        write_string(&mut buf, &value);
    }
    digest(LIQUID_PARAMS_DOMAIN, &buf)
}

fn hook_config_digest(specs: &[TapSpec]) -> [u8; 32] {
    let mut specs = specs.to_vec();
    specs.sort_by(|a, b| {
        a.hook_id
            .cmp(&b.hook_id)
            .then_with(|| tap_kind_tag(a.tap_kind).cmp(&tap_kind_tag(b.tap_kind)))
            .then_with(|| a.layer_index.cmp(&b.layer_index))
            .then_with(|| a.tensor_name.cmp(&b.tensor_name))
    });
    let mut buf = Vec::new();
    write_u32(&mut buf, specs.len() as u32);
    for spec in specs {
        write_string(&mut buf, &spec.hook_id);
        buf.push(tap_kind_tag(spec.tap_kind));
        write_u16(&mut buf, spec.layer_index);
        write_string(&mut buf, &spec.tensor_name);
    }
    digest(HOOK_CFG_DOMAIN, &buf)
}

fn language_cfg_digest(backend_id: &str, model_revision: &str, hook_digest: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::new();
    write_string(&mut buf, backend_id);
    write_string(&mut buf, model_revision);
    buf.extend_from_slice(&hook_digest);
    digest(LANG_CFG_DOMAIN, &buf)
}

fn worldmodel_cfg_digest(snapshot: &WorldModelCfgSnapshot) -> [u8; 32] {
    let mut buf = Vec::new();
    write_string(&mut buf, &snapshot.mode);
    write_string(&mut buf, &snapshot.encoder_id);
    write_string(&mut buf, &snapshot.predictor_id);
    let mut constants = snapshot.constants.clone();
    constants.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    write_u32(&mut buf, constants.len() as u32);
    for (name, value) in constants {
        write_string(&mut buf, &name);
        write_i64(&mut buf, value);
    }
    digest(WM_CFG_DOMAIN, &buf)
}

fn rlm_cfg_digest(snapshot: &RlmCfgSnapshot) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.push(snapshot.recursion_depth_cap);
    let mut directives = snapshot.directive_set.clone();
    directives.sort();
    directives.dedup();
    write_u32(&mut buf, directives.len() as u32);
    for directive in directives {
        buf.push(directive as u8);
    }
    buf.push(snapshot.max_directives);
    digest(RLM_CFG_DOMAIN, &buf)
}

fn sae_cfg_digest(sae_pack_digest: [u8; 32], top_k_base: u16, feature_caps: &[u16]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&sae_pack_digest);
    write_u16(&mut buf, top_k_base);
    write_u32(&mut buf, feature_caps.len() as u32);
    for cap in feature_caps {
        write_u16(&mut buf, *cap);
    }
    digest(SAE_CFG_DOMAIN, &buf)
}

fn mapping_cfg_digest(map_digest: [u8; 32], map_version: u32) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&map_digest);
    write_u32(&mut buf, map_version);
    digest(MAP_CFG_DOMAIN, &buf)
}

fn limits_cfg_digest(
    limits: &Limits,
    injection_limits: &InjectionLimits,
    amplitude_cap_q: u16,
    liquid_params_digest: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut buf = Vec::new();
    write_u32(&mut buf, injection_limits.max_spikes_per_tick);
    write_u32(&mut buf, injection_limits.max_targets_per_spike);
    write_u16(&mut buf, amplitude_cap_q);
    write_u32(
        &mut buf,
        u32::try_from(limits.max_output_bytes).unwrap_or(u32::MAX),
    );
    write_u32(&mut buf, u32::try_from(limits.max_taps).unwrap_or(u32::MAX));
    write_u32(
        &mut buf,
        u32::try_from(limits.max_spikes).unwrap_or(u32::MAX),
    );
    write_u32(
        &mut buf,
        u32::try_from(limits.max_mechint_bytes).unwrap_or(u32::MAX),
    );
    match liquid_params_digest {
        Some(digest_bytes) => {
            write_bool(&mut buf, true);
            buf.extend_from_slice(&digest_bytes);
        }
        None => write_bool(&mut buf, false),
    }
    digest(LIMITS_CFG_DOMAIN, &buf)
}

pub struct CfgRootDigestInputs<'a> {
    pub llm: &'a dyn LlmBackend,
    pub tap_specs: &'a [TapSpec],
    pub worldmodel_cfg: &'a WorldModelCfgSnapshot,
    pub rlm_cfg: &'a RlmCfgSnapshot,
    pub sae_pack_digest: Option<[u8; 32]>,
    pub mapping: &'a FeatureToBrainMap,
    pub limits: &'a Limits,
    pub injection_limits: &'a InjectionLimits,
    pub amplitude_cap_q: u16,
    pub policy_digest: Option<[u8; 32]>,
    pub liquid_params_digest: Option<[u8; 32]>,
}

pub fn cfg_root_digest_pack(inputs: CfgRootDigestInputs<'_>) -> Option<CfgRootDigestPack> {
    if inputs.mapping.map_digest == [0u8; 32] {
        return None;
    }
    let backend_id = inputs.llm.backend_identifier();
    if backend_id.is_empty() {
        return None;
    }
    let model_revision = inputs.llm.model_revision();
    if model_revision.is_empty() {
        return None;
    }
    if inputs.worldmodel_cfg.mode.is_empty()
        || inputs.worldmodel_cfg.encoder_id.is_empty()
        || inputs.worldmodel_cfg.predictor_id.is_empty()
    {
        return None;
    }
    let hook_digest = hook_config_digest(inputs.tap_specs);
    let language_digest = language_cfg_digest(backend_id, &model_revision, hook_digest);
    let worldmodel_digest = worldmodel_cfg_digest(inputs.worldmodel_cfg);
    let rlm_digest = rlm_cfg_digest(inputs.rlm_cfg);
    let sae_pack_digest = inputs.sae_pack_digest.unwrap_or([0u8; 32]);
    let sae_digest = sae_cfg_digest(
        sae_pack_digest,
        MAX_TOP_FEATURES as u16,
        &[MAX_TOP_FEATURES as u16],
    );
    let mapping_digest = mapping_cfg_digest(inputs.mapping.map_digest, inputs.mapping.map_version);
    let limits_digest = limits_cfg_digest(
        inputs.limits,
        inputs.injection_limits,
        inputs.amplitude_cap_q,
        inputs.liquid_params_digest,
    );
    Some(CfgRootDigestPack::new(
        language_digest,
        worldmodel_digest,
        rlm_digest,
        sae_digest,
        mapping_digest,
        limits_digest,
        inputs.policy_digest,
    ))
}

fn tap_kind_tag(kind: TapKind) -> u8 {
    match kind {
        TapKind::ResidualStream => 1,
        TapKind::MlpPost => 2,
        TapKind::AttnOut => 3,
        TapKind::Embedding => 4,
        TapKind::LiquidState => 5,
    }
}

fn decision_allows_application(decision: &ucf::v1::ApprovalDecision) -> bool {
    let form = ucf::v1::DecisionForm::try_from(decision.decision)
        .unwrap_or(ucf::v1::DecisionForm::Unspecified);
    if form != ucf::v1::DecisionForm::Allow {
        return false;
    }
    match decision.constraints.as_ref() {
        Some(constraints) => constraints_are_tightening(constraints),
        None => true,
    }
}

fn constraints_are_tightening(constraints: &ucf::v1::ConstraintsDelta) -> bool {
    if !constraints.constraints_removed.is_empty() {
        return false;
    }
    if constraints.constraints_added.is_empty() && !constraints.novelty_lock {
        return false;
    }
    constraints
        .constraints_added
        .iter()
        .all(|entry| is_tightening_constraint(entry))
}

fn is_tightening_constraint(entry: &str) -> bool {
    let lower = entry.trim().to_ascii_lowercase();
    lower.contains("reduce ")
        || lower.contains("lower ")
        || lower.contains("tighten")
        || lower.contains("simulate-first")
        || lower.contains("simulate first")
        || lower.contains("simulate_first")
        || lower.contains("increase simulate")
}

fn activation_id_for(proposal_digest: [u8; 32], approval_digest: [u8; 32]) -> String {
    let proposal_prefix = hex::encode(&proposal_digest[..ACTIVATION_ID_PREFIX_LEN]);
    let approval_prefix = hex::encode(&approval_digest[..ACTIVATION_ID_PREFIX_LEN]);
    format!("act:{proposal_prefix}:{approval_prefix}")
}

fn trace_id_for(
    active_cfg_root_digest: [u8; 32],
    shadow_cfg_root_digest: [u8; 32],
    tick: u64,
) -> String {
    let active_prefix = hex::encode(&active_cfg_root_digest[..TRACE_ID_PREFIX_LEN]);
    let shadow_prefix = hex::encode(&shadow_cfg_root_digest[..TRACE_ID_PREFIX_LEN]);
    format!("trace:{active_prefix}:{shadow_prefix}:{tick}")
}

fn load_pending_aaps(
    dir: impl AsRef<Path>,
) -> Result<std::collections::BTreeMap<String, PendingAap>, LnssRuntimeError> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Ok(std::collections::BTreeMap::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|err| LnssRuntimeError::Approval(err.to_string()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("aap_"))
                    .unwrap_or(false)
                && path.extension().map(|ext| ext == "bin").unwrap_or(false)
        })
        .collect();
    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    let mut pending = std::collections::BTreeMap::new();
    for path in entries {
        let bytes = fs::read(&path).map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        let aap = ucf::v1::ApprovalArtifactPackage::decode(bytes.as_slice())
            .map_err(|err| LnssRuntimeError::Approval(err.to_string()))?;
        let aap_digest = match aap.aap_digest.as_ref().and_then(digest_bytes) {
            Some(digest) => digest,
            None => continue,
        };
        if approval_artifact_package_digest(&aap) != aap_digest {
            continue;
        }
        let proposal_digest = aap
            .evidence_refs
            .iter()
            .find(|reference| reference.id == "proposal_digest")
            .and_then(|reference| reference.digest.as_ref())
            .and_then(digest_bytes);
        let proposal_digest = match proposal_digest {
            Some(digest) => digest,
            None => continue,
        };
        let trace_digest = aap
            .evidence_refs
            .iter()
            .find(|reference| reference.id == "trace_digest")
            .and_then(|reference| reference.digest.as_ref())
            .and_then(digest_bytes);
        let context_digest = aap
            .evidence_refs
            .iter()
            .find(|reference| reference.id == "core_context_digest")
            .and_then(|reference| reference.digest.as_ref())
            .and_then(digest_bytes);
        if !aap.aap_id.is_empty() {
            pending.insert(
                aap.aap_id.clone(),
                PendingAap {
                    aap_digest,
                    proposal_digest,
                    trace_digest,
                    context_digest,
                },
            );
        }
    }
    Ok(pending)
}

fn digest_bytes(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    let bytes: [u8; 32] = digest.value.as_slice().try_into().ok()?;
    Some(bytes)
}

fn bound_string(value: &str) -> String {
    let mut out = value.to_string();
    out.truncate(MAX_STRING_LEN);
    out
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_i32(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_i64(buf: &mut Vec<u8>, value: i64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn write_optional_feedback(buf: &mut Vec<u8>, feedback: Option<&FeedbackSummary>) {
    match feedback {
        Some(summary) => {
            write_bool(buf, true);
            write_u64(buf, summary.tick);
            buf.extend_from_slice(&summary.snapshot_digest);
            write_bool(buf, summary.event_queue_overflowed);
            write_u64(buf, summary.events_dropped);
            write_u32(buf, summary.events_injected);
            write_u64(buf, summary.injected_total);
        }
        None => write_bool(buf, false),
    }
}

fn write_optional_suggestion(buf: &mut Vec<u8>, suggestion: Option<&MappingAdaptationSuggestion>) {
    match suggestion {
        Some(suggestion) => {
            write_bool(buf, true);
            write_u16(buf, suggestion.amplitude_q_factor);
            write_u16(buf, suggestion.max_targets_per_feature);
        }
        None => write_bool(buf, false),
    }
}

fn write_optional_proposal(buf: &mut Vec<u8>, parts: &MechIntRecordParts) {
    write_bool(buf, parts.proposal_digest.is_some());
    if let Some(digest_bytes) = parts.proposal_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.proposal_kind.is_some());
    if let Some(kind) = &parts.proposal_kind {
        buf.push(proposal_kind_tag(kind));
    }
    write_bool(buf, parts.proposal_eval_score.is_some());
    if let Some(score) = parts.proposal_eval_score {
        write_i32(buf, score);
    }
    write_bool(buf, parts.proposal_verdict.is_some());
    if let Some(verdict) = &parts.proposal_verdict {
        buf.push(eval_verdict_tag(verdict));
    }
    write_bool(buf, parts.proposal_base_evidence_digest.is_some());
    if let Some(digest_bytes) = parts.proposal_base_evidence_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.aap_digest.is_some());
    if let Some(digest_bytes) = parts.aap_digest {
        buf.extend_from_slice(&digest_bytes);
    }
}

fn write_optional_activation(buf: &mut Vec<u8>, parts: &MechIntRecordParts) {
    write_bool(buf, parts.approval_digest.is_some());
    if let Some(digest_bytes) = parts.approval_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.activation_result.is_some());
    if let Some(result) = &parts.activation_result {
        buf.push(activation_result_tag(result));
    }
    write_bool(buf, parts.active_mapping_digest.is_some());
    if let Some(digest_bytes) = parts.active_mapping_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.active_sae_pack_digest.is_some());
    if let Some(digest_bytes) = parts.active_sae_pack_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.active_liquid_params_digest.is_some());
    if let Some(digest_bytes) = parts.active_liquid_params_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.active_injection_limits.is_some());
    if let Some(limits) = &parts.active_injection_limits {
        write_u32(buf, limits.max_spikes_per_tick);
        write_u32(buf, limits.max_targets_per_spike);
    }
    write_bool(buf, parts.activation_digest.is_some());
    if let Some(digest_bytes) = parts.activation_digest {
        buf.extend_from_slice(&digest_bytes);
    }
    write_bool(buf, parts.committed_to_pvgs.is_some());
    if let Some(committed) = parts.committed_to_pvgs {
        write_bool(buf, committed);
    }
}

fn write_optional_shadow(buf: &mut Vec<u8>, shadow: Option<&ShadowEvidence>) {
    match shadow {
        Some(evidence) => {
            write_bool(buf, true);
            buf.extend_from_slice(&evidence.shadow_mapping_digest);
            write_bool(buf, evidence.shadow_liquid_params_digest.is_some());
            if let Some(digest_bytes) = evidence.shadow_liquid_params_digest {
                buf.extend_from_slice(&digest_bytes);
            }
            buf.extend_from_slice(&evidence.active_feedback_digest);
            buf.extend_from_slice(&evidence.shadow_feedback_digest);
            write_i32(buf, evidence.score.active);
            write_i32(buf, evidence.score.shadow);
            write_i32(buf, evidence.score.delta);
            let mut reason_codes = evidence.reason_codes.clone();
            reason_codes.sort();
            reason_codes.dedup();
            reason_codes.truncate(MAX_REASON_CODES);
            write_u32(buf, reason_codes.len() as u32);
            for code in reason_codes {
                write_string(buf, &code);
            }
        }
        None => write_bool(buf, false),
    }
}

fn emotion_snapshot_digest(snapshot: &EmotionFieldSnapshot) -> [u8; 32] {
    let mut buf = Vec::new();
    write_string(&mut buf, &snapshot.noise);
    write_string(&mut buf, &snapshot.priority);
    write_string(&mut buf, &snapshot.recursion_depth);
    write_string(&mut buf, &snapshot.dwm);
    write_string(&mut buf, &snapshot.profile);
    buf.extend_from_slice(&(snapshot.overlays.len() as u32).to_le_bytes());
    for overlay in &snapshot.overlays {
        write_string(&mut buf, overlay);
    }
    buf.extend_from_slice(&(snapshot.top_reason_codes.len() as u32).to_le_bytes());
    for reason in &snapshot.top_reason_codes {
        write_string(&mut buf, reason);
    }
    digest("lnss.emotion_snapshot.v1", &buf)
}

fn feedback_anomaly_flags(snapshot: Option<&BiophysFeedbackSnapshot>) -> FeedbackAnomalyFlags {
    match snapshot {
        Some(snapshot) => FeedbackAnomalyFlags {
            event_queue_overflowed: snapshot.event_queue_overflowed,
            events_dropped: snapshot.events_dropped > 0,
        },
        None => FeedbackAnomalyFlags::default(),
    }
}

fn proposal_kind_tag(kind: &ProposalKind) -> u8 {
    match kind {
        ProposalKind::MappingUpdate => 1,
        ProposalKind::SaePackUpdate => 2,
        ProposalKind::LiquidParamsUpdate => 3,
        ProposalKind::InjectionLimitsUpdate => 4,
    }
}

fn eval_verdict_tag(verdict: &EvalVerdict) -> u8 {
    match verdict {
        EvalVerdict::Promising => 1,
        EvalVerdict::Neutral => 2,
        EvalVerdict::Risky => 3,
    }
}

fn activation_result_tag(result: &ActivationResult) -> u8 {
    match result {
        ActivationResult::Applied => 1,
        ActivationResult::Rejected => 2,
    }
}

pub struct TapRegistryProvider {
    registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>,
    enabled: bool,
}

#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_Q_SHIFT: i32 = 16;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_Q_ONE: i32 = 1 << LIQUID_Q_SHIFT;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_WEIGHT_SCALE: i64 = 64;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_OUTPUT_SAMPLE_DIMS: usize = 16;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_TAP_SAMPLE_DIMS: usize = 64;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_STATE_CLAMP_Q: i32 = LIQUID_Q_ONE * 8;

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
pub struct LiquidOdeConfig {
    pub state_dim: u32,
    pub dt_ms_q: u16,
    pub steps_per_call: u16,
    pub seed: u64,
    pub input_proj_dim: u32,
    pub mods_gain_q: u16,
}

#[cfg(feature = "lnss-liquid-ode")]
impl Default for LiquidOdeConfig {
    fn default() -> Self {
        Self {
            state_dim: 256,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 0,
            input_proj_dim: 64,
            mods_gain_q: 100,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
pub struct LiquidOdeState {
    pub x_q: Vec<i32>,
    pub step_count: u64,
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
struct LiquidWeights {
    w_in: Vec<i16>,
    w_rec: Vec<i16>,
    bias_q: Vec<i32>,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidWeights {
    fn new(cfg: &LiquidOdeConfig) -> Self {
        let state_dim = cfg.state_dim.max(1) as usize;
        let input_dim = cfg.input_proj_dim.max(1) as usize;
        let mut w_in = Vec::with_capacity(state_dim * input_dim);
        for idx in 0..(state_dim * input_dim) {
            w_in.push(derive_weight(cfg.seed, idx as u64, "w_in"));
        }
        let mut w_rec = Vec::with_capacity(state_dim * state_dim);
        for idx in 0..(state_dim * state_dim) {
            w_rec.push(derive_weight(cfg.seed, idx as u64, "w_rec"));
        }
        let mut bias_q = Vec::with_capacity(state_dim);
        for idx in 0..state_dim {
            bias_q.push(derive_bias(cfg.seed, idx as u64));
        }
        Self {
            w_in,
            w_rec,
            bias_q,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug)]
pub struct LiquidOdeBackend {
    cfg: LiquidOdeConfig,
    state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
    weights: LiquidWeights,
    dt_q: i32,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidOdeBackend {
    pub fn new(mut cfg: LiquidOdeConfig) -> Self {
        cfg.state_dim = cfg.state_dim.max(1);
        cfg.input_proj_dim = cfg.input_proj_dim.max(1);
        cfg.steps_per_call = cfg.steps_per_call.max(1);
        let state_dim = cfg.state_dim as usize;
        let state = LiquidOdeState {
            x_q: vec![0; state_dim],
            step_count: 0,
        };
        let dt_q =
            ((cfg.dt_ms_q as i64) * (LIQUID_Q_ONE as i64) / 1000).clamp(1, i32::MAX as i64) as i32;
        let weights = LiquidWeights::new(&cfg);
        Self {
            cfg,
            state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            weights,
            dt_q,
        }
    }

    pub fn tap_provider(&self) -> LiquidTapProvider {
        LiquidTapProvider::new(self.state.clone(), self.cfg.clone())
    }

    pub fn state_len(&self) -> usize {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.x_q.len()
    }

    fn step_state(&mut self, input_proj: &[i32], gain_q: i32) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state_dim = self.cfg.state_dim as usize;
        if guard.x_q.len() != state_dim {
            guard.x_q.resize(state_dim, 0);
        }
        let mut tanh_vals = Vec::with_capacity(state_dim);
        for &x_q in &guard.x_q {
            tanh_vals.push(tanh_approx_q(x_q));
        }
        let mut next = vec![0; state_dim];
        let alpha_q = LIQUID_Q_ONE / 8;
        let input_dim = self.cfg.input_proj_dim as usize;
        for (i, next_val) in next.iter_mut().enumerate().take(state_dim) {
            let x_q = guard.x_q[i];
            let leak = -((alpha_q as i64 * x_q as i64) >> LIQUID_Q_SHIFT);
            let mut sum_in = 0i64;
            let w_in_offset = i * input_dim;
            for (j, u_q) in input_proj.iter().enumerate() {
                let w = self.weights.w_in[w_in_offset + j] as i64;
                sum_in += w * (*u_q as i64);
            }
            let mut sum_rec = 0i64;
            let w_rec_offset = i * state_dim;
            for (j, tanh_q) in tanh_vals.iter().enumerate() {
                let w = self.weights.w_rec[w_rec_offset + j] as i64;
                sum_rec += w * (*tanh_q as i64);
            }
            let input_term = sum_in / LIQUID_WEIGHT_SCALE;
            let rec_term = sum_rec / LIQUID_WEIGHT_SCALE;
            let mut drive = input_term + rec_term + self.weights.bias_q[i] as i64;
            drive = (drive * gain_q as i64) >> LIQUID_Q_SHIFT;
            let f_q = leak + drive;
            let delta = ((self.dt_q as i64) * f_q) >> LIQUID_Q_SHIFT;
            let updated = (x_q as i64 + delta)
                .clamp(-(LIQUID_STATE_CLAMP_Q as i64), LIQUID_STATE_CLAMP_Q as i64);
            *next_val = updated as i32;
        }
        guard.x_q = next;
        guard.step_count = guard.step_count.saturating_add(1);
    }
}

#[cfg(feature = "lnss-liquid-ode")]
impl LlmBackend for LiquidOdeBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let input_proj = encode_input_projection(input, &self.cfg);
        let gain_q = modulation_gain_q(mods, self.cfg.mods_gain_q);
        for _ in 0..self.cfg.steps_per_call {
            self.step_state(&input_proj, gain_q);
        }
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let sample = sample_state_bytes(&guard.x_q, LIQUID_OUTPUT_SAMPLE_DIMS);
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.cfg.seed.to_le_bytes());
        buf.extend_from_slice(&guard.step_count.to_le_bytes());
        buf.extend_from_slice(&sample);
        let digest_bytes = digest("lnss.liquid.output.v1", &buf);
        let mut output = Vec::new();
        output.extend_from_slice(&digest_bytes);
        output.extend_from_slice(&sample);
        output
    }

    fn supports_hooks(&self) -> bool {
        true
    }

    fn backend_identifier(&self) -> &'static str {
        "liquid-ode"
    }

    fn model_revision(&self) -> String {
        format!(
            "state_dim={};dt_ms_q={};steps_per_call={};seed={};input_proj_dim={};mods_gain_q={}",
            self.cfg.state_dim,
            self.cfg.dt_ms_q,
            self.cfg.steps_per_call,
            self.cfg.seed,
            self.cfg.input_proj_dim,
            self.cfg.mods_gain_q
        )
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug)]
pub struct LiquidTapProvider {
    state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
    cfg: LiquidOdeConfig,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidTapProvider {
    pub fn new(
        state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
        cfg: LiquidOdeConfig,
    ) -> Self {
        Self { state, cfg }
    }

    fn tap_frame(&self, hook_id: &str) -> TapFrame {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state_bytes = Vec::with_capacity(guard.x_q.len() * 4);
        for x_q in &guard.x_q {
            state_bytes.extend_from_slice(&x_q.to_le_bytes());
        }
        let activation_digest = digest("lnss.liquid.tap.v1", &state_bytes);
        let sample_dims = (self.cfg.state_dim as usize).min(LIQUID_TAP_SAMPLE_DIMS);
        let activation_bytes = sample_state_bytes(&guard.x_q, sample_dims);
        TapFrame {
            hook_id: hook_id.to_string(),
            activation_digest,
            activation_bytes,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
impl HookProvider for LiquidTapProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame> {
        let liquid_specs: Vec<&TapSpec> = specs
            .iter()
            .filter(|spec| spec.tap_kind == TapKind::LiquidState)
            .collect();
        let targets: Vec<String> = if liquid_specs.is_empty() {
            vec!["liquid-state".to_string()]
        } else {
            liquid_specs
                .iter()
                .map(|spec| spec.hook_id.clone())
                .collect()
        };
        targets
            .iter()
            .map(|hook_id| self.tap_frame(hook_id))
            .collect()
    }
}

#[cfg(feature = "lnss-liquid-ode")]
fn derive_weight(seed: u64, index: u64, tag: &str) -> i16 {
    let mut buf = Vec::new();
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    let digest_bytes = digest("lnss.liquid.weight.v1", &buf);
    let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
    let bounded = raw.rem_euclid(129) - 64;
    bounded as i16
}

#[cfg(feature = "lnss-liquid-ode")]
fn derive_bias(seed: u64, index: u64) -> i32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    let digest_bytes = digest("lnss.liquid.bias.v1", &buf);
    let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
    let bounded = raw.rem_euclid(257) - 128;
    bounded * (LIQUID_Q_ONE / 128)
}

#[cfg(feature = "lnss-liquid-ode")]
fn encode_input_projection(input: &[u8], cfg: &LiquidOdeConfig) -> Vec<i32> {
    let mut base = Vec::new();
    base.extend_from_slice(&cfg.seed.to_le_bytes());
    base.extend_from_slice(input);
    let input_dim = cfg.input_proj_dim.max(1) as usize;
    let mut proj = Vec::with_capacity(input_dim);
    for idx in 0..input_dim {
        let mut buf = base.clone();
        buf.extend_from_slice(&(idx as u32).to_le_bytes());
        let digest_bytes = digest("lnss.liquid.input.v1", &buf);
        let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
        let scaled = raw / 256;
        let u_q = scaled * (LIQUID_Q_ONE / 128);
        proj.push(u_q);
    }
    proj
}

#[cfg(feature = "lnss-liquid-ode")]
fn modulation_gain_q(mods: &EmotionFieldSnapshot, base_gain: u16) -> i32 {
    let mut gain = base_gain as i32;
    if mods.noise.eq_ignore_ascii_case("high") {
        gain = gain * 90 / 100;
    } else if mods.noise.eq_ignore_ascii_case("low") {
        gain = gain * 110 / 100;
    }
    if mods.priority.eq_ignore_ascii_case("high") {
        gain = gain * 110 / 100;
    } else if mods.priority.eq_ignore_ascii_case("low") {
        gain = gain * 90 / 100;
    }
    let gain = gain.clamp(10, 200);
    (gain * LIQUID_Q_ONE) / 100
}

#[cfg(feature = "lnss-liquid-ode")]
fn tanh_approx_q(x_q: i32) -> i32 {
    let abs = x_q.abs();
    if abs >= 3 * LIQUID_Q_ONE {
        return if x_q >= 0 {
            LIQUID_Q_ONE
        } else {
            -LIQUID_Q_ONE
        };
    }
    if abs <= LIQUID_Q_ONE {
        return x_q;
    }
    let base = LIQUID_Q_ONE * 4 / 5;
    let extra = (abs - LIQUID_Q_ONE) / 10;
    let value = base + extra;
    if x_q >= 0 {
        value
    } else {
        -value
    }
}

#[cfg(feature = "lnss-liquid-ode")]
fn sample_state_bytes(x_q: &[i32], dims: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &value in x_q.iter().take(dims) {
        let quantized = (value >> 8).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        bytes.extend_from_slice(&quantized.to_le_bytes());
    }
    bytes.truncate(MAX_TAP_SAMPLE_BYTES);
    bytes
}

impl TapRegistryProvider {
    pub fn new(registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>, enabled: bool) -> Self {
        Self { registry, enabled }
    }
}

impl HookProvider for TapRegistryProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame> {
        if !self.enabled {
            return Vec::new();
        }
        let mut registry = match self.registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let frames = registry.collect();
        if specs.is_empty() {
            return frames;
        }
        let allowed: std::collections::HashSet<&str> =
            specs.iter().map(|spec| spec.hook_id.as_str()).collect();
        frames
            .into_iter()
            .filter(|frame| allowed.contains(frame.hook_id.as_str()))
            .collect()
    }
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug, Clone)]
pub struct CandleConfig {
    pub model_dir: String,
    pub model_revision: String,
    pub max_new_tokens: u32,
    pub seed: u64,
    pub device: String,
    pub hooks_enabled: bool,
}

#[cfg(feature = "lnss-candle")]
impl Default for CandleConfig {
    fn default() -> Self {
        Self {
            model_dir: ".".to_string(),
            model_revision: "unknown".to_string(),
            max_new_tokens: 1,
            seed: 0,
            device: "cpu".to_string(),
            hooks_enabled: false,
        }
    }
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug)]
pub struct CandleLlmBackend {
    cfg: CandleConfig,
    loaded: bool,
    registry: Option<std::sync::Arc<std::sync::Mutex<TapRegistry>>>,
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug, Error)]
pub enum CandleLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "lnss-candle")]
impl CandleLlmBackend {
    pub fn new(cfg: CandleConfig) -> Self {
        Self {
            cfg,
            loaded: false,
            registry: None,
        }
    }

    pub fn with_registry(
        cfg: CandleConfig,
        registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>,
    ) -> Self {
        Self {
            cfg,
            loaded: false,
            registry: Some(registry),
        }
    }

    pub fn set_registry(&mut self, registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>) {
        self.registry = Some(registry);
    }

    pub fn try_load(&mut self) -> Result<(), CandleLoadError> {
        let readme_path = std::path::Path::new(&self.cfg.model_dir).join("README");
        self.loaded = readme_path.exists();
        Ok(())
    }

    fn record_taps(&self, input: &[u8], mods: &EmotionFieldSnapshot) {
        let registry = match &self.registry {
            Some(registry) => registry,
            None => return,
        };
        let registered = match registry.lock() {
            Ok(guard) => guard.registered(),
            Err(poisoned) => poisoned.into_inner().registered(),
        };
        if registered.is_empty() {
            return;
        }
        let seed_bytes = candle_seed_bytes(input, mods, self.cfg.seed);
        let mut frames = Vec::new();
        for tap in registered {
            let sample = candle_sample_bytes(&seed_bytes, &tap, self.cfg.max_new_tokens);
            let activation_digest = candle_activation_digest(&tap, &sample);
            let frame = TapFrame {
                hook_id: tap.hook_id.clone(),
                activation_digest,
                activation_bytes: sample,
            };
            frames.push(frame);
        }
        let mut registry = match registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for frame in frames {
            registry.record_frame(frame);
        }
    }
}

#[cfg(feature = "lnss-candle")]
impl LlmBackend for CandleLlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let mut seed_bytes = candle_seed_bytes(input, mods, self.cfg.seed);
        seed_bytes.extend_from_slice(self.cfg.device.as_bytes());
        let output = if self.loaded {
            digest("lnss.candle.infer.v1", &seed_bytes).to_vec()
        } else {
            digest("lnss.candle.fallback.v1", &seed_bytes).to_vec()
        };
        if self.loaded && self.cfg.hooks_enabled {
            self.record_taps(input, mods);
        }
        output
    }

    fn supports_hooks(&self) -> bool {
        self.loaded && self.cfg.hooks_enabled
    }

    fn backend_identifier(&self) -> &'static str {
        "candle"
    }

    fn model_revision(&self) -> String {
        if self.cfg.model_revision.is_empty() {
            self.cfg.model_dir.clone()
        } else {
            self.cfg.model_revision.clone()
        }
    }
}

#[cfg(feature = "lnss-candle")]
fn candle_seed_bytes(input: &[u8], mods: &EmotionFieldSnapshot, seed: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(input);
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(mods.noise.as_bytes());
    buf.extend_from_slice(mods.priority.as_bytes());
    buf.extend_from_slice(mods.recursion_depth.as_bytes());
    buf.extend_from_slice(mods.dwm.as_bytes());
    buf.extend_from_slice(mods.profile.as_bytes());
    for overlay in &mods.overlays {
        buf.extend_from_slice(overlay.as_bytes());
    }
    for code in &mods.top_reason_codes {
        buf.extend_from_slice(code.as_bytes());
    }
    buf
}

#[cfg(feature = "lnss-candle")]
fn candle_sample_bytes(
    seed_bytes: &[u8],
    tap: &lnss_hooks::RegisteredTap,
    max_new_tokens: u32,
) -> Vec<u8> {
    let mut sample = Vec::new();
    let mut base = Vec::new();
    base.extend_from_slice(seed_bytes);
    base.extend_from_slice(tap.hook_id.as_bytes());
    base.extend_from_slice(tap.tensor_name.as_bytes());
    base.extend_from_slice(&tap.layer_index.to_le_bytes());
    base.extend_from_slice(&max_new_tokens.to_le_bytes());
    let values = 128;
    for idx in 0..values {
        let mut chunk_seed = base.clone();
        chunk_seed.extend_from_slice(&(idx as u32).to_le_bytes());
        let chunk = digest("lnss.candle.tap.sample.v1", &chunk_seed);
        let raw = u16::from_le_bytes([chunk[0], chunk[1]]);
        let f = (raw as f32 / u16::MAX as f32) * 2.0 - 1.0;
        let q = (f * 32767.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        sample.extend_from_slice(&q.to_le_bytes());
    }
    sample.truncate(MAX_TAP_SAMPLE_BYTES);
    sample
}

#[cfg(feature = "lnss-candle")]
fn candle_activation_digest(tap: &lnss_hooks::RegisteredTap, sample: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(tap.hook_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(tap.tensor_name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&tap.layer_index.to_le_bytes());
    buf.extend_from_slice(sample);
    digest("lnss.tap.summary.v1", &buf)
}
