use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_approval::{
    build_aap_for_proposal, build_activation_evidence_pb, ActivationInjectionLimits,
    ActivationStatus, ApprovalContext, ProposalActivationEvidenceLocal,
};
use lnss_core::{
    BrainTarget, ControlIntentClass, CoreContextDigestPack, EmotionFieldSnapshot,
    FeatureToBrainMap, PolicyMode, RecursionPolicy, TapFrame, TapKind, TapSpec,
};
use lnss_evolve::load_proposals;
use lnss_lifecycle::{LifecycleIndex, LifecycleKey, TRACE_VERDICT_PROMISING, TRACE_VERDICT_RISKY};
use lnss_rlm::RlmController;
use lnss_runtime::{
    ApprovalInbox, FeedbackConsumer, InjectionLimits, Limits, LnssRuntime, MappingAdaptationConfig,
    MechIntRecord, MechIntWriter, StubHookProvider, StubLlmBackend, StubRigClient,
    FILE_DIGEST_DOMAIN,
};
use lnss_sae::StubSaeBackend;
use lnss_worldmodel::WorldModelCoreStub;
use prost::Message;
use pvgs_client::{MockPvgsClient, PvgsClient, PvgsReader};
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

#[derive(Default, Clone)]
struct RecordingWriter {
    records: std::sync::Arc<std::sync::Mutex<Vec<MechIntRecord>>>,
}

const TEST_TRACE_DIGEST: [u8; 32] = [7u8; 32];

impl RecordingWriter {
    fn records(&self) -> Vec<MechIntRecord> {
        self.records.lock().expect("records lock").clone()
    }
}

fn core_context_pack(seed: u8) -> CoreContextDigestPack {
    CoreContextDigestPack {
        world_state_digest: [seed; 32],
        self_state_digest: [seed.wrapping_add(1); 32],
        control_frame_digest: [seed.wrapping_add(2); 32],
        policy_digest: None,
        last_feedback_digest: None,
        wm_pred_error_bucket: 2,
        rlm_followup_executed: false,
    }
}

impl MechIntWriter for RecordingWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.records.lock().expect("records lock").push(rec.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct SharedPvgsClient {
    inner: std::sync::Arc<std::sync::Mutex<MockPvgsClient>>,
}

impl SharedPvgsClient {
    fn new(inner: std::sync::Arc<std::sync::Mutex<MockPvgsClient>>) -> Self {
        Self { inner }
    }
}

impl PvgsClient for SharedPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_experience_record(record)
    }

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_dlp_decision(dlp)
    }

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_tool_registry(trc)
    }

    fn commit_tool_onboarding_event(
        &mut self,
        event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_tool_onboarding_event(event)
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_micro_milestone(micro)
    }

    fn commit_consistency_feedback(
        &mut self,
        feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_consistency_feedback(feedback)
    }

    fn commit_proposal_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_proposal_evidence(payload_bytes)
    }

    fn commit_proposal_activation(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_proposal_activation(payload_bytes)
    }

    fn commit_trace_run_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_trace_run_evidence(payload_bytes)
    }

    fn try_commit_next_micro(
        &mut self,
        session_id: &str,
    ) -> Result<bool, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .try_commit_next_micro(session_id)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
        self.inner.lock().expect("pvgs lock").try_commit_next_meso()
    }

    fn try_commit_next_macro(
        &mut self,
        consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .try_commit_next_macro(consistency_digest)
    }

    fn get_pending_replay_plans(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_pending_replay_plans(session_id)
    }

    fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
        self.inner.lock().expect("pvgs lock").get_pvgs_head()
    }
}

impl PvgsReader for SharedPvgsClient {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        self.inner.lock().expect("pvgs lock").get_latest_pev()
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_pev_digest()
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_current_ruleset_digest()
    }

    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_microcircuit_config(module)
    }

    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .list_microcircuit_configs()
    }

    fn get_recovery_state(
        &self,
        session_id: &str,
    ) -> Result<Option<String>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_recovery_state(session_id)
    }

    fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_cbv_digest()
    }

    fn get_latest_trace_run(
        &mut self,
    ) -> Result<Option<pvgs_client::TraceRunSummary>, pvgs_client::PvgsClientError> {
        self.inner.lock().expect("pvgs lock").get_latest_trace_run()
    }

    fn get_latest_rpp_head_meta(
        &mut self,
    ) -> Result<Option<pvgs_client::RppHeadMeta>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_rpp_head_meta()
    }

    fn get_rpp_head_meta(
        &mut self,
        head_id: u64,
    ) -> Result<Option<pvgs_client::RppHeadMeta>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_rpp_head_meta(head_id)
    }

    fn is_session_sealed(&self, session_id: &str) -> Result<bool, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .is_session_sealed(session_id)
    }

    fn has_unlock_permit(&self, session_id: &str) -> Result<bool, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .has_unlock_permit(session_id)
    }

    fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_session_seal_digest(session_id)
    }

    fn get_unlock_permit_digest(
        &self,
        session_id: &str,
    ) -> Result<Option<[u8; 32]>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_unlock_permit_digest(session_id)
    }

    fn get_pending_replay_plans(
        &self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_pending_replay_plans(session_id)
    }
}

fn temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn write_json(path: &Path, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).expect("serialize json");
    fs::write(path, bytes).expect("write json");
}

fn map_fixture_named(dir: &Path, filename: &str) -> (PathBuf, FeatureToBrainMap, [u8; 32]) {
    let target = BrainTarget::new("v1", "pop", 1, "syn", 700);
    let map = FeatureToBrainMap::new(1, vec![(1, target)]);
    let bytes = serde_json::to_vec(&map).expect("serialize map");
    let path = dir.join(filename);
    fs::write(&path, &bytes).expect("write map");
    let digest = lnss_core::digest(FILE_DIGEST_DOMAIN, &bytes);
    (path, map, digest)
}

fn map_fixture(dir: &Path) -> (PathBuf, FeatureToBrainMap, [u8; 32]) {
    map_fixture_named(dir, "map.bin")
}

fn proposal_fixture_named(
    dir: &Path,
    map_path: &Path,
    map_digest: [u8; 32],
    filename: &str,
    proposal_id: &str,
) -> lnss_evolve::Proposal {
    let core_context = core_context_pack(3);
    write_json(
        &dir.join(filename),
        serde_json::json!({
            "proposal_id": proposal_id,
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": {
                "world_state_digest": core_context.world_state_digest.to_vec(),
                "self_state_digest": core_context.self_state_digest.to_vec(),
                "control_frame_digest": core_context.control_frame_digest.to_vec(),
                "policy_digest": serde_json::Value::Null,
                "last_feedback_digest": serde_json::Value::Null,
                "wm_pred_error_bucket": core_context.wm_pred_error_bucket,
                "rlm_followup_executed": core_context.rlm_followup_executed,
            },
            "core_context_digest": core_context.digest().to_vec(),
            "payload": {
                "type": "mapping_update",
                "new_map_path": map_path.to_string_lossy(),
                "map_digest": map_digest.to_vec(),
                "change_summary": ["trim"]
            },
            "reason_codes": ["offline"]
        }),
    );
    load_proposals(dir)
        .expect("load proposals")
        .into_iter()
        .find(|proposal| proposal.proposal_id == proposal_id)
        .expect("proposal present")
}

fn proposal_fixture(dir: &Path, map_path: &Path, map_digest: [u8; 32]) -> lnss_evolve::Proposal {
    proposal_fixture_named(dir, map_path, map_digest, "proposal.json", "proposal-map-1")
}

fn aap_fixture(dir: &Path, proposal: &lnss_evolve::Proposal) -> ucf::v1::ApprovalArtifactPackage {
    let ctx = ApprovalContext {
        session_id: "session-1".to_string(),
        ruleset_digest: Some([9u8; 32]),
        current_mapping_digest: Some([8u8; 32]),
        current_sae_pack_digest: None,
        current_liquid_params_digest: None,
        latest_scorecard_digest: None,
        trace_digest: Some(TEST_TRACE_DIGEST),
        active_cfg_root_digest: Some([1u8; 32]),
        shadow_cfg_root_digest: Some([2u8; 32]),
        requested_operation: ucf::v1::OperationCategory::OpException,
    };
    let aap = build_aap_for_proposal(proposal, &ctx).expect("aap");
    let digest: [u8; 32] = aap
        .aap_digest
        .as_ref()
        .and_then(|d| d.value.as_slice().try_into().ok())
        .expect("aap digest");
    let aap_dir = dir.join("aap");
    fs::create_dir_all(&aap_dir).expect("create aap dir");
    let path = aap_dir.join(format!("aap_{}.bin", hex::encode(digest)));
    fs::write(&path, canonical_bytes(&aap)).expect("write aap");
    aap
}

fn approval_fixture(
    dir: &Path,
    aap_id: &str,
    form: ucf::v1::DecisionForm,
    constraints: Option<ucf::v1::ConstraintsDelta>,
) -> [u8; 32] {
    let mut decision = ucf::v1::ApprovalDecision {
        decision_id: "decision-1".to_string(),
        aap_id: aap_id.to_string(),
        decision: form as i32,
        reason_codes: None,
        constraints,
        approval_decision_digest: None,
    };
    let digest = digest_proto("UCF:HASH:APPROVAL_DECISION", &canonical_bytes(&decision));
    decision.approval_decision_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    let path = dir.join(format!("approval_{}.bin", hex::encode(digest)));
    fs::write(&path, canonical_bytes(&decision)).expect("write approval decision");
    digest
}

fn runtime_fixture(dir: &Path, writer: RecordingWriter) -> LnssRuntime {
    let tap_frame = TapFrame::new("hook-a", vec![1, 2, 3]);
    let mapper = FeatureToBrainMap::new(
        1,
        vec![(
            u32::from_le_bytes([
                tap_frame.activation_digest[0],
                tap_frame.activation_digest[1],
                tap_frame.activation_digest[2],
                tap_frame.activation_digest[3],
            ]),
            BrainTarget::new("v1", "pop", 1, "syn", 500),
        )],
    );

    LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(writer),
        pvgs: None,
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: None,
        approval_inbox: Some(
            ApprovalInbox::with_state_path(dir, dir.join("state/approval_state.json"), 1)
                .expect("approval inbox"),
        ),
        activation_now_ms: None,
        event_sink: None,
        shadow: lnss_runtime::ShadowConfig::default(),
        shadow_rig: None,
        trace_state: None,
        seen_trace_digests: std::collections::BTreeSet::new(),
        lifecycle_index: LifecycleIndex::default(),
        evidence_query_client: None,
        lifecycle_tick: 0,
        policy_mode: PolicyMode::Open,
        control_intent_class: ControlIntentClass::Monitor,
        recursion_policy: RecursionPolicy::default(),
        world_state_digest: [0; 32],
        last_action_digest: [0; 32],
        last_self_state_digest: [0; 32],
        pred_error_threshold: 128,
        trigger_proposals_enabled: false,
    }
}

fn seed_lifecycle_for_proposal(runtime: &mut LnssRuntime, proposal: &lnss_evolve::Proposal) {
    let key = LifecycleKey {
        proposal_digest: proposal.proposal_digest,
        context_digest: proposal.core_context_digest,
        active_cfg_root_digest: proposal.base_active_cfg_digest,
    };
    runtime
        .lifecycle_index
        .note_trace(key, TEST_TRACE_DIGEST, TRACE_VERDICT_PROMISING, 1);
}

fn runtime_fixture_with_pvgs(
    dir: &Path,
    writer: RecordingWriter,
    pvgs: std::sync::Arc<std::sync::Mutex<MockPvgsClient>>,
    activation_now_ms: u64,
) -> LnssRuntime {
    let mut runtime = runtime_fixture(dir, writer);
    runtime.pvgs = Some(Box::new(SharedPvgsClient::new(pvgs)));
    runtime.activation_now_ms = Some(activation_now_ms);
    runtime
}

fn run_once(runtime: &mut LnssRuntime) {
    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];
    let mods = EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec![],
        vec![],
    );
    runtime
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs)
        .expect("runtime step");
}

fn activation_id_for(proposal_digest: [u8; 32], approval_digest: [u8; 32]) -> String {
    let proposal_prefix = hex::encode(&proposal_digest[..8]);
    let approval_prefix = hex::encode(&approval_digest[..8]);
    format!("act:{proposal_prefix}:{approval_prefix}")
}

struct ExpectedActivationInput<'a> {
    proposal: &'a lnss_evolve::Proposal,
    approval_digest: [u8; 32],
    status: ActivationStatus,
    active_mapping_digest: Option<[u8; 32]>,
    active_sae_pack_digest: Option<[u8; 32]>,
    active_liquid_params_digest: Option<[u8; 32]>,
    active_injection_limits: Option<InjectionLimits>,
    created_at_ms: u64,
}

fn expected_activation_evidence(
    input: ExpectedActivationInput<'_>,
) -> ProposalActivationEvidenceLocal {
    let reason_code = match &input.status {
        ActivationStatus::Applied => "RC.GV.PROPOSAL.ACTIVATED".to_string(),
        ActivationStatus::Rejected => "RC.GV.PROPOSAL.REJECTED".to_string(),
    };
    ProposalActivationEvidenceLocal {
        activation_id: activation_id_for(input.proposal.proposal_digest, input.approval_digest),
        proposal_digest: input.proposal.proposal_digest,
        approval_digest: input.approval_digest,
        core_context_digest: input.proposal.core_context_digest,
        status: input.status,
        active_mapping_digest: input.active_mapping_digest,
        active_sae_pack_digest: input.active_sae_pack_digest,
        active_liquid_params_digest: input.active_liquid_params_digest,
        active_injection_limits: input.active_injection_limits.map(|limits| {
            ActivationInjectionLimits {
                max_spikes_per_tick: limits.max_spikes_per_tick,
                max_targets_per_spike: limits.max_targets_per_spike,
            }
        }),
        created_at_ms: input.created_at_ms,
        reason_codes: vec![reason_code],
        activation_digest: [0u8; 32],
    }
}

#[test]
fn approval_applies_mapping_update() {
    let dir = temp_dir("lnss_approval_apply");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn deny_does_not_apply() {
    let dir = temp_dir("lnss_approval_deny");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Deny, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);
    let original_digest = runtime.mapper.map_digest;
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, original_digest);
    assert_ne!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn loosened_constraints_are_rejected() {
    let dir = temp_dir("lnss_approval_loosened");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(
        &dir,
        &aap.aap_id,
        ucf::v1::DecisionForm::Allow,
        Some(ucf::v1::ConstraintsDelta {
            constraints_added: Vec::new(),
            constraints_removed: vec!["loosen fan-out".to_string()],
            novelty_lock: false,
        }),
    );

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);
    let original_digest = runtime.mapper.map_digest;
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, original_digest);
    assert_ne!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn approvals_are_idempotent() {
    let dir = temp_dir("lnss_approval_idempotent");
    let (map_path, _map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    let approval_digest = approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let writer_handle = writer.clone();
    let mut runtime = runtime_fixture(&dir, writer);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);
    run_once(&mut runtime);
    run_once(&mut runtime);

    let activation_records = writer_handle
        .records()
        .into_iter()
        .filter(|record| record.approval_digest == Some(approval_digest))
        .count();
    assert_eq!(activation_records, 1);
}

#[test]
fn state_persists_active_digests() {
    let dir = temp_dir("lnss_approval_state");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);
    run_once(&mut runtime);

    let state_path = dir.join("state/approval_state.json");
    let inbox = ApprovalInbox::with_state_path(&dir, state_path, 1).expect("reload inbox");
    assert_eq!(inbox.state().active_mapping_digest, Some(map.map_digest));
}

#[test]
fn activation_commit_on_apply() {
    let dir = temp_dir("lnss_activation_commit_apply");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    let approval_digest = approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();
    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture_with_pvgs(&dir, writer, pvgs_inner, 123);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);

    run_once(&mut runtime);

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_activation_bytes
        .clone();
    assert_eq!(committed.len(), 1);

    let expected = expected_activation_evidence(ExpectedActivationInput {
        proposal: &proposal,
        approval_digest,
        status: ActivationStatus::Applied,
        active_mapping_digest: Some(map.map_digest),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_injection_limits: Some(InjectionLimits::default()),
        created_at_ms: 123,
    });
    let expected_bytes = canonical_bytes(&build_activation_evidence_pb(&expected));
    assert_eq!(committed[0], expected_bytes);
}

#[test]
fn activation_commit_is_idempotent() {
    let dir = temp_dir("lnss_activation_commit_idempotent");
    let (map_path, _map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();
    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture_with_pvgs(&dir, writer, pvgs_inner, 123);
    seed_lifecycle_for_proposal(&mut runtime, &proposal);

    run_once(&mut runtime);
    run_once(&mut runtime);

    let committed_count = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_activation_bytes
        .len();
    assert_eq!(committed_count, 1);
}

#[test]
fn activation_commit_ordering_is_deterministic() {
    let dir = temp_dir("lnss_activation_commit_order");
    let (map_path_a, map_a, map_digest_a) = map_fixture_named(&dir, "map-a.bin");
    let (map_path_b, map_b, map_digest_b) = map_fixture_named(&dir, "map-b.bin");
    let proposal_a = proposal_fixture_named(
        &dir,
        &map_path_a,
        map_digest_a,
        "proposal-a.json",
        "proposal-a",
    );
    let proposal_b = proposal_fixture_named(
        &dir,
        &map_path_b,
        map_digest_b,
        "proposal-b.json",
        "proposal-b",
    );
    let aap_a = aap_fixture(&dir, &proposal_a);
    let aap_b = aap_fixture(&dir, &proposal_b);
    let approval_a = approval_fixture(&dir, &aap_a.aap_id, ucf::v1::DecisionForm::Allow, None);
    let approval_b = approval_fixture(&dir, &aap_b.aap_id, ucf::v1::DecisionForm::Allow, None);

    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();
    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture_with_pvgs(&dir, writer, pvgs_inner, 123);
    seed_lifecycle_for_proposal(&mut runtime, &proposal_a);
    seed_lifecycle_for_proposal(&mut runtime, &proposal_b);

    run_once(&mut runtime);
    run_once(&mut runtime);

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_activation_bytes
        .clone();
    assert_eq!(committed.len(), 2);

    let (first_proposal, first_approval, first_map, second_proposal, second_approval, second_map) =
        if approval_a < approval_b {
            (
                &proposal_a,
                approval_a,
                map_a.map_digest,
                &proposal_b,
                approval_b,
                map_b.map_digest,
            )
        } else {
            (
                &proposal_b,
                approval_b,
                map_b.map_digest,
                &proposal_a,
                approval_a,
                map_a.map_digest,
            )
        };

    let expected_first = expected_activation_evidence(ExpectedActivationInput {
        proposal: first_proposal,
        approval_digest: first_approval,
        status: ActivationStatus::Applied,
        active_mapping_digest: Some(first_map),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_injection_limits: Some(InjectionLimits::default()),
        created_at_ms: 123,
    });
    let expected_first_bytes = canonical_bytes(&build_activation_evidence_pb(&expected_first));
    let expected_second = expected_activation_evidence(ExpectedActivationInput {
        proposal: second_proposal,
        approval_digest: second_approval,
        status: ActivationStatus::Applied,
        active_mapping_digest: Some(second_map),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_injection_limits: Some(InjectionLimits::default()),
        created_at_ms: 123,
    });
    let expected_second_bytes = canonical_bytes(&build_activation_evidence_pb(&expected_second));

    assert_eq!(committed[0], expected_first_bytes);
    assert_eq!(committed[1], expected_second_bytes);
}

#[test]
fn activation_commit_on_reject() {
    let dir = temp_dir("lnss_activation_commit_reject");
    let (map_path, _map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    let approval_digest = approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Deny, None);

    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();
    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture_with_pvgs(&dir, writer, pvgs_inner, 123);
    let baseline_mapping = runtime.mapper.map_digest;
    seed_lifecycle_for_proposal(&mut runtime, &proposal);

    run_once(&mut runtime);

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_activation_bytes
        .clone();
    assert_eq!(committed.len(), 1);

    let expected = expected_activation_evidence(ExpectedActivationInput {
        proposal: &proposal,
        approval_digest,
        status: ActivationStatus::Rejected,
        active_mapping_digest: Some(baseline_mapping),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_injection_limits: Some(InjectionLimits::default()),
        created_at_ms: 123,
    });
    let expected_bytes = canonical_bytes(&build_activation_evidence_pb(&expected));
    assert_eq!(committed[0], expected_bytes);
}

#[test]
fn activation_precondition_failure_rejects() {
    let dir = temp_dir("lnss_activation_precondition_fail");
    let (map_path, _map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();
    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture_with_pvgs(&dir, writer, pvgs_inner, 123);
    let key = LifecycleKey {
        proposal_digest: proposal.proposal_digest,
        context_digest: proposal.core_context_digest,
        active_cfg_root_digest: proposal.base_active_cfg_digest,
    };
    runtime
        .lifecycle_index
        .note_trace(key, TEST_TRACE_DIGEST, TRACE_VERDICT_RISKY, 1);

    run_once(&mut runtime);

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_activation_bytes
        .clone();
    assert_eq!(committed.len(), 1);
    let activation =
        ucf::v1::ProposalActivationEvidence::decode(committed[0].as_slice()).expect("decode");
    let reason_codes = activation
        .reason_codes
        .map(|codes| codes.codes)
        .unwrap_or_default();
    assert!(reason_codes
        .iter()
        .any(|code| code == "RC.GV.PROPOSAL.ACTIVATION_PRECONDITION_FAILED"));
    assert_eq!(
        activation.status,
        ucf::v1::ActivationStatus::Rejected as i32
    );
}
