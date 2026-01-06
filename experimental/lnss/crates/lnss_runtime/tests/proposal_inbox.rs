use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_core::{
    BrainTarget, ControlIntentClass, CoreContextDigestPack, EmotionFieldSnapshot,
    FeatureToBrainMap, PolicyMode, RecursionPolicy, TapFrame, TapKind, TapSpec,
};
use lnss_evolve::{
    build_proposal_evidence_pb, evaluate, load_proposals, proposal_payload_digest, EvalContext,
    ProposalEvidence, ProposalKind,
};
use lnss_lifecycle::LifecycleIndex;
use lnss_rlm::RlmController;
use lnss_runtime::{
    FeedbackConsumer, Limits, LnssRuntime, MappingAdaptationConfig, MechIntRecord, MechIntWriter,
    ProposalInbox, StubHookProvider, StubLlmBackend, StubRigClient,
};
use lnss_sae::StubSaeBackend;
use lnss_worldmodel::WorldModelCoreStub;
use prost::Message;
use pvgs_client::{MockPvgsClient, PvgsClient, PvgsReader};
use ucf_protocol::canonical_bytes;
use ucf_protocol::ucf;

#[derive(Clone, Default)]
struct RecordingWriter {
    records: Arc<Mutex<Vec<MechIntRecord>>>,
}

impl RecordingWriter {
    fn records(&self) -> Vec<MechIntRecord> {
        self.records.lock().expect("lock").clone()
    }
}

impl MechIntWriter for RecordingWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.records.lock().expect("lock").push(rec.clone());
        Ok(())
    }
}

#[derive(Clone)]
struct SharedPvgsClient {
    inner: Arc<Mutex<MockPvgsClient>>,
}

impl SharedPvgsClient {
    fn new(inner: Arc<Mutex<MockPvgsClient>>) -> Self {
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
    fs::write(path, serde_json::to_vec(&value).expect("json")).expect("write json");
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

fn core_context_json(seed: u8) -> serde_json::Value {
    let pack = core_context_pack(seed);
    serde_json::json!({
        "core_context_digest_pack": {
            "world_state_digest": pack.world_state_digest.to_vec(),
            "self_state_digest": pack.self_state_digest.to_vec(),
            "control_frame_digest": pack.control_frame_digest.to_vec(),
            "policy_digest": serde_json::Value::Null,
            "last_feedback_digest": serde_json::Value::Null,
            "wm_pred_error_bucket": pack.wm_pred_error_bucket,
            "rlm_followup_executed": pack.rlm_followup_executed,
        },
        "core_context_digest": pack.digest().to_vec(),
    })
}

fn proposal_id_from_payload(payload: &[u8]) -> String {
    let evidence = ucf::v1::ProposalEvidence::decode(payload).expect("decode proposal evidence");
    evidence.proposal_id
}

#[test]
fn proposal_ingestion_is_bounded_and_does_not_apply() {
    let dir = temp_dir("lnss_inbox");
    let context_a = core_context_json(1);
    let context_b = core_context_json(2);
    let context_c = core_context_json(3);
    write_json(
        &dir.join("a.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context_a["core_context_digest_pack"].clone(),
            "core_context_digest": context_a["core_context_digest"].clone(),
            "payload": {
                "type": "mapping_update",
                "new_map_path": "maps/new.json",
                "map_digest": vec![2; 32],
                "change_summary": ["swap", "trim"]
            },
            "reason_codes": ["offline"]
        }),
    );
    write_json(
        &dir.join("b.json"),
        serde_json::json!({
            "proposal_id": "proposal-b",
            "kind": "injection_limits_update",
            "created_at_ms": 2,
            "base_evidence_digest": vec![2; 32],
            "core_context_digest_pack": context_b["core_context_digest_pack"].clone(),
            "core_context_digest": context_b["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 32,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );
    write_json(
        &dir.join("c.json"),
        serde_json::json!({
            "proposal_id": "proposal-c",
            "kind": "sae_pack_update",
            "created_at_ms": 3,
            "base_evidence_digest": vec![3; 32],
            "core_context_digest_pack": context_c["core_context_digest_pack"].clone(),
            "core_context_digest": context_c["core_context_digest"].clone(),
            "payload": {
                "type": "sae_pack_update",
                "pack_path": "packs/p.safetensors",
                "pack_digest": vec![4; 32]
            },
            "reason_codes": []
        }),
    );

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
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
            BrainTarget::new("v1", "pop", 1, "syn", 800),
        )],
    );
    let mapping_digest = mapper.map_digest;

    let writer = RecordingWriter::default();
    let writer_handle = writer.clone();

    let mut runtime = LnssRuntime {
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
        injection_limits: lnss_runtime::InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 2)),
        approval_inbox: None,
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
    };

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
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let records_after_first = writer_handle.records();
    assert_eq!(records_after_first.len(), 3);

    runtime
        .run_step(
            "session-1",
            "step-2",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let records_after_second = writer_handle.records();
    assert_eq!(records_after_second.len(), 5);
    assert_eq!(runtime.mapper.map_digest, mapping_digest);
}

#[test]
fn proposal_commits_only_once_across_ticks() {
    let dir = temp_dir("lnss_inbox_commit_once");
    let context_a = core_context_json(4);
    let context_b = core_context_json(5);
    write_json(
        &dir.join("a.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context_a["core_context_digest_pack"].clone(),
            "core_context_digest": context_a["core_context_digest"].clone(),
            "payload": {
                "type": "mapping_update",
                "new_map_path": "maps/new.json",
                "map_digest": vec![2; 32],
                "change_summary": ["swap", "trim"]
            },
            "reason_codes": ["offline"]
        }),
    );
    write_json(
        &dir.join("b.json"),
        serde_json::json!({
            "proposal_id": "proposal-b",
            "kind": "injection_limits_update",
            "created_at_ms": 2,
            "base_evidence_digest": vec![2; 32],
            "core_context_digest_pack": context_b["core_context_digest_pack"].clone(),
            "core_context_digest": context_b["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 32,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
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
            BrainTarget::new("v1", "pop", 1, "syn", 800),
        )],
    );

    let pvgs_inner = Arc::new(Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let mut runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(RecordingWriter::default()),
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: lnss_runtime::InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 10)),
        approval_inbox: None,
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
    };

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
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    runtime
        .run_step(
            "session-1",
            "step-2",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_evidence_bytes
        .len();
    assert_eq!(committed, 2);
}

#[test]
fn proposal_commits_are_bounded_and_ordered() {
    let dir = temp_dir("lnss_inbox_bounded");
    for idx in 0..20 {
        let context = core_context_json(idx as u8 + 1);
        write_json(
            &dir.join(format!("{idx:02}.json")),
            serde_json::json!({
                "proposal_id": format!("proposal-{idx:02}"),
                "kind": "injection_limits_update",
                "created_at_ms": idx,
                "base_evidence_digest": vec![idx as u8; 32],
                "core_context_digest_pack": context["core_context_digest_pack"].clone(),
                "core_context_digest": context["core_context_digest"].clone(),
                "payload": {
                    "type": "injection_limits_update",
                    "max_spikes_per_tick": 32,
                    "max_targets_per_spike": 4
                },
                "reason_codes": []
            }),
        );
    }

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
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
            BrainTarget::new("v1", "pop", 1, "syn", 800),
        )],
    );

    let pvgs_inner = Arc::new(Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let mut runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(RecordingWriter::default()),
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: lnss_runtime::InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 5)),
        approval_inbox: None,
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
    };

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
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_evidence_bytes
        .clone();
    assert_eq!(committed.len(), 5);
    let committed_ids = committed
        .iter()
        .map(|payload| proposal_id_from_payload(payload))
        .collect::<Vec<_>>();
    assert_eq!(
        committed_ids,
        vec![
            "PROPOSAL-00",
            "PROPOSAL-01",
            "PROPOSAL-02",
            "PROPOSAL-03",
            "PROPOSAL-04"
        ]
    );
}

#[test]
fn local_pvgs_receives_expected_payload() {
    let dir = temp_dir("lnss_inbox_payload");
    let context = core_context_json(30);
    write_json(
        &dir.join("a.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "injection_limits_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context["core_context_digest_pack"].clone(),
            "core_context_digest": context["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 32,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
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
            BrainTarget::new("v1", "pop", 1, "syn", 800),
        )],
    );

    let pvgs_inner = Arc::new(Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let mut runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(RecordingWriter::default()),
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: lnss_runtime::InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 5)),
        approval_inbox: None,
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
    };

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
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let proposals = load_proposals(&dir).expect("load proposals");
    let proposal = proposals.first().expect("proposal");
    let eval_ctx = EvalContext {
        latest_feedback_digest: None,
        trace_run_digest: None,
        metrics: Vec::new(),
    };
    let eval = evaluate(proposal, &eval_ctx);
    let payload_digest = proposal_payload_digest(&proposal.payload).expect("payload digest");
    let evidence = ProposalEvidence {
        proposal_id: proposal.proposal_id.clone(),
        proposal_digest: proposal.proposal_digest,
        kind: ProposalKind::InjectionLimitsUpdate,
        base_evidence_digest: [0u8; 32],
        core_context_digest: proposal.core_context_digest,
        payload_digest,
        created_at_ms: proposal.created_at_ms,
        score: eval.score,
        verdict: eval.verdict,
        reason_codes: vec!["RC.GV.PROPOSAL.MISSING_BASE_EVIDENCE".to_string()],
    };
    let expected = canonical_bytes(&build_proposal_evidence_pb(&evidence));

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .local
        .committed_proposal_evidence_bytes
        .clone();
    assert_eq!(committed.len(), 1);
    assert_eq!(committed[0], expected);
}
