use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_core::{
    digest, BiophysFeedbackSnapshot, BrainTarget, ControlIntentClass, CoreContextDigestPack,
    EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap, PolicyMode, RecursionPolicy, TapFrame,
    TapKind, TapSpec,
};
use lnss_evolve::load_proposals;
use lnss_evolve::trace_encoding::{
    build_trace_run_evidence_pb, TraceRunEvidenceLocal, TraceVerdict,
};
use lnss_lifecycle::{LifecycleIndex, LifecycleKey, ACTIVATION_STATUS_APPLIED};
use lnss_rlm::RlmController;
use lnss_runtime::{
    cfg_root_digest_pack, BrainSpike, CfgRootDigestInputs, FeedbackConsumer, InjectionLimits,
    Limits, LnssRuntime, MappingAdaptationConfig, MechIntRecord, MechIntWriter, ProposalInbox,
    RigClient, SaeBackend, ShadowConfig, StubHookProvider, StubLlmBackend, StubRigClient,
};
use lnss_worldmodel::WorldModelCoreStub;
use prost::Message;
use pvgs_client::{LocalPvgsClient, MockPvgsClient, PvgsClient, PvgsClientReader, PvgsReader};
use ucf_protocol::canonical_bytes;
use ucf_protocol::ucf;

#[derive(Clone, Default)]
struct RecordingWriter {
    records: std::sync::Arc<std::sync::Mutex<Vec<MechIntRecord>>>,
}

impl MechIntWriter for RecordingWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.records.lock().expect("records lock").push(rec.clone());
        Ok(())
    }
}

struct FixedSaeBackend {
    features: Vec<(u32, u16)>,
}

impl FixedSaeBackend {
    fn new(features: Vec<(u32, u16)>) -> Self {
        Self { features }
    }
}

impl SaeBackend for FixedSaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent {
        FeatureEvent::new(
            "session-fixed",
            "step-fixed",
            &tap.hook_id,
            self.features.clone(),
            0,
            vec![],
        )
    }
}

struct FeedbackRigClient {
    limits: InjectionLimits,
    tick: u64,
    last: Option<BiophysFeedbackSnapshot>,
}

impl FeedbackRigClient {
    fn new(limits: InjectionLimits) -> Self {
        Self {
            limits,
            tick: 0,
            last: None,
        }
    }

    fn snapshot_for(&mut self, spikes: &[BrainSpike]) -> BiophysFeedbackSnapshot {
        let max_spikes = self.limits.max_spikes_per_tick as usize;
        let dropped = spikes.len().saturating_sub(max_spikes);
        let injected = spikes.len().saturating_sub(dropped);
        let mut buf = Vec::new();
        write_u32(&mut buf, spikes.len() as u32);
        write_u32(&mut buf, self.limits.max_spikes_per_tick);
        write_u32(&mut buf, self.limits.max_targets_per_spike);
        for spike in spikes {
            write_string(&mut buf, &spike.target.region);
            write_string(&mut buf, &spike.target.population);
            write_u32(&mut buf, spike.target.neuron_group);
            write_string(&mut buf, &spike.target.syn_kind);
            write_u16(&mut buf, spike.amplitude_q);
        }
        let snapshot_digest = digest("lnss.shadow.feedback.predicted.v1", &buf);
        self.tick = self.tick.saturating_add(1);
        BiophysFeedbackSnapshot {
            tick: self.tick,
            snapshot_digest,
            event_queue_overflowed: dropped > 0,
            events_dropped: dropped as u64,
            events_injected: injected.min(u32::MAX as usize) as u32,
            injected_total: injected as u64,
        }
    }
}

impl RigClient for FeedbackRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.last = Some(self.snapshot_for(spikes));
        Ok(())
    }

    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        self.last.clone()
    }
}

struct FixedTickRigClient {
    limits: InjectionLimits,
    tick: u64,
    last: Option<BiophysFeedbackSnapshot>,
}

impl FixedTickRigClient {
    fn new(limits: InjectionLimits, tick: u64) -> Self {
        Self {
            limits,
            tick,
            last: None,
        }
    }

    fn snapshot_for(&self, spikes: &[BrainSpike]) -> BiophysFeedbackSnapshot {
        let max_spikes = self.limits.max_spikes_per_tick as usize;
        let dropped = spikes.len().saturating_sub(max_spikes);
        let injected = spikes.len().saturating_sub(dropped);
        let mut buf = Vec::new();
        write_u32(&mut buf, spikes.len() as u32);
        write_u32(&mut buf, self.limits.max_spikes_per_tick);
        write_u32(&mut buf, self.limits.max_targets_per_spike);
        for spike in spikes {
            write_string(&mut buf, &spike.target.region);
            write_string(&mut buf, &spike.target.population);
            write_u32(&mut buf, spike.target.neuron_group);
            write_string(&mut buf, &spike.target.syn_kind);
            write_u16(&mut buf, spike.amplitude_q);
        }
        let snapshot_digest = digest("lnss.shadow.feedback.predicted.v1", &buf);
        BiophysFeedbackSnapshot {
            tick: self.tick,
            snapshot_digest,
            event_queue_overflowed: dropped > 0,
            events_dropped: dropped as u64,
            events_injected: injected.min(u32::MAX as usize) as u32,
            injected_total: injected as u64,
        }
    }
}

impl RigClient for FixedTickRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.last = Some(self.snapshot_for(spikes));
        Ok(())
    }

    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        self.last.clone()
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

fn mapping_for_features(feature_ids: &[u32], targets_per_feature: usize) -> FeatureToBrainMap {
    let mut entries = Vec::new();
    for feature_id in feature_ids {
        for target_idx in 0..targets_per_feature {
            entries.push((
                *feature_id,
                BrainTarget::new("v1", "pop", target_idx as u32, "syn", 800),
            ));
        }
    }
    FeatureToBrainMap::new(1, entries)
}

fn default_mods() -> EmotionFieldSnapshot {
    EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec![],
        vec![],
    )
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

struct RuntimeFixture {
    pvgs: Option<Box<dyn PvgsClientReader>>,
    proposal_inbox: Option<ProposalInbox>,
    injection_limits: InjectionLimits,
    shadow: ShadowConfig,
    shadow_rig: Option<Box<dyn RigClient>>,
    mapper: FeatureToBrainMap,
    sae: Box<dyn SaeBackend>,
    rig: Box<dyn RigClient>,
}

fn runtime_with_shadow(fixture: RuntimeFixture) -> LnssRuntime {
    LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![TapFrame::new("hook-a", vec![1, 2, 3])],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: fixture.sae,
        mechint: Box::new(RecordingWriter::default()),
        pvgs: fixture.pvgs,
        rig: fixture.rig,
        mapper: fixture.mapper,
        limits: Limits::default(),
        injection_limits: fixture.injection_limits,
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: fixture.proposal_inbox,
        approval_inbox: None,
        activation_now_ms: None,
        event_sink: None,
        shadow: fixture.shadow,
        shadow_rig: fixture.shadow_rig,
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

fn trace_context_digests(
    pvgs: std::sync::Arc<std::sync::Mutex<MockPvgsClient>>,
) -> ([u8; 32], [u8; 32]) {
    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapping_for_features(&feature_ids[..1], 1);

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs.clone()))),
        proposal_inbox: None,
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 4,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(StubRigClient::default()),
    });

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let committed = pvgs
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .clone();
    assert_eq!(committed.len(), 1);
    let evidence =
        ucf::v1::TraceRunEvidence::decode(committed[0].as_slice()).expect("decode trace evidence");
    let active: [u8; 32] = evidence
        .active_context_digest
        .as_ref()
        .expect("active context digest")
        .value
        .as_slice()
        .try_into()
        .expect("active context bytes");
    let shadow: [u8; 32] = evidence
        .shadow_context_digest
        .as_ref()
        .expect("shadow context digest")
        .value
        .as_slice()
        .try_into()
        .expect("shadow context bytes");
    (active, shadow)
}

#[test]
fn shadow_trace_commits_once_and_is_deterministic() {
    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapping_for_features(&feature_ids[..1], 1);

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        proposal_inbox: None,
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 4,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(StubRigClient::default()),
    });

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .len();
    assert_eq!(committed, 1);
    let first_created_at = runtime
        .trace_state
        .as_ref()
        .expect("trace state")
        .created_at_ms;

    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            &[tap_spec],
        )
        .expect("runtime step");

    let committed_again = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .len();
    assert_eq!(committed_again, 2);
    let second_created_at = runtime
        .trace_state
        .as_ref()
        .expect("trace state")
        .created_at_ms;
    assert!(second_created_at >= first_created_at);
}

#[test]
fn duplicate_trace_digest_is_skipped() {
    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapping_for_features(&feature_ids[..1], 1);
    let limits = InjectionLimits {
        max_spikes_per_tick: 4,
        max_targets_per_spike: 4,
    };

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        proposal_inbox: None,
        injection_limits: limits.clone(),
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(FixedTickRigClient::new(limits, 1)),
    });

    let initial_world_state = runtime.world_state_digest;
    let initial_last_action = runtime.last_action_digest;
    let initial_self_state = runtime.last_self_state_digest;
    let initial_feedback = runtime.feedback.last.clone();

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");
    let first_trace_digest = runtime
        .trace_state
        .as_ref()
        .expect("trace state")
        .trace_digest;
    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .len();
    assert_eq!(committed, 1);

    runtime.world_state_digest = initial_world_state;
    runtime.last_action_digest = initial_last_action;
    runtime.last_self_state_digest = initial_self_state;
    runtime.feedback.last = initial_feedback;

    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");
    let second_trace_state = runtime.trace_state.as_ref().expect("trace state");
    assert_eq!(second_trace_state.trace_digest, first_trace_digest);
    assert!(second_trace_state.duplicate_skipped);

    let committed_again = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .len();
    assert_eq!(committed_again, 1);
}

#[test]
fn trace_context_digests_are_present_and_deterministic() {
    let pvgs_a = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let (active_a, shadow_a) = trace_context_digests(pvgs_a);
    assert_ne!(active_a, [0u8; 32]);
    assert_ne!(shadow_a, [0u8; 32]);
    assert_eq!(active_a, shadow_a);

    let pvgs_b = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let (active_b, shadow_b) = trace_context_digests(pvgs_b);
    assert_eq!(active_a, active_b);
    assert_eq!(shadow_a, shadow_b);
}

#[test]
fn neutral_trace_blocks_aap_generation() {
    let dir = temp_dir("lnss_trace_neutral");
    let context = core_context_json(1);
    write_json(
        &dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "injection_limits_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context["core_context_digest_pack"].clone(),
            "core_context_digest": context["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 16,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapping_for_features(&feature_ids[..1], 1);

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: None,
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 1)),
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 10,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(FeedbackRigClient::new(InjectionLimits {
            max_spikes_per_tick: 10,
            max_targets_per_spike: 4,
        })),
    });

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            &[tap_spec],
        )
        .expect("runtime step");

    let aap_dir = dir.join("aap");
    let aap_count = if aap_dir.exists() {
        fs::read_dir(&aap_dir).expect("read dir").count()
    } else {
        0
    };
    assert_eq!(aap_count, 0);
}

#[test]
fn promising_trace_allows_aap_and_binds_trace_digest() {
    let dir = temp_dir("lnss_trace_promising");
    let context = core_context_json(2);
    write_json(
        &dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "injection_limits_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context["core_context_digest_pack"].clone(),
            "core_context_digest": context["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 16,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapper.clone();

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: None,
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 1)),
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 1,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(FeedbackRigClient::new(InjectionLimits {
            max_spikes_per_tick: 1,
            max_targets_per_spike: 4,
        })),
    });

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            &[tap_spec],
        )
        .expect("runtime step");

    let trace_state = runtime.trace_state.as_ref().expect("trace state");
    let trace_digest = trace_state.trace_digest;
    let aap_dir = dir.join("aap");
    if trace_state.verdict != TraceVerdict::Promising {
        assert!(!aap_dir.exists());
        return;
    }
    let mut entries = fs::read_dir(&aap_dir).expect("aap dir");
    let entry = entries.next().expect("aap entry").expect("aap entry");
    let bytes = fs::read(entry.path()).expect("read aap");
    let aap = ucf::v1::ApprovalArtifactPackage::decode(bytes.as_slice()).expect("decode aap");
    let trace_ref = aap
        .evidence_refs
        .iter()
        .find(|item| item.id == "trace_digest")
        .expect("trace digest ref");
    assert_eq!(
        trace_ref.digest.as_ref().expect("trace digest").value,
        trace_digest
    );
}

#[test]
fn aap_is_blocked_after_activation_applied() {
    let dir = temp_dir("lnss_trace_activation_block");
    let context = core_context_json(3);
    write_json(
        &dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "injection_limits_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context["core_context_digest_pack"].clone(),
            "core_context_digest": context["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 16,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapper.clone();

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: None,
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 1)),
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 1,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(FeedbackRigClient::new(InjectionLimits {
            max_spikes_per_tick: 1,
            max_targets_per_spike: 4,
        })),
    });

    let proposal = load_proposals(&dir)
        .expect("load proposals")
        .into_iter()
        .next()
        .expect("proposal");
    let key = LifecycleKey {
        proposal_digest: proposal.proposal_digest,
        context_digest: proposal.core_context_digest,
        active_cfg_root_digest: proposal.base_active_cfg_digest,
    };
    runtime
        .lifecycle_index
        .note_activation(key, [9u8; 32], ACTIVATION_STATUS_APPLIED, 1);

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            &[tap_spec],
        )
        .expect("runtime step");

    let aap_dir = dir.join("aap");
    let aap_count = if aap_dir.exists() {
        fs::read_dir(&aap_dir).expect("read dir").count()
    } else {
        0
    };
    assert_eq!(aap_count, 0);
}

#[test]
fn trace_evidence_uses_cfg_root_digests() {
    let pvgs_inner = std::sync::Arc::new(std::sync::Mutex::new(MockPvgsClient::default()));
    let pvgs_handle = pvgs_inner.clone();

    let feature_ids = vec![1u32, 2u32];
    let mapper = mapping_for_features(&feature_ids, 2);
    let shadow_mapping = mapping_for_features(&feature_ids[..1], 1);

    let mut runtime = runtime_with_shadow(RuntimeFixture {
        pvgs: Some(Box::new(SharedPvgsClient::new(pvgs_inner))),
        proposal_inbox: None,
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 4,
            max_targets_per_spike: 4,
        },
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: None,
        mapper,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 1000), (2, 1000)])),
        rig: Box::new(StubRigClient::default()),
    });

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    runtime
        .run_step(
            "session-1",
            "step-1",
            b"input",
            &default_mods(),
            std::slice::from_ref(&tap_spec),
        )
        .expect("runtime step");

    let committed = pvgs_handle
        .lock()
        .expect("pvgs lock")
        .committed_trace_run_bytes
        .clone();
    assert_eq!(committed.len(), 1);
    let evidence =
        ucf::v1::TraceRunEvidence::decode(committed[0].as_slice()).expect("decode trace evidence");
    let active_cfg_digest: [u8; 32] = evidence
        .active_cfg_digest
        .as_ref()
        .expect("active cfg digest")
        .value
        .as_slice()
        .try_into()
        .expect("active cfg bytes");
    let shadow_cfg_digest: [u8; 32] = evidence
        .shadow_cfg_digest
        .as_ref()
        .expect("shadow cfg digest")
        .value
        .as_slice()
        .try_into()
        .expect("shadow cfg bytes");

    let world_cfg = runtime.worldmodel.cfg_snapshot();
    let rlm_cfg = runtime.rlm.cfg_snapshot();
    let active_pack = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: runtime.llm.as_ref(),
        tap_specs: std::slice::from_ref(&tap_spec),
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: runtime.active_sae_pack_digest,
        mapping: &runtime.mapper,
        limits: &runtime.limits,
        injection_limits: &runtime.injection_limits,
        amplitude_cap_q: lnss_runtime::DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: runtime.active_liquid_params_digest,
    })
    .expect("active cfg pack");
    let shadow_mapping = runtime
        .shadow
        .shadow_mapping
        .as_ref()
        .expect("shadow mapping");
    let shadow_limits = runtime
        .shadow
        .shadow_injection_limits
        .as_ref()
        .unwrap_or(&runtime.injection_limits);
    let shadow_pack = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: runtime.llm.as_ref(),
        tap_specs: std::slice::from_ref(&tap_spec),
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: runtime.active_sae_pack_digest,
        mapping: shadow_mapping,
        limits: &runtime.limits,
        injection_limits: shadow_limits,
        amplitude_cap_q: lnss_runtime::DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: runtime.active_liquid_params_digest,
    })
    .expect("shadow cfg pack");

    assert_eq!(active_cfg_digest, active_pack.root_cfg_digest);
    assert_eq!(shadow_cfg_digest, shadow_pack.root_cfg_digest);
}

#[test]
fn tampered_trace_evidence_rejected() {
    let evidence = TraceRunEvidenceLocal {
        trace_id: "trace:aa:bb:1".to_string(),
        active_cfg_digest: [1u8; 32],
        shadow_cfg_digest: [2u8; 32],
        active_feedback_digest: [3u8; 32],
        shadow_feedback_digest: [4u8; 32],
        active_context_digest: [5u8; 32],
        shadow_context_digest: [6u8; 32],
        score_active: 10,
        score_shadow: 15,
        delta: 5,
        verdict: TraceVerdict::Promising,
        created_at_ms: 20,
        reason_codes: vec!["rc.beta".to_string(), "rc.alpha".to_string()],
        trace_digest: [0u8; 32],
    };

    let pb = build_trace_run_evidence_pb(&evidence);
    let mut tampered = pb.clone();
    if let Some(reason_codes) = tampered.reason_codes.as_mut() {
        reason_codes.codes.reverse();
    }

    let mut pvgs = LocalPvgsClient::default();
    let receipt = pvgs
        .commit_trace_run_evidence(canonical_bytes(&tampered))
        .expect("commit trace");
    assert_eq!(receipt.status, ucf::v1::ReceiptStatus::Rejected as i32);
}
