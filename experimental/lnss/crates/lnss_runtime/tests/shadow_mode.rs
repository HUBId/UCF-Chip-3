use chip2::{Chip2Runtime, DefaultRouter, L4Circuit};
use lnss_core::{
    BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap,
    PolicyMode, RecursionPolicy, TapFrame, TapKind, TapSpec,
};
use lnss_lifecycle::LifecycleIndex;
use lnss_rlm::RlmController;
use lnss_runtime::{
    BiophysFeedbackSnapshot, FeedbackConsumer, InjectionLimits, Limits, LnssRuntime,
    MappingAdaptationConfig, MechIntRecord, MechIntWriter, RigClient, SaeBackend, ShadowConfig,
    StubHookProvider, StubLlmBackend,
};
use lnss_worldmodel::WorldModelCoreStub;

#[derive(Clone, Default)]
struct RecordingWriter {
    records: std::sync::Arc<std::sync::Mutex<Vec<MechIntRecord>>>,
}

impl RecordingWriter {
    fn records(&self) -> Vec<MechIntRecord> {
        self.records.lock().expect("records lock").clone()
    }
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

struct Chip2RigClient {
    router: DefaultRouter,
    last_feedback: Option<BiophysFeedbackSnapshot>,
}

impl Chip2RigClient {
    fn new(seed: u64) -> Self {
        let runtime = Chip2Runtime::new(L4Circuit::new(seed));
        Self {
            router: DefaultRouter::new(runtime),
            last_feedback: None,
        }
    }
}

impl RigClient for Chip2RigClient {
    fn send_spikes(
        &mut self,
        spikes: &[lnss_runtime::BrainSpike],
    ) -> Result<(), lnss_runtime::LnssRuntimeError> {
        let external: Vec<chip2::ExternalSpike> = spikes
            .iter()
            .map(|spike| chip2::ExternalSpike {
                region: spike.target.region.clone(),
                population: spike.target.population.clone(),
                neuron_group: spike.target.neuron_group,
                syn_kind: spike.target.syn_kind.clone(),
                amplitude_q: spike.amplitude_q,
            })
            .collect();
        let tick = self.router.runtime().tick().saturating_add(1);
        self.router
            .inject_external_spikes(tick, &external)
            .map_err(|_| lnss_runtime::LnssRuntimeError::Rig("chip2 inject failed".to_string()))?;
        self.last_feedback = Some(self.router.runtime().feedback_snapshot());
        Ok(())
    }

    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        self.last_feedback.clone()
    }
}

fn build_mapping(amplitude_for_target: &[u16]) -> FeatureToBrainMap {
    let mut entries = Vec::new();
    for feature_id in 0..32u32 {
        for (target_idx, amplitude_q) in amplitude_for_target.iter().enumerate() {
            entries.push((
                feature_id,
                BrainTarget::new("v1", "pop", target_idx as u32, "syn", *amplitude_q),
            ));
        }
    }
    FeatureToBrainMap::new(1, entries)
}

#[test]
fn shadow_mapping_reduces_amplitude_and_improves_score() {
    let features = (0..32u32).map(|id| (id, 1000)).collect();
    let sae = FixedSaeBackend::new(features);
    let tap_frame = TapFrame::new("hook-a", vec![9, 9, 9]);
    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];

    let active_mapping = build_mapping(&[1000, 1000, 1000, 1000, 1000]);
    let shadow_mapping = build_mapping(&[0, 0, 1000, 1000, 1000]);

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
        sae: Box::new(sae),
        mechint: Box::new(writer),
        pvgs: None,
        rig: Box::new(Chip2RigClient::new(7)),
        mapper: active_mapping,
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
        approval_inbox: None,
        activation_now_ms: None,
        event_sink: None,
        shadow: ShadowConfig {
            enabled: true,
            shadow_mapping: Some(shadow_mapping.clone()),
            #[cfg(feature = "lnss-liquid-ode")]
            shadow_liquid_params: None,
            shadow_injection_limits: None,
        },
        shadow_rig: Some(Box::new(Chip2RigClient::new(11))),
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

    let output = runtime
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs)
        .expect("runtime step");

    let shadow_output = output.shadow.expect("shadow output");
    assert!(shadow_output.score.shadow >= shadow_output.score.active);
    assert!(shadow_output
        .reason_codes
        .iter()
        .any(|code| { code == "RC.GV.SHADOW.BETTER" || code == "RC.GV.SHADOW.EQUAL" }));

    let records = writer_handle.records();
    let shadow_record = records
        .iter()
        .find(|record| record.shadow_evidence.is_some())
        .expect("shadow record");
    let evidence = shadow_record
        .shadow_evidence
        .as_ref()
        .expect("shadow evidence");
    assert_eq!(evidence.shadow_mapping_digest, shadow_mapping.map_digest);
    assert!(evidence.score.delta >= 0);
}
