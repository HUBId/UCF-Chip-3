#![cfg(all(feature = "lnss", feature = "lnss-chip2-bridge"))]

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use chip2::{Chip2Runtime, DefaultRouter, L4Circuit};
use lnss::lnss_bluebridge::{
    Chip2InjectClient, Chip2RouterAdapter, Chip2RouterError, ExternalSpike, InjectionReport,
};
use lnss::lnss_core::{
    BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureToBrainMap, PolicyMode,
    RecursionPolicy, TapFrame, TapKind, TapSpec,
};
use lnss::lnss_mechint::JsonlMechIntWriter;
use lnss::lnss_rlm::RlmController;
use lnss::lnss_runtime::{
    BiophysFeedbackSnapshot, FeedbackConsumer, InjectionLimits, Limits, LnssRuntime,
    MappingAdaptationConfig, MechIntRecord, StubHookProvider, StubLlmBackend,
};
use lnss::lnss_sae::StubSaeBackend;
use lnss::lnss_worldmodel::WorldModelCoreStub;
use lnss_lifecycle::LifecycleIndex;

#[derive(Clone)]
struct Chip2RouterBridge {
    router: Arc<Mutex<DefaultRouter>>,
}

impl Chip2RouterBridge {
    fn new(router: DefaultRouter) -> Self {
        Self {
            router: Arc::new(Mutex::new(router)),
        }
    }

    fn handle(&self) -> Arc<Mutex<DefaultRouter>> {
        self.router.clone()
    }
}

impl Chip2RouterAdapter for Chip2RouterBridge {
    fn inject_external_spikes(
        &mut self,
        tick: u64,
        spikes: &[ExternalSpike],
    ) -> Result<InjectionReport, Chip2RouterError> {
        let mut guard = match self.router.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let chip2_spikes: Vec<chip2::ExternalSpike> = spikes
            .iter()
            .map(|spike| chip2::ExternalSpike {
                region: spike.region.clone(),
                population: spike.population.clone(),
                neuron_group: spike.neuron_group,
                syn_kind: spike.syn_kind.clone(),
                amplitude_q: spike.amplitude_q,
            })
            .collect();
        let report = guard
            .inject_external_spikes(tick, &chip2_spikes)
            .map_err(|_| Chip2RouterError)?;
        let applied = report
            .applied
            .into_iter()
            .map(|target| lnss::lnss_bluebridge::AppliedTarget {
                region: target.region,
                population: target.population,
                neuron_group: target.neuron_group,
                syn_kind: target.syn_kind,
            })
            .collect();
        Ok(InjectionReport { applied })
    }

    fn feedback_snapshot(&mut self) -> Option<BiophysFeedbackSnapshot> {
        let guard = match self.router.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Some(guard.runtime().feedback_snapshot())
    }
}

fn run_once(seed: u64, path: &Path) -> (MechIntRecord, BiophysFeedbackSnapshot) {
    let circuit = L4Circuit::new(seed);
    let runtime = Chip2Runtime::new(circuit);
    let router = DefaultRouter::new(runtime);
    let bridge = Chip2RouterBridge::new(router);
    let handle = bridge.handle();
    let client = Chip2InjectClient::with_max_spikes_per_tick(Box::new(bridge), 32);

    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    let tap_frame = TapFrame::new("hook-a", vec![9, 9, 9]);
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

    let _ = fs::remove_file(path);
    let mechint = JsonlMechIntWriter::new(path, Some(2048)).expect("jsonl writer");

    let mut runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss::lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(mechint),
        pvgs: None,
        rig: Box::new(client),
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
        approval_inbox: None,
        activation_now_ms: None,
        event_sink: None,
        shadow: lnss::lnss_runtime::ShadowConfig::default(),
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

    let line = fs::read_to_string(path).expect("read jsonl");
    let record: MechIntRecord = serde_json::from_str(line.lines().next().expect("record line"))
        .expect("deserialize mechint");

    let snapshot = {
        let guard = handle.lock().expect("router lock");
        guard.runtime().feedback_snapshot()
    };

    (record, snapshot)
}

#[test]
fn end_to_end_feedback_is_logged_deterministically() {
    let tmp_path_a = std::env::temp_dir().join("lnss_feedback_a.jsonl");
    let tmp_path_b = std::env::temp_dir().join("lnss_feedback_b.jsonl");

    let (record_a, snapshot_a) = run_once(77, &tmp_path_a);
    let (record_b, snapshot_b) = run_once(77, &tmp_path_b);

    let feedback_a = record_a.feedback.as_ref().expect("feedback summary");
    assert_eq!(feedback_a.snapshot_digest, snapshot_a.snapshot_digest);
    assert_eq!(feedback_a.snapshot_digest, snapshot_b.snapshot_digest);
    assert_eq!(record_a, record_b);
}
