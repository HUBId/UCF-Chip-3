use lnss_core::{
    BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap,
    PolicyMode, RecursionPolicy, TapFrame, TapKind, TapSpec, WorldModelCore, WorldModelInput,
    WorldModelOutput,
};
use lnss_lifecycle::LifecycleIndex;
use lnss_rlm::RlmController;
use lnss_runtime::{
    apply_world_modulation_limits, effective_top_k, map_features_to_spikes_with_limits,
    InjectionLimits, Limits, LnssRuntime, MappingAdaptationConfig, MechIntWriter,
    SpikeBudgetResult, StubHookProvider, StubLlmBackend,
};
use lnss_worldmodulation::{compute_world_modulation, BaseLimits, RC_WM_MODULATION_ACTIVE};

struct FixedWorldModel {
    prediction_error_score: i32,
}

impl WorldModelCore for FixedWorldModel {
    fn step(&mut self, _input: &WorldModelInput) -> WorldModelOutput {
        WorldModelOutput {
            world_state_digest: [self.prediction_error_score as u8; 32],
            prediction_error_score: self.prediction_error_score,
            world_taps: None,
        }
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

impl lnss_runtime::SaeBackend for FixedSaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent {
        FeatureEvent::new(
            "session",
            "step",
            &tap.hook_id,
            self.features.clone(),
            0,
            vec![],
        )
    }
}

#[derive(Default)]
struct RecordingWriter;

impl MechIntWriter for RecordingWriter {
    fn write_step(
        &mut self,
        _rec: &lnss_runtime::MechIntRecord,
    ) -> Result<(), lnss_runtime::LnssRuntimeError> {
        Ok(())
    }
}

fn build_runtime(prediction_error_score: i32, mapper: FeatureToBrainMap) -> LnssRuntime {
    let tap_frame = TapFrame::new("hook-a", vec![1, 2, 3]);
    LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        worldmodel: Box::new(FixedWorldModel {
            prediction_error_score,
        }),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(FixedSaeBackend::new(vec![(1, 900), (2, 800), (3, 700)])),
        mechint: Box::new(RecordingWriter),
        pvgs: None,
        rig: Box::new(lnss_runtime::StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: InjectionLimits {
            max_spikes_per_tick: 9,
            max_targets_per_spike: 3,
        },
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        active_cfg_root_digest: None,
        shadow_cfg_root_digest: None,
        #[cfg(feature = "lnss-liquid-ode")]
        active_liquid_params: None,
        feedback: lnss_runtime::FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: None,
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
    }
}

#[test]
fn modulation_is_deterministic_for_same_inputs() {
    let base_limits = BaseLimits {
        top_k_base: 6,
        max_spikes_per_tick: 12,
        amplitude_cap_q: 1000,
        fanout_cap: 4,
    };
    let plan = compute_world_modulation(60, &base_limits);
    let effective = apply_world_modulation_limits(
        &InjectionLimits {
            max_spikes_per_tick: 12,
            max_targets_per_spike: 4,
        },
        1000,
        &plan,
    );

    let event = FeatureEvent::new("s", "t", "h", vec![(1, 900), (2, 800)], 0, vec![]);
    let mapper = FeatureToBrainMap::new(
        1,
        vec![
            (1, BrainTarget::new("v1", "pop", 1, "syn", 900)),
            (1, BrainTarget::new("v1", "pop", 2, "syn", 700)),
            (2, BrainTarget::new("v1", "pop", 3, "syn", 600)),
        ],
    );

    let SpikeBudgetResult { spikes: first, .. } =
        map_features_to_spikes_with_limits(&mapper, std::slice::from_ref(&event), &effective, 12);
    let SpikeBudgetResult { spikes: second, .. } =
        map_features_to_spikes_with_limits(&mapper, &[event], &effective, 12);

    assert_eq!(first, second);
}

#[test]
fn high_prediction_error_reduces_spike_budget() {
    let base_limits = BaseLimits {
        top_k_base: 6,
        max_spikes_per_tick: 10,
        amplitude_cap_q: 1000,
        fanout_cap: 3,
    };
    let low_plan = compute_world_modulation(10, &base_limits);
    let high_plan = compute_world_modulation(90, &base_limits);

    let mapper = FeatureToBrainMap::new(
        1,
        vec![
            (1, BrainTarget::new("v1", "pop", 1, "syn", 900)),
            (1, BrainTarget::new("v1", "pop", 2, "syn", 700)),
            (1, BrainTarget::new("v1", "pop", 3, "syn", 600)),
            (2, BrainTarget::new("v1", "pop", 4, "syn", 500)),
            (2, BrainTarget::new("v1", "pop", 5, "syn", 400)),
            (2, BrainTarget::new("v1", "pop", 6, "syn", 300)),
        ],
    );
    let event = FeatureEvent::new("s", "t", "h", vec![(1, 900), (2, 850)], 0, vec![]);

    let low_effective = apply_world_modulation_limits(
        &InjectionLimits {
            max_spikes_per_tick: 10,
            max_targets_per_spike: 3,
        },
        1000,
        &low_plan,
    );
    let high_effective = apply_world_modulation_limits(
        &InjectionLimits {
            max_spikes_per_tick: 10,
            max_targets_per_spike: 3,
        },
        1000,
        &high_plan,
    );

    let low_spikes = map_features_to_spikes_with_limits(
        &mapper,
        std::slice::from_ref(&event),
        &low_effective,
        10,
    )
    .spikes
    .len();
    let high_spikes = map_features_to_spikes_with_limits(&mapper, &[event], &high_effective, 10)
        .spikes
        .len();

    assert!(high_spikes < low_spikes);
}

#[test]
fn end_to_end_world_modulation_updates_spike_count() {
    let tap_spec = TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid");
    let mapper = FeatureToBrainMap::new(
        1,
        vec![
            (1, BrainTarget::new("v1", "pop", 1, "syn", 900)),
            (1, BrainTarget::new("v1", "pop", 2, "syn", 800)),
            (1, BrainTarget::new("v1", "pop", 3, "syn", 700)),
            (2, BrainTarget::new("v1", "pop", 4, "syn", 600)),
            (2, BrainTarget::new("v1", "pop", 5, "syn", 500)),
            (2, BrainTarget::new("v1", "pop", 6, "syn", 400)),
            (3, BrainTarget::new("v1", "pop", 7, "syn", 300)),
            (3, BrainTarget::new("v1", "pop", 8, "syn", 200)),
            (3, BrainTarget::new("v1", "pop", 9, "syn", 100)),
        ],
    );

    let mods = EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec![],
        vec![],
    );

    let mut low_runtime = build_runtime(10, mapper.clone());
    let mut high_runtime = build_runtime(90, mapper);

    let low_output = low_runtime
        .run_step(
            "session",
            "step-low",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("low run");
    let high_output = high_runtime
        .run_step(
            "session",
            "step-high",
            b"input",
            &mods,
            std::slice::from_ref(&tap_spec),
        )
        .expect("high run");

    assert!(high_output.spikes.len() < low_output.spikes.len());
    assert!(high_output
        .mechint_record
        .wm_modulation_reason_codes
        .contains(&RC_WM_MODULATION_ACTIVE.to_string()));
    assert!(high_output.mechint_record.max_spikes_eff < low_output.mechint_record.max_spikes_eff);
    assert_eq!(
        effective_top_k(
            3,
            high_output
                .mechint_record
                .wm_modulation_plan
                .feature_top_k_scale_q
        ),
        high_output.mechint_record.top_k_eff as usize
    );
}
