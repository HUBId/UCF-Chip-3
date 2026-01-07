#![forbid(unsafe_code)]

#[cfg(all(feature = "lnss-burn", feature = "lnss-liquid-ode"))]
mod real_sae_backend_tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use lnss_core::{
        BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureToBrainMap, PolicyMode,
        RecursionPolicy, TapKind, TapSpec,
    };
    use lnss_lifecycle::LifecycleIndex;
    use lnss_mechint::JsonlMechIntWriter;
    use lnss_rig::InMemoryRigClient;
    use lnss_rlm::RlmController;
    use lnss_runtime::{
        FeedbackConsumer, Limits, LiquidOdeBackend, LiquidOdeConfig, LnssRuntime,
        MappingAdaptationConfig,
    };
    use lnss_sae::{RealSaeBackend, SaeNonlinearity};
    use lnss_worldmodel::WorldModelCoreStub;

    fn write_pack(dir: &Path) -> PathBuf {
        fs::create_dir_all(dir).expect("create pack dir");
        let meta = serde_json::json!({
            "version": 1,
            "hook_id": "liquid-state",
            "input_dim": 4,
            "feature_dim": 4,
            "top_k": 2,
            "scaling_q": 10
        });
        fs::write(
            dir.join("meta.json"),
            serde_json::to_string(&meta).expect("meta json"),
        )
        .expect("write meta");
        let mut w_bytes = Vec::new();
        for i in 0..4 {
            for j in 0..4 {
                let value = if i == j { 1.0f32 } else { 0.0f32 };
                w_bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        fs::write(dir.join("w_enc.bin"), &w_bytes).expect("write w_enc");
        let mut b_bytes = Vec::new();
        for _ in 0..4 {
            b_bytes.extend_from_slice(&0.0f32.to_le_bytes());
        }
        fs::write(dir.join("b_enc.bin"), &b_bytes).expect("write b_enc");
        dir.to_path_buf()
    }

    fn base_mods() -> EmotionFieldSnapshot {
        EmotionFieldSnapshot::new(
            "low",
            "high",
            "shallow",
            "baseline",
            "stable",
            vec![],
            vec![],
        )
    }

    #[test]
    fn liquid_to_real_sae_pipeline_is_deterministic() {
        let cfg = LiquidOdeConfig {
            state_dim: 4,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 7,
            input_proj_dim: 4,
            mods_gain_q: 100,
        };
        let backend_a = LiquidOdeBackend::new(cfg.clone());
        let backend_b = LiquidOdeBackend::new(cfg);
        let hooks_a = backend_a.tap_provider();
        let hooks_b = backend_b.tap_provider();
        let tap_specs = vec![TapSpec::new(
            "liquid-state",
            TapKind::LiquidState,
            0,
            "state",
        )];

        let mechint_a = JsonlMechIntWriter::new(
            std::env::temp_dir().join("lnss_real_sae_a.jsonl"),
            Some(512),
        )
        .expect("jsonl writer");
        let mechint_b = JsonlMechIntWriter::new(
            std::env::temp_dir().join("lnss_real_sae_b.jsonl"),
            Some(512),
        )
        .expect("jsonl writer");
        let rig_a = InMemoryRigClient::default();
        let rig_b = InMemoryRigClient::default();

        let targets = (0..4)
            .map(|feature_id| {
                (
                    feature_id,
                    BrainTarget::new("v1", "pop", feature_id, "syn", 800),
                )
            })
            .collect();
        let mapper = FeatureToBrainMap::new(1, targets);

        let pack_dir_a = std::env::temp_dir().join("lnss_runtime_sae_pack_a");
        let pack_dir_b = std::env::temp_dir().join("lnss_runtime_sae_pack_b");
        let mut runtime_a = LnssRuntime {
            llm: Box::new(backend_a),
            hooks: Box::new(hooks_a),
            worldmodel: Box::new(WorldModelCoreStub),
            rlm: Box::new(RlmController::default()),
            orchestrator: lnss_core::CoreOrchestrator,
            sae: Box::new(RealSaeBackend::new(
                write_pack(&pack_dir_a),
                SaeNonlinearity::Relu,
            )),
            mechint: Box::new(mechint_a),
            pvgs: None,
            rig: Box::new(rig_a),
            mapper: mapper.clone(),
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
        };
        let mut runtime_b = LnssRuntime {
            llm: Box::new(backend_b),
            hooks: Box::new(hooks_b),
            worldmodel: Box::new(WorldModelCoreStub),
            rlm: Box::new(RlmController::default()),
            orchestrator: lnss_core::CoreOrchestrator,
            sae: Box::new(RealSaeBackend::new(
                write_pack(&pack_dir_b),
                SaeNonlinearity::Relu,
            )),
            mechint: Box::new(mechint_b),
            pvgs: None,
            rig: Box::new(rig_b),
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
        };

        let mods = base_mods();
        let output_a = runtime_a
            .run_step("session", "step", b"input", &mods, &tap_specs)
            .expect("runtime step");
        let output_b = runtime_b
            .run_step("session", "step", b"input", &mods, &tap_specs)
            .expect("runtime step");

        assert_eq!(output_a.feature_events, output_b.feature_events);
        assert_eq!(output_a.spikes, output_b.spikes);
    }
}
