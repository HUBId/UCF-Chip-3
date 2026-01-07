#[cfg(all(feature = "lnss-burn", feature = "lnss-liquid-ode"))]
mod liquid_backend_tests {
    use std::fs;

    use lnss_core::{
        BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureToBrainMap, PolicyMode,
        RecursionPolicy, TapKind, TapSpec,
    };
    use lnss_lifecycle::LifecycleIndex;
    use lnss_mechint::JsonlMechIntWriter;
    use lnss_rig::InMemoryRigClient;
    use lnss_rlm::RlmController;
    use lnss_runtime::{
        FeedbackConsumer, HookProvider, Limits, LiquidOdeBackend, LiquidOdeConfig, LlmBackend,
        LnssRuntime, MappingAdaptationConfig,
    };
    use lnss_sae::StubSaeBackend;
    use lnss_worldmodel::WorldModelCoreStub;

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
    fn liquid_backend_is_deterministic() {
        let cfg = LiquidOdeConfig {
            state_dim: 32,
            dt_ms_q: 1000,
            steps_per_call: 2,
            seed: 7,
            input_proj_dim: 8,
            mods_gain_q: 100,
        };
        let mut backend_a = LiquidOdeBackend::new(cfg.clone());
        let mut backend_b = LiquidOdeBackend::new(cfg.clone());
        let mut hooks_a = backend_a.tap_provider();
        let mut hooks_b = backend_b.tap_provider();
        let mods = base_mods();
        let input = b"liquid-input";
        let output_a = backend_a.infer_step(input, &mods);
        let output_b = backend_b.infer_step(input, &mods);
        assert_eq!(output_a, output_b);

        let spec = TapSpec::new("liquid-state", TapKind::LiquidState, 0, "state");
        let taps_a = hooks_a.collect_taps(std::slice::from_ref(&spec));
        let taps_b = hooks_b.collect_taps(std::slice::from_ref(&spec));
        assert_eq!(taps_a.len(), 1);
        assert_eq!(taps_a[0].activation_digest, taps_b[0].activation_digest);
        assert_eq!(taps_a[0].activation_bytes, taps_b[0].activation_bytes);
    }

    #[test]
    fn liquid_backend_is_bounded_and_state_dim_matches() {
        let cfg = LiquidOdeConfig {
            state_dim: 12,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 42,
            input_proj_dim: 4,
            mods_gain_q: 100,
        };
        let mut backend = LiquidOdeBackend::new(cfg);
        let mods = base_mods();
        let output = backend.infer_step(b"bounded", &mods);
        assert!(output.len() <= 8 * 1024);
        assert_eq!(backend.state_len(), 12);
    }

    #[test]
    fn liquid_backend_modulation_changes_state() {
        let cfg = LiquidOdeConfig {
            state_dim: 16,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 100,
            input_proj_dim: 4,
            mods_gain_q: 100,
        };
        let mut backend_high = LiquidOdeBackend::new(cfg.clone());
        let mut backend_low = LiquidOdeBackend::new(cfg);
        let mut hooks_high = backend_high.tap_provider();
        let mut hooks_low = backend_low.tap_provider();
        let mods_high = EmotionFieldSnapshot::new(
            "high",
            "low",
            "shallow",
            "baseline",
            "stable",
            vec![],
            vec![],
        );
        let mods_low = EmotionFieldSnapshot::new(
            "low",
            "low",
            "shallow",
            "baseline",
            "stable",
            vec![],
            vec![],
        );
        backend_high.infer_step(b"mods", &mods_high);
        backend_low.infer_step(b"mods", &mods_low);
        let spec = TapSpec::new("liquid-state", TapKind::LiquidState, 0, "state");
        let taps_high = hooks_high.collect_taps(std::slice::from_ref(&spec));
        let taps_low = hooks_low.collect_taps(std::slice::from_ref(&spec));
        let high_val = i16::from_le_bytes([
            taps_high[0].activation_bytes[0],
            taps_high[0].activation_bytes[1],
        ]);
        let low_val = i16::from_le_bytes([
            taps_low[0].activation_bytes[0],
            taps_low[0].activation_bytes[1],
        ]);
        assert!(low_val.abs() >= high_val.abs());
        assert_ne!(low_val, high_val);
    }

    #[test]
    fn end_to_end_liquid_pipeline_is_stable() {
        let cfg = LiquidOdeConfig {
            state_dim: 24,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 11,
            input_proj_dim: 6,
            mods_gain_q: 100,
        };
        let backend_a = LiquidOdeBackend::new(cfg.clone());
        let backend_b = LiquidOdeBackend::new(cfg.clone());
        let hooks_a = backend_a.tap_provider();
        let hooks_b = backend_b.tap_provider();
        let tap_specs = vec![TapSpec::new(
            "liquid-state",
            TapKind::LiquidState,
            0,
            "state",
        )];

        let tmp_path_a = std::env::temp_dir().join("lnss_liquid_mechint_a.jsonl");
        let tmp_path_b = std::env::temp_dir().join("lnss_liquid_mechint_b.jsonl");
        let _ = fs::remove_file(&tmp_path_a);
        let _ = fs::remove_file(&tmp_path_b);

        let mechint_a = JsonlMechIntWriter::new(&tmp_path_a, Some(1024)).expect("jsonl writer");
        let mechint_b = JsonlMechIntWriter::new(&tmp_path_b, Some(1024)).expect("jsonl writer");
        let rig_a = InMemoryRigClient::default();
        let rig_b = InMemoryRigClient::default();

        let target = BrainTarget::new("v1", "pop", 1, "syn", 800);
        let mapper = FeatureToBrainMap::new(1, vec![(1, target)]);

        let mut runtime_a = LnssRuntime {
            llm: Box::new(backend_a),
            hooks: Box::new(hooks_a),
            worldmodel: Box::new(WorldModelCoreStub),
            rlm: Box::new(RlmController::default()),
            orchestrator: lnss_core::CoreOrchestrator,
            sae: Box::new(StubSaeBackend::new(4)),
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
            active_liquid_params: Some(cfg.clone()),
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
            sae: Box::new(StubSaeBackend::new(4)),
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
            active_liquid_params: Some(cfg),
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
