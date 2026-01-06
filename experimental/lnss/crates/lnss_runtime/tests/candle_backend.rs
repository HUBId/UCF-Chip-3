#![cfg(feature = "lnss-candle")]

use std::fs;
use std::sync::{Arc, Mutex};

use lnss_core::{
    BrainTarget, ControlIntentClass, EmotionFieldSnapshot, PolicyMode, RecursionPolicy, TapKind,
    TapSpec,
};
use lnss_hooks::TapRegistry;
use lnss_lifecycle::LifecycleIndex;
use lnss_mechint::JsonlMechIntWriter;
use lnss_rig::InMemoryRigClient;
use lnss_rlm::RlmController;
use lnss_runtime::{
    CandleConfig, CandleLlmBackend, FeedbackConsumer, HookProvider, Limits, LlmBackend,
    LnssRuntime, MappingAdaptationConfig, TapRegistryProvider, DEFAULT_MAX_MECHINT_BYTES,
};
use lnss_sae::CandleSaeBackend;
use lnss_worldmodel::WorldModelCoreStub;

fn create_loaded_model_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lnss_candle_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create model dir");
    fs::write(dir.join("README"), "stub").expect("write readme");
    dir
}

fn default_mods() -> EmotionFieldSnapshot {
    EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec!["overlay".to_string()],
        vec!["reason".to_string()],
    )
}

#[test]
fn candle_tap_summary_is_deterministic_and_bounded() {
    let model_dir = create_loaded_model_dir();
    let registry = Arc::new(Mutex::new(TapRegistry::new()));
    {
        let mut guard = registry.lock().expect("registry lock");
        guard.register_tap("hook-a", "resid", 0);
    }

    let cfg = CandleConfig {
        model_dir: model_dir.to_string_lossy().to_string(),
        model_revision: "rev-1".to_string(),
        max_new_tokens: 1,
        seed: 42,
        device: "cpu".to_string(),
        hooks_enabled: true,
    };
    let mut backend = CandleLlmBackend::with_registry(cfg, registry.clone());
    backend.try_load().expect("load stub");
    let mods = default_mods();
    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];

    backend.infer_step(b"input", &mods);
    let mut provider = TapRegistryProvider::new(registry.clone(), true);
    let taps_first = provider.collect_taps(&tap_specs);

    backend.infer_step(b"input", &mods);
    let taps_second = provider.collect_taps(&tap_specs);

    assert_eq!(taps_first.len(), 1);
    assert_eq!(taps_second.len(), 1);
    assert_eq!(
        taps_first[0].activation_digest,
        taps_second[0].activation_digest
    );
    assert_eq!(
        taps_first[0].activation_bytes,
        taps_second[0].activation_bytes
    );
    assert!(taps_first[0].activation_bytes.len() <= 4096);
}

#[test]
fn candle_end_to_end_is_deterministic() {
    let model_dir = create_loaded_model_dir();
    let registry = Arc::new(Mutex::new(TapRegistry::new()));
    {
        let mut guard = registry.lock().expect("registry lock");
        guard.register_tap("hook-a", "resid", 0);
    }

    let cfg = CandleConfig {
        model_dir: model_dir.to_string_lossy().to_string(),
        model_revision: "rev-1".to_string(),
        max_new_tokens: 1,
        seed: 7,
        device: "cpu".to_string(),
        hooks_enabled: true,
    };
    let mut backend = CandleLlmBackend::with_registry(cfg, registry.clone());
    backend.try_load().expect("load stub");

    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];

    let mut entries = Vec::new();
    for feature_id in 0..1024u32 {
        entries.push((
            feature_id,
            BrainTarget::new("v1", "pop", feature_id, "syn", 800),
        ));
    }

    let mapper = lnss_core::FeatureToBrainMap::new(1, entries);
    let tmp_path = std::env::temp_dir().join("lnss_mechint_candle.jsonl");
    let _ = fs::remove_file(&tmp_path);

    let mechint =
        JsonlMechIntWriter::new(&tmp_path, Some(DEFAULT_MAX_MECHINT_BYTES)).expect("jsonl writer");
    let rig = InMemoryRigClient::default();
    let mut runtime = LnssRuntime {
        llm: Box::new(backend),
        hooks: Box::new(TapRegistryProvider::new(registry.clone(), true)),
        worldmodel: Box::new(WorldModelCoreStub),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(CandleSaeBackend::new(4)),
        mechint: Box::new(mechint),
        pvgs: None,
        rig: Box::new(rig),
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

    let mods = default_mods();
    let output = runtime
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs)
        .expect("runtime step");

    assert_eq!(output.taps.len(), 1);
    assert_eq!(output.feature_events.len(), 1);
    assert!(!output.spikes.is_empty());
    assert!(output.feature_events[0].top_features.len() <= 4);

    let line = fs::read_to_string(&tmp_path).expect("read jsonl");
    let expected = format!(
        "{}\n",
        serde_json::to_string(&output.mechint_record).expect("serialize record")
    );
    assert_eq!(line, expected);
}
