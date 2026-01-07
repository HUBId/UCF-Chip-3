use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use lnss_core::{
    BrainTarget, ControlIntentClass, EmotionFieldSnapshot, FeatureToBrainMap, PolicyMode,
    RecursionPolicy, RlmDirective, TapFrame, TapKind, TapSpec, WorldModelCore, WorldModelInput,
    WorldModelOutput,
};
use lnss_hooks::TapPlan;
use lnss_lifecycle::LifecycleIndex;
use lnss_mechint::JsonlMechIntWriter;
use lnss_rlm::RlmController;
use lnss_runtime::{
    HookProvider, Limits, LnssRuntime, MappingAdaptationConfig, StubLlmBackend, StubRigClient,
};
use lnss_sae::StubSaeBackend;
struct SequencedHookProvider {
    tap_sets: Vec<Vec<TapFrame>>,
    call_count: Arc<AtomicUsize>,
}

impl HookProvider for SequencedHookProvider {
    fn collect_taps(&mut self, _specs: &[TapSpec]) -> Vec<TapFrame> {
        let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
        self.tap_sets.get(idx).cloned().unwrap_or_default()
    }
}

struct CalmWorldModel;

impl WorldModelCore for CalmWorldModel {
    fn step(&mut self, _input: &WorldModelInput) -> WorldModelOutput {
        WorldModelOutput {
            world_state_digest: [7; 32],
            prediction_error_score: 0,
            world_taps: None,
        }
    }
}

fn build_runtime(hooks: SequencedHookProvider) -> (LnssRuntime, Arc<AtomicUsize>) {
    let tmp_path = std::env::temp_dir().join("lnss_followup_mechint.jsonl");
    let _ = std::fs::remove_file(&tmp_path);
    let mechint = JsonlMechIntWriter::new(&tmp_path, Some(1024)).expect("jsonl writer");
    let mapper = FeatureToBrainMap::new(1, vec![(0, BrainTarget::new("r", "p", 1, "syn", 500))]);
    let call_count = hooks.call_count.clone();
    let runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(hooks),
        worldmodel: Box::new(CalmWorldModel),
        rlm: Box::new(RlmController::default()),
        orchestrator: lnss_core::CoreOrchestrator,
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(mechint),
        pvgs: None,
        rig: Box::new(StubRigClient::new()),
        mapper,
        limits: Limits {
            max_taps: 3,
            ..Limits::default()
        },
        injection_limits: lnss_runtime::InjectionLimits::default(),
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
        control_intent_class: ControlIntentClass::Explore,
        recursion_policy: RecursionPolicy::default(),
        world_state_digest: [0; 32],
        last_action_digest: [0; 32],
        last_self_state_digest: [0; 32],
        pred_error_threshold: 128,
        trigger_proposals_enabled: false,
    };
    (runtime, call_count)
}

#[test]
fn followup_executes_once_and_combines_taps() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let hooks = SequencedHookProvider {
        tap_sets: vec![
            vec![
                TapFrame::new("hook-a", vec![1, 2, 3]),
                TapFrame::new("hook-b", vec![4, 5, 6]),
            ],
            vec![
                TapFrame::new("hook-c", vec![7, 8, 9]),
                TapFrame::new("hook-d", vec![10, 11, 12]),
            ],
        ],
        call_count: call_count.clone(),
    };
    let (mut runtime, call_count) = build_runtime(hooks);
    let mods = EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec![],
        vec![],
    );
    let tap_specs = TapPlan::new(vec![TapSpec::new(
        "hook-a",
        TapKind::ResidualStream,
        0,
        "tensor",
    )]);

    let output = runtime
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs.specs)
        .expect("runtime step");

    assert_eq!(call_count.load(Ordering::SeqCst), 2);
    assert!(output.mechint_record.deliberation_budget.allow_followup);
    assert_eq!(
        output.mechint_record.deliberation_budget.selected_directive,
        Some(RlmDirective::FollowUpClarify)
    );
    assert!(output.mechint_record.followup_executed);
    assert!(output
        .mechint_record
        .followup_control_frame_digest
        .is_some());
    assert!(output
        .mechint_record
        .followup_language_step_digest
        .is_some());
    assert_eq!(output.taps.len(), 3);
    assert_eq!(output.taps[0].hook_id, "hook-a");
    assert_eq!(output.taps[1].hook_id, "hook-b");
    assert_eq!(output.taps[2].hook_id, "hook-c");
}
