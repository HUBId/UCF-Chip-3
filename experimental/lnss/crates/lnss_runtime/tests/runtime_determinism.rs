use std::fs;

use lnss_core::{
    BrainTarget, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap, TapFrame, TapKind, TapSpec,
    MAX_TOP_FEATURES,
};
use lnss_hooks::TapPlan;
use lnss_mechint::JsonlMechIntWriter;
use lnss_rig::InMemoryRigClient;
use lnss_runtime::{
    map_features_to_spikes, Limits, LnssRuntime, MechIntRecord, TapSummary, StubHookProvider,
    StubLlmBackend,
};
use lnss_sae::StubSaeBackend;

#[test]
fn deterministic_feature_event_ordering() {
    let features = vec![(2, 500), (1, 500), (3, 900), (4, 1001)];
    let event = FeatureEvent::new(
        "session",
        "step",
        "hook",
        features,
        123,
        vec!["b".to_string(), "a".to_string(), "a".to_string()],
    );

    assert_eq!(event.top_features[0].0, 4);
    assert_eq!(event.top_features[1].0, 3);
    assert_eq!(event.top_features[2].0, 1);
    assert_eq!(event.top_features[3].0, 2);
    assert_eq!(event.reason_codes, vec!["a", "b"]);
}

#[test]
fn mapping_digest_is_stable() {
    let target = BrainTarget::new("r", "p", 1, "syn", 500);
    let map_a = FeatureToBrainMap::new(1, vec![(2, target.clone()), (1, target.clone())]);
    let map_b = FeatureToBrainMap::new(1, vec![(1, target.clone()), (2, target.clone())]);

    assert_eq!(map_a.map_digest, map_b.map_digest);
}

#[test]
fn boundedness_caps_are_enforced() {
    let mut features = Vec::new();
    for i in 0..(MAX_TOP_FEATURES as u32 + 10) {
        features.push((i, 800));
    }
    let event = FeatureEvent::new("s", "t", "h", features, 0, vec![]);
    assert_eq!(event.top_features.len(), MAX_TOP_FEATURES);

    let target = BrainTarget::new("r", "p", 1, "syn", 1000);
    let mapping = FeatureToBrainMap::new(1, vec![(0, target)]);
    let spikes = map_features_to_spikes(&mapping, &[event]);
    assert!(spikes.len() <= MAX_TOP_FEATURES);

    let summaries = (0..4)
        .map(|idx| TapSummary {
            hook_id: format!("hook-{idx}"),
            activation_digest: [2; 32],
            sample_len: 0,
        })
        .collect();
    let record = MechIntRecord::new("s", "t", [1; 32], summaries, vec![], [3; 32]);
    assert_eq!(record.tap_digests.len(), 4);
}

#[test]
fn end_to_end_stub_pipeline() {
    let tap_specs = TapPlan::new(vec![TapSpec::new(
        "hook-a",
        TapKind::ResidualStream,
        0,
        "resid",
    )]);
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

    let tmp_path = std::env::temp_dir().join("lnss_mechint_test.jsonl");
    let _ = fs::remove_file(&tmp_path);

    let mechint = JsonlMechIntWriter::new(&tmp_path, Some(1024)).expect("jsonl writer");
    let rig = InMemoryRigClient::default();

    let mut runtime = LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame.clone()],
        }),
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(mechint),
        rig: Box::new(rig),
        mapper,
        limits: Limits::default(),
    };

    let mods = EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec!["overlay".to_string()],
        vec!["reason".to_string()],
    );

    let output = runtime
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs.specs)
        .expect("runtime step");

    let line = fs::read_to_string(&tmp_path).expect("read jsonl");
    assert!(line.contains("session-1"));
    assert!(line.contains("step-1"));
    assert_eq!(output.taps.len(), 1);
}
