use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_core::{BrainTarget, EmotionFieldSnapshot, FeatureToBrainMap, TapFrame, TapKind, TapSpec};
use lnss_runtime::{
    FeedbackConsumer, Limits, LnssRuntime, MappingAdaptationConfig, MechIntRecord, MechIntWriter,
    ProposalInbox, StubHookProvider, StubLlmBackend, StubRigClient,
};
use lnss_sae::StubSaeBackend;

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

#[test]
fn proposal_ingestion_is_bounded_and_does_not_apply() {
    let dir = temp_dir("lnss_inbox");
    write_json(
        &dir.join("a.json"),
        serde_json::json!({
            "proposal_id": "proposal-a",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
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
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(writer),
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: Some(ProposalInbox::with_limits(&dir, 1, 2)),
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
