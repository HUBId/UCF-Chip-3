use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_approval::{build_aap_for_proposal, ApprovalContext};
use lnss_core::{BrainTarget, EmotionFieldSnapshot, FeatureToBrainMap, TapFrame, TapKind, TapSpec};
use lnss_evolve::load_proposals;
use lnss_runtime::{
    ApprovalInbox, FeedbackConsumer, InjectionLimits, Limits, LnssRuntime, MappingAdaptationConfig,
    MechIntRecord, MechIntWriter, StubHookProvider, StubLlmBackend, StubRigClient,
    FILE_DIGEST_DOMAIN,
};
use lnss_sae::StubSaeBackend;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

#[derive(Default, Clone)]
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
    let bytes = serde_json::to_vec(&value).expect("serialize json");
    fs::write(path, bytes).expect("write json");
}

fn map_fixture(dir: &Path) -> (PathBuf, FeatureToBrainMap, [u8; 32]) {
    let target = BrainTarget::new("v1", "pop", 1, "syn", 700);
    let map = FeatureToBrainMap::new(1, vec![(1, target)]);
    let bytes = serde_json::to_vec(&map).expect("serialize map");
    let path = dir.join("map.json");
    fs::write(&path, &bytes).expect("write map");
    let digest = lnss_core::digest(FILE_DIGEST_DOMAIN, &bytes);
    (path, map, digest)
}

fn proposal_fixture(dir: &Path, map_path: &Path, map_digest: [u8; 32]) -> lnss_evolve::Proposal {
    write_json(
        &dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-map-1",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![1; 32],
            "payload": {
                "type": "mapping_update",
                "new_map_path": map_path.to_string_lossy(),
                "map_digest": map_digest.to_vec(),
                "change_summary": ["trim"]
            },
            "reason_codes": ["offline"]
        }),
    );
    load_proposals(dir).expect("load proposals").remove(0)
}

fn aap_fixture(dir: &Path, proposal: &lnss_evolve::Proposal) -> ucf::v1::ApprovalArtifactPackage {
    let ctx = ApprovalContext {
        session_id: "session-1".to_string(),
        ruleset_digest: Some([9u8; 32]),
        current_mapping_digest: Some([8u8; 32]),
        current_sae_pack_digest: None,
        current_liquid_params_digest: None,
        latest_scorecard_digest: None,
        requested_operation: ucf::v1::OperationCategory::OpException,
    };
    let aap = build_aap_for_proposal(proposal, &ctx);
    let digest: [u8; 32] = aap
        .aap_digest
        .as_ref()
        .and_then(|d| d.value.as_slice().try_into().ok())
        .expect("aap digest");
    let aap_dir = dir.join("aap");
    fs::create_dir_all(&aap_dir).expect("create aap dir");
    let path = aap_dir.join(format!("aap_{}.bin", hex::encode(digest)));
    fs::write(&path, canonical_bytes(&aap)).expect("write aap");
    aap
}

fn approval_fixture(
    dir: &Path,
    aap_id: &str,
    form: ucf::v1::DecisionForm,
    constraints: Option<ucf::v1::ConstraintsDelta>,
) -> [u8; 32] {
    let mut decision = ucf::v1::ApprovalDecision {
        decision_id: "decision-1".to_string(),
        aap_id: aap_id.to_string(),
        decision: form as i32,
        reason_codes: None,
        constraints,
        approval_decision_digest: None,
    };
    let digest = digest_proto("UCF:HASH:APPROVAL_DECISION", &canonical_bytes(&decision));
    decision.approval_decision_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    let path = dir.join(format!("approval_{}.bin", hex::encode(digest)));
    fs::write(&path, canonical_bytes(&decision)).expect("write approval decision");
    digest
}

fn runtime_fixture(dir: &Path, writer: RecordingWriter) -> LnssRuntime {
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
            BrainTarget::new("v1", "pop", 1, "syn", 500),
        )],
    );

    LnssRuntime {
        llm: Box::new(StubLlmBackend),
        hooks: Box::new(StubHookProvider {
            taps: vec![tap_frame],
        }),
        sae: Box::new(StubSaeBackend::new(4)),
        mechint: Box::new(writer),
        pvgs: None,
        rig: Box::new(StubRigClient::default()),
        mapper,
        limits: Limits::default(),
        injection_limits: InjectionLimits::default(),
        active_sae_pack_digest: None,
        active_liquid_params_digest: None,
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: None,
        approval_inbox: Some(
            ApprovalInbox::with_state_path(dir, dir.join("state.json"), 1).expect("approval inbox"),
        ),
    }
}

fn run_once(runtime: &mut LnssRuntime) {
    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];
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
        .run_step("session-1", "step-1", b"input", &mods, &tap_specs)
        .expect("runtime step");
}

#[test]
fn approval_applies_mapping_update() {
    let dir = temp_dir("lnss_approval_apply");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn deny_does_not_apply() {
    let dir = temp_dir("lnss_approval_deny");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Deny, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    let original_digest = runtime.mapper.map_digest;
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, original_digest);
    assert_ne!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn loosened_constraints_are_rejected() {
    let dir = temp_dir("lnss_approval_loosened");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(
        &dir,
        &aap.aap_id,
        ucf::v1::DecisionForm::Allow,
        Some(ucf::v1::ConstraintsDelta {
            constraints_added: Vec::new(),
            constraints_removed: vec!["loosen fan-out".to_string()],
            novelty_lock: false,
        }),
    );

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    let original_digest = runtime.mapper.map_digest;
    run_once(&mut runtime);

    assert_eq!(runtime.mapper.map_digest, original_digest);
    assert_ne!(runtime.mapper.map_digest, map.map_digest);
}

#[test]
fn approvals_are_idempotent() {
    let dir = temp_dir("lnss_approval_idempotent");
    let (map_path, _map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    let approval_digest = approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let writer_handle = writer.clone();
    let mut runtime = runtime_fixture(&dir, writer);
    run_once(&mut runtime);
    run_once(&mut runtime);

    let activation_records = writer_handle
        .records()
        .into_iter()
        .filter(|record| record.approval_digest == Some(approval_digest))
        .count();
    assert_eq!(activation_records, 1);
}

#[test]
fn state_persists_active_digests() {
    let dir = temp_dir("lnss_approval_state");
    let (map_path, map, map_digest) = map_fixture(&dir);
    let proposal = proposal_fixture(&dir, &map_path, map_digest);
    let aap = aap_fixture(&dir, &proposal);
    approval_fixture(&dir, &aap.aap_id, ucf::v1::DecisionForm::Allow, None);

    let writer = RecordingWriter::default();
    let mut runtime = runtime_fixture(&dir, writer);
    run_once(&mut runtime);

    let state_path = dir.join("state.json");
    let inbox = ApprovalInbox::with_state_path(&dir, state_path, 1).expect("reload inbox");
    assert_eq!(inbox.state().active_mapping_digest, Some(map.map_digest));
}
