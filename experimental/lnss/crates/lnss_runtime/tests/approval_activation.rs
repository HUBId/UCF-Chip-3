use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lnss_approval::{clear_pending_aaps, clear_seen_approval_digests, create_aap_from_proposal};
use lnss_core::{BrainTarget, EmotionFieldSnapshot, FeatureToBrainMap, TapFrame};
use lnss_evolve::load_proposals;
use lnss_runtime::{
    mapping_file_digest, ActivationRecord, ActivationState, ApprovalInbox, FeedbackConsumer,
    InjectionLimits, Limits, LnssRuntime, LocalProposalApplier, MappingAdaptationConfig,
    MechIntRecord, MechIntWriter, StubHookProvider, StubLlmBackend, StubRigClient,
};
use lnss_sae::StubSaeBackend;
use prost::Message;
use ucf_protocol::ucf;

#[derive(Clone, Default)]
struct RecordingWriter {
    steps: Arc<Mutex<Vec<MechIntRecord>>>,
    activations: Arc<Mutex<Vec<ActivationRecord>>>,
}

impl RecordingWriter {
    fn activations(&self) -> Vec<ActivationRecord> {
        self.activations.lock().expect("activation lock").clone()
    }
}

impl MechIntWriter for RecordingWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.steps.lock().expect("steps lock").push(rec.clone());
        Ok(())
    }

    fn write_activation(
        &mut self,
        rec: &ActivationRecord,
    ) -> Result<(), lnss_runtime::LnssRuntimeError> {
        self.activations
            .lock()
            .expect("activation lock")
            .push(rec.clone());
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

fn write_decision(path: &Path, decision: &ucf::v1::ApprovalDecision) {
    fs::write(path, decision.encode_to_vec()).expect("write decision");
}

fn build_runtime(
    writer: RecordingWriter,
    approval_inbox: ApprovalInbox,
    activation_state: ActivationState,
) -> LnssRuntime {
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
        feedback: FeedbackConsumer::default(),
        adaptation: MappingAdaptationConfig::default(),
        proposal_inbox: None,
        approval_inbox: Some(approval_inbox),
        activation_state,
        proposal_applier: Box::new(LocalProposalApplier::default()),
    }
}

fn default_mods() -> EmotionFieldSnapshot {
    EmotionFieldSnapshot::new(
        "calm",
        "low",
        "shallow",
        "baseline",
        "stable",
        vec![],
        vec![],
    )
}

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("test lock")
}

#[test]
fn approval_applies_mapping_update() {
    let _guard = test_lock();
    clear_pending_aaps();
    clear_seen_approval_digests();

    let proposals_dir = temp_dir("lnss_proposals");
    let approvals_dir = temp_dir("lnss_approvals");
    let state_dir = temp_dir("lnss_state");

    let map_path = proposals_dir.join("maps.bin");
    fs::write(&map_path, b"map-bytes").expect("write map");
    let map_digest = mapping_file_digest(b"map-bytes");

    write_json(
        &proposals_dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-1",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![0; 32],
            "payload": {
                "type": "mapping_update",
                "new_map_path": map_path.to_string_lossy(),
                "map_digest": map_digest.to_vec(),
                "change_summary": []
            },
            "reason_codes": []
        }),
    );

    let proposals = load_proposals(&proposals_dir).expect("load proposals");
    let proposal = proposals.first().expect("proposal");
    let aap = create_aap_from_proposal(proposal);
    lnss_approval::register_pending_aap(aap.clone());

    let decision = ucf::v1::ApprovalDecision {
        approval_digest: Some(ucf::v1::Digest32 {
            value: vec![9; 32],
        }),
        aap_digest: Some(ucf::v1::Digest32 {
            value: aap.aap_digest.to_vec(),
        }),
        decision: ucf::v1::ApprovalDecisionForm::Approve as i32,
        modifications: None,
    };
    write_decision(&approvals_dir.join("a.bin"), &decision);

    let writer = RecordingWriter::default();
    let activation_state =
        ActivationState::load_or_default(state_dir.join("activation_state.txt"))
            .expect("state");
    let mut approval_inbox = ApprovalInbox::new(&approvals_dir, &proposals_dir);
    approval_inbox.ticks_per_scan = 1;
    let mut runtime = build_runtime(writer.clone(), approval_inbox, activation_state);

    runtime
        .run_step("session", "step", b"input", &default_mods(), &[])
        .expect("run step");

    assert_eq!(
        runtime.activation_state.active_mapping_digest,
        Some(map_digest)
    );
    let activations = writer.activations();
    assert_eq!(activations.len(), 1);
    assert_eq!(activations[0].outcome, lnss_runtime::ActivationOutcome::Applied);
}

#[test]
fn deny_does_not_apply() {
    let _guard = test_lock();
    clear_pending_aaps();
    clear_seen_approval_digests();

    let proposals_dir = temp_dir("lnss_proposals_deny");
    let approvals_dir = temp_dir("lnss_approvals_deny");
    let state_dir = temp_dir("lnss_state_deny");

    let map_path = proposals_dir.join("maps.bin");
    fs::write(&map_path, b"map-bytes").expect("write map");
    let map_digest = mapping_file_digest(b"map-bytes");

    write_json(
        &proposals_dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-1",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![0; 32],
            "payload": {
                "type": "mapping_update",
                "new_map_path": map_path.to_string_lossy(),
                "map_digest": map_digest.to_vec(),
                "change_summary": []
            },
            "reason_codes": []
        }),
    );

    let proposals = load_proposals(&proposals_dir).expect("load proposals");
    let proposal = proposals.first().expect("proposal");
    let aap = create_aap_from_proposal(proposal);
    lnss_approval::register_pending_aap(aap.clone());

    let decision = ucf::v1::ApprovalDecision {
        approval_digest: Some(ucf::v1::Digest32 {
            value: vec![7; 32],
        }),
        aap_digest: Some(ucf::v1::Digest32 {
            value: aap.aap_digest.to_vec(),
        }),
        decision: ucf::v1::ApprovalDecisionForm::Deny as i32,
        modifications: None,
    };
    write_decision(&approvals_dir.join("a.bin"), &decision);

    let writer = RecordingWriter::default();
    let activation_state =
        ActivationState::load_or_default(state_dir.join("activation_state.txt"))
            .expect("state");
    let mut approval_inbox = ApprovalInbox::new(&approvals_dir, &proposals_dir);
    approval_inbox.ticks_per_scan = 1;
    let mut runtime = build_runtime(writer, approval_inbox, activation_state);

    runtime
        .run_step("session", "step", b"input", &default_mods(), &[])
        .expect("run step");

    assert_eq!(runtime.activation_state.active_mapping_digest, None);
}

#[test]
fn loosening_modifications_are_rejected() {
    let _guard = test_lock();
    clear_pending_aaps();
    clear_seen_approval_digests();

    let proposals_dir = temp_dir("lnss_proposals_loosen");
    let approvals_dir = temp_dir("lnss_approvals_loosen");
    let state_dir = temp_dir("lnss_state_loosen");

    write_json(
        &proposals_dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-1",
            "kind": "injection_limits_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![0; 32],
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 50,
                "max_targets_per_spike": 4
            },
            "reason_codes": []
        }),
    );

    let proposals = load_proposals(&proposals_dir).expect("load proposals");
    let proposal = proposals.first().expect("proposal");
    let aap = create_aap_from_proposal(proposal);
    lnss_approval::register_pending_aap(aap.clone());

    let decision = ucf::v1::ApprovalDecision {
        approval_digest: Some(ucf::v1::Digest32 {
            value: vec![6; 32],
        }),
        aap_digest: Some(ucf::v1::Digest32 {
            value: aap.aap_digest.to_vec(),
        }),
        decision: ucf::v1::ApprovalDecisionForm::ApproveWithModifications as i32,
        modifications: Some(ucf::v1::ApprovalModifications {
            max_spikes_per_tick: Some(200),
            max_targets_per_spike: None,
            max_targets_per_feature: None,
            max_amplitude_q: None,
            require_simulation_first: None,
        }),
    };
    write_decision(&approvals_dir.join("a.bin"), &decision);

    let writer = RecordingWriter::default();
    let activation_state =
        ActivationState::load_or_default(state_dir.join("activation_state.txt"))
            .expect("state");
    let mut approval_inbox = ApprovalInbox::new(&approvals_dir, &proposals_dir);
    approval_inbox.ticks_per_scan = 1;
    let mut runtime = build_runtime(writer, approval_inbox, activation_state);

    runtime
        .run_step("session", "step", b"input", &default_mods(), &[])
        .expect("run step");

    assert_eq!(runtime.activation_state.active_injection_limits, None);
}

#[test]
fn approvals_are_idempotent_and_state_persists() {
    let _guard = test_lock();
    clear_pending_aaps();
    clear_seen_approval_digests();

    let proposals_dir = temp_dir("lnss_proposals_idempotent");
    let approvals_dir = temp_dir("lnss_approvals_idempotent");
    let state_dir = temp_dir("lnss_state_idempotent");

    let map_path = proposals_dir.join("maps.bin");
    fs::write(&map_path, b"map-bytes").expect("write map");
    let map_digest = mapping_file_digest(b"map-bytes");

    write_json(
        &proposals_dir.join("proposal.json"),
        serde_json::json!({
            "proposal_id": "proposal-1",
            "kind": "mapping_update",
            "created_at_ms": 1,
            "base_evidence_digest": vec![0; 32],
            "payload": {
                "type": "mapping_update",
                "new_map_path": map_path.to_string_lossy(),
                "map_digest": map_digest.to_vec(),
                "change_summary": []
            },
            "reason_codes": []
        }),
    );

    let proposals = load_proposals(&proposals_dir).expect("load proposals");
    let proposal = proposals.first().expect("proposal");
    let aap = create_aap_from_proposal(proposal);
    lnss_approval::register_pending_aap(aap.clone());

    let decision = ucf::v1::ApprovalDecision {
        approval_digest: Some(ucf::v1::Digest32 {
            value: vec![2; 32],
        }),
        aap_digest: Some(ucf::v1::Digest32 {
            value: aap.aap_digest.to_vec(),
        }),
        decision: ucf::v1::ApprovalDecisionForm::Approve as i32,
        modifications: None,
    };
    write_decision(&approvals_dir.join("a.bin"), &decision);

    let writer = RecordingWriter::default();
    let activation_state =
        ActivationState::load_or_default(state_dir.join("activation_state.txt"))
            .expect("state");
    let mut approval_inbox = ApprovalInbox::new(&approvals_dir, &proposals_dir);
    approval_inbox.ticks_per_scan = 1;
    let mut runtime = build_runtime(writer.clone(), approval_inbox, activation_state);

    runtime
        .run_step("session", "step", b"input", &default_mods(), &[])
        .expect("run step");
    runtime
        .run_step("session", "step-2", b"input", &default_mods(), &[])
        .expect("run step");

    let activations = writer.activations();
    assert_eq!(activations.len(), 1);

    let restored = ActivationState::load_or_default(
        runtime.activation_state.path().to_path_buf(),
    )
    .expect("restore state");
    assert_eq!(restored.active_mapping_digest, Some(map_digest));
    assert_eq!(
        runtime.activation_state.active_injection_limits,
        None::<InjectionLimits>
    );
}
