#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use control::ControlFrameStore;
use ed25519_dalek::{Signer, SigningKey};
use frames::{FramesConfig, WindowEngine};
use gem::{Gate, GateContext, GateResult};
use pbm::{DecisionForm, PolicyEngine};
use pvgs_client::{KeyEpochSync, LocalPvgsClient};
use pvgs_verify::{
    pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
    verify_pvgs_receipt, PvgsKeyEpochStore,
};
use tam::MockAdapter;
use trm::registry_fixture;
use ucf_protocol::ucf;

fn main() {
    let frames_config = FramesConfig::load_from_dir(".").unwrap_or_else(|err| {
        eprintln!("using fallback frames config: {err}");
        FramesConfig::fallback()
    });
    let aggregator = Arc::new(Mutex::new(
        WindowEngine::new(frames_config).expect("window engine from config"),
    ));
    let control_store = Arc::new(Mutex::new(ControlFrameStore::new()));
    let receipt_store = bootstrap_pvgs_store();
    let gate = Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(MockAdapter),
        aggregator: aggregator.clone(),
        control_store: control_store.clone(),
        receipt_store: receipt_store.clone(),
        registry: Arc::new(registry_fixture()),
        pvgs_client: Arc::new(Mutex::new(
            Box::new(LocalPvgsClient::default()) as Box<dyn pvgs_client::PvgsClient>
        )),
        integrity_issues: Arc::new(Mutex::new(0)),
    };

    let control_frame_m0 = control_frame_m0();
    let control_frame_m1 = control_frame_m1();

    {
        control_store
            .lock()
            .expect("control store lock")
            .update(control_frame_m0.clone())
            .expect("valid control frame");
    }

    let ctx = GateContext {
        integrity_state: "OK".to_string(),
        charter_version_digest: "charter-mvp".to_string(),
        allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
        control_frame: None,
        pvgs_receipt: None,
        approval_grant_id: None,
    };

    let read_action = ucf::v1::ActionSpec {
        verb: "mock.read/get".to_string(),
        resources: vec!["demo".to_string()],
    };

    let export_action = ucf::v1::ActionSpec {
        verb: "mock.export/render".to_string(),
        resources: vec!["demo".to_string()],
    };

    let result = gate.handle_action_spec("session-1", "step-1", read_action.clone(), ctx.clone());
    print_result(result);

    {
        control_store
            .lock()
            .expect("control store lock")
            .update(control_frame_m1.clone())
            .expect("valid control frame");
    }

    let result = gate.handle_action_spec("session-1", "step-2", read_action.clone(), ctx.clone());
    print_result(result);

    let result = gate.handle_action_spec("session-1", "step-3", export_action, ctx.clone());
    print_result(result);

    let frames = aggregator.lock().expect("aggregator lock").force_flush();

    for frame in frames {
        print_frame_summary(&frame);
    }
}

fn bootstrap_pvgs_store() -> Arc<PvgsKeyEpochStore> {
    const EPOCH_ONE_SEED: [u8; 32] = [1; 32];
    const EPOCH_TWO_SEED: [u8; 32] = [2; 32];

    let epoch_one = key_epoch_fixture(
        1,
        "pvgs-bootstrap-1",
        &SigningKey::from_bytes(&EPOCH_ONE_SEED),
        1_700_000_000_000,
    );
    let epoch_two = key_epoch_fixture(
        2,
        "pvgs-bootstrap-2",
        &SigningKey::from_bytes(&EPOCH_TWO_SEED),
        1_700_000_500_000,
    );

    let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
    sync.sync_from_list(vec![epoch_two, epoch_one])
        .expect("deterministic key epoch sync");

    let receipt = receipt_fixture(&SigningKey::from_bytes(&EPOCH_TWO_SEED), "pvgs-bootstrap-2");
    verify_pvgs_receipt(&receipt, sync.store()).expect("receipt verification");
    println!("sync ok, receipt verify ok");

    Arc::new(sync.store().clone())
}

fn print_result(result: GateResult) {
    match result {
        GateResult::ValidationError { code, message } => {
            println!("DENIED validation_error code={code} message={message}");
        }
        GateResult::Denied { decision } => {
            println!(
                "DENIED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::ApprovalRequired { decision } => {
            println!(
                "APPROVAL_REQUIRED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::SimulationRequired { decision } => {
            println!(
                "SIMULATION_REQUIRED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::Executed { decision, outcome } => {
            let outcome_status = match ucf::v1::OutcomeStatus::try_from(outcome.status) {
                Ok(ucf::v1::OutcomeStatus::Success) => "EXECUTED",
                _ => "FAILED",
            };
            let payload_str = String::from_utf8_lossy(&outcome.payload);
            let form_str = match decision.form {
                DecisionForm::AllowWithConstraints => "ALLOW_WITH_CONSTRAINTS",
                DecisionForm::Allow => "ALLOW",
                DecisionForm::Deny => "DENY",
                DecisionForm::RequireApproval => "REQUIRE_APPROVAL",
                DecisionForm::RequireSimulationFirst => "REQUIRE_SIMULATION_FIRST",
            };
            println!(
                "{outcome_status} form={} reasons={:?} payload={payload_str}",
                form_str,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
    }
}

fn key_epoch_fixture(
    epoch_id: u64,
    key_id: &str,
    signing_key: &SigningKey,
    timestamp_ms: u64,
) -> ucf::v1::PvgsKeyEpoch {
    let mut key_epoch = ucf::v1::PvgsKeyEpoch {
        epoch_id,
        attestation_key_id: key_id.to_string(),
        attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        announcement_digest: None,
        signature: None,
        timestamp_ms,
        vrf_key_id: Some("pvgs-vrf-demo".to_string()),
    };

    let digest = pvgs_key_epoch_digest(&key_epoch);
    key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
    key_epoch.signature = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_id.as_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
    });

    key_epoch
}

fn receipt_fixture(signing_key: &SigningKey, key_id: &str) -> ucf::v1::PvgsReceipt {
    let mut receipt = ucf::v1::PvgsReceipt {
        receipt_epoch: "pvgs-epoch-2".to_string(),
        receipt_id: "demo-receipt".to_string(),
        receipt_digest: Some(sample_digest(1)),
        status: ucf::v1::ReceiptStatus::Accepted.into(),
        action_digest: Some(sample_digest(2)),
        decision_digest: Some(sample_digest(3)),
        grant_id: "demo-grant".to_string(),
        charter_version_digest: Some(sample_digest(4)),
        policy_version_digest: Some(sample_digest(5)),
        prev_record_digest: Some(sample_digest(6)),
        profile_digest: Some(sample_digest(7)),
        tool_profile_digest: Some(sample_digest(8)),
        reject_reason_codes: Vec::new(),
        signer: None,
    };

    let sig = signing_key.sign(&pvgs_receipt_signing_preimage(&receipt));
    receipt.signer = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_id.as_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
    });
    receipt
}

fn sample_digest(seed: u8) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: vec![seed; 32],
    }
}

fn print_frame_summary(frame: &ucf::v1::SignalFrame) {
    let policy = frame.policy_stats.as_ref().unwrap();
    let exec = frame.exec_stats.as_ref().unwrap();
    let digest_hex = frame
        .signal_frame_digest
        .as_ref()
        .map(|d| hex::encode(&d.value))
        .unwrap_or_default();

    println!(
        "SIGNAL_FRAME window={} policy_allow={} policy_deny={} exec_success={} exec_failure={} top_rcs={:?} digest={}",
        frame.window.as_ref().map(|w| w.window_id.clone()).unwrap_or_default(),
        policy.allow_count,
        policy.deny_count,
        exec.success_count,
        exec.failure_count,
        policy
            .top_reason_codes
            .iter()
            .map(|rc| rc.code.clone())
            .collect::<Vec<_>>(),
        digest_hex
    );
}

fn control_frame_m0() -> ucf::v1::ControlFrame {
    ucf::v1::ControlFrame {
        frame_id: "cf-m0".to_string(),
        note: "open profile".to_string(),
        active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
        overlays: Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: false,
            ovl_novelty_lock: false,
        }),
        toolclass_mask: Some(ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        }),
        deescalation_lock: false,
        reason_codes: None,
    }
}

fn control_frame_m1() -> ucf::v1::ControlFrame {
    ucf::v1::ControlFrame {
        frame_id: "cf-m1".to_string(),
        note: "restricted overlays".to_string(),
        active_profile: ucf::v1::ControlFrameProfile::M1Restricted.into(),
        overlays: Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: true,
            ovl_export_lock: true,
            ovl_novelty_lock: false,
        }),
        toolclass_mask: Some(ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        }),
        deescalation_lock: true,
        reason_codes: None,
    }
}
