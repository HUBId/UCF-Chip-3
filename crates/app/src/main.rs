#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

use control::ControlFrameStore;
use frames::ShortWindowAggregator;
use gem::{Gate, GateContext, GateResult};
use pbm::{DecisionForm, PolicyEngine};
use tam::MockAdapter;
use ucf_protocol::ucf;

fn main() {
    let aggregator = Arc::new(Mutex::new(ShortWindowAggregator::new(32)));
    let control_store = Arc::new(Mutex::new(ControlFrameStore::new()));
    let gate = Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(MockAdapter),
        aggregator: aggregator.clone(),
        control_store: control_store.clone(),
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
    };

    let read_action = ucf::v1::ActionSpec {
        verb: "mock.read".to_string(),
        resources: vec!["demo".to_string()],
    };

    let export_action = ucf::v1::ActionSpec {
        verb: "mock.export".to_string(),
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
