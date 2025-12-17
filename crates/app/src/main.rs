#![forbid(unsafe_code)]

use gem::{Gate, GateContext, GateResult, OutcomePacketStatus};
use pbm::{DecisionForm, PolicyEngine};
use tam::MockAdapter;
use ucf_protocol::ucf;

fn main() {
    let gate = Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(MockAdapter),
    };

    let action = ucf::v1::ActionSpec {
        verb: "mock.read".to_string(),
        resources: vec!["demo".to_string()],
    };

    let ctx = GateContext {
        integrity_state: "OK".to_string(),
        charter_version_digest: "charter-mvp".to_string(),
        allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
    };

    let result = gate.handle_action_spec("session-1", "step-1", action, ctx);
    print_result(result);
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
            let outcome_status = match outcome.status {
                OutcomePacketStatus::Success => "EXECUTED",
                OutcomePacketStatus::Failure => "FAILED",
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
