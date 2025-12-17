#![forbid(unsafe_code)]

use blake3::Hasher;
use ucf_protocol::ucf;

const POLICY_VERSION_DIGEST: &str = "policy-v1-mvp";
const DECISION_HASH_DOMAIN: &str = "UCF:HASH:POLICY_DECISION";

#[derive(Debug, Clone)]
pub struct PolicyEngine;

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionForm {
    Allow,
    Deny,
    RequireApproval,
    RequireSimulationFirst,
    AllowWithConstraints,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub integrity_state: String,
    pub charter_version_digest: String,
    pub control_frame: ucf::v1::ControlFrame,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluationRequest {
    pub decision_id: String,
    pub query: ucf::v1::PolicyQuery,
    pub context: PolicyContext,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDecisionRecord {
    pub form: DecisionForm,
    pub decision: ucf::v1::PolicyDecision,
    pub policy_version_digest: String,
    pub decision_id: String,
    pub decision_digest: [u8; 32],
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    /// Compatibility shim that evaluates with provided context.
    /// The deterministic record, including digest, is computed by the contextual API.
    pub fn decide(&self, q: ucf::v1::PolicyQuery, ctx: &PolicyContext) -> ucf::v1::PolicyDecision {
        self.decide_with_context(PolicyEvaluationRequest {
            decision_id: "default-decision".to_string(),
            query: q,
            context: ctx.clone(),
        })
        .decision
    }

    pub fn decide_with_context(&self, request: PolicyEvaluationRequest) -> PolicyDecisionRecord {
        let PolicyEvaluationRequest {
            decision_id,
            query,
            context,
        } = request;

        let PolicyContext {
            integrity_state,
            charter_version_digest,
            control_frame,
            mut allowed_tools,
        } = context;

        allowed_tools.sort();

        let action = query.action.unwrap_or(ucf::v1::ActionSpec {
            verb: String::new(),
            resources: Vec::new(),
        });
        let tool_id = action.verb.clone();

        let overlays = control_frame.overlays.clone().unwrap_or_default();
        let toolclass_mask = control_frame.toolclass_mask.clone().unwrap_or_default();

        let (form, decision_enum, mut reason_codes) = if integrity_state != "OK" {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.INTEGRITY_REQUIRED".to_string()],
            )
        } else if charter_version_digest.is_empty() {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.CHARTER_SCOPE".to_string()],
            )
        } else if overlays.ovl_export_lock && is_export_tool(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()],
            )
        } else if overlays.ovl_novelty_lock && is_new_source_action(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.NOVELTY_LOCK".to_string()],
            )
        } else if !allowed_tools.contains(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()],
            )
        } else if overlays.ovl_simulate_first {
            (
                DecisionForm::RequireSimulationFirst,
                ucf::v1::DecisionForm::RequireSimulationFirst,
                vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()],
            )
        } else if !toolclass_mask.enable_execute && is_execute_action(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()],
            )
        } else if !toolclass_mask.enable_export && is_export_tool(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()],
            )
        } else if tool_id == "mock.export" {
            (
                DecisionForm::RequireApproval,
                ucf::v1::DecisionForm::RequireApproval,
                vec!["RC.PB.REQ_APPROVAL.EXPORT_SENSITIVE".to_string()],
            )
        } else {
            (
                DecisionForm::AllowWithConstraints,
                ucf::v1::DecisionForm::Allow,
                vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()],
            )
        };

        reason_codes.sort();
        let decision = ucf::v1::PolicyDecision {
            decision: decision_enum.into(),
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: reason_codes.clone(),
            }),
            constraints: Some(ucf::v1::ConstraintsDelta {
                constraints_added: Vec::new(),
                constraints_removed: Vec::new(),
            }),
        };

        let decision_digest = compute_decision_digest(&decision_id, &form, &reason_codes);

        PolicyDecisionRecord {
            form,
            decision,
            policy_version_digest: POLICY_VERSION_DIGEST.to_string(),
            decision_id,
            decision_digest,
        }
    }
}

fn compute_decision_digest(
    decision_id: &str,
    form: &DecisionForm,
    reason_codes: &[String],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DECISION_HASH_DOMAIN.as_bytes());
    hasher.update(decision_id.as_bytes());
    hasher.update(form_label(form).as_bytes());
    hasher.update(POLICY_VERSION_DIGEST.as_bytes());
    for code in reason_codes {
        hasher.update(code.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn is_export_tool(tool_id: &str) -> bool {
    tool_id == "mock.export" || tool_id.starts_with("mock.export")
}

fn is_execute_action(tool_id: &str) -> bool {
    tool_id == "execute" || tool_id.starts_with("mock.execute")
}

fn is_new_source_action(tool_id: &str) -> bool {
    tool_id == "mock.newsource"
}

fn form_label(form: &DecisionForm) -> &'static str {
    match form {
        DecisionForm::Allow => "ALLOW",
        DecisionForm::Deny => "DENY",
        DecisionForm::RequireApproval => "REQUIRE_APPROVAL",
        DecisionForm::RequireSimulationFirst => "REQUIRE_SIMULATION_FIRST",
        DecisionForm::AllowWithConstraints => "ALLOW_WITH_CONSTRAINTS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_frame_base() -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "cf1".to_string(),
            note: String::new(),
            active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            overlays: None,
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

    fn base_query(tool_id: &str) -> ucf::v1::PolicyQuery {
        ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(ucf::v1::ActionSpec {
                verb: tool_id.to_string(),
                resources: vec![],
            }),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        }
    }

    fn request(tool_id: &str) -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            decision_id: "dec1".to_string(),
            query: base_query(tool_id),
            context: PolicyContext {
                integrity_state: "OK".to_string(),
                charter_version_digest: "charter".to_string(),
                allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
                control_frame: control_frame_base(),
            },
        }
    }

    #[test]
    fn deny_when_integrity_not_ok() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.read");
        req.context.integrity_state = "FAIL".to_string();
        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::Deny);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.DENY.INTEGRITY_REQUIRED".to_string()]
        );
    }

    #[test]
    fn require_approval_for_mock_export() {
        let engine = PolicyEngine::new();
        let req = request("mock.export");
        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::RequireApproval);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.REQ_APPROVAL.EXPORT_SENSITIVE".to_string()]
        );
    }

    #[test]
    fn decision_digest_is_deterministic() {
        let engine = PolicyEngine::new();
        let req = request("mock.read");
        let record_a = engine.decide_with_context(req.clone());
        let record_b = engine.decide_with_context(req);
        assert_eq!(record_a.decision_digest, record_b.decision_digest);
    }

    #[test]
    fn simulate_first_requires_simulation() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.read");
        req.context.control_frame.overlays = Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: true,
            ovl_export_lock: false,
            ovl_novelty_lock: false,
        });

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::RequireSimulationFirst);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()]
        );
    }

    #[test]
    fn export_lock_denies_export() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.export");
        req.context.control_frame.overlays = Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: true,
            ovl_novelty_lock: false,
        });

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::Deny);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()]
        );
    }

    #[test]
    fn novelty_lock_denies_new_source() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.newsource");
        req.context.control_frame.overlays = Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: false,
            ovl_novelty_lock: true,
        });

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::Deny);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.DENY.NOVELTY_LOCK".to_string()]
        );
    }
}
