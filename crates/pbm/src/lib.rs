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
pub struct PolicyEvaluationRequest {
    pub decision_id: String,
    pub query: ucf::v1::PolicyQuery,
    pub integrity_state: String,
    pub charter_version_digest: String,
    pub allowed_tools: Vec<String>,
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

    /// Compatibility shim that evaluates with default context.
    /// The deterministic record, including digest, is computed by the contextual API.
    pub fn decide(&self, q: ucf::v1::PolicyQuery) -> ucf::v1::PolicyDecision {
        self.decide_with_context(PolicyEvaluationRequest {
            decision_id: "default-decision".to_string(),
            query: q,
            integrity_state: "OK".to_string(),
            charter_version_digest: String::new(),
            allowed_tools: Vec::new(),
        })
        .decision
    }

    pub fn decide_with_context(&self, request: PolicyEvaluationRequest) -> PolicyDecisionRecord {
        let PolicyEvaluationRequest {
            decision_id,
            query,
            integrity_state,
            charter_version_digest,
            mut allowed_tools,
        } = request;

        allowed_tools.sort();

        let action = query.action.unwrap_or(ucf::v1::ActionSpec {
            verb: String::new(),
            resources: Vec::new(),
        });
        let tool_id = action.verb.clone();

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
        } else if !allowed_tools.contains(&tool_id) {
            (
                DecisionForm::Deny,
                ucf::v1::DecisionForm::Deny,
                vec!["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()],
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
            integrity_state: "OK".to_string(),
            charter_version_digest: "charter".to_string(),
            allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
        }
    }

    #[test]
    fn deny_when_integrity_not_ok() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.read");
        req.integrity_state = "FAIL".to_string();
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
}
