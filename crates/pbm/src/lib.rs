#![forbid(unsafe_code)]

use std::{collections::HashMap, convert::TryFrom};

use blake3::Hasher;
use ucf_protocol::{canonical_bytes, digest32, ucf};

const POLICY_VERSION_DIGEST: &str = "policy-v1-mvp";
const POLICY_QUERY_HASH_DOMAIN: &str = "UCF:HASH:POLICY_QUERY";
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
    pub allowed_tools: Vec<String>,
    pub control_frame: ucf::v1::ControlFrame,
    pub tool_action_type: ucf::v1::ToolActionType,
    pub pev: Option<ucf::v1::PolicyEcologyVector>,
    pub pev_digest: Option<[u8; 32]>,
    pub ruleset_digest: Option<[u8; 32]>,
    pub session_sealed: bool,
    pub unlock_present: bool,
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
    pub policy_query_digest: [u8; 32],
    pub decision_id: String,
    pub decision_digest: [u8; 32],
    pub pev_digest: Option<[u8; 32]>,
    pub ruleset_digest: Option<[u8; 32]>,
    pub metadata: HashMap<String, String>,
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
            tool_action_type,
            pev,
            pev_digest,
            ruleset_digest,
            session_sealed: _,
            unlock_present: _,
        } = context;

        allowed_tools.sort();

        let policy_query_digest = policy_query_digest(&query);

        let action = query.action.unwrap_or(ucf::v1::ActionSpec {
            verb: String::new(),
            resources: Vec::new(),
        });
        let (tool_id, _action_id) = split_tool_and_action(&action.verb);

        let overlays = control_frame.overlays.clone().unwrap_or_default();
        let toolclass_mask = control_frame.toolclass_mask.clone().unwrap_or_default();
        let mut decision_state = base_decision_state(
            &integrity_state,
            &charter_version_digest,
            &overlays,
            &toolclass_mask,
            &allowed_tools,
            &tool_id,
            tool_action_type,
        );

        if let Some(pev_ref) = pev.as_ref() {
            apply_pev_biases(&mut decision_state, pev_ref, tool_action_type);
        }

        if ruleset_digest.is_some() {
            decision_state
                .reason_codes
                .push("RC.GV.RULESET.BOUND".to_string());
        }

        decision_state.reason_codes.sort();
        decision_state.reason_codes.dedup();
        let decision = ucf::v1::PolicyDecision {
            decision: decision_state.decision_enum.into(),
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: decision_state.reason_codes.clone(),
            }),
            constraints: Some(decision_state.constraints.clone()),
        };

        let pev_digest = effective_pev_digest(pev_digest, pev.as_ref());
        let decision_digest = compute_decision_digest(
            &decision_id,
            &decision_state.form,
            &decision_state.reason_codes,
            pev_digest,
            ruleset_digest,
            &policy_query_digest,
        );

        PolicyDecisionRecord {
            form: decision_state.form,
            decision,
            policy_version_digest: POLICY_VERSION_DIGEST.to_string(),
            policy_query_digest,
            decision_id,
            decision_digest,
            pev_digest,
            ruleset_digest,
            metadata: HashMap::new(),
        }
    }
}

pub fn compute_decision_digest(
    decision_id: &str,
    form: &DecisionForm,
    reason_codes: &[String],
    pev_digest: Option<[u8; 32]>,
    ruleset_digest: Option<[u8; 32]>,
    policy_query_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DECISION_HASH_DOMAIN.as_bytes());
    hasher.update(decision_id.as_bytes());
    hasher.update(form_label(form).as_bytes());
    hasher.update(POLICY_VERSION_DIGEST.as_bytes());
    hasher.update(policy_query_digest);
    for code in reason_codes {
        hasher.update(code.as_bytes());
    }
    if let Some(pev_digest) = pev_digest {
        hasher.update(pev_digest.as_slice());
    }
    if let Some(ruleset_digest) = ruleset_digest {
        hasher.update(ruleset_digest.as_slice());
    }
    *hasher.finalize().as_bytes()
}

pub fn policy_query_digest(query: &ucf::v1::PolicyQuery) -> [u8; 32] {
    let mut canonical_query = query.clone();
    if let Some(reason_codes) = canonical_query.reason_codes.as_mut() {
        reason_codes.codes.sort();
    }
    if let Some(action) = canonical_query.action.as_mut() {
        action.resources.sort();
    }
    let canonical = canonical_bytes(&canonical_query);

    digest32(POLICY_QUERY_HASH_DOMAIN, "PolicyQuery", "v1", &canonical)
}

#[derive(Clone)]
struct DecisionState {
    form: DecisionForm,
    decision_enum: ucf::v1::DecisionForm,
    reason_codes: Vec<String>,
    constraints: ucf::v1::ConstraintsDelta,
}

fn base_decision_state(
    integrity_state: &str,
    charter_version_digest: &str,
    overlays: &ucf::v1::ControlFrameOverlays,
    toolclass_mask: &ucf::v1::ToolClassMask,
    allowed_tools: &[String],
    tool_id: &str,
    tool_action_type: ucf::v1::ToolActionType,
) -> DecisionState {
    if integrity_state != "OK" {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec!["RC.PB.DENY.INTEGRITY_REQUIRED".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if charter_version_digest.is_empty() {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec!["RC.PB.DENY.CHARTER_SCOPE".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if overlays.ovl_export_lock && is_export_action(tool_action_type) {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if overlays.ovl_novelty_lock && is_new_source_action(tool_id) {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec!["RC.PB.DENY.NOVELTY_LOCK".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if !allowed_tools.iter().any(|tool| tool == tool_id) {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec!["RC.PB.DENY.TOOL_NOT_ALLOWED".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if overlays.ovl_simulate_first {
        return DecisionState {
            form: DecisionForm::RequireSimulationFirst,
            decision_enum: ucf::v1::DecisionForm::RequireSimulationFirst,
            reason_codes: vec!["RC.PB.REQ_SIMULATION.COMPLEX_CHAIN".to_string()],
            constraints: default_constraints_delta(),
        };
    }

    if let Some(reason) = toolclass_denied_reason(tool_action_type, toolclass_mask) {
        return DecisionState {
            form: DecisionForm::Deny,
            decision_enum: ucf::v1::DecisionForm::Deny,
            reason_codes: vec![reason],
            constraints: default_constraints_delta(),
        };
    }

    DecisionState {
        form: DecisionForm::AllowWithConstraints,
        decision_enum: ucf::v1::DecisionForm::Allow,
        reason_codes: vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()],
        constraints: default_constraints_delta(),
    }
}

fn apply_pev_biases(
    state: &mut DecisionState,
    pev: &ucf::v1::PolicyEcologyVector,
    tool_action_type: ucf::v1::ToolActionType,
) {
    if matches!(state.form, DecisionForm::Deny) {
        return;
    }

    if bias_at_least_medium(pev.conservatism_bias)
        && matches!(state.form, DecisionForm::AllowWithConstraints)
    {
        state.form = DecisionForm::RequireSimulationFirst;
        state.decision_enum = ucf::v1::DecisionForm::RequireSimulationFirst;
        state
            .reason_codes
            .push("RC.PB.REQ_SIMULATION.TOOL_UNCERTAIN".to_string());
    }

    if bias_at_least_medium(pev.reversibility_bias) && is_irreversible_action(tool_action_type) {
        state.form = DecisionForm::RequireApproval;
        state.decision_enum = ucf::v1::DecisionForm::RequireApproval;
        state
            .reason_codes
            .push("RC.PB.REQ_APPROVAL.HIGH_RISK".to_string());
    }

    if bias_at_least_medium(pev.novelty_penalty_bias) {
        state.constraints.novelty_lock = true;
        state
            .reason_codes
            .push("RC.PB.CONSTRAINT.NOVELTY_LIMIT".to_string());
    }
}

fn effective_pev_digest(
    provided: Option<[u8; 32]>,
    pev: Option<&ucf::v1::PolicyEcologyVector>,
) -> Option<[u8; 32]> {
    provided.or_else(|| {
        pev.and_then(|vector| vector.pev_digest.as_ref())
            .and_then(digest32_as_array)
    })
}

fn default_constraints_delta() -> ucf::v1::ConstraintsDelta {
    ucf::v1::ConstraintsDelta {
        constraints_added: Vec::new(),
        constraints_removed: Vec::new(),
        novelty_lock: false,
    }
}

fn is_export_action(action_type: ucf::v1::ToolActionType) -> bool {
    matches!(action_type, ucf::v1::ToolActionType::Export)
}

fn is_irreversible_action(action_type: ucf::v1::ToolActionType) -> bool {
    matches!(
        action_type,
        ucf::v1::ToolActionType::Write
            | ucf::v1::ToolActionType::Execute
            | ucf::v1::ToolActionType::Export
    )
}

fn is_new_source_action(tool_id: &str) -> bool {
    tool_id == "mock.newsource"
}

fn toolclass_denied_reason(
    action_type: ucf::v1::ToolActionType,
    mask: &ucf::v1::ToolClassMask,
) -> Option<String> {
    match action_type {
        ucf::v1::ToolActionType::Execute if !mask.enable_execute => {
            Some("RC.PB.DENY.TOOL_NOT_ALLOWED".to_string())
        }
        ucf::v1::ToolActionType::Export if !mask.enable_export => {
            Some("RC.CD.DLP.EXPORT_BLOCKED".to_string())
        }
        ucf::v1::ToolActionType::Write if !mask.enable_write => {
            Some("RC.PB.DENY.TOOL_NOT_ALLOWED".to_string())
        }
        ucf::v1::ToolActionType::Read if !mask.enable_read => {
            Some("RC.PB.DENY.TOOL_NOT_ALLOWED".to_string())
        }
        ucf::v1::ToolActionType::Transform if !mask.enable_transform => {
            Some("RC.PB.DENY.TOOL_NOT_ALLOWED".to_string())
        }
        _ => None,
    }
}

fn bias_at_least_medium(bias: i32) -> bool {
    match ucf::v1::PolicyEcologyBias::try_from(bias) {
        Ok(ucf::v1::PolicyEcologyBias::Medium | ucf::v1::PolicyEcologyBias::High) => true,
        Ok(_) => false,
        Err(_) => bias >= ucf::v1::PolicyEcologyBias::Medium as i32,
    }
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

fn split_tool_and_action(verb: &str) -> (String, String) {
    verb.split_once('/')
        .map(|(tool, action)| (tool.to_string(), action.to_string()))
        .unwrap_or_else(|| (verb.to_string(), verb.to_string()))
}

fn digest32_as_array(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    digest.value.clone().try_into().ok()
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
            evidence_refs: Vec::new(),
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
        let (tool_name, _action_id) = split_tool_and_action(tool_id);
        let tool_action_type = match tool_name.as_str() {
            "mock.read" => ucf::v1::ToolActionType::Read,
            "mock.export" => ucf::v1::ToolActionType::Export,
            "mock.write" => ucf::v1::ToolActionType::Write,
            _ => ucf::v1::ToolActionType::Unspecified,
        };

        PolicyEvaluationRequest {
            decision_id: "dec1".to_string(),
            query: base_query(tool_id),
            context: PolicyContext {
                integrity_state: "OK".to_string(),
                charter_version_digest: "charter".to_string(),
                allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
                control_frame: control_frame_base(),
                tool_action_type,
                pev: None,
                pev_digest: None,
                ruleset_digest: None,
                session_sealed: false,
                unlock_present: false,
            },
        }
    }

    fn pev_vector(
        conservatism: ucf::v1::PolicyEcologyBias,
        novelty: ucf::v1::PolicyEcologyBias,
        reversibility: ucf::v1::PolicyEcologyBias,
    ) -> ucf::v1::PolicyEcologyVector {
        ucf::v1::PolicyEcologyVector {
            conservatism_bias: conservatism.into(),
            novelty_penalty_bias: novelty.into(),
            reversibility_bias: reversibility.into(),
            pev_digest: None,
        }
    }

    fn pev_digest(seed: u8) -> [u8; 32] {
        [seed; 32]
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
    fn export_allows_with_constraints() {
        let engine = PolicyEngine::new();
        let req = request("mock.export/render");
        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::AllowWithConstraints);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()]
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
    fn policy_query_digest_is_deterministic() {
        let base = base_query("mock.read");
        let mut with_reason_codes = base.clone();
        with_reason_codes.reason_codes = Some(ucf::v1::ReasonCodes {
            codes: vec!["b".to_string(), "a".to_string()],
        });

        let mut shuffled = with_reason_codes.clone();
        shuffled
            .reason_codes
            .as_mut()
            .expect("reason codes")
            .codes
            .reverse();

        let digest_a = policy_query_digest(&with_reason_codes);
        let digest_b = policy_query_digest(&shuffled);

        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn policy_query_digest_normalizes_resource_order() {
        let mut with_resources = base_query("mock.read");
        with_resources
            .action
            .as_mut()
            .expect("action present")
            .resources = vec!["b".to_string(), "a".to_string()];

        let mut reversed = with_resources.clone();
        reversed
            .action
            .as_mut()
            .expect("action present")
            .resources
            .reverse();

        let digest_a = policy_query_digest(&with_resources);
        let digest_b = policy_query_digest(&reversed);

        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn decision_digest_binds_policy_query() {
        let engine = PolicyEngine::new();
        let req_a = request("mock.read");
        let mut req_b = req_a.clone();

        req_b.query.principal = "chip3b".to_string();

        let record_a = engine.decide_with_context(req_a);
        let record_b = engine.decide_with_context(req_b);

        assert_eq!(record_a.form, record_b.form);
        assert_eq!(
            record_a.policy_query_digest,
            policy_query_digest(&base_query("mock.read"))
        );
        assert_ne!(record_a.policy_query_digest, record_b.policy_query_digest);
        assert_ne!(record_a.decision_digest, record_b.decision_digest);
    }

    #[test]
    fn decision_digest_changes_with_ruleset_digest() {
        let engine = PolicyEngine::new();
        let mut req_one = request("mock.read");
        req_one.context.ruleset_digest = Some([1u8; 32]);
        let mut req_two = req_one.clone();
        req_two.context.ruleset_digest = Some([2u8; 32]);

        let record_one = engine.decide_with_context(req_one);
        let record_two = engine.decide_with_context(req_two);

        assert_ne!(record_one.decision_digest, record_two.decision_digest);
        assert_eq!(
            record_one.decision.reason_codes.unwrap().codes,
            vec![
                "RC.GV.RULESET.BOUND".to_string(),
                "RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()
            ]
        );
    }

    #[test]
    fn decision_digest_unaffected_when_ruleset_missing() {
        let engine = PolicyEngine::new();
        let req = request("mock.read");
        let record = engine.decide_with_context(req);

        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()]
        );
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
        let mut req = request("mock.export/render");
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

    #[test]
    fn pev_absent_behavior_unchanged() {
        let engine = PolicyEngine::new();
        let req = request("mock.export/render");

        let record = engine.decide_with_context(req);

        assert_eq!(record.form, DecisionForm::AllowWithConstraints);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string()]
        );
        assert!(
            !record
                .decision
                .constraints
                .expect("constraints present")
                .novelty_lock
        );
    }

    #[test]
    fn conservatism_bias_requires_simulation_first() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.export/render");
        let mut pev = pev_vector(
            ucf::v1::PolicyEcologyBias::Medium,
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Low,
        );
        let digest = pev_digest(2);
        pev.pev_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
        req.context.pev = Some(pev);
        req.context.pev_digest = Some(digest);

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::RequireSimulationFirst);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec![
                "RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string(),
                "RC.PB.REQ_SIMULATION.TOOL_UNCERTAIN".to_string(),
            ]
        );
    }

    #[test]
    fn reversibility_bias_requires_approval() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.export/render");
        req.context.allowed_tools.push("mock.write".to_string());
        req.context.pev = Some(pev_vector(
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Medium,
        ));
        req.context.pev_digest = Some(pev_digest(3));

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::RequireApproval);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec![
                "RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string(),
                "RC.PB.REQ_APPROVAL.HIGH_RISK".to_string(),
            ]
        );
    }

    #[test]
    fn novelty_penalty_sets_lock() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.export/render");
        req.context.pev = Some(pev_vector(
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Medium,
            ucf::v1::PolicyEcologyBias::Low,
        ));

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::AllowWithConstraints);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec![
                "RC.PB.CONSTRAINT.NOVELTY_LIMIT".to_string(),
                "RC.PB.CONSTRAINT.SCOPE_SHRINK".to_string(),
            ]
        );
        assert!(
            record
                .decision
                .constraints
                .expect("constraints present")
                .novelty_lock
        );
    }

    #[test]
    fn pev_does_not_loosen_denials() {
        let engine = PolicyEngine::new();
        let mut req = request("mock.export/render");
        req.context.control_frame.overlays = Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: true,
            ovl_novelty_lock: false,
        });
        req.context.pev = Some(pev_vector(
            ucf::v1::PolicyEcologyBias::High,
            ucf::v1::PolicyEcologyBias::High,
            ucf::v1::PolicyEcologyBias::High,
        ));
        req.context.pev_digest = Some(pev_digest(4));

        let record = engine.decide_with_context(req);
        assert_eq!(record.form, DecisionForm::Deny);
        assert_eq!(
            record.decision.reason_codes.unwrap().codes,
            vec!["RC.CD.DLP.EXPORT_BLOCKED".to_string()]
        );
    }

    #[test]
    fn decision_digest_binds_pev_digest() {
        let engine = PolicyEngine::new();
        let mut req_a = request("mock.export/render");
        req_a.context.pev = Some(pev_vector(
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Low,
            ucf::v1::PolicyEcologyBias::Low,
        ));
        req_a.context.pev_digest = Some(pev_digest(5));

        let mut req_b = req_a.clone();
        req_b.context.pev_digest = Some(pev_digest(6));

        let record_a = engine.decide_with_context(req_a);
        let record_b = engine.decide_with_context(req_b);

        assert_ne!(record_a.decision_digest, record_b.decision_digest);
    }
}
