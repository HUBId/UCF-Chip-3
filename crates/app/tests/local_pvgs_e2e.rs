mod common;

use std::sync::{Arc, Mutex};

use chip4_pvgs::receipt_digest;
use ckm_orchestrator::CkmOrchestrator;
use common::spawn_local_pvgs;
use frames::{FramesConfig, WindowEngine};
use gem::{DecisionLogStore, Gate, GateContext, GateResult};
use pbm::{PolicyContext, PolicyDecisionRecord, PolicyEngine, PolicyEvaluationRequest};
use pvgs_client::{MockPvgsClient, PvgsClientReader};
use pvgs_verify::{verify_pvgs_receipt, PvgsKeyEpochStore};
use tam::ToolAdapter;
use trm::ToolRegistry;
use ucf_protocol::{canonical_bytes, digest32, ucf};
use ucf_test_utils::{make_control_frame, make_tool_action_profile};

#[derive(Clone, Default)]
struct CountingAdapter {
    calls: Arc<Mutex<usize>>,
}

impl CountingAdapter {
    fn count(&self) -> usize {
        *self.calls.lock().expect("count lock")
    }
}

impl ToolAdapter for CountingAdapter {
    fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket {
        let mut guard = self.calls.lock().expect("count lock");
        *guard += 1;
        ucf::v1::OutcomePacket {
            outcome_id: format!("{}:outcome", req.request_id),
            request_id: req.request_id,
            status: ucf::v1::OutcomeStatus::Success.into(),
            payload: Vec::new(),
            payload_digest: None,
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        }
    }
}

#[test]
fn ruleset_digest_changes_decision_digest() {
    let mut pvgs = spawn_local_pvgs();
    pvgs.publish_key_epoch(1);

    let mut registry_v1 = ToolRegistry::new();
    registry_v1
        .insert(make_tool_action_profile(
            "mock.read",
            "get",
            ucf::v1::ToolActionType::Read,
        ))
        .expect("valid read tap");
    let trc_v1 = registry_v1.build_registry_container("trc", "v1", 1);
    pvgs.commit_tool_registry(trc_v1);
    let ruleset_digest_1 = pvgs.get_current_ruleset_digest();

    let (control_frame, _) = make_control_frame(
        ucf::v1::ControlFrameProfile::M0Baseline,
        None,
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        },
    );

    let action = ucf::v1::ActionSpec {
        verb: "mock.read/get".to_string(),
        resources: Vec::new(),
    };
    let policy = PolicyEngine::new();
    let policy_ctx = PolicyContext {
        integrity_state: "OK".to_string(),
        charter_version_digest: "charter-v1".to_string(),
        allowed_tools: vec!["mock.read".to_string()],
        control_frame: control_frame.clone(),
        tool_action_type: ucf::v1::ToolActionType::Read,
        pev: None,
        pev_digest: None,
        ruleset_digest: Some(ruleset_digest_1),
        session_sealed: false,
        unlock_present: false,
    };

    let query = ucf::v1::PolicyQuery {
        principal: "chip3".to_string(),
        action: Some(action.clone()),
        channel: ucf::v1::Channel::Unspecified.into(),
        risk_level: ucf::v1::RiskLevel::Unspecified.into(),
        data_class: ucf::v1::DataClass::Unspecified.into(),
        reason_codes: None,
    };

    let decision_1 = policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "session:step".to_string(),
        query: query.clone(),
        context: policy_ctx.clone(),
    });
    let decision_1_repeat = policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "session:step".to_string(),
        query: query.clone(),
        context: policy_ctx.clone(),
    });
    assert_eq!(
        decision_1.decision_digest,
        decision_1_repeat.decision_digest
    );

    let mut registry_v2 = ToolRegistry::new();
    registry_v2
        .insert(make_tool_action_profile(
            "mock.read",
            "get",
            ucf::v1::ToolActionType::Read,
        ))
        .expect("valid read tap");
    registry_v2
        .insert(make_tool_action_profile(
            "mock.export",
            "render",
            ucf::v1::ToolActionType::Export,
        ))
        .expect("valid export tap");
    let trc_v2 = registry_v2.build_registry_container("trc", "v2", 2);
    pvgs.commit_tool_registry(trc_v2);
    let ruleset_digest_2 = pvgs.get_current_ruleset_digest();

    assert_ne!(ruleset_digest_1, ruleset_digest_2);

    let policy_ctx_v2 = PolicyContext {
        ruleset_digest: Some(ruleset_digest_2),
        ..policy_ctx
    };

    let decision_2 = policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "session:step".to_string(),
        query: query.clone(),
        context: policy_ctx_v2.clone(),
    });
    let decision_2_repeat = policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "session:step".to_string(),
        query,
        context: policy_ctx_v2,
    });

    assert_ne!(decision_1.decision_digest, decision_2.decision_digest);
    assert_eq!(
        decision_2.decision_digest,
        decision_2_repeat.decision_digest
    );
}

#[test]
fn export_requires_bound_receipt() {
    let mut pvgs = spawn_local_pvgs();
    pvgs.publish_key_epoch(1);

    let mut registry = ToolRegistry::new();
    let export_tap =
        make_tool_action_profile("mock.export", "render", ucf::v1::ToolActionType::Export);
    registry
        .insert(export_tap.clone())
        .expect("valid export tap");
    let trc = registry.build_registry_container("trc", "v1", 1);
    pvgs.commit_tool_registry(trc);

    let gate_registry = Arc::new(registry);
    let adapter = CountingAdapter::default();
    let gate = gate_with_components(
        Box::new(adapter.clone()),
        gate_registry.clone(),
        pvgs.key_epoch_store.clone(),
    );
    let action = ucf::v1::ActionSpec {
        verb: "mock.export/render".to_string(),
        resources: Vec::new(),
    };
    let control_frame = export_control_frame();
    let control_frame_digest = digest_to_proto(control::control_frame_digest(&control_frame));

    let mut base_ctx = gate_context(&control_frame, None, pvgs.pvgs.get_current_ruleset_digest());
    let decision = policy_decision_for(&gate, &action, &base_ctx, "session", "step");
    let action_digest = action_spec_digest(&action);
    let valid_receipt = pvgs.issue_receipt_for_action(
        action_digest,
        decision.decision_digest,
        control_frame_digest.clone(),
        export_tap
            .profile_digest
            .clone()
            .expect("tool profile digest"),
        Some("grant-registry".to_string()),
    );
    let computed_receipt_digest = receipt_digest(&valid_receipt);
    assert_eq!(
        valid_receipt
            .receipt_digest
            .as_ref()
            .expect("receipt digest"),
        &digest_to_proto(computed_receipt_digest)
    );
    assert_eq!(
        valid_receipt.action_digest.as_ref().expect("action digest"),
        &digest_to_proto(action_digest)
    );
    assert_eq!(
        valid_receipt
            .decision_digest
            .as_ref()
            .expect("decision digest"),
        &digest_to_proto(decision.decision_digest)
    );
    assert_eq!(
        valid_receipt
            .profile_digest
            .as_ref()
            .expect("profile digest"),
        &control_frame_digest
    );
    assert_eq!(
        valid_receipt
            .tool_profile_digest
            .as_ref()
            .expect("tool profile digest"),
        export_tap.profile_digest.as_ref().expect("export digest")
    );
    verify_pvgs_receipt(&valid_receipt, &pvgs.key_epoch_store).expect("receipt verifies");
    base_ctx.pvgs_receipt = Some(valid_receipt.clone());

    let result = gate.handle_action_spec("session", "step", action.clone(), base_ctx);
    assert!(
        matches!(result, GateResult::Executed { .. }),
        "unexpected gate result: {:?}",
        result
    );
    assert_eq!(adapter.count(), 1);

    let bad_signature = {
        let mut receipt = valid_receipt.clone();
        if let Some(signer) = receipt.signer.as_mut() {
            signer.signature[0] ^= 0xFF;
        }
        receipt
    };

    let mismatched_tool_profile = {
        let mut receipt = valid_receipt.clone();
        receipt.tool_profile_digest = Some(ucf::v1::Digest32 {
            value: vec![9u8; 32],
        });
        receipt
    };

    let mismatched_profile = {
        let mut receipt = valid_receipt.clone();
        receipt.profile_digest = Some(ucf::v1::Digest32 {
            value: vec![8u8; 32],
        });
        receipt
    };

    let export_locked = locked_control_frame();

    let denied_cases = vec![
        gate_context(&control_frame, None, pvgs.pvgs.get_current_ruleset_digest()),
        gate_context(
            &control_frame,
            Some(bad_signature),
            pvgs.pvgs.get_current_ruleset_digest(),
        ),
        gate_context(
            &control_frame,
            Some(mismatched_tool_profile),
            pvgs.pvgs.get_current_ruleset_digest(),
        ),
        gate_context(
            &control_frame,
            Some(mismatched_profile),
            pvgs.pvgs.get_current_ruleset_digest(),
        ),
        gate_context(
            &export_locked,
            Some(valid_receipt),
            pvgs.pvgs.get_current_ruleset_digest(),
        ),
    ];

    for (idx, ctx) in denied_cases.into_iter().enumerate() {
        let result =
            gate.handle_action_spec("session", &format!("deny-{idx}"), action.clone(), ctx);
        assert!(matches!(result, GateResult::Denied { .. }));
    }

    assert_eq!(adapter.count(), 1);
}

fn gate_with_components(
    adapter: Box<dyn ToolAdapter>,
    registry: Arc<ToolRegistry>,
    receipt_store: Arc<PvgsKeyEpochStore>,
) -> Gate {
    let aggregator = Arc::new(Mutex::new(
        WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
    ));
    let orchestrator = Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
        aggregator.clone(),
    )));
    Gate {
        policy: PolicyEngine::new(),
        adapter,
        aggregator: aggregator.clone(),
        orchestrator,
        control_store: control_store_with_frame(export_control_frame()),
        receipt_store,
        registry,
        pvgs_client: Arc::new(Mutex::new(
            Box::new(MockPvgsClient::default()) as Box<dyn PvgsClientReader>
        )),
        integrity_issues: Arc::new(Mutex::new(0)),
        decision_log: Arc::new(Mutex::new(DecisionLogStore::default())),
        query_decisions: Arc::new(Mutex::new(gem::QueryDecisionMap::default())),
        rpp_cache: Arc::new(Mutex::new(gem::RppMetaCache::default())),
    }
}

fn control_store_with_frame(
    frame: ucf::v1::ControlFrame,
) -> Arc<Mutex<control::ControlFrameStore>> {
    let store = Arc::new(Mutex::new(control::ControlFrameStore::default()));
    {
        let mut guard = store.lock().expect("control frame store lock");
        guard.update(frame).expect("valid control frame");
    }
    store
}

fn gate_context(
    control_frame: &ucf::v1::ControlFrame,
    pvgs_receipt: Option<ucf::v1::PvgsReceipt>,
    ruleset_digest: Option<[u8; 32]>,
) -> GateContext {
    GateContext {
        integrity_state: "OK".to_string(),
        charter_version_digest: "charter-v1".to_string(),
        allowed_tools: vec!["mock.export".to_string()],
        control_frame: Some(control_frame.clone()),
        pvgs_receipt,
        approval_grant_id: None,
        pev: None,
        pev_digest: None,
        ruleset_digest,
        session_sealed: false,
        session_unlock_permit: false,
    }
}

fn policy_decision_for(
    gate: &Gate,
    action: &ucf::v1::ActionSpec,
    ctx: &GateContext,
    session_id: &str,
    step_id: &str,
) -> PolicyDecisionRecord {
    let policy_ctx = PolicyContext {
        integrity_state: ctx.integrity_state.clone(),
        charter_version_digest: ctx.charter_version_digest.clone(),
        allowed_tools: ctx.allowed_tools.clone(),
        control_frame: ctx
            .control_frame
            .clone()
            .unwrap_or_else(export_control_frame),
        tool_action_type: ucf::v1::ToolActionType::Export,
        pev: ctx.pev.clone(),
        pev_digest: ctx.pev_digest,
        ruleset_digest: ctx.ruleset_digest,
        session_sealed: ctx.session_sealed,
        unlock_present: ctx.session_unlock_permit,
    };

    gate.policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: format!("{session_id}:{step_id}"),
        query: ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        },
        context: policy_ctx,
    })
}

fn action_spec_digest(action: &ucf::v1::ActionSpec) -> [u8; 32] {
    let canonical = canonical_bytes(action);
    digest32("UCF:HASH:ACTION_SPEC", "ActionSpec", "v1", &canonical)
}

fn digest_to_proto(bytes: [u8; 32]) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: bytes.to_vec(),
    }
}

fn export_control_frame() -> ucf::v1::ControlFrame {
    make_control_frame(
        ucf::v1::ControlFrameProfile::M0Baseline,
        None,
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        },
    )
    .0
}

fn locked_control_frame() -> ucf::v1::ControlFrame {
    make_control_frame(
        ucf::v1::ControlFrameProfile::M0Baseline,
        Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: true,
            ovl_novelty_lock: false,
        }),
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: false,
            enable_write: true,
            enable_execute: true,
        },
    )
    .0
}
