#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use ckm_orchestrator::CkmOrchestrator;
use control::ControlFrameStore;
use ed25519_dalek::SigningKey;
use frames::{FramesConfig, WindowEngine};
use gem::{DecisionLogStore, Gate, GateContext, GateResult};
use pbm::{PolicyContext, PolicyDecisionRecord, PolicyEvaluationRequest};
use pvgs_client::LocalPvgsClient;
use pvgs_verify::PvgsKeyEpochStore;
use tam::ToolAdapter;
use trm::ToolRegistry;
use ucf_protocol::{canonical_bytes, digest32, ucf};
use ucf_test_utils::{
    make_control_frame, make_pvgs_key_epoch, make_pvgs_receipt_accepted, make_tool_action_profile,
};

#[derive(Clone, Default)]
struct CountingAdapter {
    calls: Arc<Mutex<usize>>,
}

impl CountingAdapter {
    fn count(&self) -> usize {
        *self.calls.lock().expect("adapter count lock")
    }
}

impl ToolAdapter for CountingAdapter {
    fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket {
        let mut guard = self.calls.lock().expect("adapter count lock");
        *guard += 1;
        ucf::v1::OutcomePacket {
            outcome_id: format!("{}:outcome", req.request_id),
            request_id: req.request_id,
            status: ucf::v1::OutcomeStatus::Success.into(),
            payload: b"ok:export".to_vec(),
            payload_digest: None,
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        }
    }
}

struct Harness {
    gate: Gate,
    adapter: CountingAdapter,
    aggregator: Arc<Mutex<WindowEngine>>,
    control_store: Arc<Mutex<ControlFrameStore>>,
    registry: Arc<ToolRegistry>,
    control_digest: ucf::v1::Digest32,
    action: ucf::v1::ActionSpec,
    action_digest: [u8; 32],
    signing_key: SigningKey,
    key_epoch: ucf::v1::PvgsKeyEpoch,
}

impl Harness {
    fn new(enable_export: bool, ingest_key_epoch: bool) -> Self {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let key_epoch = make_pvgs_key_epoch(1, &signing_key);
        let mut receipt_store = PvgsKeyEpochStore::new();
        if ingest_key_epoch {
            receipt_store
                .ingest_key_epoch(key_epoch.clone())
                .expect("ingest key epoch");
        }

        let (control_frame, control_digest) = make_control_frame(
            ucf::v1::ControlFrameProfile::M0Baseline,
            None,
            ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export,
                enable_write: true,
                enable_execute: true,
            },
        );

        let mut control_store = ControlFrameStore::new();
        control_store
            .update(control_frame.clone())
            .expect("valid control frame");
        let control_store = Arc::new(Mutex::new(control_store));

        let mut registry = ToolRegistry::new();
        let tap =
            make_tool_action_profile("mock.export", "render", ucf::v1::ToolActionType::Export);
        registry.insert(tap).expect("valid tool profile");
        let registry = Arc::new(registry);

        let adapter = CountingAdapter::default();
        let aggregator = Arc::new(Mutex::new(
            WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
        ));
        let gate = Gate {
            policy: pbm::PolicyEngine::new(),
            adapter: Box::new(adapter.clone()),
            aggregator: aggregator.clone(),
            orchestrator: Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
                aggregator.clone(),
            ))),
            control_store: control_store.clone(),
            receipt_store: Arc::new(receipt_store),
            registry: registry.clone(),
            pvgs_client: Arc::new(Mutex::new(
                Box::new(LocalPvgsClient::default()) as Box<dyn pvgs_client::PvgsClientReader>
            )),
            integrity_issues: Arc::new(Mutex::new(0)),
            decision_log: Arc::new(Mutex::new(DecisionLogStore::default())),
            query_decisions: Arc::new(Mutex::new(gem::QueryDecisionMap::default())),
            rpp_cache: Arc::new(Mutex::new(gem::RppMetaCache::default())),
        };

        let action = ucf::v1::ActionSpec {
            verb: "mock.export/render".to_string(),
            resources: vec!["demo".to_string()],
        };
        let action_digest = compute_action_digest(&action);

        Self {
            gate,
            adapter,
            aggregator,
            control_store,
            registry,
            control_digest,
            action,
            action_digest,
            signing_key,
            key_epoch,
        }
    }

    fn with_control_frame(
        &mut self,
        control_frame: ucf::v1::ControlFrame,
        digest: ucf::v1::Digest32,
    ) {
        self.control_store
            .lock()
            .expect("control store lock")
            .update(control_frame)
            .expect("updated control frame");
        self.control_digest = digest;
    }

    fn ctx(&self) -> GateContext {
        GateContext {
            integrity_state: "OK".to_string(),
            charter_version_digest: "charter-beta".to_string(),
            allowed_tools: vec!["mock.export".to_string()],
            control_frame: None,
            pvgs_receipt: None,
            approval_grant_id: None,
            pev: None,
            pev_digest: None,
            ruleset_digest: None,
            session_sealed: false,
            session_unlock_permit: false,
        }
    }

    fn decision_for(&self, session: &str, step: &str) -> PolicyDecisionRecord {
        let control_frame = self
            .control_store
            .lock()
            .expect("control frame lock")
            .current()
            .cloned()
            .expect("control frame present");

        let base_ctx = self.ctx();

        let context = PolicyContext {
            integrity_state: base_ctx.integrity_state,
            charter_version_digest: base_ctx.charter_version_digest,
            control_frame,
            allowed_tools: base_ctx.allowed_tools,
            tool_action_type: ucf::v1::ToolActionType::Export,
            pev: base_ctx.pev,
            pev_digest: base_ctx.pev_digest,
            ruleset_digest: base_ctx.ruleset_digest,
            session_sealed: base_ctx.session_sealed,
            unlock_present: base_ctx.session_unlock_permit,
        };

        let query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(self.action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        self.gate
            .policy
            .decide_with_context(PolicyEvaluationRequest {
                decision_id: format!("{session}:{step}"),
                query,
                context,
            })
    }

    fn tool_profile_digest(&self) -> ucf::v1::Digest32 {
        self.registry
            .tool_profile_digest("mock.export", "render")
            .expect("profile digest")
    }

    fn valid_receipt(&self, session: &str, step: &str) -> ucf::v1::PvgsReceipt {
        let decision = self.decision_for(session, step);
        make_pvgs_receipt_accepted(
            self.action_digest,
            decision.decision_digest,
            self.control_digest.clone(),
            self.tool_profile_digest(),
            &self.signing_key,
            &self.key_epoch,
            None,
        )
    }
}

fn compute_action_digest(action: &ucf::v1::ActionSpec) -> [u8; 32] {
    let canonical = canonical_bytes(action);
    digest32("UCF:HASH:ACTION_SPEC", "ActionSpec", "v1", &canonical)
}

#[test]
fn success_path_executes_with_valid_receipt() {
    let harness = Harness::new(true, true);
    let mut ctx = harness.ctx();
    ctx.pvgs_receipt = Some(harness.valid_receipt("sess", "step"));

    let result = harness
        .gate
        .handle_action_spec("sess", "step", harness.action.clone(), ctx);

    match result {
        GateResult::Executed { decision, outcome } => {
            assert_eq!(decision.decision.reason_codes.unwrap().codes.len(), 1);
            assert_eq!(
                ucf::v1::OutcomeStatus::try_from(outcome.status),
                Ok(ucf::v1::OutcomeStatus::Success)
            );
        }
        other => panic!("expected execution, got {other:?}"),
    }

    assert_eq!(harness.adapter.count(), 1, "adapter should execute once");
}

#[test]
fn missing_receipt_denies_and_blocks_adapter() {
    let harness = Harness::new(true, true);
    let ctx = harness.ctx();

    let result = harness
        .gate
        .handle_action_spec("sess", "missing", harness.action.clone(), ctx);

    match result {
        GateResult::Denied { decision } => {
            assert_eq!(
                decision.decision.reason_codes.unwrap().codes,
                vec!["RC.GE.EXEC.DISPATCH_BLOCKED".to_string()]
            );
        }
        other => panic!("expected denial, got {other:?}"),
    }

    assert_eq!(harness.adapter.count(), 0, "adapter must not run");
}

#[test]
fn invalid_signature_denies_execution() {
    let harness = Harness::new(true, true);
    let mut ctx = harness.ctx();
    let mut receipt = harness.valid_receipt("sess", "bad-sig");
    receipt
        .signer
        .as_mut()
        .expect("signature present")
        .signature[0] ^= 0xFF;
    ctx.pvgs_receipt = Some(receipt);

    let result = harness
        .gate
        .handle_action_spec("sess", "bad-sig", harness.action.clone(), ctx);

    assert!(matches!(result, GateResult::Denied { .. }));
    assert_eq!(harness.adapter.count(), 0, "adapter must stay blocked");
}

#[test]
fn tool_profile_digest_mismatch_blocks_execution() {
    let harness = Harness::new(true, true);
    let mut ctx = harness.ctx();
    let decision = harness.decision_for("sess", "wrong-tap");
    let mismatched_tool_digest = ucf::v1::Digest32 {
        value: vec![8u8; 32],
    };
    let receipt = make_pvgs_receipt_accepted(
        harness.action_digest,
        decision.decision_digest,
        harness.control_digest.clone(),
        mismatched_tool_digest,
        &harness.signing_key,
        &harness.key_epoch,
        None,
    );
    ctx.pvgs_receipt = Some(receipt);

    let result = harness
        .gate
        .handle_action_spec("sess", "wrong-tap", harness.action.clone(), ctx);

    assert!(matches!(result, GateResult::Denied { .. }));
    assert_eq!(harness.adapter.count(), 0, "adapter must not run");
}

#[test]
fn control_frame_digest_mismatch_denies() {
    let harness = Harness::new(true, true);
    let mut ctx = harness.ctx();
    let decision = harness.decision_for("sess", "cf-mismatch");
    let (_, alt_digest) = make_control_frame(
        ucf::v1::ControlFrameProfile::M1Restricted,
        None,
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: false,
            enable_execute: false,
        },
    );
    let receipt = make_pvgs_receipt_accepted(
        harness.action_digest,
        decision.decision_digest,
        alt_digest,
        harness.tool_profile_digest(),
        &harness.signing_key,
        &harness.key_epoch,
        None,
    );
    ctx.pvgs_receipt = Some(receipt);

    let result =
        harness
            .gate
            .handle_action_spec("sess", "cf-mismatch", harness.action.clone(), ctx);

    assert!(matches!(result, GateResult::Denied { .. }));
    assert_eq!(harness.adapter.count(), 0, "adapter must not run");
}

#[test]
fn export_disabled_control_frame_stops_action() {
    let mut harness = Harness::new(true, true);
    let (locked_frame, digest) = make_control_frame(
        ucf::v1::ControlFrameProfile::M0Baseline,
        None,
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: false,
            enable_write: true,
            enable_execute: true,
        },
    );
    harness.with_control_frame(locked_frame, digest.clone());

    let mut ctx = harness.ctx();
    let decision = harness.decision_for("sess", "export-locked");
    let receipt = make_pvgs_receipt_accepted(
        harness.action_digest,
        decision.decision_digest,
        digest,
        harness.tool_profile_digest(),
        &harness.signing_key,
        &harness.key_epoch,
        None,
    );
    ctx.pvgs_receipt = Some(receipt);

    let result =
        harness
            .gate
            .handle_action_spec("sess", "export-locked", harness.action.clone(), ctx);

    match result {
        GateResult::Denied { decision } => {
            assert!(decision
                .decision
                .reason_codes
                .unwrap()
                .codes
                .contains(&"RC.CD.DLP.EXPORT_BLOCKED".to_string()));
        }
        other => panic!("expected deny, got {other:?}"),
    }

    assert_eq!(harness.adapter.count(), 0, "adapter blocked by policy");
}

#[test]
fn missing_key_epoch_fails_closed() {
    let harness = Harness::new(true, false);
    let mut ctx = harness.ctx();
    ctx.pvgs_receipt = Some(harness.valid_receipt("sess", "unknown-key"));

    let result =
        harness
            .gate
            .handle_action_spec("sess", "unknown-key", harness.action.clone(), ctx);

    match result {
        GateResult::Denied { decision } => {
            assert_eq!(
                decision.decision.reason_codes.unwrap().codes,
                vec!["RC.RE.INTEGRITY.DEGRADED".to_string()]
            );
        }
        other => panic!("expected receipt gate denial, got {other:?}"),
    }

    assert_eq!(harness.adapter.count(), 0, "adapter must not run");
}

#[test]
fn receipt_stats_capture_missing_and_invalid_counts() {
    let harness = Harness::new(true, true);
    let ctx = harness.ctx();

    for idx in 0..2 {
        let _ = harness.gate.handle_action_spec(
            "sess",
            &format!("missing-{idx}"),
            harness.action.clone(),
            ctx.clone(),
        );
    }

    let mut ctx_with_receipt = harness.ctx();
    let mut invalid_receipt = harness.valid_receipt("sess", "invalid");
    invalid_receipt
        .signer
        .as_mut()
        .expect("signature present")
        .signature[1] ^= 0xAA;
    ctx_with_receipt.pvgs_receipt = Some(invalid_receipt);

    let _ = harness.gate.handle_action_spec(
        "sess",
        "invalid",
        harness.action.clone(),
        ctx_with_receipt,
    );

    let frames = harness.aggregator.lock().expect("agg lock").force_flush();
    let receipt_stats = frames
        .first()
        .and_then(|f| f.receipt_stats.as_ref())
        .cloned()
        .expect("receipt stats present");

    assert_eq!(receipt_stats.receipt_missing_count, 2);
    assert_eq!(receipt_stats.receipt_invalid_count, 1);
    assert!(receipt_stats
        .top_reason_codes
        .iter()
        .any(|rc| rc.code == "RC.GE.EXEC.DISPATCH_BLOCKED"));
    assert_eq!(harness.adapter.count(), 0, "adapter must not run");
}
