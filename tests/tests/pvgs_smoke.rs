#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use ckm_orchestrator::CkmOrchestrator;
use control::ControlFrameStore;
use ed25519_dalek::SigningKey;
use frames::{FramesConfig, WindowEngine};
use gem::{DecisionLogStore, Gate, GateContext, GateResult, QueryDecisionMap};
use pbm::{PolicyContext, PolicyEngine, PolicyEvaluationRequest};
use pvgs_client::{
    MockPvgsClient, PvgsClient, PvgsClientError, PvgsHead, PvgsReader, Scorecard, SpotCheckReport,
};
use tam::ToolAdapter;
use trm::ToolRegistry;
use ucf_protocol::{canonical_bytes, digest32, ucf};
use ucf_test_utils::{make_control_frame, make_pvgs_key_epoch, make_pvgs_receipt_accepted};

#[derive(Clone)]
struct SharedMockPvgsClient {
    inner: Arc<Mutex<MockPvgsClient>>,
}

impl SharedMockPvgsClient {
    fn new(inner: Arc<Mutex<MockPvgsClient>>) -> Self {
        Self { inner }
    }
}

impl PvgsClient for SharedMockPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_experience_record(record)
    }

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_dlp_decision(dlp)
    }

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_tool_registry(trc)
    }

    fn commit_tool_onboarding_event(
        &mut self,
        event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_tool_onboarding_event(event)
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_micro_milestone(micro)
    }

    fn commit_consistency_feedback(
        &mut self,
        feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .commit_consistency_feedback(feedback)
    }

    fn try_commit_next_micro(&mut self, session_id: &str) -> Result<bool, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .try_commit_next_micro(session_id)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError> {
        self.inner.lock().expect("pvgs lock").try_commit_next_meso()
    }

    fn try_commit_next_macro(
        &mut self,
        consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .try_commit_next_macro(consistency_digest)
    }

    fn get_pending_replay_plans(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_pending_replay_plans(session_id)
    }

    fn get_pvgs_head(&self) -> PvgsHead {
        self.inner.lock().expect("pvgs lock").get_pvgs_head()
    }

    fn get_scorecard_global(&mut self) -> Result<Scorecard, PvgsClientError> {
        self.inner.lock().expect("pvgs lock").get_scorecard_global()
    }

    fn get_scorecard_session(&mut self, session_id: &str) -> Result<Scorecard, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_scorecard_session(session_id)
    }

    fn run_spotcheck(&mut self, session_id: &str) -> Result<SpotCheckReport, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .run_spotcheck(session_id)
    }
}

impl PvgsReader for SharedMockPvgsClient {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        self.inner.lock().expect("pvgs lock").get_latest_pev()
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_pev_digest()
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_current_ruleset_digest()
    }

    fn is_session_sealed(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .is_session_sealed(session_id)
    }

    fn has_unlock_permit(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .has_unlock_permit(session_id)
    }

    fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_session_seal_digest(session_id)
    }

    fn get_unlock_permit_digest(
        &self,
        session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_unlock_permit_digest(session_id)
    }

    fn get_latest_cbv_digest(&self) -> Option<pvgs_client::CbvDigest> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_cbv_digest()
    }

    fn get_latest_trace_run(
        &mut self,
    ) -> Result<Option<pvgs_client::TraceRunSummary>, PvgsClientError> {
        self.inner.lock().expect("pvgs lock").get_latest_trace_run()
    }

    fn get_latest_rpp_head_meta(
        &mut self,
    ) -> Result<Option<pvgs_client::RppHeadMeta>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_rpp_head_meta()
    }

    fn get_rpp_head_meta(
        &mut self,
        head_id: u64,
    ) -> Result<Option<pvgs_client::RppHeadMeta>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_rpp_head_meta(head_id)
    }

    fn get_pending_replay_plans(
        &self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_pending_replay_plans(session_id)
    }
}

#[derive(Clone, Default)]
struct NoopAdapter;

impl ToolAdapter for NoopAdapter {
    fn execute(&self, req: ucf::v1::ExecutionRequest) -> ucf::v1::OutcomePacket {
        ucf::v1::OutcomePacket {
            outcome_id: format!("{}:outcome", req.request_id),
            request_id: req.request_id,
            status: ucf::v1::OutcomeStatus::Success.into(),
            payload: b"ok".to_vec(),
            payload_digest: None,
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        }
    }
}

fn build_gate(
    pvgs_client: Arc<Mutex<MockPvgsClient>>,
    registry: Arc<ToolRegistry>,
    control_frame: ucf::v1::ControlFrame,
    receipt_store: pvgs_verify::PvgsKeyEpochStore,
) -> Gate {
    let mut control_store = ControlFrameStore::new();
    control_store.update(control_frame).expect("control frame");

    let aggregator = Arc::new(Mutex::new(
        WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
    ));

    Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(NoopAdapter),
        aggregator: aggregator.clone(),
        orchestrator: Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(aggregator))),
        control_store: Arc::new(Mutex::new(control_store)),
        receipt_store: Arc::new(receipt_store),
        registry,
        pvgs_client: Arc::new(Mutex::new(Box::new(SharedMockPvgsClient::new(pvgs_client)))),
        integrity_issues: Arc::new(Mutex::new(0)),
        decision_log: Arc::new(Mutex::new(DecisionLogStore::default())),
        query_decisions: Arc::new(Mutex::new(QueryDecisionMap::default())),
        rpp_cache: Arc::new(Mutex::new(gem::RppMetaCache::default())),
    }
}

#[test]
fn pvgs_smoke_builds_decision_and_action_records() {
    let pvgs_inner = Arc::new(Mutex::new(MockPvgsClient::default()));
    let registry = Arc::new(trm::registry_fixture());
    let (control_frame, control_digest) = make_control_frame(
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
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let key_epoch = make_pvgs_key_epoch(1, &signing_key);
    let mut receipt_store = pvgs_verify::PvgsKeyEpochStore::new();
    receipt_store
        .ingest_key_epoch(key_epoch.clone())
        .expect("ingest key epoch");

    let gate = build_gate(
        pvgs_inner.clone(),
        registry.clone(),
        control_frame.clone(),
        receipt_store,
    );

    let mut client = pvgs_inner.lock().expect("pvgs lock");
    client
        .commit_tool_onboarding_event(ucf::v1::ToolOnboardingEvent {
            event_id: "tool-onboarding-1".to_string(),
            event_digest: None,
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: vec!["TO6".to_string()],
            }),
        })
        .expect("tool onboarding");
    let trc = registry.build_registry_container("registry", "v1", 123);
    client.commit_tool_registry(trc).expect("tool registry");
    drop(client);

    let ctx = GateContext {
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
    };

    let action = ucf::v1::ActionSpec {
        verb: "mock.export/render".to_string(),
        resources: vec!["dataset".to_string()],
    };

    let action_digest = digest32(
        "UCF:HASH:ACTION_SPEC",
        "ActionSpec",
        "v1",
        &canonical_bytes(&action),
    );
    let tool_profile_digest = registry
        .tool_profile_digest("mock.export", "render")
        .expect("tool profile digest");

    let policy_context = PolicyContext {
        integrity_state: ctx.integrity_state.clone(),
        charter_version_digest: ctx.charter_version_digest.clone(),
        allowed_tools: ctx.allowed_tools.clone(),
        control_frame: control_frame.clone(),
        tool_action_type: ucf::v1::ToolActionType::Export,
        pev: None,
        pev_digest: None,
        ruleset_digest: None,
        session_sealed: false,
        unlock_present: false,
    };

    let decision_record = gate.policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "s1:step-1".to_string(),
        query: ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        },
        context: policy_context.clone(),
    });
    let receipt = make_pvgs_receipt_accepted(
        action_digest,
        decision_record.decision_digest,
        control_digest.clone(),
        tool_profile_digest.clone(),
        &signing_key,
        &key_epoch,
        None,
    );
    let ctx_with_receipt = GateContext {
        pvgs_receipt: Some(receipt),
        ..ctx.clone()
    };

    let decision_record_b = gate.policy.decide_with_context(PolicyEvaluationRequest {
        decision_id: "s1:step-2".to_string(),
        query: ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(action.clone()),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        },
        context: policy_context,
    });
    let receipt_b = make_pvgs_receipt_accepted(
        action_digest,
        decision_record_b.decision_digest,
        control_digest,
        tool_profile_digest,
        &signing_key,
        &key_epoch,
        None,
    );
    let ctx_with_receipt_b = GateContext {
        pvgs_receipt: Some(receipt_b),
        ..ctx
    };

    assert!(matches!(
        gate.handle_action_spec("s1", "step-1", action.clone(), ctx_with_receipt),
        GateResult::Executed { .. }
    ));
    assert!(matches!(
        gate.handle_action_spec("s1", "step-2", action.clone(), ctx_with_receipt_b),
        GateResult::Executed { .. }
    ));

    let committed = &pvgs_inner
        .lock()
        .expect("pvgs lock")
        .local
        .committed_records;
    assert_eq!(committed.len(), 4);

    let decision_a = &committed[0];
    let action_a = &committed[1];
    let decision_b = &committed[2];
    let action_b = &committed[3];

    assert_eq!(
        ucf::v1::RecordType::try_from(decision_a.record_type),
        Ok(ucf::v1::RecordType::Decision)
    );
    assert_eq!(
        ucf::v1::RecordType::try_from(action_a.record_type),
        Ok(ucf::v1::RecordType::ActionExec)
    );

    let decision_ids: Vec<_> = decision_a
        .related_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(decision_ids[0..2], ["policy_query", "policy_decision"]);
    let decision_rpp_ids: Vec<_> = decision_a
        .related_refs
        .iter()
        .filter(|r| r.id.starts_with("rpp:"))
        .map(|r| r.id.as_str())
        .collect();
    if !decision_rpp_ids.is_empty() {
        assert_eq!(
            decision_rpp_ids,
            vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]
        );
    }

    let decision_ids_b: Vec<_> = decision_b
        .related_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(decision_ids_b, decision_ids);

    let action_ids: Vec<_> = action_a
        .related_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(action_ids[0..2], ["policy_query", "decision"]);
    let action_rpp_ids: Vec<_> = action_a
        .related_refs
        .iter()
        .filter(|r| r.id.starts_with("rpp:"))
        .map(|r| r.id.as_str())
        .collect();
    if !action_rpp_ids.is_empty() {
        assert_eq!(
            action_rpp_ids,
            vec!["rpp:prev_acc", "rpp:acc", "rpp:new_root"]
        );
    }

    let action_ids_b: Vec<_> = action_b
        .related_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(action_ids_b, action_ids);
}
