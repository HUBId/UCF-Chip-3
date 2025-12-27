#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use ckm_orchestrator::CkmOrchestrator;
use control::ControlFrameStore;
use frames::{FramesConfig, WindowEngine};
use gem::{DecisionLogStore, Gate, GateContext, GateResult, QueryDecisionMap};
use pbm::PolicyEngine;
use pvgs_client::{
    MockPvgsClient, PvgsClient, PvgsClientError, PvgsHead, PvgsReader, Scorecard, SpotCheckReport,
};
use tam::ToolAdapter;
use trm::ToolRegistry;
use ucf_protocol::ucf;
use ucf_test_utils::make_control_frame;

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
        self.inner
            .lock()
            .expect("pvgs lock")
            .try_commit_next_meso()
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
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_scorecard_global()
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
        self.inner.lock().expect("pvgs lock").get_latest_cbv_digest()
    }

    fn get_latest_trace_run(
        &mut self,
    ) -> Result<Option<pvgs_client::TraceRunSummary>, PvgsClientError> {
        self.inner
            .lock()
            .expect("pvgs lock")
            .get_latest_trace_run()
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

fn build_gate(pvgs_client: Arc<Mutex<MockPvgsClient>>, registry: Arc<ToolRegistry>) -> Gate {
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
    let mut control_store = ControlFrameStore::new();
    control_store
        .update(control_frame)
        .expect("control frame");

    let aggregator = Arc::new(Mutex::new(
        WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
    ));

    Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(NoopAdapter::default()),
        aggregator: aggregator.clone(),
        orchestrator: Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
            aggregator,
        ))),
        control_store: Arc::new(Mutex::new(control_store)),
        receipt_store: Arc::new(pvgs_verify::PvgsKeyEpochStore::new()),
        registry,
        pvgs_client: Arc::new(Mutex::new(Box::new(SharedMockPvgsClient::new(
            pvgs_client,
        )))),
        integrity_issues: Arc::new(Mutex::new(0)),
        decision_log: Arc::new(Mutex::new(DecisionLogStore::default())),
        query_decisions: Arc::new(Mutex::new(QueryDecisionMap::default())),
    }
}

#[test]
fn pvgs_smoke_builds_decision_and_action_records() {
    let pvgs_inner = Arc::new(Mutex::new(MockPvgsClient::default()));
    let registry = Arc::new(trm::registry_fixture());
    let gate = build_gate(pvgs_inner.clone(), registry.clone());

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
    client
        .commit_tool_registry(trc)
        .expect("tool registry");
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

    assert!(matches!(
        gate.handle_action_spec("s1", "step-1", action.clone(), ctx.clone()),
        GateResult::Executed { .. }
    ));
    assert!(matches!(
        gate.handle_action_spec("s1", "step-2", action.clone(), ctx),
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
    assert_eq!(decision_ids, vec!["policy_query", "policy_decision"]);

    let action_ids: Vec<_> = action_a
        .related_refs
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(action_ids, vec!["policy_query", "decision"]);

    assert_eq!(decision_a.related_refs, decision_b.related_refs);
    assert_eq!(action_a.related_refs, action_b.related_refs);
}
