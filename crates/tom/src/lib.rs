#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use pvgs_client::PvgsClient;
use pvgs_client::PvgsClientReader;
use suspension::{SuspensionResult, SuspensionState};
use thiserror::Error;
use trm::ToolRegistry;
use ucf_protocol::ucf;

// TODO: Model onboarding state transitions with ucf-protocol types.

#[derive(Debug, Error)]
pub enum OnboardingError {
    #[error("invalid transition from {0}")]
    InvalidTransition(String),
    #[error("tool registry commit failed: {0}")]
    RegistryCommitFailed(String),
    #[error("tool registry commit rejected: {reason_codes:?}")]
    RegistryCommitRejected { reason_codes: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingState {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingStage {
    To5Active,
}

const RC_GV_RULESET_CHANGED: &str = "RC.GV.RULESET.CHANGED";
const RC_GV_TOOL_REGISTRY_DEGRADED: &str = "RC.GV.TOOL_REGISTRY.INTEGRITY_DEGRADED";

pub trait OnboardingStateMachine: Send + Sync {
    fn advance(&self, current: OnboardingState) -> Result<OnboardingState, OnboardingError>;
}

pub trait IntegritySignal: Send + Sync {
    fn emit(&self, reason_code: &str);
}

pub struct DefaultOnboarding;

impl OnboardingStateMachine for DefaultOnboarding {
    fn advance(&self, current: OnboardingState) -> Result<OnboardingState, OnboardingError> {
        match current {
            OnboardingState::Pending => Ok(OnboardingState::Approved),
            OnboardingState::Approved | OnboardingState::Rejected => {
                Err(OnboardingError::InvalidTransition(format!("{current:?}")))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum SuspensionError {
    #[error("tool registry commit failed: {0}")]
    RegistryCommitFailed(String),
    #[error("tool registry commit rejected: {reason_codes:?}")]
    RegistryCommitRejected { reason_codes: Vec<String> },
}

pub struct ToolSuspensionManager<C: PvgsClientReader, S: IntegritySignal> {
    registry: Arc<Mutex<ToolRegistry>>,
    state: SuspensionState,
    pvgs_client: C,
    signal_sink: S,
    registry_id: String,
    base_registry_version: String,
    registry_version_counter: u64,
    ruleset_digest: Option<[u8; 32]>,
    integrity_degraded: bool,
}

impl<C: PvgsClientReader, S: IntegritySignal> ToolSuspensionManager<C, S> {
    pub fn new(
        registry: Arc<Mutex<ToolRegistry>>,
        pvgs_client: C,
        signal_sink: S,
        registry_id: impl Into<String>,
        base_registry_version: impl Into<String>,
    ) -> Self {
        let ruleset_digest = pvgs_client.get_current_ruleset_digest();
        Self {
            registry,
            state: SuspensionState::new(),
            pvgs_client,
            signal_sink,
            registry_id: registry_id.into(),
            base_registry_version: base_registry_version.into(),
            registry_version_counter: 0,
            ruleset_digest,
            integrity_degraded: false,
        }
    }

    pub fn apply_suspensions(
        &mut self,
        recs: Vec<suspension::SuspendRecommendation>,
        now_ms: u64,
    ) -> Result<Vec<SuspensionResult>, SuspensionError> {
        let mut applied = false;
        let results = self
            .state
            .apply_recommendations_with_hook(recs, now_ms, |result| {
                if result.applied {
                    applied = true;
                    if let Ok(mut guard) = self.registry.lock() {
                        guard.suspend(&result.tool_id, &result.action_id);
                    }
                }
            });

        if !applied {
            return Ok(results);
        }

        self.registry_version_counter = self.registry_version_counter.saturating_add(1);
        let registry_version = format!(
            "{}-susp{}",
            self.base_registry_version, self.registry_version_counter
        );

        let trc = self
            .registry
            .lock()
            .expect("registry lock")
            .build_registry_container(&self.registry_id, &registry_version, now_ms);
        let receipt = self
            .pvgs_client
            .commit_tool_registry(trc)
            .map_err(|err| SuspensionError::RegistryCommitFailed(err.to_string()))?;

        match ucf::v1::ReceiptStatus::try_from(receipt.status) {
            Ok(ucf::v1::ReceiptStatus::Accepted) => {
                self.integrity_degraded = false;
                let updated_ruleset = self.pvgs_client.get_current_ruleset_digest();
                if updated_ruleset != self.ruleset_digest {
                    self.signal_sink.emit(RC_GV_RULESET_CHANGED);
                    self.ruleset_digest = updated_ruleset;
                } else {
                    self.ruleset_digest = updated_ruleset;
                }
                self.signal_sink.emit("RC.GV.TOOL_REGISTRY.UPDATED");
                Ok(results)
            }
            _ => {
                self.integrity_degraded = true;
                self.signal_sink.emit(RC_GV_TOOL_REGISTRY_DEGRADED);
                Err(SuspensionError::RegistryCommitRejected {
                    reason_codes: receipt.reject_reason_codes,
                })
            }
        }
    }

    pub fn ruleset_digest(&self) -> Option<[u8; 32]> {
        self.ruleset_digest
    }

    pub fn integrity_degraded(&self) -> bool {
        self.integrity_degraded
    }
}

pub struct ToolOnboarding<C: PvgsClient, S: IntegritySignal> {
    registry: Arc<ToolRegistry>,
    pvgs_client: C,
    signal_sink: S,
}

impl<C: PvgsClient, S: IntegritySignal> ToolOnboarding<C, S> {
    pub fn new(registry: Arc<ToolRegistry>, pvgs_client: C, signal_sink: S) -> Self {
        Self {
            registry,
            pvgs_client,
            signal_sink,
        }
    }

    pub fn pvgs_client(&self) -> &C {
        &self.pvgs_client
    }

    pub fn signal_sink(&self) -> &S {
        &self.signal_sink
    }

    pub fn handle_stage(
        &mut self,
        stage: OnboardingStage,
        registry_id: &str,
        registry_version: &str,
        created_at_ms: u64,
    ) -> Result<(), OnboardingError> {
        match stage {
            OnboardingStage::To5Active => {
                let trc = self.registry.build_registry_container(
                    registry_id,
                    registry_version,
                    created_at_ms,
                );
                let receipt = self
                    .pvgs_client
                    .commit_tool_registry(trc)
                    .map_err(|err| OnboardingError::RegistryCommitFailed(err.to_string()))?;

                match ucf::v1::ReceiptStatus::try_from(receipt.status) {
                    Ok(ucf::v1::ReceiptStatus::Accepted) => {
                        self.signal_sink.emit("RC.GV.TOOL_REGISTRY.UPDATED");
                        Ok(())
                    }
                    _ => {
                        self.signal_sink
                            .emit("RC.GV.TOOL_REGISTRY.INTEGRITY_DEGRADED");
                        Err(OnboardingError::RegistryCommitRejected {
                            reason_codes: receipt.reject_reason_codes,
                        })
                    }
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockIntegritySignal {
    emitted: Arc<Mutex<Vec<String>>>,
}

impl MockIntegritySignal {
    pub fn events(&self) -> Vec<String> {
        self.emitted.lock().expect("lock poisoned").clone()
    }
}

impl IntegritySignal for MockIntegritySignal {
    fn emit(&self, reason_code: &str) {
        self.emitted
            .lock()
            .expect("lock poisoned")
            .push(reason_code.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use control::ControlFrameStore;
    use pbm::{PolicyContext, PolicyEngine, PolicyEvaluationRequest};
    use pvgs_client::{LocalPvgsClient, MockPvgsClient};
    use suspension::SuspendRecommendation;
    use trm::registry_fixture;

    fn base_policy_context(ruleset_digest: Option<[u8; 32]>) -> PolicyContext {
        PolicyContext {
            integrity_state: "OK".to_string(),
            charter_version_digest: "charter".to_string(),
            allowed_tools: vec!["mock.read".to_string()],
            control_frame: ControlFrameStore::new().strict_fallback(),
            tool_action_type: ucf::v1::ToolActionType::Read,
            pev: None,
            pev_digest: None,
            ruleset_digest,
            session_sealed: false,
            unlock_present: false,
        }
    }

    #[test]
    fn commit_called_on_to5_active() {
        let registry = Arc::new(registry_fixture());
        let signals = MockIntegritySignal::default();
        let mut onboarding = ToolOnboarding::new(registry, LocalPvgsClient::default(), signals);

        onboarding
            .handle_stage(OnboardingStage::To5Active, "registry", "v1", 123)
            .expect("commit accepted");

        assert_eq!(
            onboarding.pvgs_client().committed_tool_registries().len(),
            1
        );
    }

    #[test]
    fn fail_closed_on_pvgs_reject() {
        let registry = Arc::new(registry_fixture());
        let signals = MockIntegritySignal::default();
        let rejecting_client = MockPvgsClient::rejecting(vec!["RC.GV.INTEGRITY.DEGRADED".into()]);
        let mut onboarding = ToolOnboarding::new(registry, rejecting_client, signals.clone());

        let err = onboarding
            .handle_stage(OnboardingStage::To5Active, "registry", "v1", 123)
            .expect_err("commit rejected");

        assert!(matches!(
            err,
            OnboardingError::RegistryCommitRejected { .. }
        ));
        assert!(signals
            .events()
            .iter()
            .any(|rc| rc == "RC.GV.TOOL_REGISTRY.INTEGRITY_DEGRADED"));
    }

    #[test]
    fn pvgs_accept_path_signals_update() {
        let registry = Arc::new(registry_fixture());
        let signals = MockIntegritySignal::default();
        let mut onboarding =
            ToolOnboarding::new(registry, MockPvgsClient::default(), signals.clone());

        onboarding
            .handle_stage(OnboardingStage::To5Active, "registry", "v1", 456)
            .expect("commit accepted");

        assert!(signals
            .events()
            .iter()
            .any(|rc| rc == "RC.GV.TOOL_REGISTRY.UPDATED"));
    }

    #[test]
    fn suspension_triggers_registry_rebuild_and_commit() {
        let registry = Arc::new(Mutex::new(registry_fixture()));
        let signals = MockIntegritySignal::default();
        let pvgs = MockPvgsClient {
            ruleset_digest: Some([9u8; 32]),
            ..Default::default()
        };
        let mut suspensions =
            ToolSuspensionManager::new(registry.clone(), pvgs, signals.clone(), "registry", "v1");

        let rec = SuspendRecommendation {
            tool_id: "mock.read".into(),
            action_id: "get".into(),
            severity: suspension::LevelClass::High,
            reason_codes: vec!["RC.GV.TOOL.SUSPENDED".into()],
        };

        let results = suspensions
            .apply_suspensions(vec![rec], 1000)
            .expect("commit accepted");

        assert!(results.iter().any(|r| r.applied));
        assert_eq!(suspensions.ruleset_digest(), Some([9u8; 32]));
        assert_eq!(
            signals.events().last(),
            Some(&"RC.GV.TOOL_REGISTRY.UPDATED".into())
        );
        assert_eq!(
            suspensions
                .pvgs_client
                .local
                .committed_tool_registries
                .len(),
            1
        );

        let committed = suspensions
            .pvgs_client
            .local
            .committed_tool_registries
            .first()
            .expect("committed trc");
        let verbs: Vec<_> = committed
            .tool_actions
            .iter()
            .map(|tap| format!("{}/{}", tap.tool_id, tap.action_id))
            .collect();

        assert_eq!(committed.registry_version, "v1-susp1");
        assert_eq!(
            verbs,
            vec![
                "mock.export/render".to_string(),
                "mock.write/apply".to_string()
            ]
        );
    }

    #[test]
    fn ruleset_digest_refreshes_and_changes_policy_digest() {
        let registry = Arc::new(Mutex::new(registry_fixture()));
        let signals = MockIntegritySignal::default();
        let pvgs = MockPvgsClient {
            ruleset_digest: Some([1u8; 32]),
            ..Default::default()
        };
        let mut suspensions =
            ToolSuspensionManager::new(registry, pvgs, signals.clone(), "registry", "v1");

        let engine = PolicyEngine::new();
        let query = ucf::v1::PolicyQuery {
            principal: "chip3".to_string(),
            action: Some(ucf::v1::ActionSpec {
                verb: "mock.read/get".to_string(),
                resources: Vec::new(),
            }),
            channel: ucf::v1::Channel::Unspecified.into(),
            risk_level: ucf::v1::RiskLevel::Unspecified.into(),
            data_class: ucf::v1::DataClass::Unspecified.into(),
            reason_codes: None,
        };

        let initial_decision = engine.decide_with_context(PolicyEvaluationRequest {
            decision_id: "d1".into(),
            query: query.clone(),
            context: base_policy_context(suspensions.ruleset_digest()),
        });

        suspensions.pvgs_client.ruleset_digest = Some([2u8; 32]);
        suspensions
            .apply_suspensions(
                vec![SuspendRecommendation {
                    tool_id: "mock.export".into(),
                    action_id: "render".into(),
                    severity: suspension::LevelClass::Medium,
                    reason_codes: vec!["RC.GV.TOOL.SUSPENDED".into()],
                }],
                2000,
            )
            .expect("commit accepted");

        let refreshed_decision = engine.decide_with_context(PolicyEvaluationRequest {
            decision_id: "d2".into(),
            query,
            context: base_policy_context(suspensions.ruleset_digest()),
        });

        assert_ne!(
            initial_decision.decision_digest,
            refreshed_decision.decision_digest
        );
        assert!(signals
            .events()
            .iter()
            .any(|code| code == RC_GV_RULESET_CHANGED));
    }

    #[test]
    fn fail_closed_on_registry_reject() {
        let registry = Arc::new(Mutex::new(registry_fixture()));
        let signals = MockIntegritySignal::default();
        let rejecting_client = MockPvgsClient::rejecting(vec!["RC.REJECT".into()]);
        let mut suspensions = ToolSuspensionManager::new(
            registry,
            rejecting_client,
            signals.clone(),
            "registry",
            "v1",
        );

        let rec = SuspendRecommendation {
            tool_id: "mock.read".into(),
            action_id: "get".into(),
            severity: suspension::LevelClass::High,
            reason_codes: vec!["RC.GV.TOOL.SUSPENDED".into()],
        };

        let err = suspensions
            .apply_suspensions(vec![rec], 3000)
            .expect_err("rejects commit");

        assert!(matches!(
            err,
            SuspensionError::RegistryCommitRejected { .. }
        ));
        assert!(suspensions.integrity_degraded());
        assert!(signals
            .events()
            .iter()
            .any(|rc| rc == RC_GV_TOOL_REGISTRY_DEGRADED));
    }
}
