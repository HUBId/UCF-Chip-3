#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use pvgs_client::PvgsClient;
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
    use pvgs_client::{LocalPvgsClient, MockPvgsClient};
    use trm::registry_fixture;

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
}
