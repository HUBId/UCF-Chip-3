#![forbid(unsafe_code)]

use thiserror::Error;

// TODO: Model onboarding state transitions with ucf-protocol types.

#[derive(Debug, Error)]
pub enum OnboardingError {
    #[error("invalid transition from {0}")]
    InvalidTransition(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingState {
    Pending,
    Approved,
    Rejected,
}

pub trait OnboardingStateMachine: Send + Sync {
    fn advance(&self, current: OnboardingState) -> Result<OnboardingState, OnboardingError>;
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
