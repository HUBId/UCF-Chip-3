#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LnssGovEvent {
    ProposalIngested { proposal_digest: [u8; 32] },
    ProposalCommitted { proposal_digest: [u8; 32] },
    AapCreated { aap_digest: [u8; 32] },
    ApprovalApplied { approval_digest: [u8; 32] },
    ActivationApplied { activation_digest: [u8; 32] },
    ActivationRejected { activation_digest: [u8; 32] },
    SaePackUpdated { new_digest: [u8; 32] },
    MappingUpdated { new_digest: [u8; 32] },
    LiquidParamsUpdated { new_digest: [u8; 32] },
    InjectionLimitsUpdated { new_digest: [u8; 32] },
    LnssDegraded { reason_codes: Vec<String> },
}

impl LnssGovEvent {
    pub fn reason_code(&self) -> Option<&'static str> {
        match self {
            LnssGovEvent::ActivationApplied { .. } => Some("RC.GV.PROPOSAL.ACTIVATED"),
            LnssGovEvent::ActivationRejected { .. } => Some("RC.GV.PROPOSAL.REJECTED"),
            LnssGovEvent::SaePackUpdated { .. } => Some("RC.GV.SAE.PACK_UPDATED"),
            LnssGovEvent::MappingUpdated { .. } => Some("RC.GV.MAP.UPDATED"),
            LnssGovEvent::LiquidParamsUpdated { .. } => Some("RC.GV.LIQUID.PARAMS_UPDATED"),
            LnssGovEvent::LnssDegraded { .. } => Some("RC.RE.INTEGRITY.DEGRADED"),
            _ => None,
        }
    }
}
