#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub evidence_digest: [u8; 32],
    pub summary: String,
}

pub fn propose_updates(evidence_digest: [u8; 32]) -> Vec<Proposal> {
    let proposal_id = format!("proposal-{}", hex::encode(evidence_digest));
    vec![Proposal {
        proposal_id,
        evidence_digest,
        summary: "offline-evolve-stub".to_string(),
    }]
}
