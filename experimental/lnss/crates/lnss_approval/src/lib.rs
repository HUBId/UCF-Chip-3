#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use lnss_core::digest;
use lnss_evolve::{Proposal, ProposalPayload};
use prost::Message;
use thiserror::Error;
use ucf_protocol::ucf;

const DEFAULT_MAX_AMPLITUDE_Q: u16 = 1000;
const DEFAULT_MAX_TARGETS_PER_FEATURE: u16 = 8;
const DEFAULT_MAX_SPIKES_PER_TICK: u32 = 2048;
const DEFAULT_MAX_TARGETS_PER_SPIKE: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalConstraints {
    pub max_amplitude_q: u16,
    pub max_targets_per_feature: u16,
    pub require_simulation_first: bool,
    pub max_spikes_per_tick: u32,
    pub max_targets_per_spike: u32,
}

impl Default for ApprovalConstraints {
    fn default() -> Self {
        Self {
            max_amplitude_q: DEFAULT_MAX_AMPLITUDE_Q,
            max_targets_per_feature: DEFAULT_MAX_TARGETS_PER_FEATURE,
            require_simulation_first: false,
            max_spikes_per_tick: DEFAULT_MAX_SPIKES_PER_TICK,
            max_targets_per_spike: DEFAULT_MAX_TARGETS_PER_SPIKE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalActionPlan {
    pub aap_digest: [u8; 32],
    pub proposal_digest: [u8; 32],
    pub constraints: ApprovalConstraints,
}

impl ApprovalActionPlan {
    pub fn new(proposal_digest: [u8; 32], constraints: ApprovalConstraints) -> Self {
        let aap_digest = approval_action_plan_digest(proposal_digest, &constraints);
        Self {
            aap_digest,
            proposal_digest,
            constraints,
        }
    }
}

#[derive(Debug, Error)]
pub enum LnssApprovalError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("validation error: {0}")]
    Validation(String),
}

pub fn create_aap_from_proposal(proposal: &Proposal) -> ApprovalActionPlan {
    let mut constraints = ApprovalConstraints::default();
    if let ProposalPayload::InjectionLimitsUpdate {
        max_spikes_per_tick,
        max_targets_per_spike,
    } = proposal.payload
    {
        constraints.max_spikes_per_tick = max_spikes_per_tick;
        constraints.max_targets_per_spike = max_targets_per_spike;
    }
    ApprovalActionPlan::new(proposal.proposal_digest, constraints)
}

pub fn register_pending_aap(aap: ApprovalActionPlan) {
    let mut store = pending_aap_store().lock().expect("pending aap store");
    store.insert(aap.aap_digest, aap);
}

pub fn clear_pending_aaps() {
    pending_aap_store().lock().expect("pending aap store").clear();
}

pub fn clear_seen_approval_digests() {
    seen_approval_store()
        .lock()
        .expect("seen approvals")
        .clear();
}

pub fn load_approval_decisions(
    dir: &Path,
) -> Result<Vec<ucf::v1::ApprovalDecision>, LnssApprovalError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .collect();

    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    let mut decisions = Vec::new();
    for path in entries {
        let bytes = fs::read(&path)?;
        let decision = ucf::v1::ApprovalDecision::decode(bytes.as_slice())
            .map_err(|err| LnssApprovalError::Decode(err.to_string()))?;

        let approval_digest = decision
            .approval_digest
            .as_ref()
            .ok_or_else(|| LnssApprovalError::Validation("missing approval_digest".to_string()))?;
        let approval_digest = digest32_from_proto(approval_digest)?;
        let mut seen = seen_approval_store().lock().expect("seen approvals");
        if seen.contains(&approval_digest) {
            continue;
        }

        let aap_digest = decision
            .aap_digest
            .as_ref()
            .ok_or_else(|| LnssApprovalError::Validation("missing aap_digest".to_string()))?;
        let aap_digest = digest32_from_proto(aap_digest)?;
        let pending = pending_aap_store().lock().expect("pending aap store");
        if !pending.contains_key(&aap_digest) {
            return Err(LnssApprovalError::Validation(format!(
                "unknown aap_digest: {}",
                hex::encode(aap_digest)
            )));
        }

        seen.insert(approval_digest);
        decisions.push(decision);
    }

    Ok(decisions)
}

pub fn decision_allows_activation(
    decision: &ucf::v1::ApprovalDecision,
    aap: &ApprovalActionPlan,
) -> bool {
    let form =
        ucf::v1::ApprovalDecisionForm::try_from(decision.decision).unwrap_or(
            ucf::v1::ApprovalDecisionForm::Unspecified,
        );
    match form {
        ucf::v1::ApprovalDecisionForm::Approve => {
            decision
                .modifications
                .as_ref()
                .map(|mods| modifications_tighten_constraints(mods, &aap.constraints))
                .unwrap_or(true)
        }
        ucf::v1::ApprovalDecisionForm::ApproveWithModifications => decision
            .modifications
            .as_ref()
            .map(|mods| modifications_tighten_constraints(mods, &aap.constraints))
            .unwrap_or(false),
        _ => false,
    }
}

pub fn digest32_from_proto(digest: &ucf::v1::Digest32) -> Result<[u8; 32], LnssApprovalError> {
    if digest.value.len() != 32 {
        return Err(LnssApprovalError::Validation(
            "digest length mismatch".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.value);
    Ok(out)
}

pub fn digest32_to_proto(digest: [u8; 32]) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: digest.to_vec(),
    }
}

fn modifications_tighten_constraints(
    mods: &ucf::v1::ApprovalModifications,
    constraints: &ApprovalConstraints,
) -> bool {
    if let Some(max_spikes) = mods.max_spikes_per_tick {
        if max_spikes > constraints.max_spikes_per_tick {
            return false;
        }
    }
    if let Some(max_targets) = mods.max_targets_per_spike {
        if max_targets > constraints.max_targets_per_spike {
            return false;
        }
    }
    if let Some(max_targets) = mods.max_targets_per_feature {
        if max_targets > constraints.max_targets_per_feature as u32 {
            return false;
        }
    }
    if let Some(max_amplitude) = mods.max_amplitude_q {
        if max_amplitude > constraints.max_amplitude_q as u32 {
            return false;
        }
    }
    if let Some(require_simulation_first) = mods.require_simulation_first {
        if !require_simulation_first && constraints.require_simulation_first {
            return false;
        }
    }
    true
}

fn pending_aap_store() -> &'static Mutex<BTreeMap<[u8; 32], ApprovalActionPlan>> {
    static STORE: OnceLock<Mutex<BTreeMap<[u8; 32], ApprovalActionPlan>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn seen_approval_store() -> &'static Mutex<BTreeSet<[u8; 32]>> {
    static STORE: OnceLock<Mutex<BTreeSet<[u8; 32]>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn approval_action_plan_digest(
    proposal_digest: [u8; 32],
    constraints: &ApprovalConstraints,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&proposal_digest);
    buf.extend_from_slice(&constraints.max_amplitude_q.to_le_bytes());
    buf.extend_from_slice(&constraints.max_targets_per_feature.to_le_bytes());
    buf.push(u8::from(constraints.require_simulation_first));
    buf.extend_from_slice(&constraints.max_spikes_per_tick.to_le_bytes());
    buf.extend_from_slice(&constraints.max_targets_per_spike.to_le_bytes());
    digest("lnss.aap.v1", &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_decision(path: &Path, decision: &ucf::v1::ApprovalDecision) {
        let bytes = decision.encode_to_vec();
        fs::write(path, bytes).expect("write decision");
    }

    #[test]
    fn approval_decisions_are_deduped() {
        clear_pending_aaps();
        clear_seen_approval_digests();

        let dir = temp_dir("lnss_approval_dedup");
        let proposal = Proposal {
            proposal_id: "p".to_string(),
            proposal_digest: [1; 32],
            kind: lnss_evolve::ProposalKind::MappingUpdate,
            created_at_ms: 1,
            base_evidence_digest: [0; 32],
            payload: ProposalPayload::MappingUpdate {
                new_map_path: "maps/a.json".to_string(),
                map_digest: [2; 32],
                change_summary: vec![],
            },
            reason_codes: vec![],
        };
        let aap = create_aap_from_proposal(&proposal);
        register_pending_aap(aap.clone());

        let decision = ucf::v1::ApprovalDecision {
            approval_digest: Some(digest32_to_proto([9; 32])),
            aap_digest: Some(digest32_to_proto(aap.aap_digest)),
            decision: ucf::v1::ApprovalDecisionForm::Approve as i32,
            modifications: None,
        };
        write_decision(&dir.join("a.bin"), &decision);
        write_decision(&dir.join("b.bin"), &decision);

        let first = load_approval_decisions(&dir).expect("load approvals");
        let second = load_approval_decisions(&dir).expect("load approvals");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 0);
    }
}
