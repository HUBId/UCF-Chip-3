#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use lnss_core::MAX_STRING_LEN;
use lnss_evolve::{Proposal, ProposalKind};
use prost::Message;
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const AAP_DOMAIN: &str = "UCF:HASH:APPROVAL_ARTIFACT_PACKAGE";
const AAP_ID_PREFIX_LEN: usize = 8;
const MAX_EVIDENCE_REFS: usize = 7;
const MAX_ALTERNATIVES: usize = 3;
const MAX_CONSTRAINTS: usize = 8;
const ACTIVATION_DOMAIN: &str = "UCF:ACTIVATION_EVIDENCE";
const MAX_ACTIVATION_ID_LEN: usize = 64;
const MAX_ACTIVATION_REASON_CODES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationStatus {
    Applied,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationInjectionLimits {
    pub max_spikes_per_tick: u32,
    pub max_targets_per_spike: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalActivationEvidenceLocal {
    pub activation_id: String,
    pub proposal_digest: [u8; 32],
    pub approval_digest: [u8; 32],
    pub core_context_digest: [u8; 32],
    pub status: ActivationStatus,
    pub active_mapping_digest: Option<[u8; 32]>,
    pub active_sae_pack_digest: Option<[u8; 32]>,
    pub active_liquid_params_digest: Option<[u8; 32]>,
    pub active_injection_limits: Option<ActivationInjectionLimits>,
    pub created_at_ms: u64,
    pub reason_codes: Vec<String>,
    pub activation_digest: [u8; 32],
}

pub fn build_activation_evidence_pb(
    ev: &ProposalActivationEvidenceLocal,
) -> ucf::v1::ProposalActivationEvidence {
    let mut reason_codes = ev
        .reason_codes
        .iter()
        .map(|code| bound_string(code).to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_ACTIVATION_REASON_CODES);

    let mut evidence = ucf::v1::ProposalActivationEvidence {
        activation_id: bound_string_with_limit(&ev.activation_id, MAX_ACTIVATION_ID_LEN)
            .trim()
            .to_uppercase(),
        proposal_digest: Some(ucf::v1::Digest32 {
            value: ev.proposal_digest.to_vec(),
        }),
        approval_digest: Some(ucf::v1::Digest32 {
            value: ev.approval_digest.to_vec(),
        }),
        status: activation_status_proto(&ev.status) as i32,
        created_at_ms: ev.created_at_ms,
        active_mapping_digest: ev.active_mapping_digest.map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        active_sae_pack_digest: ev.active_sae_pack_digest.map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        active_liquid_params_digest: ev.active_liquid_params_digest.map(|digest| {
            ucf::v1::Digest32 {
                value: digest.to_vec(),
            }
        }),
        active_injection_limits: ev.active_injection_limits.as_ref().map(|limits| {
            ucf::v1::ActivationInjectionLimits {
                max_spikes_per_tick: limits.max_spikes_per_tick,
                max_targets_per_spike: limits.max_targets_per_spike,
            }
        }),
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: reason_codes,
        }),
        activation_digest: Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        }),
        context_digest: Some(ucf::v1::Digest32 {
            value: ev.core_context_digest.to_vec(),
        }),
    };

    let digest_bytes = digest_proto(ACTIVATION_DOMAIN, &canonical_bytes(&evidence));
    evidence.activation_digest = Some(ucf::v1::Digest32 {
        value: digest_bytes.to_vec(),
    });
    evidence
}

#[cfg(feature = "lnss-legacy-evidence")]
pub fn encode_activation(ev: &ProposalActivationEvidenceLocal) -> Vec<u8> {
    let mut buf = Vec::new();

    let activation_id = bound_string_with_limit(&ev.activation_id, MAX_ACTIVATION_ID_LEN)
        .trim()
        .to_uppercase();
    write_string_u16(&mut buf, &activation_id);
    buf.extend_from_slice(&ev.proposal_digest);
    buf.extend_from_slice(&ev.approval_digest);
    buf.extend_from_slice(&ev.core_context_digest);
    buf.push(activation_status_tag(&ev.status));
    write_u64(&mut buf, ev.created_at_ms);
    write_optional_digest(&mut buf, ev.active_mapping_digest);
    write_optional_digest(&mut buf, ev.active_sae_pack_digest);
    write_optional_digest(&mut buf, ev.active_liquid_params_digest);
    write_optional_injection_limits(&mut buf, ev.active_injection_limits.as_ref());

    let mut reason_codes = ev
        .reason_codes
        .iter()
        .map(|code| bound_string(code).to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_ACTIVATION_REASON_CODES);
    write_u16(&mut buf, reason_codes.len() as u16);
    for code in reason_codes {
        write_string_u16(&mut buf, &code);
    }

    buf.extend_from_slice(&ev.activation_digest);

    buf
}

pub fn compute_activation_digest(ev: &mut ProposalActivationEvidenceLocal) -> [u8; 32] {
    let evidence = build_activation_evidence_pb(ev);
    let digest_bytes = evidence
        .activation_digest
        .as_ref()
        .and_then(digest_bytes)
        .unwrap_or([0u8; 32]);
    ev.activation_digest = digest_bytes;
    digest_bytes
}

#[derive(Debug, Error)]
pub enum ApprovalLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum ApprovalBuildError {
    #[error("missing core context binding")]
    MissingContextBinding,
}

#[derive(Debug, Clone)]
pub struct ApprovalContext {
    pub session_id: String,
    pub ruleset_digest: Option<[u8; 32]>,
    pub current_mapping_digest: Option<[u8; 32]>,
    pub current_sae_pack_digest: Option<[u8; 32]>,
    pub current_liquid_params_digest: Option<[u8; 32]>,
    pub latest_scorecard_digest: Option<[u8; 32]>,
    pub trace_digest: Option<[u8; 32]>,
    pub active_cfg_root_digest: Option<[u8; 32]>,
    pub shadow_cfg_root_digest: Option<[u8; 32]>,
    pub requested_operation: ucf::v1::OperationCategory,
}

pub fn build_aap_for_proposal(
    proposal: &Proposal,
    ctx: &ApprovalContext,
) -> Result<ucf::v1::ApprovalArtifactPackage, ApprovalBuildError> {
    if is_zero_digest(&proposal.core_context_digest) {
        return Err(ApprovalBuildError::MissingContextBinding);
    }
    let aap_id = aap_id_for_proposal(proposal);
    let mut evidence_refs = Vec::new();
    evidence_refs.push(related_ref("proposal_digest", proposal.proposal_digest));
    evidence_refs.push(related_ref(
        "base_evidence_digest",
        proposal.base_evidence_digest,
    ));
    evidence_refs.push(related_ref(
        "core_context_digest",
        proposal.core_context_digest,
    ));
    if let Some(trace_digest) = ctx.trace_digest {
        evidence_refs.push(related_ref("trace_digest", trace_digest));
    }
    if let Some(active_cfg_root_digest) = ctx.active_cfg_root_digest {
        evidence_refs.push(related_ref(
            "active_cfg_root_digest",
            active_cfg_root_digest,
        ));
    }
    if let Some(shadow_cfg_root_digest) = ctx.shadow_cfg_root_digest {
        evidence_refs.push(related_ref(
            "shadow_cfg_root_digest",
            shadow_cfg_root_digest,
        ));
    }
    evidence_refs.push(related_ref(
        "world_state_digest",
        proposal.core_context_digest_pack.world_state_digest,
    ));
    evidence_refs.push(related_ref(
        "self_state_digest",
        proposal.core_context_digest_pack.self_state_digest,
    ));
    if let Some(scorecard) = ctx.latest_scorecard_digest {
        evidence_refs.push(related_ref("scorecard_digest", scorecard));
    }
    evidence_refs.truncate(MAX_EVIDENCE_REFS);

    let alternatives = build_alternatives();
    let constraints = constraints_for_proposal(proposal);

    let mut aap = ucf::v1::ApprovalArtifactPackage {
        aap_id: bound_string(&aap_id),
        session_id: bound_string(&ctx.session_id),
        requested_operation: ctx.requested_operation as i32,
        ruleset_digest: ctx.ruleset_digest.map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        mapping_digest: match proposal.kind {
            ProposalKind::MappingUpdate => ctx.current_mapping_digest,
            _ => None,
        }
        .map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        sae_pack_digest: match proposal.kind {
            ProposalKind::SaePackUpdate => ctx.current_sae_pack_digest,
            _ => None,
        }
        .map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        liquid_params_digest: match proposal.kind {
            ProposalKind::LiquidParamsUpdate => ctx.current_liquid_params_digest,
            _ => None,
        }
        .map(|digest| ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
        evidence_refs,
        alternatives,
        constraints,
        aap_digest: None,
    };

    let digest = approval_artifact_package_digest(&aap);
    aap.aap_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    Ok(aap)
}

pub fn approval_artifact_package_digest(aap: &ucf::v1::ApprovalArtifactPackage) -> [u8; 32] {
    let mut canonical = aap.clone();
    canonical.aap_digest = None;
    digest_proto(AAP_DOMAIN, &canonical_bytes(&canonical))
}

pub fn encode_aap(aap: &ucf::v1::ApprovalArtifactPackage) -> Vec<u8> {
    canonical_bytes(aap)
}

pub fn load_approval_decisions(
    dir: &Path,
) -> Result<Vec<ucf::v1::ApprovalDecision>, ApprovalLoadError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("approval_"))
                    .unwrap_or(false)
                && path.extension().map(|ext| ext == "bin").unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    let pending_aap_ids = pending_aap_ids(dir)?;
    let mut seen_approval_digests = BTreeSet::new();
    let mut decisions = Vec::new();

    for path in entries {
        let bytes = fs::read(&path)?;
        let decision = ucf::v1::ApprovalDecision::decode(bytes.as_slice())
            .map_err(|err| ApprovalLoadError::Decode(err.to_string()))?;
        let digest = match decision.approval_decision_digest.as_ref() {
            Some(digest) => match digest_bytes(digest) {
                Some(bytes) => bytes,
                None => continue,
            },
            None => continue,
        };
        if seen_approval_digests.contains(&digest) {
            continue;
        }
        if decision.aap_id.is_empty() || !pending_aap_ids.contains(&decision.aap_id) {
            continue;
        }
        seen_approval_digests.insert(digest);
        decisions.push(decision);
    }

    Ok(decisions)
}

fn aap_id_for_proposal(proposal: &Proposal) -> String {
    let prefix = hex::encode(&proposal.proposal_digest[..AAP_ID_PREFIX_LEN]);
    format!("aap:proposal:{prefix}")
}

fn related_ref(id: &str, digest: [u8; 32]) -> ucf::v1::RelatedRef {
    ucf::v1::RelatedRef {
        id: bound_string(id),
        digest: Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        }),
    }
}

fn build_alternatives() -> Vec<ucf::v1::ApprovalAlternative> {
    let mut alternatives = vec![
        ucf::v1::ApprovalAlternative {
            form: ucf::v1::ApprovalAlternativeForm::DoNothing as i32,
            label: bound_string("do_nothing"),
        },
        ucf::v1::ApprovalAlternative {
            form: ucf::v1::ApprovalAlternativeForm::SimulateFirst as i32,
            label: bound_string("simulate_first"),
        },
    ];
    alternatives.truncate(MAX_ALTERNATIVES);
    alternatives
}

fn constraints_for_proposal(proposal: &Proposal) -> Option<ucf::v1::ConstraintsDelta> {
    let mut constraints_added = match proposal.kind {
        ProposalKind::MappingUpdate => vec![
            "reduce amplitude_q".to_string(),
            "reduce fan-out".to_string(),
        ],
        ProposalKind::SaePackUpdate => vec!["keep inference hooks unchanged".to_string()],
        ProposalKind::LiquidParamsUpdate => vec!["restrict dt/substeps bounds".to_string()],
        ProposalKind::InjectionLimitsUpdate => Vec::new(),
    };

    if constraints_added.is_empty() {
        return None;
    }

    for constraint in &mut constraints_added {
        *constraint = bound_string(constraint);
    }
    constraints_added.truncate(MAX_CONSTRAINTS);

    Some(ucf::v1::ConstraintsDelta {
        constraints_added,
        constraints_removed: Vec::new(),
        novelty_lock: false,
    })
}

fn bound_string(value: &str) -> String {
    let mut out = value.trim().to_string();
    out.truncate(MAX_STRING_LEN);
    out
}

fn bound_string_with_limit(value: &str, limit: usize) -> String {
    let mut out = value.trim().to_string();
    out.truncate(limit);
    out
}

#[cfg(feature = "lnss-legacy-evidence")]
fn activation_status_tag(status: &ActivationStatus) -> u8 {
    match status {
        ActivationStatus::Applied => 1,
        ActivationStatus::Rejected => 2,
    }
}

fn activation_status_proto(status: &ActivationStatus) -> ucf::v1::ActivationStatus {
    match status {
        ActivationStatus::Applied => ucf::v1::ActivationStatus::Applied,
        ActivationStatus::Rejected => ucf::v1::ActivationStatus::Rejected,
    }
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_string_u16(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_optional_digest(buf: &mut Vec<u8>, digest: Option<[u8; 32]>) {
    write_bool(buf, digest.is_some());
    if let Some(digest) = digest {
        buf.extend_from_slice(&digest);
    }
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_optional_injection_limits(buf: &mut Vec<u8>, limits: Option<&ActivationInjectionLimits>) {
    write_bool(buf, limits.is_some());
    if let Some(limits) = limits {
        write_u32(buf, limits.max_spikes_per_tick);
        write_u32(buf, limits.max_targets_per_spike);
    }
}

fn pending_aap_ids(dir: &Path) -> Result<BTreeSet<String>, ApprovalLoadError> {
    let aap_dir = dir.join("aap");
    let mut ids = BTreeSet::new();
    if !aap_dir.exists() {
        return Ok(ids);
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(aap_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.starts_with("aap_"))
                    .unwrap_or(false)
                && path.extension().map(|ext| ext == "bin").unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    for path in entries {
        let bytes = fs::read(&path)?;
        let aap = ucf::v1::ApprovalArtifactPackage::decode(bytes.as_slice())
            .map_err(|err| ApprovalLoadError::Decode(err.to_string()))?;
        let aap_digest = match aap.aap_digest.as_ref().and_then(digest_bytes) {
            Some(digest) => digest,
            None => continue,
        };
        let computed = approval_artifact_package_digest(&aap);
        if computed != aap_digest {
            continue;
        }
        if !aap.aap_id.is_empty() {
            ids.insert(aap.aap_id);
        }
    }

    Ok(ids)
}

fn digest_bytes(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    let bytes: [u8; 32] = digest.value.as_slice().try_into().ok()?;
    Some(bytes)
}

fn is_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_evolve::{Proposal, ProposalKind, ProposalPayload};

    fn sample_proposal() -> Proposal {
        let core_context_digest_pack = lnss_core::CoreContextDigestPack {
            world_state_digest: [6u8; 32],
            self_state_digest: [7u8; 32],
            control_frame_digest: [8u8; 32],
            policy_digest: None,
            last_feedback_digest: None,
            wm_pred_error_bucket: 1,
            rlm_followup_executed: false,
        };
        let core_context_digest = core_context_digest_pack.digest();
        Proposal {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: [3u8; 32],
            kind: ProposalKind::MappingUpdate,
            created_at_ms: 100,
            base_evidence_digest: [5u8; 32],
            base_active_cfg_digest: Some([4u8; 32]),
            core_context_digest_pack,
            core_context_digest,
            payload: ProposalPayload::MappingUpdate {
                new_map_path: "maps/new.json".to_string(),
                map_digest: [9u8; 32],
                change_summary: vec!["adjust".to_string()],
            },
            reason_codes: vec!["RC.MAP.UPDATE".to_string()],
        }
    }

    fn sample_context(session_id: &str) -> ApprovalContext {
        ApprovalContext {
            session_id: session_id.to_string(),
            ruleset_digest: Some([7u8; 32]),
            current_mapping_digest: Some([8u8; 32]),
            current_sae_pack_digest: None,
            current_liquid_params_digest: None,
            latest_scorecard_digest: Some([1u8; 32]),
            trace_digest: Some([9u8; 32]),
            active_cfg_root_digest: Some([2u8; 32]),
            shadow_cfg_root_digest: Some([3u8; 32]),
            requested_operation: ucf::v1::OperationCategory::OpException,
        }
    }

    #[test]
    fn aap_requires_context_binding() {
        let mut proposal = sample_proposal();
        proposal.core_context_digest = [0u8; 32];
        let ctx = sample_context("session-missing");
        let err = build_aap_for_proposal(&proposal, &ctx).expect_err("missing context");
        assert!(matches!(err, ApprovalBuildError::MissingContextBinding));
    }

    #[test]
    fn aap_id_and_digest_are_deterministic() {
        let proposal = sample_proposal();
        let ctx = sample_context("session-1");

        let first = build_aap_for_proposal(&proposal, &ctx).expect("aap");
        let second = build_aap_for_proposal(&proposal, &ctx).expect("aap");

        assert_eq!(first.aap_id, second.aap_id);
        assert_eq!(first.aap_digest, second.aap_digest);
    }

    #[test]
    fn alternatives_present_and_ordered() {
        let proposal = sample_proposal();
        let ctx = sample_context("session-2");
        let aap = build_aap_for_proposal(&proposal, &ctx).expect("aap");

        assert!(aap.alternatives.len() >= 2);
        assert_eq!(
            aap.alternatives[0].form,
            ucf::v1::ApprovalAlternativeForm::DoNothing as i32
        );
        assert_eq!(
            aap.alternatives[1].form,
            ucf::v1::ApprovalAlternativeForm::SimulateFirst as i32
        );
    }

    #[test]
    fn evidence_refs_include_proposal_and_base_evidence() {
        let proposal = sample_proposal();
        let ctx = sample_context("session-3");
        let aap = build_aap_for_proposal(&proposal, &ctx).expect("aap");

        let proposal_ref = aap
            .evidence_refs
            .iter()
            .find(|item| item.id == "proposal_digest")
            .expect("proposal digest ref");
        assert_eq!(
            proposal_ref.digest.as_ref().unwrap().value,
            proposal.proposal_digest
        );

        let base_ref = aap
            .evidence_refs
            .iter()
            .find(|item| item.id == "base_evidence_digest")
            .expect("base evidence digest ref");
        assert_eq!(
            base_ref.digest.as_ref().unwrap().value,
            proposal.base_evidence_digest
        );

        let trace_ref = aap
            .evidence_refs
            .iter()
            .find(|item| item.id == "trace_digest")
            .expect("trace digest ref");
        assert_eq!(trace_ref.digest.as_ref().unwrap().value, [9u8; 32]);
    }

    #[test]
    fn fields_are_bounded() {
        let proposal = sample_proposal();
        let long_session = "s".repeat(MAX_STRING_LEN + 32);
        let ctx = sample_context(&long_session);
        let aap = build_aap_for_proposal(&proposal, &ctx).expect("aap");

        assert!(aap.session_id.len() <= MAX_STRING_LEN);
        assert!(aap.aap_id.len() <= MAX_STRING_LEN);
        assert!(aap.evidence_refs.len() <= MAX_EVIDENCE_REFS);
        assert!(aap.alternatives.len() <= MAX_ALTERNATIVES);
        if let Some(constraints) = aap.constraints.as_ref() {
            assert!(constraints.constraints_added.len() <= MAX_CONSTRAINTS);
        }
    }

    #[test]
    fn activation_encoding_is_deterministic() {
        let mut evidence = ProposalActivationEvidenceLocal {
            activation_id: "act:aa:bb".to_string(),
            proposal_digest: [1u8; 32],
            approval_digest: [2u8; 32],
            core_context_digest: [3u8; 32],
            status: ActivationStatus::Applied,
            active_mapping_digest: Some([3u8; 32]),
            active_sae_pack_digest: None,
            active_liquid_params_digest: Some([4u8; 32]),
            active_injection_limits: Some(ActivationInjectionLimits {
                max_spikes_per_tick: 10,
                max_targets_per_spike: 5,
            }),
            created_at_ms: 42,
            reason_codes: vec![
                "rc.gv.proposal.activated".to_string(),
                "rc.gv.proposal.activated".to_string(),
                "zz".to_string(),
                "aa".to_string(),
            ],
            activation_digest: [0u8; 32],
        };

        let first_digest = compute_activation_digest(&mut evidence);
        let first = canonical_bytes(&build_activation_evidence_pb(&evidence));
        let second = canonical_bytes(&build_activation_evidence_pb(&evidence));

        assert_eq!(first, second);
        assert_eq!(first_digest, evidence.activation_digest);
    }

    #[test]
    fn activation_digest_matches() {
        let evidence = ProposalActivationEvidenceLocal {
            activation_id: "act:aa:bb".to_string(),
            proposal_digest: [1u8; 32],
            approval_digest: [2u8; 32],
            core_context_digest: [3u8; 32],
            status: ActivationStatus::Applied,
            active_mapping_digest: Some([3u8; 32]),
            active_sae_pack_digest: None,
            active_liquid_params_digest: Some([4u8; 32]),
            active_injection_limits: Some(ActivationInjectionLimits {
                max_spikes_per_tick: 10,
                max_targets_per_spike: 5,
            }),
            created_at_ms: 42,
            reason_codes: vec!["rc.gv.proposal.activated".to_string()],
            activation_digest: [0u8; 32],
        };

        let mut pb = build_activation_evidence_pb(&evidence);
        let digest = pb
            .activation_digest
            .as_ref()
            .and_then(digest_bytes)
            .expect("activation digest");
        pb.activation_digest = Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        });
        let recomputed = digest_proto(ACTIVATION_DOMAIN, &canonical_bytes(&pb));
        assert_eq!(digest, recomputed);
    }
}
