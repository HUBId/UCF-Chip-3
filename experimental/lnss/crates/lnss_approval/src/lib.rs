#![forbid(unsafe_code)]

use lnss_core::MAX_STRING_LEN;
use lnss_evolve::{Proposal, ProposalKind};
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const AAP_DOMAIN: &str = "UCF:HASH:APPROVAL_ARTIFACT_PACKAGE";
const AAP_ID_PREFIX_LEN: usize = 8;
const MAX_EVIDENCE_REFS: usize = 4;
const MAX_ALTERNATIVES: usize = 3;
const MAX_CONSTRAINTS: usize = 8;

#[derive(Debug, Clone)]
pub struct ApprovalContext {
    pub session_id: String,
    pub ruleset_digest: Option<[u8; 32]>,
    pub current_mapping_digest: Option<[u8; 32]>,
    pub current_sae_pack_digest: Option<[u8; 32]>,
    pub current_liquid_params_digest: Option<[u8; 32]>,
    pub latest_scorecard_digest: Option<[u8; 32]>,
    pub requested_operation: ucf::v1::OperationCategory,
}

pub fn build_aap_for_proposal(
    proposal: &Proposal,
    ctx: &ApprovalContext,
) -> ucf::v1::ApprovalArtifactPackage {
    let aap_id = aap_id_for_proposal(proposal);
    let mut evidence_refs = Vec::new();
    evidence_refs.push(related_ref("proposal_digest", proposal.proposal_digest));
    evidence_refs.push(related_ref(
        "base_evidence_digest",
        proposal.base_evidence_digest,
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
    aap
}

pub fn approval_artifact_package_digest(aap: &ucf::v1::ApprovalArtifactPackage) -> [u8; 32] {
    let mut canonical = aap.clone();
    canonical.aap_digest = None;
    digest_proto(AAP_DOMAIN, &canonical_bytes(&canonical))
}

pub fn encode_aap(aap: &ucf::v1::ApprovalArtifactPackage) -> Vec<u8> {
    canonical_bytes(aap)
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

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_evolve::{Proposal, ProposalKind, ProposalPayload};

    fn sample_proposal() -> Proposal {
        Proposal {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: [3u8; 32],
            kind: ProposalKind::MappingUpdate,
            created_at_ms: 100,
            base_evidence_digest: [5u8; 32],
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
            requested_operation: ucf::v1::OperationCategory::OpException,
        }
    }

    #[test]
    fn aap_id_and_digest_are_deterministic() {
        let proposal = sample_proposal();
        let ctx = sample_context("session-1");

        let first = build_aap_for_proposal(&proposal, &ctx);
        let second = build_aap_for_proposal(&proposal, &ctx);

        assert_eq!(first.aap_id, second.aap_id);
        assert_eq!(first.aap_digest, second.aap_digest);
    }

    #[test]
    fn alternatives_present_and_ordered() {
        let proposal = sample_proposal();
        let ctx = sample_context("session-2");
        let aap = build_aap_for_proposal(&proposal, &ctx);

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
        let aap = build_aap_for_proposal(&proposal, &ctx);

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
    }

    #[test]
    fn fields_are_bounded() {
        let proposal = sample_proposal();
        let long_session = "s".repeat(MAX_STRING_LEN + 32);
        let ctx = sample_context(&long_session);
        let aap = build_aap_for_proposal(&proposal, &ctx);

        assert!(aap.session_id.len() <= MAX_STRING_LEN);
        assert!(aap.aap_id.len() <= MAX_STRING_LEN);
        assert!(aap.evidence_refs.len() <= MAX_EVIDENCE_REFS);
        assert!(aap.alternatives.len() <= MAX_ALTERNATIVES);
        if let Some(constraints) = aap.constraints.as_ref() {
            assert!(constraints.constraints_added.len() <= MAX_CONSTRAINTS);
        }
    }
}
