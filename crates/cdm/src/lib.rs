#![forbid(unsafe_code)]

use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

pub mod emotion;

const OUTPUT_ARTIFACT_DOMAIN: &str = "UCF:HASH:OUTPUT_ARTIFACT";
const DLP_DECISION_DOMAIN: &str = "UCF:HASH:DLP_DECISION";

#[derive(Debug, Error)]
pub enum CuratorError {
    #[error("content inspection failed: {0}")]
    Inspection(String),
}

#[derive(Debug, Clone)]
pub struct ContentDescriptor {
    pub label: String,
    pub preview: String,
}

#[derive(Debug, Clone)]
pub enum InspectionOutcome {
    Clean,
    Redacted(String),
}

pub trait Curator: Send + Sync {
    fn inspect(&self, content: ContentDescriptor) -> Result<InspectionOutcome, CuratorError>;
}

pub struct NoopCurator;

impl Curator for NoopCurator {
    fn inspect(&self, content: ContentDescriptor) -> Result<InspectionOutcome, CuratorError> {
        let _ = content;
        Ok(InspectionOutcome::Clean)
    }
}

pub fn dlp_check_output(artifact: &ucf::v1::OutputArtifact) -> ucf::v1::DlpDecision {
    let mut reason_codes = Vec::new();

    if artifact.content.contains("SECRET") {
        reason_codes.push("RC.CD.DLP.SECRET_PATTERN".to_string());
    }

    reason_codes.sort();
    reason_codes.dedup();

    let artifact_digest = output_artifact_digest(artifact);

    let mut decision = ucf::v1::DlpDecision {
        form: if reason_codes.is_empty() {
            ucf::v1::DlpDecisionForm::Allow.into()
        } else {
            ucf::v1::DlpDecisionForm::Block.into()
        },
        reason_codes: if reason_codes.is_empty() {
            None
        } else {
            Some(ucf::v1::ReasonCodes {
                codes: reason_codes.clone(),
            })
        },
        dlp_decision_digest: None,
        artifact_ref: Some(ucf::v1::Digest32 {
            value: artifact_digest.to_vec(),
        }),
    };

    let decision_digest = dlp_decision_digest(&decision);
    decision.dlp_decision_digest = Some(ucf::v1::Digest32 {
        value: decision_digest.to_vec(),
    });

    decision
}

pub fn output_artifact_digest(artifact: &ucf::v1::OutputArtifact) -> [u8; 32] {
    let mut canonical = artifact.clone();
    canonical.artifact_digest = None;
    digest_proto(OUTPUT_ARTIFACT_DOMAIN, &canonical_bytes(&canonical))
}

pub fn dlp_decision_digest(decision: &ucf::v1::DlpDecision) -> [u8; 32] {
    let mut canonical = decision.clone();
    canonical.dlp_decision_digest = None;
    if let Some(reason_codes) = canonical.reason_codes.as_mut() {
        reason_codes.codes.sort();
        reason_codes.codes.dedup();
    }
    digest_proto(DLP_DECISION_DOMAIN, &canonical_bytes(&canonical))
}

#[cfg(test)]
mod tests {
    use super::{dlp_decision_digest, output_artifact_digest};
    use ucf_protocol::ucf;

    #[test]
    fn output_artifact_digest_is_deterministic() {
        let artifact = ucf::v1::OutputArtifact {
            artifact_id: "a1".to_string(),
            content: "example".to_string(),
            artifact_digest: None,
        };

        let digest_a = output_artifact_digest(&artifact);
        let mut with_digest = artifact.clone();
        with_digest.artifact_digest = Some(ucf::v1::Digest32 {
            value: digest_a.to_vec(),
        });

        let digest_b = output_artifact_digest(&with_digest);

        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn dlp_decision_digest_sorts_reason_codes() {
        let decision = ucf::v1::DlpDecision {
            form: ucf::v1::DlpDecisionForm::Allow.into(),
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: vec![
                    "RC.BETA".to_string(),
                    "RC.ALPHA".to_string(),
                    "RC.ALPHA".to_string(),
                ],
            }),
            dlp_decision_digest: None,
            artifact_ref: None,
        };

        let digest_a = dlp_decision_digest(&decision);

        let mut shuffled = decision.clone();
        if let Some(rc) = shuffled.reason_codes.as_mut() {
            rc.codes.reverse();
        }

        let digest_b = dlp_decision_digest(&shuffled);

        assert_eq!(digest_a, digest_b);
    }
}
