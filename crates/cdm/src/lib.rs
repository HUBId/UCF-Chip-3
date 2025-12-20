#![forbid(unsafe_code)]

use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

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

    let artifact_digest = digest_proto(OUTPUT_ARTIFACT_DOMAIN, &canonical_bytes(artifact));

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

    let decision_digest = digest_proto(DLP_DECISION_DOMAIN, &canonical_bytes(&decision));
    decision.dlp_decision_digest = Some(ucf::v1::Digest32 {
        value: decision_digest.to_vec(),
    });

    decision
}
