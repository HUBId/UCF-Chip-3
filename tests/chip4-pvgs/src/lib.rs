#![forbid(unsafe_code)]

use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use pvgs_verify::{pvgs_receipt_signing_preimage, PvgsKeyEpochStore};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use ucf_protocol::{canonical_bytes, digest32, digest_proto, ucf};
use ucf_test_utils::{make_pvgs_key_epoch, make_pvgs_receipt_accepted};

const RECEIPT_DOMAIN: &str = "UCF:HASH:PVGS_RECEIPT";

#[derive(Debug, Clone)]
pub struct SepEvent {
    pub record_digest: [u8; 32],
    pub status: ucf::v1::ReceiptStatus,
}

#[derive(Debug)]
struct LocalPvgsState {
    signing_key: SigningKey,
    attestation_key_id: String,
    key_epochs: Vec<ucf::v1::PvgsKeyEpoch>,
    latest_ruleset_digest: Option<[u8; 32]>,
    registry_commit_count: usize,
    head_id: u64,
    head_record_digest: Option<[u8; 32]>,
    sep_events: Vec<SepEvent>,
    proof_receipts: Vec<ucf::v1::ProofReceipt>,
    micro_milestones: Vec<ucf::v1::MicroMilestone>,
}

#[derive(Clone, Debug)]
pub struct LocalPvgs {
    inner: Arc<Mutex<LocalPvgsState>>,
}

impl Default for LocalPvgs {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPvgs {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        // Deterministic seed keeps tests stable.
        StdRng::seed_from_u64(7).fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let attestation_key_id = "pvgs-key-test".to_string();

        Self {
            inner: Arc::new(Mutex::new(LocalPvgsState {
                signing_key,
                attestation_key_id,
                key_epochs: Vec::new(),
                latest_ruleset_digest: None,
                registry_commit_count: 0,
                head_id: 0,
                head_record_digest: None,
                sep_events: Vec::new(),
                proof_receipts: Vec::new(),
                micro_milestones: Vec::new(),
            })),
        }
    }

    pub fn publish_key_epoch(&self, epoch_id: u64) -> ucf::v1::PvgsKeyEpoch {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let key_epoch = make_pvgs_key_epoch(epoch_id, &guard.signing_key);
        guard.attestation_key_id = key_epoch.attestation_key_id.clone();
        guard.key_epochs.push(key_epoch.clone());
        key_epoch
    }

    pub fn key_epochs(&self) -> Vec<ucf::v1::PvgsKeyEpoch> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.key_epochs.clone()
    }

    pub fn commit_tool_registry(
        &self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&trc);
        let registry_digest = digest_proto("UCF:HASH:TOOL_REGISTRY", &bytes);
        guard.latest_ruleset_digest = Some(registry_digest);
        guard.registry_commit_count += 1;

        let mut receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.registry_commit_count),
            receipt_id: format!("registry-{}", guard.registry_commit_count),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: registry_digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: trc.registry_digest.clone(),
            decision_digest: None,
            grant_id: "grant-registry".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let signature = guard.signing_key.sign(&preimage);
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: guard.attestation_key_id.as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        });

        receipt
    }

    pub fn append_micro_milestone(
        &self,
        mut micro: ucf::v1::MicroMilestone,
    ) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        if micro.micro_digest.is_none() {
            let digest = digest_proto("UCF:HASH:MICRO_MILESTONE", &canonical_bytes(&micro));
            micro.micro_digest = Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            });
        }

        let digest: [u8; 32] = micro
            .micro_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);
        guard.micro_milestones.push(micro.clone());

        ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-micro-{}", guard.micro_milestones.len()),
            receipt_id: format!("micro-{}", guard.micro_milestones.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: micro.micro_digest.clone(),
            grant_id: "grant-micro".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    pub fn append_experience_record(
        &self,
        record: ucf::v1::ExperienceRecord,
    ) -> (ucf::v1::PvgsReceipt, ucf::v1::ProofReceipt) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&record);
        let digest = digest_proto("UCF:HASH:EXPERIENCE_RECORD", &bytes);
        let has_governance =
            record.governance_frame.is_some() || record.governance_frame_ref.is_some();

        let status = if has_governance {
            ucf::v1::ReceiptStatus::Accepted
        } else {
            ucf::v1::ReceiptStatus::Rejected
        };

        let action_digest = record.core_frame_ref.clone().or_else(|| {
            record
                .core_frame
                .as_ref()
                .and_then(|cf| cf.candidate_refs.first().cloned())
        });

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.head_id + 1),
            receipt_id: format!("record-{}", guard.head_id + 1),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: status.into(),
            action_digest,
            decision_digest: record.governance_frame_ref.clone(),
            grant_id: "grant-local".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: record
                .metabolic_frame
                .as_ref()
                .and_then(|m| m.control_frame_ref.clone())
                .or_else(|| record.metabolic_frame_ref.clone()),
            tool_profile_digest: record
                .governance_frame
                .as_ref()
                .and_then(|g| g.policy_decision_refs.first().cloned())
                .or_else(|| record.governance_frame_ref.clone()),
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                vec!["RC.RE.SCHEMA.INVALID".to_string()]
            } else {
                Vec::new()
            },
            signer: None,
        };

        if status == ucf::v1::ReceiptStatus::Accepted {
            guard.head_id += 1;
            guard.head_record_digest = Some(digest);
        }

        let proof_receipt = ucf::v1::ProofReceipt {
            status: receipt.status,
            receipt_digest: receipt.receipt_digest.clone(),
            validator: Some(ucf::v1::Signature {
                algorithm: "local-proof".to_string(),
                signer: b"pvgs-proof".to_vec(),
                signature: vec![1u8; 64],
            }),
        };

        let event = SepEvent {
            record_digest: digest,
            status,
        };
        guard.sep_events.push(event);
        guard.proof_receipts.push(proof_receipt.clone());

        (receipt, proof_receipt)
    }

    pub fn head(&self) -> (u64, [u8; 32]) {
        let guard = self.inner.lock().expect("pvgs state lock");
        (guard.head_id, guard.head_record_digest.unwrap_or([0u8; 32]))
    }

    pub fn append_dlp_decision(
        &self,
        dlp: ucf::v1::DlpDecision,
    ) -> (ucf::v1::PvgsReceipt, ucf::v1::ProofReceipt) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&dlp);
        let digest = digest_proto("UCF:HASH:DLP_DECISION", &bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.head_id + 1),
            receipt_id: format!("dlp-{}", guard.head_id + 1),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: dlp.artifact_ref.clone(),
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: "grant-local".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        guard.head_id += 1;
        guard.head_record_digest = Some(digest);

        let proof_receipt = ucf::v1::ProofReceipt {
            status: receipt.status,
            receipt_digest: receipt.receipt_digest.clone(),
            validator: Some(ucf::v1::Signature {
                algorithm: "local-proof".to_string(),
                signer: b"pvgs-proof".to_vec(),
                signature: vec![2u8; 64],
            }),
        };

        guard.sep_events.push(SepEvent {
            record_digest: digest,
            status: ucf::v1::ReceiptStatus::Accepted,
        });
        guard.proof_receipts.push(proof_receipt.clone());

        (receipt, proof_receipt)
    }

    pub fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .latest_ruleset_digest
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_receipt_for_action(
        &self,
        action_digest: [u8; 32],
        decision_digest: [u8; 32],
        profile_digest: ucf::v1::Digest32,
        tool_profile_digest: ucf::v1::Digest32,
        grant_id: Option<String>,
    ) -> ucf::v1::PvgsReceipt {
        let guard = self.inner.lock().expect("pvgs state lock");
        let key_epoch = guard
            .key_epochs
            .last()
            .expect("publish a key epoch before issuing receipts");

        make_pvgs_receipt_accepted(
            action_digest,
            decision_digest,
            profile_digest,
            tool_profile_digest,
            &guard.signing_key,
            key_epoch,
            grant_id,
        )
    }

    pub fn attestation_key_id(&self) -> String {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .attestation_key_id
            .clone()
    }

    pub fn head_record_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .head_record_digest
    }

    pub fn head_id(&self) -> u64 {
        self.inner.lock().expect("pvgs state lock").head_id
    }

    pub fn sep_events(&self) -> Vec<SepEvent> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .sep_events
            .clone()
    }

    pub fn proof_receipts(&self) -> Vec<ucf::v1::ProofReceipt> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .proof_receipts
            .clone()
    }

    pub fn validate_chain(&self) -> bool {
        let guard = self.inner.lock().expect("pvgs state lock");
        match (guard.head_id, guard.head_record_digest.as_ref()) {
            (0, None) => true,
            (id, Some(_)) => id as usize == guard.sep_events.len(),
            _ => false,
        }
    }
}

pub fn ingest_published_epochs(
    pvgs: &LocalPvgs,
    store: &mut PvgsKeyEpochStore,
) -> Result<(), pvgs_verify::IngestError> {
    for epoch in pvgs.key_epochs() {
        store.ingest_key_epoch(epoch)?;
    }
    Ok(())
}

pub fn receipt_digest(receipt: &ucf::v1::PvgsReceipt) -> [u8; 32] {
    let mut canonical = receipt.clone();
    canonical.receipt_digest = None;
    canonical.signer = None;
    let bytes = canonical_bytes(&canonical);
    digest32(RECEIPT_DOMAIN, "PvgsReceipt", "v1", &bytes)
}
