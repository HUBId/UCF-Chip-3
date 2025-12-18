#![forbid(unsafe_code)]

use pvgs_verify::{IngestError, PvgsKeyEpochStore};
use thiserror::Error;
use ucf_protocol::ucf;

// TODO: Bind commit/receipt messages to ucf-protocol definitions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEpochSyncEvent {
    Accepted { epoch_id: u64 },
    Rejected { epoch_id: u64 },
}

pub struct KeyEpochSync {
    store: PvgsKeyEpochStore,
}

impl KeyEpochSync {
    pub fn new(store: PvgsKeyEpochStore) -> Self {
        Self { store }
    }

    pub fn sync_from_list(&mut self, epochs: Vec<ucf::v1::PvgsKeyEpoch>) -> Result<(), SyncError> {
        let mut sorted_epochs = epochs;
        sorted_epochs.sort_by_key(|e| e.epoch_id);

        let mut last_epoch_id: Option<u64> = None;
        for epoch in sorted_epochs {
            if let Some(prev) = last_epoch_id {
                if epoch.epoch_id < prev {
                    self.on_keyepoch_sync_event(KeyEpochSyncEvent::Rejected {
                        epoch_id: epoch.epoch_id,
                    });
                    return Err(SyncError::NonMonotonic {
                        epoch_id: epoch.epoch_id,
                        previous: prev,
                    });
                }
            }

            last_epoch_id = Some(epoch.epoch_id);
            match self.store.ingest_key_epoch(epoch) {
                Ok(()) => self.on_keyepoch_sync_event(KeyEpochSyncEvent::Accepted {
                    epoch_id: last_epoch_id.expect("epoch id set"),
                }),
                Err(source) => {
                    let epoch_id = last_epoch_id.expect("epoch id set");
                    self.on_keyepoch_sync_event(KeyEpochSyncEvent::Rejected { epoch_id });
                    return Err(SyncError::Ingest { epoch_id, source });
                }
            }
        }

        Ok(())
    }

    pub fn store(&self) -> &PvgsKeyEpochStore {
        &self.store
    }

    fn on_keyepoch_sync_event(&self, _event: KeyEpochSyncEvent) {
        // TODO: integrate PVGS sync logging
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("epoch ids must be monotonic: {epoch_id} after {previous}")]
    NonMonotonic { epoch_id: u64, previous: u64 },
    #[error("failed to ingest epoch {epoch_id}: {source}")]
    Ingest {
        epoch_id: u64,
        #[source]
        source: IngestError,
    },
}

#[derive(Debug, Error)]
pub enum PvgsClientError {
    #[error("pvgs commit failed: {0}")]
    CommitFailed(String),
}

pub trait PvgsClient: Send + Sync {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;
}

pub trait PvgsReader: Send + Sync {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector>;
    fn get_latest_pev_digest(&self) -> Option<[u8; 32]>;
}

#[derive(Debug, Clone)]
pub struct LocalPvgsClient {
    receipt_epoch: String,
    grant_id: String,
    default_status: ucf::v1::ReceiptStatus,
    reject_reason_codes: Vec<String>,
    pub committed_records: Vec<ucf::v1::ExperienceRecord>,
    pub committed_bytes: Vec<Vec<u8>>,
}

impl Default for LocalPvgsClient {
    fn default() -> Self {
        Self {
            receipt_epoch: "local-epoch".to_string(),
            grant_id: "local-grant".to_string(),
            default_status: ucf::v1::ReceiptStatus::Accepted,
            reject_reason_codes: Vec::new(),
            committed_records: Vec::new(),
            committed_bytes: Vec::new(),
        }
    }
}

impl LocalPvgsClient {
    pub fn rejecting(reason_codes: Vec<String>) -> Self {
        Self {
            default_status: ucf::v1::ReceiptStatus::Rejected,
            reject_reason_codes: reason_codes,
            ..Self::default()
        }
    }

    pub fn with_status(status: ucf::v1::ReceiptStatus) -> Self {
        Self {
            default_status: status,
            ..Self::default()
        }
    }
}

impl PvgsClient for LocalPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let bytes = ucf_protocol::canonical_bytes(&record);
        let record_digest = ucf_protocol::digest_proto("UCF:HASH:EXPERIENCE_RECORD", &bytes);
        let has_governance =
            record.governance_frame.is_some() || record.governance_frame_ref.is_some();

        let mut status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if !has_governance {
            status = ucf::v1::ReceiptStatus::Rejected;
            if reject_reason_codes.is_empty() {
                reject_reason_codes.push("RC.GV.MISSING".to_string());
            }
        }

        self.committed_records.push(record.clone());
        self.committed_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!("pvgs-local-{}", self.committed_records.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: record_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: record
                .core_frame
                .as_ref()
                .and_then(|cf| cf.candidate_refs.first())
                .cloned(),
            decision_digest: record.governance_frame_ref.clone(),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: record
                .metabolic_frame
                .as_ref()
                .and_then(|mf| mf.control_frame_ref.clone()),
            tool_profile_digest: None,
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                reject_reason_codes
            } else {
                Vec::new()
            },
            signer: None,
        };

        Ok(receipt)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MockPvgsClient {
    pub local: LocalPvgsClient,
}

impl MockPvgsClient {
    pub fn rejecting(reason_codes: Vec<String>) -> Self {
        Self {
            local: LocalPvgsClient::rejecting(reason_codes),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockPvgsReader {
    pev: Option<ucf::v1::PolicyEcologyVector>,
    pev_digest: Option<[u8; 32]>,
}

impl Default for MockPvgsReader {
    fn default() -> Self {
        let mut pev = ucf::v1::PolicyEcologyVector {
            conservatism_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            novelty_penalty_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            reversibility_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            pev_digest: None,
        };
        let digest = digest_pev(&pev);
        pev.pev_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        Self {
            pev: Some(pev),
            pev_digest: Some(digest),
        }
    }
}

impl MockPvgsReader {
    pub fn new(pev: Option<ucf::v1::PolicyEcologyVector>) -> Self {
        let pev_digest = pev
            .as_ref()
            .and_then(|vector| vector.pev_digest.as_ref())
            .and_then(digest32_to_array)
            .or_else(|| pev.as_ref().map(digest_pev));

        let mut pev_with_digest = pev;
        if let (Some(digest), Some(ref mut vector)) = (pev_digest, pev_with_digest.as_mut()) {
            if vector.pev_digest.is_none() {
                vector.pev_digest = Some(ucf::v1::Digest32 {
                    value: digest.to_vec(),
                });
            }
        }

        Self {
            pev: pev_with_digest,
            pev_digest,
        }
    }

    pub fn with_pev_digest(mut self, pev_digest: [u8; 32]) -> Self {
        self.pev_digest = Some(pev_digest);
        if let Some(ref mut vector) = self.pev {
            vector.pev_digest = Some(ucf::v1::Digest32 {
                value: pev_digest.to_vec(),
            });
        }
        self
    }
}

impl PvgsReader for MockPvgsReader {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        self.pev.clone()
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        self.pev_digest.or_else(|| {
            self.pev
                .as_ref()
                .and_then(|pev| pev.pev_digest.as_ref())
                .and_then(digest32_to_array)
        })
    }
}

impl PvgsClient for MockPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_experience_record(record)
    }
}

fn digest_pev(pev: &ucf::v1::PolicyEcologyVector) -> [u8; 32] {
    ucf_protocol::digest_proto(
        "UCF:HASH:POLICY_ECOLOGY_VECTOR",
        &ucf_protocol::canonical_bytes(pev),
    )
}

fn digest32_to_array(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    digest.value.clone().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pvgs_verify::{
        pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
        verify_pvgs_receipt, VerifyError,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::convert::TryFrom;

    fn sample_digest(seed: u8) -> ucf::v1::Digest32 {
        ucf::v1::Digest32 {
            value: vec![seed; 32],
        }
    }

    fn sample_receipt_template() -> ucf::v1::PvgsReceipt {
        ucf::v1::PvgsReceipt {
            receipt_epoch: "epoch-1".to_string(),
            receipt_id: "receipt-abc".to_string(),
            receipt_digest: Some(sample_digest(1)),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: Some(sample_digest(2)),
            decision_digest: Some(sample_digest(3)),
            grant_id: "grant-1".to_string(),
            charter_version_digest: Some(sample_digest(4)),
            policy_version_digest: Some(sample_digest(5)),
            prev_record_digest: Some(sample_digest(6)),
            profile_digest: Some(sample_digest(7)),
            tool_profile_digest: Some(sample_digest(8)),
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    fn signing_key(seed: u64, key_id_suffix: u8) -> (SigningKey, String) {
        let mut bytes = [0u8; 32];
        StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        (sk, format!("pvgs-key-{key_id_suffix}"))
    }

    fn signed_key_epoch_with_timestamp(
        signing_key: &SigningKey,
        epoch_id: u64,
        key_id: &str,
        timestamp_ms: u64,
    ) -> ucf::v1::PvgsKeyEpoch {
        let mut key_epoch = ucf::v1::PvgsKeyEpoch {
            epoch_id,
            attestation_key_id: key_id.to_string(),
            attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            announcement_digest: None,
            signature: None,
            timestamp_ms,
            vrf_key_id: Some("pvgs-vrf-1".to_string()),
        };

        let digest = pvgs_key_epoch_digest(&key_epoch);
        key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
        let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
        key_epoch.signature = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_epoch.attestation_key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        key_epoch
    }

    fn signed_key_epoch(
        signing_key: &SigningKey,
        epoch_id: u64,
        key_id: &str,
    ) -> ucf::v1::PvgsKeyEpoch {
        signed_key_epoch_with_timestamp(signing_key, epoch_id, key_id, 1_700_000_000_000)
    }

    fn sign_receipt(
        mut receipt: ucf::v1::PvgsReceipt,
        signing_key: &SigningKey,
        key_id: &str,
    ) -> ucf::v1::PvgsReceipt {
        let sig = signing_key.sign(&pvgs_receipt_signing_preimage(&receipt));
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        receipt
    }

    #[test]
    fn sync_sorts_and_ingests() {
        let (signing_key, key_id) = signing_key(7, 1);
        let epoch_one = signed_key_epoch(&signing_key, 1, &key_id);
        let epoch_two = signed_key_epoch(&signing_key, 2, &key_id);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        sync.sync_from_list(vec![epoch_two, epoch_one]).unwrap();

        assert_eq!(sync.store().latest_epoch(), Some(2));
        assert_eq!(
            sync.store().pubkey_for_key_id(&key_id),
            Some(signing_key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn mock_reader_exposes_pev_and_digest() {
        let reader = MockPvgsReader::default();
        let pev = reader.get_latest_pev().expect("pev available");
        assert_eq!(
            ucf::v1::PolicyEcologyBias::try_from(pev.conservatism_bias),
            Ok(ucf::v1::PolicyEcologyBias::Medium)
        );

        let digest = reader
            .get_latest_pev_digest()
            .expect("pev digest available");
        assert_eq!(
            pev.pev_digest.as_ref().and_then(digest32_to_array),
            Some(digest)
        );
    }

    fn experience_record(include_governance: bool) -> ucf::v1::ExperienceRecord {
        let core_frame = ucf::v1::CoreFrame {
            session_id: "s".to_string(),
            step_id: "step".to_string(),
            input_packet_refs: Vec::new(),
            intent_refs: Vec::new(),
            candidate_refs: vec![sample_digest(9)],
            workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
        };
        let metabolic_frame = ucf::v1::MetabolicFrame {
            profile_state: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            control_frame_ref: Some(sample_digest(8)),
            hormone_classes: vec![ucf::v1::HormoneClass::Low.into()],
            noise_class: ucf::v1::NoiseClass::Medium.into(),
            priority_class: ucf::v1::PriorityClass::Medium.into(),
        };

        let governance_frame = include_governance.then(|| ucf::v1::GovernanceFrame {
            policy_decision_refs: vec![sample_digest(7)],
            grant_refs: Vec::new(),
            dlp_refs: Vec::new(),
            budget_snapshot_ref: Some(sample_digest(6)),
            pvgs_receipt_ref: None,
            reason_codes: None,
        });

        let governance_frame_ref = governance_frame.as_ref().map(|gf| ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:GOVERNANCE_FRAME",
                &ucf_protocol::canonical_bytes(gf),
            )
            .to_vec(),
        });

        let core_frame_ref = ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:CORE_FRAME",
                &ucf_protocol::canonical_bytes(&core_frame),
            )
            .to_vec(),
        };

        let metabolic_frame_ref = ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:METABOLIC_FRAME",
                &ucf_protocol::canonical_bytes(&metabolic_frame),
            )
            .to_vec(),
        };

        ucf::v1::ExperienceRecord {
            record_type: ucf::v1::RecordType::ActionExec.into(),
            core_frame: Some(core_frame),
            metabolic_frame: Some(metabolic_frame),
            governance_frame,
            core_frame_ref: Some(core_frame_ref),
            metabolic_frame_ref: Some(metabolic_frame_ref),
            governance_frame_ref,
        }
    }

    #[test]
    fn local_client_rejects_missing_governance() {
        let mut client = LocalPvgsClient::default();
        let receipt = client
            .commit_experience_record(experience_record(false))
            .expect("receipt returned");

        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Rejected)
        );
        assert!(receipt
            .reject_reason_codes
            .iter()
            .any(|rc| rc == "RC.GV.MISSING"));
    }

    #[test]
    fn local_client_serializes_deterministically() {
        let mut client = LocalPvgsClient::default();
        let record = experience_record(true);

        let _ = client
            .commit_experience_record(record.clone())
            .expect("first receipt");
        let _ = client
            .commit_experience_record(record)
            .expect("second receipt");

        assert_eq!(client.committed_bytes.len(), 2);
        assert_eq!(client.committed_bytes[0], client.committed_bytes[1]);
    }

    #[test]
    fn rejecting_client_flags_rejected_status() {
        let mut client = LocalPvgsClient::rejecting(vec!["RC.RE.INTEGRITY.DEGRADED".to_string()]);
        let receipt = client
            .commit_experience_record(experience_record(true))
            .expect("receipt returned");

        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Rejected)
        );
        assert!(receipt
            .reject_reason_codes
            .iter()
            .any(|rc| rc == "RC.RE.INTEGRITY.DEGRADED"));
    }

    #[test]
    fn sync_rejects_invalid_signature() {
        let (signing_key, key_id) = signing_key(11, 2);
        let mut invalid_epoch = signed_key_epoch(&signing_key, 2, &key_id);
        invalid_epoch
            .signature
            .as_mut()
            .expect("signature")
            .signature
            .reverse();

        let valid_epoch = signed_key_epoch(&signing_key, 1, &key_id);
        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());

        let err = sync
            .sync_from_list(vec![invalid_epoch, valid_epoch])
            .unwrap_err();

        assert!(matches!(
            err,
            SyncError::Ingest {
                epoch_id: 2,
                source: IngestError::InvalidSignature
            }
        ));
        assert_eq!(sync.store().latest_epoch(), Some(1));
    }

    #[test]
    fn sync_rejects_conflicting_duplicate_epoch() {
        let (signing_key, key_id) = signing_key(21, 3);
        let epoch = signed_key_epoch_with_timestamp(&signing_key, 3, &key_id, 1_700_000_000_000);
        let conflicting =
            signed_key_epoch_with_timestamp(&signing_key, 3, &key_id, 1_700_100_000_000);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        let err = sync
            .sync_from_list(vec![epoch.clone(), conflicting])
            .unwrap_err();

        assert!(matches!(
            err,
            SyncError::Ingest {
                epoch_id: 3,
                source: IngestError::ConflictingEpoch
            }
        ));
        assert_eq!(sync.store().latest_epoch(), Some(3));
    }

    #[test]
    fn receipt_verify_after_sync() {
        let (epoch_one_key, epoch_one_id) = signing_key(31, 4);
        let (epoch_two_key, epoch_two_id) = signing_key(41, 5);

        let epochs = vec![
            signed_key_epoch(&epoch_one_key, 1, &epoch_one_id),
            signed_key_epoch(&epoch_two_key, 2, &epoch_two_id),
        ];

        let receipt = sign_receipt(sample_receipt_template(), &epoch_two_key, &epoch_two_id);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        let err = verify_pvgs_receipt(&receipt, sync.store()).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKeyId(_)));

        sync.sync_from_list(epochs).unwrap();

        assert_eq!(verify_pvgs_receipt(&receipt, sync.store()), Ok(()));
    }

    #[test]
    fn store_consistency_after_sync() {
        let (signing_key, key_id) = signing_key(51, 6);
        let epoch_one = signed_key_epoch(&signing_key, 1, &key_id);
        let epoch_two =
            signed_key_epoch_with_timestamp(&signing_key, 2, &key_id, 1_700_200_000_000);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        sync.sync_from_list(vec![epoch_two, epoch_one]).unwrap();

        assert_eq!(sync.store().latest_epoch(), Some(2));
        assert_eq!(
            sync.store().pubkey_for_key_id(&key_id),
            Some(signing_key.verifying_key().to_bytes())
        );
    }
}
