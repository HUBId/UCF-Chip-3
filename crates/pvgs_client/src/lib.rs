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
pub enum ClientError {
    #[error("receipt verification failed")]
    VerificationFailed,
    #[error("commit rejected: {0}")]
    CommitRejected(String),
}

#[derive(Debug, Clone)]
pub struct CommitRequest {
    pub payload_hint: String,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub receipt_id: String,
}

pub trait PvgsClient: Send + Sync {
    fn commit(&self, request: CommitRequest) -> Result<Receipt, ClientError>;
    fn verify(&self, receipt: &Receipt) -> Result<(), ClientError>;
}

pub struct NoopPvgsClient;

impl PvgsClient for NoopPvgsClient {
    fn commit(&self, request: CommitRequest) -> Result<Receipt, ClientError> {
        Ok(Receipt {
            receipt_id: format!("noop-{}", request.payload_hint),
        })
    }

    fn verify(&self, _receipt: &Receipt) -> Result<(), ClientError> {
        Ok(())
    }
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
