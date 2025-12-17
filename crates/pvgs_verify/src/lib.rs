#![forbid(unsafe_code)]

use std::collections::HashMap;

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;
use ucf_protocol::ucf;

const SIGNATURE_DOMAIN: &[u8] = b"UCF:SIGN:PVGS_RECEIPT";
const KEY_EPOCH_HASH_DOMAIN: &[u8] = b"UCF:HASH:PVGS_KEY_EPOCH";
const KEY_EPOCH_SIGN_DOMAIN: &[u8] = b"UCF:SIGN:PVGS_KEY_EPOCH";
const ED25519: &str = "ed25519";

#[derive(Debug, Default, Clone)]
pub struct PvgsKeyEpochStore {
    keys: HashMap<String, [u8; 32]>,
    epoch_keys: HashMap<String, String>,
    latest_epoch_id: Option<u64>,
}

impl PvgsKeyEpochStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            epoch_keys: HashMap::new(),
            latest_epoch_id: None,
        }
    }

    pub fn insert_key(&mut self, key_id: String, pubkey: [u8; 32]) {
        self.keys.insert(key_id, pubkey);
    }

    pub fn get_pubkey(&self, key_id: &str) -> Option<[u8; 32]> {
        self.keys.get(key_id).copied()
    }

    #[allow(dead_code)]
    pub fn insert_epoch_binding(&mut self, epoch_id: String, key_id: String) {
        self.epoch_keys.insert(epoch_id, key_id);
    }

    #[allow(dead_code)]
    pub fn get_epoch_key(&self, epoch_id: &str) -> Option<&String> {
        self.epoch_keys.get(epoch_id)
    }

    pub fn latest_epoch_id(&self) -> Option<u64> {
        self.latest_epoch_id
    }

    pub fn ingest_announcement(&mut self, ann: KeyEpochAnnouncement) -> Result<(), IngestError> {
        if !verify_key_epoch_announcement(&ann) {
            return Err(IngestError::InvalidAnnouncement);
        }

        self.insert_key(ann.key_id.clone(), ann.public_key);
        match self.latest_epoch_id {
            Some(current) if ann.epoch_id > current => self.latest_epoch_id = Some(ann.epoch_id),
            None => self.latest_epoch_id = Some(ann.epoch_id),
            _ => {}
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEpochAnnouncement {
    pub epoch_id: u64,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub announcement_digest: [u8; 32],
    pub signature: Vec<u8>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngestError {
    #[error("invalid announcement")]
    InvalidAnnouncement,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("missing signer")]
    MissingSigner,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid signer key id bytes")]
    InvalidSigner,
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),
    #[error("invalid public key for signer: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("schema invalid: {0}")]
    Schema(String),
}

pub fn pvgs_receipt_signing_preimage(receipt: &ucf::v1::PvgsReceipt) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(receipt.receipt_epoch.as_bytes());
    preimage.extend_from_slice(receipt.receipt_id.as_bytes());
    preimage.extend_from_slice(digest_bytes(&receipt.receipt_digest));
    preimage.extend_from_slice(&receipt.status.to_be_bytes());
    preimage.extend_from_slice(digest_bytes(&receipt.action_digest));
    preimage.extend_from_slice(digest_bytes(&receipt.decision_digest));
    preimage.extend_from_slice(receipt.grant_id.as_bytes());
    preimage.extend_from_slice(digest_bytes(&receipt.charter_version_digest));
    preimage.extend_from_slice(digest_bytes(&receipt.policy_version_digest));
    preimage.extend_from_slice(digest_bytes(&receipt.prev_record_digest));
    preimage.extend_from_slice(digest_bytes(&receipt.profile_digest));
    preimage.extend_from_slice(digest_bytes(&receipt.tool_profile_digest));

    let mut reject_codes = receipt.reject_reason_codes.clone();
    reject_codes.sort();
    for code in reject_codes {
        preimage.extend_from_slice(code.as_bytes());
    }

    preimage
}

pub fn verify_pvgs_receipt(
    receipt: &ucf::v1::PvgsReceipt,
    store: &PvgsKeyEpochStore,
) -> Result<(), VerifyError> {
    let signer = receipt.signer.as_ref().ok_or(VerifyError::MissingSigner)?;

    if signer.algorithm.to_ascii_lowercase() != ED25519 {
        return Err(VerifyError::UnsupportedAlgorithm(signer.algorithm.clone()));
    }

    let key_id =
        String::from_utf8(signer.signer.clone()).map_err(|_| VerifyError::InvalidSigner)?;
    let pubkey = store
        .get_pubkey(&key_id)
        .ok_or_else(|| VerifyError::UnknownKeyId(key_id.clone()))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|_| VerifyError::InvalidPublicKey(key_id.clone()))?;

    ensure_required_fields(receipt)?;
    let preimage = pvgs_receipt_signing_preimage(receipt);
    let sig = Signature::from_slice(&signer.signature)
        .map_err(|_| VerifyError::InvalidSignatureEncoding)?;
    verifying_key
        .verify(&preimage, &sig)
        .map_err(|_| VerifyError::InvalidSignature)?;

    let status = ucf::v1::ReceiptStatus::try_from(receipt.status)
        .map_err(|_| VerifyError::Schema("invalid receipt status".to_string()))?;
    match status {
        ucf::v1::ReceiptStatus::Accepted => {
            if !receipt.reject_reason_codes.is_empty() {
                return Err(VerifyError::Schema(
                    "accepted receipts must not contain reject reason codes".to_string(),
                ));
            }
        }
        ucf::v1::ReceiptStatus::Rejected => {
            if receipt.reject_reason_codes.is_empty() {
                return Err(VerifyError::Schema(
                    "rejected receipts must include reject reason codes".to_string(),
                ));
            }
        }
        _ => {
            return Err(VerifyError::Schema(
                "receipt must be accepted or rejected".to_string(),
            ))
        }
    }

    Ok(())
}

fn ensure_required_fields(receipt: &ucf::v1::PvgsReceipt) -> Result<(), VerifyError> {
    for (label, present) in [
        ("receipt_epoch", !receipt.receipt_epoch.is_empty()),
        ("receipt_id", !receipt.receipt_id.is_empty()),
        ("receipt_digest", receipt.receipt_digest.is_some()),
        ("action_digest", receipt.action_digest.is_some()),
        ("decision_digest", receipt.decision_digest.is_some()),
        (
            "charter_version_digest",
            receipt.charter_version_digest.is_some(),
        ),
        (
            "policy_version_digest",
            receipt.policy_version_digest.is_some(),
        ),
        ("prev_record_digest", receipt.prev_record_digest.is_some()),
        ("profile_digest", receipt.profile_digest.is_some()),
        ("tool_profile_digest", receipt.tool_profile_digest.is_some()),
    ] {
        if !present {
            return Err(VerifyError::Schema(format!("missing {label}")));
        }
    }

    Ok(())
}

fn digest_bytes(opt: &Option<ucf::v1::Digest32>) -> &[u8] {
    opt.as_ref()
        .map(|d| d.value.as_slice())
        .unwrap_or_else(|| &[])
}

pub fn key_epoch_announcement_digest(ann: &KeyEpochAnnouncement) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(KEY_EPOCH_HASH_DOMAIN);
    hasher.update(&ann.epoch_id.to_be_bytes());
    hasher.update(ann.key_id.as_bytes());
    hasher.update(&ann.public_key);
    hasher.update(&ann.timestamp_ms.to_be_bytes());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(hasher.finalize().as_bytes());
    digest
}

pub fn key_epoch_announcement_preimage(ann: &KeyEpochAnnouncement) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(KEY_EPOCH_SIGN_DOMAIN);
    preimage.extend_from_slice(&ann.epoch_id.to_be_bytes());
    preimage.extend_from_slice(ann.key_id.as_bytes());
    preimage.extend_from_slice(&ann.public_key);
    preimage.extend_from_slice(&ann.announcement_digest);
    preimage.extend_from_slice(&ann.timestamp_ms.to_be_bytes());
    preimage
}

pub fn verify_key_epoch_announcement(ann: &KeyEpochAnnouncement) -> bool {
    if key_epoch_announcement_digest(ann) != ann.announcement_digest {
        return false;
    }

    let preimage = key_epoch_announcement_preimage(ann);
    let signature = match Signature::from_slice(&ann.signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_bytes(&ann.public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    verifying_key.verify(&preimage, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    fn sample_announcement(signing_key: &ed25519_dalek::SigningKey) -> KeyEpochAnnouncement {
        let mut ann = KeyEpochAnnouncement {
            epoch_id: 1,
            key_id: "pvgs-key-1".to_string(),
            public_key: signing_key.verifying_key().to_bytes(),
            announcement_digest: [0; 32],
            signature: Vec::new(),
            timestamp_ms: 1_700_000_000_000,
        };

        ann.announcement_digest = key_epoch_announcement_digest(&ann);
        let sig = signing_key.sign(&key_epoch_announcement_preimage(&ann));
        ann.signature = sig.to_bytes().to_vec();
        ann
    }

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

    fn keypair() -> (ed25519_dalek::SigningKey, String) {
        let mut seed = [0u8; 32];
        StdRng::seed_from_u64(42).fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        (sk, "pvgs-key-1".to_string())
    }

    fn sign_receipt(mut receipt: ucf::v1::PvgsReceipt) -> ucf::v1::PvgsReceipt {
        let (sk, key_id) = keypair();
        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let sig = sk.sign(&preimage);
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: ED25519.to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        receipt
    }

    #[test]
    fn verify_passes_for_valid_receipt() {
        let mut store = PvgsKeyEpochStore::new();
        let (sk, key_id) = keypair();
        store.insert_key(key_id.clone(), sk.verifying_key().to_bytes());

        let receipt = sign_receipt(sample_receipt_template());
        assert_eq!(verify_pvgs_receipt(&receipt, &store), Ok(()));
    }

    #[test]
    fn verify_fails_for_tampered_receipt() {
        let mut store = PvgsKeyEpochStore::new();
        let (sk, key_id) = keypair();
        store.insert_key(key_id.clone(), sk.verifying_key().to_bytes());

        let mut receipt = sign_receipt(sample_receipt_template());
        receipt.charter_version_digest = Some(sample_digest(9));
        let result = verify_pvgs_receipt(&receipt, &store);
        assert!(matches!(result, Err(VerifyError::InvalidSignature)));
    }

    #[test]
    fn ingest_and_verify_announcement_succeeds() {
        let (sk, key_id) = keypair();
        let announcement = sample_announcement(&sk);

        let mut store = PvgsKeyEpochStore::new();
        store.ingest_announcement(announcement.clone()).unwrap();

        assert_eq!(
            store.get_pubkey(&key_id),
            Some(announcement.public_key),
            "ingestor should populate store"
        );
        assert_eq!(store.latest_epoch_id(), Some(announcement.epoch_id));
    }

    #[test]
    fn ingest_rejects_tampered_announcement() {
        let (sk, _) = keypair();
        let mut announcement = sample_announcement(&sk);
        announcement.announcement_digest[0] ^= 0xFF;

        let mut store = PvgsKeyEpochStore::new();
        let err = store.ingest_announcement(announcement).unwrap_err();
        assert_eq!(err, IngestError::InvalidAnnouncement);
    }

    #[test]
    fn ingest_rejects_invalid_signature() {
        let (sk, _) = keypair();
        let mut announcement = sample_announcement(&sk);
        announcement.signature.reverse();

        let mut store = PvgsKeyEpochStore::new();
        let err = store.ingest_announcement(announcement).unwrap_err();
        assert_eq!(err, IngestError::InvalidAnnouncement);
    }

    #[test]
    fn verify_receipt_requires_known_key() {
        let receipt = sign_receipt(sample_receipt_template());
        let store = PvgsKeyEpochStore::new();
        let err = verify_pvgs_receipt(&receipt, &store).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKeyId(_)));
    }

    #[test]
    fn receipt_verification_succeeds_after_ingest() {
        let (sk, key_id) = keypair();
        let announcement = sample_announcement(&sk);

        let mut store = PvgsKeyEpochStore::new();
        store.ingest_announcement(announcement).unwrap();

        let receipt = sign_receipt(sample_receipt_template());
        assert_eq!(verify_pvgs_receipt(&receipt, &store), Ok(()));
        assert_eq!(
            store.get_pubkey(&key_id),
            Some(sk.verifying_key().to_bytes())
        );
    }
}
