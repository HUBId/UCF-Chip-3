#![forbid(unsafe_code)]

use std::collections::HashMap;

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;
use ucf_protocol::{canonical_bytes, ucf};

const SIGNATURE_DOMAIN: &[u8] = b"UCF:SIGN:PVGS_RECEIPT";
const KEY_EPOCH_HASH_DOMAIN: &[u8] = b"UCF:HASH:PVGS_KEY_EPOCH";
const KEY_EPOCH_SIGN_DOMAIN: &[u8] = b"UCF:SIGN:PVGS_KEY_EPOCH";
const ED25519: &str = "ed25519";

#[derive(Debug, Default, Clone)]
pub struct PvgsKeyEpochStore {
    keys: HashMap<String, [u8; 32]>,
    epoch_keys: HashMap<u64, EpochBinding>,
    latest_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EpochBinding {
    attestation_key_id: String,
    vrf_key_id: Option<String>,
    digest: [u8; 32],
}

impl PvgsKeyEpochStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            epoch_keys: HashMap::new(),
            latest_epoch: None,
        }
    }

    pub fn pubkey_for_key_id(&self, key_id: &str) -> Option<[u8; 32]> {
        self.keys.get(key_id).copied()
    }

    pub fn latest_epoch(&self) -> Option<u64> {
        self.latest_epoch
    }

    pub fn ingest_key_epoch(
        &mut self,
        key_epoch: ucf::v1::PvgsKeyEpoch,
    ) -> Result<(), IngestError> {
        let pubkey = attestation_public_key(&key_epoch)?;
        let digest = announcement_digest_bytes(&key_epoch)?;

        let expected_digest = pvgs_key_epoch_digest(&key_epoch);
        if digest != expected_digest {
            return Err(IngestError::DigestMismatch);
        }

        verify_key_epoch_signature(&key_epoch, &pubkey)?;

        if let Some(existing) = self.epoch_keys.get(&key_epoch.epoch_id) {
            if existing.digest != digest {
                return Err(IngestError::ConflictingEpoch);
            }

            self.keys
                .entry(key_epoch.attestation_key_id.clone())
                .or_insert(pubkey);
            return Ok(());
        }

        self.keys
            .insert(key_epoch.attestation_key_id.clone(), pubkey);
        self.epoch_keys.insert(
            key_epoch.epoch_id,
            EpochBinding {
                attestation_key_id: key_epoch.attestation_key_id.clone(),
                vrf_key_id: key_epoch.vrf_key_id.clone(),
                digest,
            },
        );

        match self.latest_epoch {
            Some(current) if key_epoch.epoch_id > current => {
                self.latest_epoch = Some(key_epoch.epoch_id)
            }
            None => self.latest_epoch = Some(key_epoch.epoch_id),
            _ => {}
        }

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IngestError {
    #[error("missing announcement digest")]
    MissingAnnouncementDigest,
    #[error("announcement digest must be 32 bytes")]
    InvalidAnnouncementDigestLength,
    #[error("missing signature")]
    MissingSignature,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    #[error("attestation public key must be 32 bytes")]
    InvalidAttestationPublicKey,
    #[error("invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("announcement digest mismatch")]
    DigestMismatch,
    #[error("conflicting key epoch")]
    ConflictingEpoch,
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
    #[error("latest epoch {latest:?} behind required {required}")]
    LatestEpochTooLow { required: u64, latest: Option<u64> },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VerifyOptions {
    pub require_latest_epoch_at_least: Option<u64>,
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
    verify_pvgs_receipt_with_options(receipt, store, &VerifyOptions::default())
}

pub fn verify_pvgs_receipt_with_options(
    receipt: &ucf::v1::PvgsReceipt,
    store: &PvgsKeyEpochStore,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signer = receipt.signer.as_ref().ok_or(VerifyError::MissingSigner)?;

    if signer.algorithm.to_ascii_lowercase() != ED25519 {
        return Err(VerifyError::UnsupportedAlgorithm(signer.algorithm.clone()));
    }

    let key_id =
        String::from_utf8(signer.signer.clone()).map_err(|_| VerifyError::InvalidSigner)?;
    let pubkey = store
        .pubkey_for_key_id(&key_id)
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

    if let Some(required_epoch) = options.require_latest_epoch_at_least {
        let latest = store.latest_epoch();
        if latest.is_none_or(|epoch| epoch < required_epoch) {
            return Err(VerifyError::LatestEpochTooLow {
                required: required_epoch,
                latest,
            });
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

pub fn pvgs_key_epoch_digest(key_epoch: &ucf::v1::PvgsKeyEpoch) -> [u8; 32] {
    let canonical = canonical_key_epoch_without_signature_or_digest(key_epoch);
    let mut hasher = Hasher::new();
    hasher.update(KEY_EPOCH_HASH_DOMAIN);
    hasher.update(&canonical);
    *hasher.finalize().as_bytes()
}

pub fn pvgs_key_epoch_signing_preimage(key_epoch: &ucf::v1::PvgsKeyEpoch) -> Vec<u8> {
    let canonical = canonical_key_epoch_without_signature(key_epoch);
    let mut preimage = Vec::new();
    preimage.extend_from_slice(KEY_EPOCH_SIGN_DOMAIN);
    preimage.extend_from_slice(&canonical);
    preimage
}

fn canonical_key_epoch_without_signature(key_epoch: &ucf::v1::PvgsKeyEpoch) -> Vec<u8> {
    let mut canonicalized = key_epoch.clone();
    canonicalized.signature = None;
    canonical_bytes(&canonicalized)
}

fn canonical_key_epoch_without_signature_or_digest(key_epoch: &ucf::v1::PvgsKeyEpoch) -> Vec<u8> {
    let mut canonicalized = key_epoch.clone();
    canonicalized.signature = None;
    canonicalized.announcement_digest = None;
    canonical_bytes(&canonicalized)
}

fn attestation_public_key(key_epoch: &ucf::v1::PvgsKeyEpoch) -> Result<[u8; 32], IngestError> {
    let key_bytes = &key_epoch.attestation_public_key;
    if key_bytes.len() != 32 {
        return Err(IngestError::InvalidAttestationPublicKey);
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(key_bytes);
    Ok(pubkey)
}

fn announcement_digest_bytes(key_epoch: &ucf::v1::PvgsKeyEpoch) -> Result<[u8; 32], IngestError> {
    let digest = key_epoch
        .announcement_digest
        .as_ref()
        .ok_or(IngestError::MissingAnnouncementDigest)?;

    if digest.value.len() != 32 {
        return Err(IngestError::InvalidAnnouncementDigestLength);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest.value);
    Ok(bytes)
}

fn verify_key_epoch_signature(
    key_epoch: &ucf::v1::PvgsKeyEpoch,
    attestation_pubkey: &[u8; 32],
) -> Result<(), IngestError> {
    let signature = key_epoch
        .signature
        .as_ref()
        .ok_or(IngestError::MissingSignature)?;

    if signature.algorithm.to_ascii_lowercase() != ED25519 {
        return Err(IngestError::UnsupportedSignatureAlgorithm(
            signature.algorithm.clone(),
        ));
    }

    let preimage = pvgs_key_epoch_signing_preimage(key_epoch);
    let verifying_key = VerifyingKey::from_bytes(attestation_pubkey)
        .map_err(|_| IngestError::InvalidAttestationPublicKey)?;
    let sig = Signature::from_slice(&signature.signature)
        .map_err(|_| IngestError::InvalidSignatureEncoding)?;

    verifying_key
        .verify(&preimage, &sig)
        .map_err(|_| IngestError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

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

    fn signing_key() -> (ed25519_dalek::SigningKey, String) {
        let mut seed = [0u8; 32];
        StdRng::seed_from_u64(42).fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        (sk, "pvgs-key-1".to_string())
    }

    fn signed_key_epoch(
        signing_key: &ed25519_dalek::SigningKey,
        epoch_id: u64,
    ) -> ucf::v1::PvgsKeyEpoch {
        let mut key_epoch = ucf::v1::PvgsKeyEpoch {
            epoch_id,
            attestation_key_id: "pvgs-key-1".to_string(),
            attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            announcement_digest: None,
            signature: None,
            timestamp_ms: 1_700_000_000_000,
            vrf_key_id: Some("pvgs-vrf-1".to_string()),
        };

        let digest = pvgs_key_epoch_digest(&key_epoch);
        key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
        let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
        key_epoch.signature = Some(ucf::v1::Signature {
            algorithm: ED25519.to_string(),
            signer: key_epoch.attestation_key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        key_epoch
    }

    fn sign_receipt(
        mut receipt: ucf::v1::PvgsReceipt,
        signing_key: &ed25519_dalek::SigningKey,
        key_id: &str,
    ) -> ucf::v1::PvgsReceipt {
        let sig = signing_key.sign(&pvgs_receipt_signing_preimage(&receipt));
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: ED25519.to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        receipt
    }

    #[test]
    fn ingest_valid_pvgs_key_epoch() {
        let (sk, key_id) = signing_key();
        let key_epoch = signed_key_epoch(&sk, 7);
        let mut store = PvgsKeyEpochStore::new();

        store.ingest_key_epoch(key_epoch.clone()).unwrap();

        assert_eq!(
            store.pubkey_for_key_id(&key_id),
            Some(sk.verifying_key().to_bytes())
        );
        assert_eq!(store.latest_epoch(), Some(key_epoch.epoch_id));
    }

    #[test]
    fn reject_invalid_digest() {
        let (sk, _) = signing_key();
        let mut key_epoch = signed_key_epoch(&sk, 1);
        key_epoch
            .announcement_digest
            .as_mut()
            .expect("digest")
            .value[0] ^= 0xFF;

        let mut store = PvgsKeyEpochStore::new();
        let err = store.ingest_key_epoch(key_epoch).unwrap_err();
        assert_eq!(err, IngestError::DigestMismatch);
    }

    #[test]
    fn reject_invalid_signature() {
        let (sk, _) = signing_key();
        let mut key_epoch = signed_key_epoch(&sk, 2);
        key_epoch
            .signature
            .as_mut()
            .expect("signature")
            .signature
            .reverse();

        let mut store = PvgsKeyEpochStore::new();
        let err = store.ingest_key_epoch(key_epoch).unwrap_err();
        assert_eq!(err, IngestError::InvalidSignature);
    }

    #[test]
    fn verify_receipt_requires_known_key() {
        let (sk, key_id) = signing_key();
        let receipt = sign_receipt(sample_receipt_template(), &sk, &key_id);
        let store = PvgsKeyEpochStore::new();
        let err = verify_pvgs_receipt(&receipt, &store).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKeyId(_)));
    }

    #[test]
    fn receipt_verification_succeeds_after_ingest() {
        let (sk, key_id) = signing_key();
        let key_epoch = signed_key_epoch(&sk, 3);

        let mut store = PvgsKeyEpochStore::new();
        store.ingest_key_epoch(key_epoch).unwrap();

        let receipt = sign_receipt(sample_receipt_template(), &sk, &key_id);
        assert_eq!(verify_pvgs_receipt(&receipt, &store), Ok(()));
    }

    #[test]
    fn verify_fails_for_tampered_receipt() {
        let (sk, key_id) = signing_key();
        let key_epoch = signed_key_epoch(&sk, 4);
        let mut store = PvgsKeyEpochStore::new();
        store.ingest_key_epoch(key_epoch).unwrap();

        let mut receipt = sign_receipt(sample_receipt_template(), &sk, &key_id);
        receipt.charter_version_digest = Some(sample_digest(9));
        let result = verify_pvgs_receipt(&receipt, &store);
        assert!(matches!(result, Err(VerifyError::InvalidSignature)));
    }

    #[test]
    fn verify_checks_latest_epoch_when_required() {
        let (sk, key_id) = signing_key();
        let key_epoch = signed_key_epoch(&sk, 5);
        let mut store = PvgsKeyEpochStore::new();
        store.ingest_key_epoch(key_epoch).unwrap();

        let receipt = sign_receipt(sample_receipt_template(), &sk, &key_id);
        let opts = VerifyOptions {
            require_latest_epoch_at_least: Some(5),
        };

        assert_eq!(
            verify_pvgs_receipt_with_options(&receipt, &store, &opts),
            Ok(())
        );

        let err = verify_pvgs_receipt_with_options(
            &receipt,
            &store,
            &VerifyOptions {
                require_latest_epoch_at_least: Some(6),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::LatestEpochTooLow {
                required: 6,
                latest: Some(5)
            }
        ));
    }
}
