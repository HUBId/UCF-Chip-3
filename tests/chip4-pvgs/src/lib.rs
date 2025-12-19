#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use pvgs_verify::{pvgs_receipt_signing_preimage, PvgsKeyEpochStore};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use ucf_protocol::{canonical_bytes, digest32, digest_proto, ucf};
use ucf_test_utils::{make_pvgs_key_epoch, make_pvgs_receipt_accepted};

const RECEIPT_DOMAIN: &str = "UCF:HASH:PVGS_RECEIPT";

#[derive(Debug, Clone)]
pub struct LocalPvgs {
    signing_key: SigningKey,
    attestation_key_id: String,
    key_epochs: Vec<ucf::v1::PvgsKeyEpoch>,
    latest_ruleset_digest: Option<[u8; 32]>,
    registry_commit_count: usize,
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
            signing_key,
            attestation_key_id,
            key_epochs: Vec::new(),
            latest_ruleset_digest: None,
            registry_commit_count: 0,
        }
    }

    pub fn publish_key_epoch(&mut self, epoch_id: u64) -> ucf::v1::PvgsKeyEpoch {
        let key_epoch = make_pvgs_key_epoch(epoch_id, &self.signing_key);
        self.attestation_key_id = key_epoch.attestation_key_id.clone();
        self.key_epochs.push(key_epoch.clone());
        key_epoch
    }

    pub fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> ucf::v1::PvgsReceipt {
        let bytes = canonical_bytes(&trc);
        let registry_digest = digest_proto("UCF:HASH:TOOL_REGISTRY", &bytes);
        self.latest_ruleset_digest = Some(registry_digest);
        self.registry_commit_count += 1;

        let mut receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", self.registry_commit_count),
            receipt_id: format!("registry-{}", self.registry_commit_count),
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
            prev_record_digest: Some(ucf::v1::Digest32 {
                value: vec![3u8; 32],
            }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let signature = self.signing_key.sign(&preimage);
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: self.attestation_key_id.as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        });

        receipt
    }

    pub fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.latest_ruleset_digest
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
        let key_epoch = self
            .key_epochs
            .last()
            .expect("publish a key epoch before issuing receipts");

        make_pvgs_receipt_accepted(
            action_digest,
            decision_digest,
            profile_digest,
            tool_profile_digest,
            &self.signing_key,
            key_epoch,
            grant_id,
        )
    }

    pub fn attestation_key_id(&self) -> &str {
        &self.attestation_key_id
    }

    pub fn key_epochs(&self) -> &[ucf::v1::PvgsKeyEpoch] {
        &self.key_epochs
    }
}

pub fn ingest_published_epochs(
    pvgs: &LocalPvgs,
    store: &mut PvgsKeyEpochStore,
) -> Result<(), pvgs_verify::IngestError> {
    for epoch in pvgs.key_epochs() {
        store.ingest_key_epoch(epoch.clone())?;
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
