#![forbid(unsafe_code)]

use blake3::Hasher;
use control::control_frame_digest as compute_control_frame_digest;
use ed25519_dalek::{Signer, SigningKey};
use pvgs_verify::{
    pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
};
use ucf_protocol::{canonical_bytes, digest32, ucf};

const TOOL_PROFILE_HASH_DOMAIN: &str = "UCF:HASH:TOOL_PROFILE";
const RECEIPT_HASH_DOMAIN: &str = "UCF:HASH:PVGS_RECEIPT";

pub fn make_control_frame(
    profile: ucf::v1::ControlFrameProfile,
    overlays: Option<ucf::v1::ControlFrameOverlays>,
    mask: ucf::v1::ToolClassMask,
) -> (ucf::v1::ControlFrame, ucf::v1::Digest32) {
    let frame = ucf::v1::ControlFrame {
        frame_id: format!("cf-{profile:?}"),
        note: String::new(),
        active_profile: profile.into(),
        overlays,
        toolclass_mask: Some(mask),
        deescalation_lock: false,
        reason_codes: None,
        evidence_refs: Vec::new(),
    };

    let digest = control_frame_digest(&frame);
    (frame, digest)
}

pub fn control_frame_digest(frame: &ucf::v1::ControlFrame) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: compute_control_frame_digest(frame).to_vec(),
    }
}

pub fn make_tool_action_profile(
    tool_id: &str,
    action_id: &str,
    action_type: ucf::v1::ToolActionType,
) -> ucf::v1::ToolActionProfile {
    let mut base = ucf::v1::ToolActionProfile {
        tool_id: tool_id.to_string(),
        action_id: action_id.to_string(),
        action_type: action_type.into(),
        profile_digest: None,
        input_schema: Some(ucf::v1::Ref {
            uri: format!("schema://{tool_id}/{action_id}/input"),
            label: format!("{tool_id}.{action_id}.Input"),
        }),
        output_schema: Some(ucf::v1::Ref {
            uri: format!("schema://{tool_id}/{action_id}/output"),
            label: format!("{tool_id}.{action_id}.Output"),
        }),
    };

    let digest = tool_profile_digest(&base);
    base.profile_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    base
}

pub fn make_pvgs_key_epoch(epoch_id: u64, signing_key: &SigningKey) -> ucf::v1::PvgsKeyEpoch {
    let key_id = format!("pvgs-key-{epoch_id}");
    let mut key_epoch = ucf::v1::PvgsKeyEpoch {
        epoch_id,
        attestation_key_id: key_id,
        attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        announcement_digest: None,
        signature: None,
        timestamp_ms: 1_700_000_000_000,
        vrf_key_id: None,
    };

    let digest = pvgs_key_epoch_digest(&key_epoch);
    key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });

    let signature = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
    key_epoch.signature = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_epoch.attestation_key_id.as_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
    });

    key_epoch
}

pub fn make_pvgs_receipt_accepted(
    action_digest: [u8; 32],
    decision_digest: [u8; 32],
    control_frame_digest: ucf::v1::Digest32,
    tool_profile_digest: ucf::v1::Digest32,
    signing_key: &SigningKey,
    key_epoch: &ucf::v1::PvgsKeyEpoch,
    grant_id: Option<String>,
) -> ucf::v1::PvgsReceipt {
    let mut receipt = ucf::v1::PvgsReceipt {
        receipt_epoch: format!("epoch-{}", key_epoch.epoch_id),
        receipt_id: "receipt-mvp".to_string(),
        receipt_digest: None,
        status: ucf::v1::ReceiptStatus::Accepted.into(),
        action_digest: Some(ucf::v1::Digest32 {
            value: action_digest.to_vec(),
        }),
        decision_digest: Some(ucf::v1::Digest32 {
            value: decision_digest.to_vec(),
        }),
        grant_id: grant_id.unwrap_or_else(|| "grant-mvp".to_string()),
        charter_version_digest: Some(digest_from_label("charter-beta")),
        policy_version_digest: Some(digest_from_label("policy-beta")),
        prev_record_digest: Some(digest_from_label("pvgs-prev")),
        profile_digest: Some(control_frame_digest),
        tool_profile_digest: Some(tool_profile_digest),
        reject_reason_codes: Vec::new(),
        signer: None,
    };

    let digest = receipt_digest(&receipt);
    receipt.receipt_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });

    let preimage = pvgs_receipt_signing_preimage(&receipt);
    let signature = signing_key.sign(&preimage);
    receipt.signer = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_epoch.attestation_key_id.as_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
    });

    receipt
}

fn tool_profile_digest(tap: &ucf::v1::ToolActionProfile) -> [u8; 32] {
    let mut canonical = tap.clone();
    canonical.profile_digest = None;
    let canonical = canonical_bytes(&canonical);
    digest32(
        TOOL_PROFILE_HASH_DOMAIN,
        "ToolActionProfile",
        "v1",
        &canonical,
    )
}

fn receipt_digest(receipt: &ucf::v1::PvgsReceipt) -> [u8; 32] {
    let mut canonical = receipt.clone();
    canonical.receipt_digest = None;
    canonical.signer = None;
    let canonical = canonical_bytes(&canonical);
    digest32(RECEIPT_HASH_DOMAIN, "PvgsReceipt", "v1", &canonical)
}

fn digest_from_label(label: &str) -> ucf::v1::Digest32 {
    let mut hasher = Hasher::new();
    hasher.update(label.as_bytes());
    ucf::v1::Digest32 {
        value: hasher.finalize().as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn control_frame_builder_sets_digest() {
        let (frame, digest) = make_control_frame(
            ucf::v1::ControlFrameProfile::M0Baseline,
            None,
            ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: true,
                enable_write: true,
                enable_execute: true,
            },
        );

        assert_eq!(digest.value.len(), 32);
        assert_eq!(digest.value, control_frame_digest(&frame).value);
    }

    #[test]
    fn tool_profile_digest_is_stable() {
        let profile =
            make_tool_action_profile("mock.tool", "act", ucf::v1::ToolActionType::Execute);

        let digest_a = profile.profile_digest.clone().unwrap();
        let digest_b =
            make_tool_action_profile("mock.tool", "act", ucf::v1::ToolActionType::Execute)
                .profile_digest
                .unwrap();

        assert_eq!(digest_a.value, digest_b.value);
    }

    #[test]
    fn receipt_builder_signs_with_key_epoch() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let key_epoch = make_pvgs_key_epoch(1, &signing_key);
        let receipt = make_pvgs_receipt_accepted(
            [1u8; 32],
            [2u8; 32],
            digest_from_label("cf"),
            digest_from_label("tap"),
            &signing_key,
            &key_epoch,
            None,
        );

        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let sig = signing_key.sign(&preimage);

        assert_eq!(receipt.signer.as_ref().unwrap().signature, sig.to_bytes());
    }
}
