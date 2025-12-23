#![forbid(unsafe_code)]

use std::convert::TryFrom;

use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest32, ucf};

const CONTROL_FRAME_HASH_DOMAIN: &str = "UCF:HASH:CONTROL_FRAME";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlFrameError {
    #[error("active_profile is required")]
    MissingActiveProfile,
    #[error("toolclass_mask is required")]
    MissingToolclassMask,
}

#[derive(Debug, Default, Clone)]
pub struct ControlFrameStore {
    current: Option<ucf::v1::ControlFrame>,
}

impl ControlFrameStore {
    pub fn new() -> Self {
        Self { current: None }
    }

    pub fn update(&mut self, cf: ucf::v1::ControlFrame) -> Result<(), ControlFrameError> {
        let profile = ucf::v1::ControlFrameProfile::try_from(cf.active_profile)
            .unwrap_or(ucf::v1::ControlFrameProfile::Unspecified);

        if matches!(profile, ucf::v1::ControlFrameProfile::Unspecified) {
            return Err(ControlFrameError::MissingActiveProfile);
        }

        if cf.toolclass_mask.is_none() {
            return Err(ControlFrameError::MissingToolclassMask);
        }

        // TODO: tighten-only against charter minimum.
        self.current = Some(cf);
        Ok(())
    }

    pub fn current(&self) -> Option<&ucf::v1::ControlFrame> {
        self.current.as_ref()
    }

    pub fn strict_fallback(&self) -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "fallback".to_string(),
            note: "strict fail-closed".to_string(),
            active_profile: ucf::v1::ControlFrameProfile::M1Restricted.into(),
            overlays: Some(ucf::v1::ControlFrameOverlays {
                ovl_simulate_first: true,
                ovl_export_lock: true,
                ovl_novelty_lock: true,
            }),
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: false,
                enable_write: false,
                enable_execute: false,
            }),
            deescalation_lock: true,
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: vec!["RC.RE.INTEGRITY.DEGRADED".to_string()],
            }),
            evidence_refs: Vec::new(),
        }
    }
}

pub fn control_frame_digest(control_frame: &ucf::v1::ControlFrame) -> [u8; 32] {
    let canonical = canonical_bytes(control_frame);
    digest32(CONTROL_FRAME_HASH_DOMAIN, "ControlFrame", "v1", &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_frame() -> ucf::v1::ControlFrame {
        ucf::v1::ControlFrame {
            frame_id: "cf1".to_string(),
            note: String::new(),
            active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            overlays: None,
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: true,
                enable_transform: true,
                enable_export: true,
                enable_write: true,
                enable_execute: true,
            }),
            deescalation_lock: false,
            reason_codes: None,
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn rejects_missing_profile() {
        let mut store = ControlFrameStore::new();
        let mut frame = base_frame();
        frame.active_profile = ucf::v1::ControlFrameProfile::Unspecified.into();

        let err = store
            .update(frame)
            .expect_err("should reject missing profile");
        assert_eq!(err, ControlFrameError::MissingActiveProfile);
        assert!(store.current().is_none());
    }

    #[test]
    fn rejects_missing_toolclass_mask() {
        let mut store = ControlFrameStore::new();
        let mut frame = base_frame();
        frame.toolclass_mask = None;

        let err = store
            .update(frame)
            .expect_err("should reject missing toolclass_mask");
        assert_eq!(err, ControlFrameError::MissingToolclassMask);
        assert!(store.current().is_none());
    }

    #[test]
    fn accepts_valid_control_frame() {
        let mut store = ControlFrameStore::new();
        let frame = base_frame();
        store.update(frame.clone()).expect("valid control frame");

        let stored = store.current().expect("stored frame");
        assert_eq!(stored.frame_id, frame.frame_id);
    }

    #[test]
    fn strict_fallback_is_fail_closed() {
        let store = ControlFrameStore::new();
        let fallback = store.strict_fallback();

        let overlays = fallback.overlays.unwrap();
        let mask = fallback.toolclass_mask.unwrap();

        assert!(overlays.ovl_simulate_first);
        assert!(overlays.ovl_export_lock);
        assert!(overlays.ovl_novelty_lock);
        assert!(mask.enable_read);
        assert!(!mask.enable_export);
        assert_eq!(
            ucf::v1::ControlFrameProfile::try_from(fallback.active_profile),
            Ok(ucf::v1::ControlFrameProfile::M1Restricted)
        );
    }

    #[test]
    fn control_frame_digest_is_deterministic() {
        let frame = base_frame();
        let digest_a = control_frame_digest(&frame);
        let digest_b = control_frame_digest(&frame);

        assert_eq!(digest_a, digest_b);
        assert_ne!(digest_a, [0u8; 32]);
    }
}
