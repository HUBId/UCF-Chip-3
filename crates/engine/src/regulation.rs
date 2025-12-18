use control::control_frame_digest as compute_control_digest;
use ucf_protocol::ucf;

use crate::config::{
    OverlayEffects, RegulatorOverlaysConfig, RegulatorProfilesConfig, RegulatorUpdateTablesConfig,
};
use crate::{ClassifiedSignals, EngineError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OverlayState {
    pub simulate_first: bool,
    pub export_lock: bool,
    pub novelty_lock: bool,
}

impl OverlayState {
    pub fn apply_effects(&mut self, effects: &OverlayEffects) {
        self.simulate_first |= effects.ovl_simulate_first;
        self.export_lock |= effects.ovl_export_lock;
        self.novelty_lock |= effects.ovl_novelty_lock;
    }
}

#[derive(Debug, Clone)]
pub struct RegulationState {
    pub profile_id: String,
    pub overlays: OverlayState,
    pub deescalation_lock: bool,
    pub reason_codes: Vec<String>,
}

impl RegulationState {
    pub fn from_profile(
        profile_id: &str,
        profiles: &RegulatorProfilesConfig,
    ) -> Result<Self, EngineError> {
        let profile = profiles
            .profiles
            .get(profile_id)
            .ok_or_else(|| EngineError::MissingProfile(profile_id.to_string()))?;

        Ok(Self {
            profile_id: profile_id.to_string(),
            overlays: OverlayState {
                simulate_first: false,
                export_lock: profile.export_policy.export_lock_default,
                novelty_lock: false,
            },
            deescalation_lock: profile.deescalation.lock,
            reason_codes: Vec::new(),
        })
    }

    pub fn apply_update_tables(
        &mut self,
        classified: &ClassifiedSignals,
        updates: &RegulatorUpdateTablesConfig,
        overlays: &RegulatorOverlaysConfig,
    ) -> Result<bool, EngineError> {
        let mut matched = false;

        for rule in &updates.profile_switch {
            if rule.when.matches(classified) {
                matched = true;
                self.profile_id = rule.profile.clone();
                break;
            }
        }

        for rule in &updates.overlay_enable {
            if rule.when.matches(classified) {
                matched = true;
                for overlay_id in &rule.overlays {
                    let overlay = overlays
                        .overlays
                        .get(overlay_id)
                        .ok_or_else(|| EngineError::UnknownOverlay(overlay_id.to_string()))?;
                    self.overlays.apply_effects(&overlay.effects);
                    self.reason_codes
                        .extend(overlay.reason_codes.iter().cloned());
                }
            }
        }

        Ok(matched)
    }

    pub fn control_frame(
        &self,
        profiles: &RegulatorProfilesConfig,
    ) -> Result<ucf::v1::ControlFrame, EngineError> {
        let profile = profiles
            .profiles
            .get(&self.profile_id)
            .ok_or_else(|| EngineError::MissingProfile(self.profile_id.clone()))?;

        let active_profile = match profile.control_profile {
            crate::config::ControlProfileId::M0 => ucf::v1::ControlFrameProfile::M0Baseline,
            crate::config::ControlProfileId::M1 => ucf::v1::ControlFrameProfile::M1Restricted,
            crate::config::ControlProfileId::M2 | crate::config::ControlProfileId::M3 => {
                ucf::v1::ControlFrameProfile::Unspecified
            }
        };

        if active_profile == ucf::v1::ControlFrameProfile::Unspecified {
            return Err(EngineError::UnsupportedControlProfile(
                self.profile_id.clone(),
            ));
        }

        let mut reason_codes: Vec<String> = self.reason_codes.clone();
        reason_codes.sort();
        reason_codes.dedup();

        Ok(ucf::v1::ControlFrame {
            frame_id: "regulator".to_string(),
            note: profile.note.clone(),
            active_profile: active_profile.into(),
            overlays: Some(ucf::v1::ControlFrameOverlays {
                ovl_simulate_first: self.overlays.simulate_first,
                ovl_export_lock: self.overlays.export_lock,
                ovl_novelty_lock: self.overlays.novelty_lock,
            }),
            toolclass_mask: Some(ucf::v1::ToolClassMask {
                enable_read: profile.toolclass_mask.enable_read,
                enable_transform: profile.toolclass_mask.enable_transform,
                enable_export: profile.toolclass_mask.enable_export,
                enable_write: profile.toolclass_mask.enable_write,
                enable_execute: profile.toolclass_mask.enable_execute,
            }),
            deescalation_lock: self.deescalation_lock,
            reason_codes: if reason_codes.is_empty() {
                None
            } else {
                Some(ucf::v1::ReasonCodes {
                    codes: reason_codes,
                })
            },
        })
    }
}

pub fn strict_fallback_control_frame() -> ucf::v1::ControlFrame {
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
    }
}

pub fn control_frame_digest(frame: &ucf::v1::ControlFrame) -> ucf::v1::Digest32 {
    let digest = compute_control_digest(frame);
    ucf::v1::Digest32 {
        value: digest.to_vec(),
    }
}

pub fn apply_configured_regulation(
    default_profile: &str,
    configs: &crate::config::EngineConfig,
    classified: &ClassifiedSignals,
) -> Result<ucf::v1::ControlFrame, EngineError> {
    let mut state = RegulationState::from_profile(default_profile, &configs.profiles)?;
    let matched =
        state.apply_update_tables(classified, &configs.update_tables, &configs.overlays)?;

    if matched {
        state.control_frame(&configs.profiles)
    } else {
        Ok(strict_fallback_control_frame())
    }
}
