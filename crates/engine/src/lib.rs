#![forbid(unsafe_code)]

mod classify;
pub mod config;
mod regulation;

pub use classify::classify_signal_frame;
pub use config::{EngineConfig, WindowKind};
pub use regulation::{
    apply_configured_regulation, control_frame_digest, strict_fallback_control_frame, OverlayState,
    RegulationState,
};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SeverityClass {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityStateClass {
    Ok,
    Degraded,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedSignals {
    pub integrity_state: IntegrityStateClass,
    pub policy_pressure_class: SeverityClass,
    pub receipt_failures_class: SeverityClass,
    pub dlp_severity_class: Option<SeverityClass>,
    pub exec_reliability_class: Option<SeverityClass>,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("failed to read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("profile not found: {0}")]
    MissingProfile(String),
    #[error("overlay not found: {0}")]
    UnknownOverlay(String),
    #[error("unsupported control profile mapping for {0}")]
    UnsupportedControlProfile(String),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::EngineConfig;
    use crate::regulation::apply_configured_regulation;
    use ucf_protocol::ucf;

    fn config_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("config")
    }

    fn sample_signal_frame() -> ucf::v1::SignalFrame {
        ucf::v1::SignalFrame {
            frame_id: "sample".to_string(),
            window: Some(ucf::v1::WindowMetadata {
                window_type: "short".to_string(),
                max_events: 32,
                event_count: 10,
                window_id: "window-1".to_string(),
            }),
            integrity_state: ucf::v1::IntegrityState::Fail.into(),
            policy_stats: Some(ucf::v1::PolicyStats {
                allow_count: 1,
                deny_count: 6,
                require_approval_count: 0,
                require_simulation_count: 0,
                top_reason_codes: vec![],
            }),
            exec_stats: Some(ucf::v1::ExecStats {
                success_count: 0,
                failure_count: 4,
                timeout_count: 1,
                partial_count: 0,
                tool_unavailable_count: 0,
                top_reason_codes: vec![],
            }),
            dlp_stats: Some(ucf::v1::DlpStats {
                top_reason_codes: vec![ucf::v1::ReasonCodeCount {
                    code: "dlp".to_string(),
                    count: 1,
                }],
            }),
            budget_stats: Some(ucf::v1::BudgetStats {
                budget_exhausted_count: 0,
                top_reason_codes: Vec::new(),
            }),
            human_stats: Some(ucf::v1::HumanStats {
                approval_denied_count: 0,
                stop: false,
            }),
            signal_frame_digest: None,
            signature: None,
            receipt_stats: Some(ucf::v1::ReceiptStats {
                receipt_missing_count: 2,
                receipt_invalid_count: 2,
                top_reason_codes: vec![],
            }),
        }
    }

    #[test]
    fn loads_engine_config_from_repo() {
        let cfg = EngineConfig::load_from_dir(config_dir()).expect("config files load");
        assert_eq!(cfg.windowing.short.max_records, 32);
        assert!(cfg.profiles.profiles.contains_key("M0"));
        assert!(cfg.overlays.overlays.contains_key("simulate_first"));
    }

    #[test]
    fn missing_fields_fail_parsing() {
        let yaml = r#"
medium:
  min_records: 1
  max_records: 10
  max_age_ms: 10
long:
  min_records: 1
  max_records: 10
  max_age_ms: 10
"#;

        let result: Result<config::WindowingConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "missing short window should error");
    }

    #[test]
    fn classification_respects_thresholds() {
        let cfg = EngineConfig::load_from_dir(config_dir()).expect("config files load");
        let classified = classify_signal_frame(&sample_signal_frame(), &cfg.thresholds);

        assert_eq!(classified.policy_pressure_class, SeverityClass::High);
        assert_eq!(classified.receipt_failures_class, SeverityClass::High);
        assert_eq!(classified.exec_reliability_class, Some(SeverityClass::High));
        assert_eq!(classified.integrity_state, IntegrityStateClass::Fail);
    }

    #[test]
    fn rules_drive_profile_and_overlays() {
        let cfg = EngineConfig::load_from_dir(config_dir()).expect("config files load");
        let classified = classify_signal_frame(&sample_signal_frame(), &cfg.thresholds);

        let mut state = RegulationState::from_profile("M0", &cfg.profiles).expect("base profile");
        let matched = state
            .apply_update_tables(&classified, &cfg.update_tables, &cfg.overlays)
            .expect("apply updates");

        assert!(matched);
        assert_eq!(state.profile_id, "M1");
        assert!(state.overlays.export_lock);
        assert!(state.overlays.simulate_first);
        assert!(state.overlays.novelty_lock);
    }

    #[test]
    fn control_frame_digest_is_deterministic() {
        let cfg = EngineConfig::load_from_dir(config_dir()).expect("config files load");
        let classified = classify_signal_frame(&sample_signal_frame(), &cfg.thresholds);
        let frame_a = apply_configured_regulation("M0", &cfg, &classified).expect("control frame");
        let frame_b = apply_configured_regulation("M0", &cfg, &classified).expect("control frame");

        let digest_a = control_frame_digest(&frame_a);
        let digest_b = control_frame_digest(&frame_b);

        assert_eq!(digest_a.value, digest_b.value);
    }

    #[test]
    fn fallback_used_when_config_is_bad() {
        let cfg_err =
            EngineConfig::load_from_dir(PathBuf::from("/tmp/does-not-exist")).unwrap_err();
        assert!(
            matches!(cfg_err, EngineError::Io(_)),
            "bad config surfaces io error"
        );

        let fallback = strict_fallback_control_frame();
        assert_eq!(
            ucf::v1::ControlFrameProfile::try_from(fallback.active_profile),
            Ok(ucf::v1::ControlFrameProfile::M1Restricted)
        );
        let overlays = fallback.overlays.unwrap();
        assert!(overlays.ovl_export_lock);
        assert!(overlays.ovl_simulate_first);
        assert!(overlays.ovl_novelty_lock);
        let mask = fallback.toolclass_mask.unwrap();
        assert!(!mask.enable_export && !mask.enable_write && !mask.enable_execute);
        let reasons = fallback.reason_codes.unwrap();
        assert_eq!(reasons.codes, vec!["RC.RE.INTEGRITY.DEGRADED".to_string()]);
    }
}
