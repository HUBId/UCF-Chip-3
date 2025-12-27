#![forbid(unsafe_code)]

use prost::Message;
use ucf_protocol::{canonical_bytes, ucf};

fn assert_roundtrip<T>(value: T)
where
    T: Message + Default + Clone + PartialEq,
{
    let encoded = value.encode_to_vec();
    let decoded = T::decode(encoded.as_slice()).expect("decode roundtrip");
    assert_eq!(value, decoded);
    assert_eq!(canonical_bytes(&value), canonical_bytes(&decoded));
}

#[test]
fn proto_roundtrip_is_deterministic() {
    let signal = ucf::v1::SignalFrame {
        frame_id: "signal-1".to_string(),
        window: Some(ucf::v1::WindowMetadata {
            window_type: "rolling".to_string(),
            max_events: 64,
            event_count: 2,
            window_id: "w-1".to_string(),
        }),
        integrity_state: ucf::v1::IntegrityState::Ok.into(),
        policy_stats: Some(ucf::v1::PolicyStats {
            allow_count: 1,
            deny_count: 0,
            require_approval_count: 0,
            require_simulation_count: 0,
            top_reason_codes: Vec::new(),
        }),
        exec_stats: None,
        dlp_stats: None,
        budget_stats: None,
        human_stats: None,
        signal_frame_digest: None,
        signature: None,
        receipt_stats: None,
        integrity_stats: None,
    };

    let (control, _) = ucf_test_utils::make_control_frame(
        ucf::v1::ControlFrameProfile::M0Baseline,
        Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: false,
            ovl_novelty_lock: false,
        }),
        ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        },
    );

    let experience = ucf::v1::ExperienceRecord {
        record_type: ucf::v1::RecordType::Decision.into(),
        core_frame: None,
        metabolic_frame: Some(ucf::v1::MetabolicFrame {
            profile_state: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            control_frame_ref: Some(ucf::v1::Digest32 {
                value: vec![7u8; 32],
            }),
            hormone_classes: vec![ucf::v1::HormoneClass::Low.into()],
            noise_class: ucf::v1::NoiseClass::Low.into(),
            priority_class: ucf::v1::PriorityClass::Medium.into(),
        }),
        governance_frame: Some(ucf::v1::GovernanceFrame {
            policy_decision_refs: vec![ucf::v1::Digest32 {
                value: vec![3u8; 32],
            }],
            grant_refs: Vec::new(),
            dlp_refs: Vec::new(),
            budget_snapshot_ref: None,
            pvgs_receipt_ref: None,
            reason_codes: Some(ucf::v1::ReasonCodes {
                codes: vec!["RC.OK".to_string()],
            }),
        }),
        core_frame_ref: None,
        metabolic_frame_ref: Some(ucf::v1::Digest32 {
            value: vec![9u8; 32],
        }),
        governance_frame_ref: Some(ucf::v1::Digest32 {
            value: vec![10u8; 32],
        }),
        related_refs: vec![ucf::v1::RelatedRef {
            id: "policy_query".to_string(),
            digest: Some(ucf::v1::Digest32 {
                value: vec![11u8; 32],
            }),
        }],
    };

    assert_roundtrip(signal);
    assert_roundtrip(control);
    assert_roundtrip(experience);
}
