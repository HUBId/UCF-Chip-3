#![forbid(unsafe_code)]

use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const DIGEST_DOMAIN: &str = "UCF:HASH:CONSISTENCY_FEEDBACK";
const FLAG_BEHAVIOR_DRIFT: &str = "BEHAVIOR_DRIFT";
const FLAG_IDENTITY_BREAK: &str = "IDENTITY_BREAK";
const RC_CONSISTENCY_LOW: &str = "RC.GV.CONSISTENCY.LOW";
const RC_CONSISTENCY_HIGH: &str = "RC.GV.CONSISTENCY.HIGH";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeistSignals {
    pub deny_count_medium_window: u32,
    pub integrity_state: ucf::v1::IntegrityState,
    pub receipt_failures: u32,
    pub ruleset_digest: Option<[u8; 32]>,
    pub cbv_digest: Option<[u8; 32]>,
}

impl Default for GeistSignals {
    fn default() -> Self {
        Self {
            deny_count_medium_window: 0,
            integrity_state: ucf::v1::IntegrityState::Ok,
            receipt_failures: 0,
            ruleset_digest: None,
            cbv_digest: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsistencyCause {
    Integrity,
    DenyStorm,
    ReceiptFailures,
    None,
}

fn evaluate_consistency(signals: &GeistSignals) -> (ucf::v1::ConsistencyClass, ConsistencyCause) {
    if signals.integrity_state != ucf::v1::IntegrityState::Ok {
        return (ucf::v1::ConsistencyClass::Low, ConsistencyCause::Integrity);
    }

    if signals.deny_count_medium_window >= 20 {
        return (ucf::v1::ConsistencyClass::Low, ConsistencyCause::DenyStorm);
    }

    if signals.receipt_failures >= 1 {
        return (
            ucf::v1::ConsistencyClass::Medium,
            ConsistencyCause::ReceiptFailures,
        );
    }

    (ucf::v1::ConsistencyClass::High, ConsistencyCause::None)
}

fn to_digest32(value: [u8; 32]) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: value.to_vec(),
    }
}

pub fn digest_consistency_feedback(feedback: &ucf::v1::ConsistencyFeedback) -> [u8; 32] {
    let mut canonical = feedback.clone();
    canonical.cf_digest = None;
    digest_proto(DIGEST_DOMAIN, &canonical_bytes(&canonical))
}

pub fn build_consistency_feedback(
    session_id: &str,
    tick_counter: u64,
    signals: &GeistSignals,
) -> ucf::v1::ConsistencyFeedback {
    let (class, cause) = evaluate_consistency(signals);
    let mut flags = Vec::new();
    let mut replay_trigger_hint = false;

    match cause {
        ConsistencyCause::Integrity => {
            flags.push(FLAG_IDENTITY_BREAK.to_string());
            replay_trigger_hint = true;
        }
        ConsistencyCause::DenyStorm => {
            flags.push(FLAG_BEHAVIOR_DRIFT.to_string());
            replay_trigger_hint = true;
        }
        ConsistencyCause::ReceiptFailures | ConsistencyCause::None => {}
    }

    flags.sort();
    flags.dedup();

    let reason_code = if class == ucf::v1::ConsistencyClass::Low {
        RC_CONSISTENCY_LOW
    } else {
        RC_CONSISTENCY_HIGH
    };

    let recommended_noise_class = if class == ucf::v1::ConsistencyClass::Low {
        ucf::v1::NoiseClass::High
    } else {
        ucf::v1::NoiseClass::Medium
    };

    let consolidation_eligibility = if class == ucf::v1::ConsistencyClass::Low {
        ucf::v1::ConsolidationEligibility::Deny
    } else {
        ucf::v1::ConsolidationEligibility::Allow
    };

    let mut feedback = ucf::v1::ConsistencyFeedback {
        cf_id: format!("cf:{session_id}:{tick_counter}"),
        cf_digest: None,
        consistency_class: class as i32,
        flags,
        recommended_noise_class: recommended_noise_class as i32,
        consolidation_eligibility: consolidation_eligibility as i32,
        replay_trigger_hint,
        pev_ref: None,
        ism_refs: Vec::new(),
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: vec![reason_code.to_string()],
        }),
        deny_count_medium_window: signals.deny_count_medium_window,
        integrity_state: signals.integrity_state as i32,
        receipt_failures: signals.receipt_failures,
        ruleset_digest: signals.ruleset_digest.map(to_digest32),
        cbv_digest: signals.cbv_digest.map(to_digest32),
    };

    let digest = digest_consistency_feedback(&feedback);
    feedback.cf_digest = Some(to_digest32(digest));
    feedback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_consistency_under_normal_conditions() {
        let signals = GeistSignals::default();
        let feedback = build_consistency_feedback("sess", 1, &signals);

        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::High as i32
        );
        assert_eq!(
            feedback.recommended_noise_class,
            ucf::v1::NoiseClass::Medium as i32
        );
        assert_eq!(
            feedback.consolidation_eligibility,
            ucf::v1::ConsolidationEligibility::Allow as i32
        );
        assert!(!feedback.replay_trigger_hint);
        assert_eq!(feedback.flags, Vec::<String>::new());
        assert_eq!(
            feedback.reason_codes.unwrap().codes,
            vec![RC_CONSISTENCY_HIGH]
        );
    }

    #[test]
    fn low_consistency_on_deny_storm() {
        let signals = GeistSignals {
            deny_count_medium_window: 25,
            ..Default::default()
        };
        let feedback = build_consistency_feedback("sess", 2, &signals);

        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::Low as i32
        );
        assert!(feedback.flags.contains(&FLAG_BEHAVIOR_DRIFT.to_string()));
        assert_eq!(
            feedback.recommended_noise_class,
            ucf::v1::NoiseClass::High as i32
        );
        assert_eq!(
            feedback.consolidation_eligibility,
            ucf::v1::ConsolidationEligibility::Deny as i32
        );
        assert!(feedback.replay_trigger_hint);
        assert_eq!(
            feedback.reason_codes.unwrap().codes,
            vec![RC_CONSISTENCY_LOW]
        );
    }

    #[test]
    fn deterministic_digest_with_same_signals() {
        let signals = GeistSignals {
            receipt_failures: 3,
            ..Default::default()
        };

        let feedback_a = build_consistency_feedback("sess", 3, &signals);
        let feedback_b = build_consistency_feedback("sess", 3, &signals);

        assert_eq!(feedback_a.cf_digest, feedback_b.cf_digest);
        assert_eq!(
            feedback_a.cf_digest.as_ref().map(|d| d.value.clone()),
            Some(digest_consistency_feedback(&feedback_a).to_vec())
        );
    }
}
