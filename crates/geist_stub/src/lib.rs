#![forbid(unsafe_code)]

use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const DIGEST_DOMAIN: &str = "UCF:HASH:CONSISTENCY_FEEDBACK";
const FLAG_BEHAVIOR_DRIFT: &str = "BEHAVIOR_DRIFT";
const FLAG_IDENTITY_BREAK: &str = "IDENTITY_BREAK";
const FLAG_RISK_DRIFT: &str = "RISK_DRIFT";
const RC_GE_EXEC_DISPATCH_BLOCKED: &str = "RC.GE.EXEC.DISPATCH_BLOCKED";
const RC_GV_CBV_UPDATED: &str = "RC.GV.CBV.UPDATED";
const RC_GV_PEV_UPDATED: &str = "RC.GV.PEV.UPDATED";
const RC_GV_RULESET_CHANGED: &str = "RC.GV.RULESET.CHANGED";
const RC_RE_INTEGRITY_DEGRADED: &str = "RC.RE.INTEGRITY.DEGRADED";
const RC_TH_POLICY_PROBING: &str = "RC.TH.POLICY_PROBING";

#[derive(Debug, Clone, PartialEq)]
pub struct GeistSignals {
    pub deny_count_medium_window: u32,
    pub integrity_state: ucf::v1::IntegrityState,
    pub receipt_invalid_count: u32,
    pub receipt_missing_count: u32,
    pub ruleset_digest: Option<[u8; 32]>,
    pub ruleset_digest_current: Option<[u8; 32]>,
    pub ruleset_change_count_medium_window: u32,
    pub cbv: Option<ucf::v1::CharacterBaselineVector>,
    pub cbv_digest: Option<[u8; 32]>,
    pub pev: Option<ucf::v1::PolicyEcologyVector>,
    pub pev_digest: Option<[u8; 32]>,
    pub dlp_block_count_medium_window: Option<u32>,
}

impl Default for GeistSignals {
    fn default() -> Self {
        Self {
            deny_count_medium_window: 0,
            integrity_state: ucf::v1::IntegrityState::Ok,
            receipt_invalid_count: 0,
            receipt_missing_count: 0,
            ruleset_digest: None,
            ruleset_digest_current: None,
            ruleset_change_count_medium_window: 0,
            cbv: None,
            cbv_digest: None,
            pev: None,
            pev_digest: None,
            dlp_block_count_medium_window: None,
        }
    }
}

#[derive(Debug, Default)]
struct Evaluation {
    consistency_class: ucf::v1::ConsistencyClass,
    flags: Vec<String>,
    reason_codes: Vec<String>,
    recommended_noise_class: ucf::v1::NoiseClass,
    consolidation_eligibility: ucf::v1::ConsolidationEligibility,
    replay_trigger_hint: bool,
}

fn cbv_caution_offset(cbv: &ucf::v1::CharacterBaselineVector) -> Option<i32> {
    cbv.values.first().map(|v| *v as i32)
}

fn evaluate_consistency(signals: &GeistSignals) -> Evaluation {
    let mut score = 0;
    let mut flags = Vec::new();
    let mut reason_codes = Vec::new();

    if signals.integrity_state != ucf::v1::IntegrityState::Ok {
        score += 5;
        flags.push(FLAG_IDENTITY_BREAK.to_string());
        reason_codes.push(RC_RE_INTEGRITY_DEGRADED.to_string());
        score = score.max(7);
    }

    if signals.receipt_invalid_count > 0 {
        score += 4;
        flags.push(FLAG_RISK_DRIFT.to_string());
        reason_codes.push(RC_TH_POLICY_PROBING.to_string());
        score = score.max(7);
    }

    if signals.receipt_missing_count >= 2 {
        score += 3;
        reason_codes.push(RC_TH_POLICY_PROBING.to_string());
    }

    let deny_storm = signals.deny_count_medium_window >= 20;
    if deny_storm {
        score += 3;
        flags.push(FLAG_BEHAVIOR_DRIFT.to_string());
        reason_codes.push(RC_GE_EXEC_DISPATCH_BLOCKED.to_string());
    }

    if signals.ruleset_change_count_medium_window >= 2 {
        score += 2;
        flags.push(FLAG_RISK_DRIFT.to_string());
        reason_codes.push(RC_GV_RULESET_CHANGED.to_string());
        score = score.max(3);
    }

    if signals.dlp_block_count_medium_window.unwrap_or_default() >= 5 {
        score += 2;
        reason_codes.push(RC_TH_POLICY_PROBING.to_string());
    }

    if let Some(cbv) = &signals.cbv {
        if cbv_caution_offset(cbv).unwrap_or_default() >= 2 {
            score += 1;
            reason_codes.push(RC_GV_CBV_UPDATED.to_string());
        }
    }

    if let Some(pev) = &signals.pev {
        if pev.conservatism_bias >= ucf::v1::PolicyEcologyBias::Medium as i32 {
            score += 1;
            reason_codes.push(RC_GV_PEV_UPDATED.to_string());
        }
    }

    let consistency_class = match score {
        s if s >= 7 => ucf::v1::ConsistencyClass::Low,
        s if (3..=6).contains(&s) => ucf::v1::ConsistencyClass::Medium,
        _ => ucf::v1::ConsistencyClass::High,
    };

    let recommended_noise_class = match consistency_class {
        ucf::v1::ConsistencyClass::Low => ucf::v1::NoiseClass::High,
        ucf::v1::ConsistencyClass::Medium => ucf::v1::NoiseClass::Medium,
        ucf::v1::ConsistencyClass::High => ucf::v1::NoiseClass::Low,
        _ => ucf::v1::NoiseClass::Medium,
    };

    let consolidation_eligibility = match consistency_class {
        ucf::v1::ConsistencyClass::Low => ucf::v1::ConsolidationEligibility::Deny,
        ucf::v1::ConsistencyClass::Medium | ucf::v1::ConsistencyClass::High => {
            ucf::v1::ConsolidationEligibility::Allow
        }
        _ => ucf::v1::ConsolidationEligibility::Allow,
    };

    let replay_trigger_hint = consistency_class == ucf::v1::ConsistencyClass::Low
        || (deny_storm && consistency_class == ucf::v1::ConsistencyClass::Medium);

    reason_codes.sort();
    reason_codes.dedup();
    flags.sort();
    flags.dedup();

    Evaluation {
        consistency_class,
        flags,
        reason_codes,
        recommended_noise_class,
        consolidation_eligibility,
        replay_trigger_hint,
    }
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
    let evaluation = evaluate_consistency(signals);

    let mut feedback = ucf::v1::ConsistencyFeedback {
        cf_id: format!("cf:{session_id}:{tick_counter}"),
        cf_digest: None,
        consistency_class: evaluation.consistency_class as i32,
        flags: evaluation.flags.clone(),
        recommended_noise_class: evaluation.recommended_noise_class as i32,
        consolidation_eligibility: evaluation.consolidation_eligibility as i32,
        replay_trigger_hint: evaluation.replay_trigger_hint,
        pev_ref: signals.pev_digest.map(to_digest32),
        ism_refs: Vec::new(),
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: evaluation.reason_codes.clone(),
        }),
        deny_count_medium_window: signals.deny_count_medium_window,
        integrity_state: signals.integrity_state as i32,
        receipt_failures: signals
            .receipt_invalid_count
            .saturating_add(signals.receipt_missing_count),
        ruleset_digest: signals.ruleset_digest.map(to_digest32),
        cbv_digest: signals.cbv_digest.map(to_digest32),
        cbv: signals.cbv.clone(),
        pev: signals.pev.clone(),
        ruleset_digest_current: signals.ruleset_digest_current.map(to_digest32),
        ruleset_change_count_medium_window: signals.ruleset_change_count_medium_window,
        receipt_invalid_count: signals.receipt_invalid_count,
        receipt_missing_count: signals.receipt_missing_count,
        dlp_block_count_medium_window: signals.dlp_block_count_medium_window,
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
            ucf::v1::NoiseClass::Low as i32
        );
        assert_eq!(
            feedback.consolidation_eligibility,
            ucf::v1::ConsolidationEligibility::Allow as i32
        );
        assert!(!feedback.replay_trigger_hint);
        assert_eq!(feedback.flags, Vec::<String>::new());
        assert_eq!(feedback.reason_codes.unwrap().codes, Vec::<String>::new());
    }

    #[test]
    fn low_consistency_on_integrity_degraded() {
        let signals = GeistSignals {
            integrity_state: ucf::v1::IntegrityState::Degraded,
            ..Default::default()
        };
        let feedback = build_consistency_feedback("sess", 2, &signals);

        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::Low as i32
        );
        assert!(feedback.flags.contains(&FLAG_IDENTITY_BREAK.to_string()));
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
            vec![RC_RE_INTEGRITY_DEGRADED.to_string()]
        );
    }

    #[test]
    fn low_consistency_on_receipt_invalid() {
        let signals = GeistSignals {
            receipt_invalid_count: 1,
            ..Default::default()
        };

        let feedback = build_consistency_feedback("sess", 3, &signals);

        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::Low as i32
        );
        assert!(feedback.flags.contains(&FLAG_RISK_DRIFT.to_string()));
        assert_eq!(
            feedback.recommended_noise_class,
            ucf::v1::NoiseClass::High as i32
        );
        assert_eq!(
            feedback.reason_codes.unwrap().codes,
            vec![RC_TH_POLICY_PROBING.to_string()]
        );
    }

    #[test]
    fn ruleset_changes_push_medium() {
        let signals = GeistSignals {
            ruleset_change_count_medium_window: 2,
            ..Default::default()
        };

        let feedback = build_consistency_feedback("sess", 4, &signals);

        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::Medium as i32
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
        assert!(feedback.flags.contains(&FLAG_RISK_DRIFT.to_string()));
        assert_eq!(
            feedback.reason_codes.unwrap().codes,
            vec![RC_GV_RULESET_CHANGED.to_string()]
        );
    }

    #[test]
    fn cbv_pev_shift_borderline_score() {
        let base_signals = GeistSignals {
            dlp_block_count_medium_window: Some(5),
            ..Default::default()
        };

        let baseline_feedback = build_consistency_feedback("sess", 5, &base_signals);
        assert_eq!(
            baseline_feedback.consistency_class,
            ucf::v1::ConsistencyClass::High as i32
        );

        let signals = GeistSignals {
            cbv: Some(ucf::v1::CharacterBaselineVector {
                weights: vec![1.0],
                values: vec![2.0],
            }),
            pev: Some(ucf::v1::PolicyEcologyVector {
                conservatism_bias: ucf::v1::PolicyEcologyBias::Medium as i32,
                novelty_penalty_bias: ucf::v1::PolicyEcologyBias::Low as i32,
                reversibility_bias: ucf::v1::PolicyEcologyBias::Low as i32,
                pev_digest: None,
            }),
            ..base_signals
        };

        let feedback = build_consistency_feedback("sess", 6, &signals);
        assert_eq!(
            feedback.consistency_class,
            ucf::v1::ConsistencyClass::Medium as i32
        );
    }

    #[test]
    fn deterministic_digest_with_same_signals() {
        let signals = GeistSignals {
            ruleset_change_count_medium_window: 2,
            ruleset_digest: Some([1; 32]),
            ruleset_digest_current: Some([2; 32]),
            receipt_missing_count: 2,
            cbv: Some(ucf::v1::CharacterBaselineVector {
                weights: vec![],
                values: vec![3.0],
            }),
            pev: Some(ucf::v1::PolicyEcologyVector {
                conservatism_bias: ucf::v1::PolicyEcologyBias::High as i32,
                novelty_penalty_bias: ucf::v1::PolicyEcologyBias::Low as i32,
                reversibility_bias: ucf::v1::PolicyEcologyBias::Low as i32,
                pev_digest: None,
            }),
            ..Default::default()
        };

        let feedback_a = build_consistency_feedback("sess", 7, &signals);
        let feedback_b = build_consistency_feedback("sess", 7, &signals);

        assert_eq!(feedback_a.cf_digest, feedback_b.cf_digest);
        assert_eq!(
            feedback_a.cf_digest.as_ref().map(|d| d.value.clone()),
            Some(digest_consistency_feedback(&feedback_a).to_vec())
        );
    }
}
