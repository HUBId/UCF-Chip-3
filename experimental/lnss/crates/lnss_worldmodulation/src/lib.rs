#![forbid(unsafe_code)]

use lnss_core::{MAX_REASON_CODES, MAX_STRING_LEN};
use serde::{Deserialize, Serialize};

pub const SCALE_MAX_Q: u16 = 1000;

pub const RC_WM_PRED_ERROR_HIGH: &str = "RC.GV.WM.PRED_ERROR_HIGH";
pub const RC_WM_PRED_ERROR_CRITICAL: &str = "RC.GV.WM.PRED_ERROR_CRITICAL";
pub const RC_WM_MODULATION_ACTIVE: &str = "RC.GV.WM.MODULATION_ACTIVE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseLimits {
    pub top_k_base: usize,
    pub max_spikes_per_tick: u32,
    pub amplitude_cap_q: u16,
    pub fanout_cap: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModulationPlan {
    pub feature_top_k_scale_q: u16,
    pub spike_budget_scale_q: u16,
    pub amplitude_cap_scale_q: u16,
    pub fanout_cap_scale_q: u16,
    pub reason_codes: Vec<String>,
}

impl Default for WorldModulationPlan {
    fn default() -> Self {
        Self {
            feature_top_k_scale_q: SCALE_MAX_Q,
            spike_budget_scale_q: SCALE_MAX_Q,
            amplitude_cap_scale_q: SCALE_MAX_Q,
            fanout_cap_scale_q: SCALE_MAX_Q,
            reason_codes: Vec::new(),
        }
    }
}

pub fn compute_world_modulation(pred_err: i32, _base: &BaseLimits) -> WorldModulationPlan {
    let mut plan = WorldModulationPlan::default();
    if pred_err >= 80 {
        plan.spike_budget_scale_q = 600;
        plan.feature_top_k_scale_q = 700;
        plan.amplitude_cap_scale_q = 800;
        plan.fanout_cap_scale_q = 800;
    } else if pred_err >= 50 {
        plan.spike_budget_scale_q = 750;
        plan.feature_top_k_scale_q = 800;
        plan.amplitude_cap_scale_q = 900;
        plan.fanout_cap_scale_q = 850;
    } else if pred_err >= 20 {
        plan.spike_budget_scale_q = 900;
        plan.feature_top_k_scale_q = 900;
    }

    let mut reason_codes = Vec::new();
    if pred_err >= 50 {
        reason_codes.push(RC_WM_PRED_ERROR_HIGH.to_string());
    }
    if pred_err >= 80 {
        reason_codes.push(RC_WM_PRED_ERROR_CRITICAL.to_string());
    }
    if plan.feature_top_k_scale_q < SCALE_MAX_Q
        || plan.spike_budget_scale_q < SCALE_MAX_Q
        || plan.amplitude_cap_scale_q < SCALE_MAX_Q
        || plan.fanout_cap_scale_q < SCALE_MAX_Q
    {
        reason_codes.push(RC_WM_MODULATION_ACTIVE.to_string());
    }

    plan.reason_codes = bound_reason_codes(reason_codes);
    plan
}

fn bound_reason_codes(mut reason_codes: Vec<String>) -> Vec<String> {
    reason_codes
        .iter_mut()
        .for_each(|code| code.truncate(MAX_STRING_LEN));
    reason_codes.sort();
    reason_codes.dedup();
    reason_codes.truncate(MAX_REASON_CODES);
    reason_codes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_limits() -> BaseLimits {
        BaseLimits {
            top_k_base: 8,
            max_spikes_per_tick: 32,
            amplitude_cap_q: 1000,
            fanout_cap: 16,
        }
    }

    #[test]
    fn modulation_levels_follow_matrix() {
        let plan = compute_world_modulation(10, &base_limits());
        assert_eq!(plan.feature_top_k_scale_q, 1000);
        assert_eq!(plan.spike_budget_scale_q, 1000);

        let plan = compute_world_modulation(25, &base_limits());
        assert_eq!(plan.feature_top_k_scale_q, 900);
        assert_eq!(plan.spike_budget_scale_q, 900);

        let plan = compute_world_modulation(55, &base_limits());
        assert_eq!(plan.feature_top_k_scale_q, 800);
        assert_eq!(plan.spike_budget_scale_q, 750);
        assert_eq!(plan.amplitude_cap_scale_q, 900);
        assert_eq!(plan.fanout_cap_scale_q, 850);

        let plan = compute_world_modulation(95, &base_limits());
        assert_eq!(plan.feature_top_k_scale_q, 700);
        assert_eq!(plan.spike_budget_scale_q, 600);
        assert_eq!(plan.amplitude_cap_scale_q, 800);
        assert_eq!(plan.fanout_cap_scale_q, 800);
    }

    #[test]
    fn modulation_reason_codes_are_bounded() {
        let plan = compute_world_modulation(90, &base_limits());
        assert!(plan
            .reason_codes
            .contains(&RC_WM_MODULATION_ACTIVE.to_string()));
        assert!(plan
            .reason_codes
            .contains(&RC_WM_PRED_ERROR_HIGH.to_string()));
        assert!(plan
            .reason_codes
            .contains(&RC_WM_PRED_ERROR_CRITICAL.to_string()));
        assert!(plan.reason_codes.len() <= MAX_REASON_CODES);
    }

    #[test]
    fn modulation_scales_never_exceed_default() {
        for pred_err in [0, 10, 25, 55, 80, 120] {
            let plan = compute_world_modulation(pred_err, &base_limits());
            assert!(plan.feature_top_k_scale_q <= SCALE_MAX_Q);
            assert!(plan.spike_budget_scale_q <= SCALE_MAX_Q);
            assert!(plan.amplitude_cap_scale_q <= SCALE_MAX_Q);
            assert!(plan.fanout_cap_scale_q <= SCALE_MAX_Q);
        }
    }
}
