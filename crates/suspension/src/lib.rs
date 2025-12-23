#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::str::FromStr;

use ucf_protocol::ucf;

const MAX_RECOMMENDATIONS: usize = 8;
const MAX_REASON_CODES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelClass {
    Unspecified,
    Low,
    Medium,
    High,
}

impl From<ucf::v1::PriorityClass> for LevelClass {
    fn from(value: ucf::v1::PriorityClass) -> Self {
        match value {
            ucf::v1::PriorityClass::Unspecified => LevelClass::Unspecified,
            ucf::v1::PriorityClass::Low => LevelClass::Low,
            ucf::v1::PriorityClass::Medium => LevelClass::Medium,
            ucf::v1::PriorityClass::High => LevelClass::High,
        }
    }
}

impl From<LevelClass> for ucf::v1::PriorityClass {
    fn from(value: LevelClass) -> Self {
        match value {
            LevelClass::Unspecified => ucf::v1::PriorityClass::Unspecified,
            LevelClass::Low => ucf::v1::PriorityClass::Low,
            LevelClass::Medium => ucf::v1::PriorityClass::Medium,
            LevelClass::High => ucf::v1::PriorityClass::High,
        }
    }
}

impl FromStr for LevelClass {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ucf::v1::PriorityClass::from_str_name(s)
            .map(Into::into)
            .ok_or("invalid LevelClass")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspendRecommendation {
    pub tool_id: String,
    pub action_id: String,
    pub severity: LevelClass,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspensionResult {
    pub tool_id: String,
    pub action_id: String,
    pub severity: LevelClass,
    pub reason_codes: Vec<String>,
    pub suspended_at_ms: u64,
    pub applied: bool,
}

#[derive(Debug, Default)]
pub struct SuspensionState {
    suspended: BTreeSet<(String, String)>,
}

impl SuspensionState {
    pub fn new() -> Self {
        Self {
            suspended: BTreeSet::new(),
        }
    }

    pub fn suspended(&self) -> &BTreeSet<(String, String)> {
        &self.suspended
    }

    pub fn apply_recommendations(
        &mut self,
        recs: Vec<SuspendRecommendation>,
        now_ms: u64,
    ) -> Vec<SuspensionResult> {
        recs.into_iter()
            .take(MAX_RECOMMENDATIONS)
            .map(|rec| {
                let key = (rec.tool_id.clone(), rec.action_id.clone());
                let applied = self.suspended.insert(key);
                let reason_codes = bound_reason_codes(rec.reason_codes);

                SuspensionResult {
                    tool_id: rec.tool_id,
                    action_id: rec.action_id,
                    severity: rec.severity,
                    reason_codes,
                    suspended_at_ms: now_ms,
                    applied,
                }
            })
            .collect()
    }
}

fn bound_reason_codes(codes: Vec<String>) -> Vec<String> {
    let mut bounded = BTreeSet::new();
    for code in codes.into_iter().take(MAX_REASON_CODES * 2) {
        bounded.insert(code);
        if bounded.len() >= MAX_REASON_CODES {
            break;
        }
    }
    bounded.into_iter().take(MAX_REASON_CODES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_single_recommendation() {
        let mut state = SuspensionState::new();
        let rec = SuspendRecommendation {
            tool_id: "tool-123".into(),
            action_id: "action-abc".into(),
            severity: LevelClass::High,
            reason_codes: vec!["RC.TEST.ONE".into(), "RC.TEST.TWO".into()],
        };

        let results = state.apply_recommendations(vec![rec], 42);

        assert_eq!(state.suspended.len(), 1);
        assert!(state
            .suspended
            .contains(&("tool-123".into(), "action-abc".into())));
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert_eq!(results[0].reason_codes.len(), 2);
        assert_eq!(results[0].suspended_at_ms, 42);
        assert_eq!(results[0].severity, LevelClass::High);
    }

    #[test]
    fn apply_recommendations_is_idempotent() {
        let mut state = SuspensionState::new();
        let rec = SuspendRecommendation {
            tool_id: "tool-123".into(),
            action_id: "action-abc".into(),
            severity: LevelClass::Medium,
            reason_codes: vec!["RC.TEST.THREE".into(), "RC.TEST.THREE".into()],
        };

        let first = state.apply_recommendations(vec![rec.clone()], 99);
        let second = state.apply_recommendations(vec![rec], 100);

        assert_eq!(state.suspended.len(), 1);
        assert!(first[0].applied);
        assert!(!second[0].applied);
        assert_eq!(first[0].reason_codes, vec!["RC.TEST.THREE".to_string()]);
        assert_eq!(second[0].reason_codes, vec!["RC.TEST.THREE".to_string()]);
    }
}
