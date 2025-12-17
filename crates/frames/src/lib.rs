#![forbid(unsafe_code)]

use std::collections::HashMap;

use pbm::DecisionForm;
use ucf_protocol::{canonical_bytes, digest32, ucf};

const SHORT_WINDOW: &str = "short";
const SIGNAL_DIGEST_DOMAIN: &str = "UCF:HASH:SIGNAL_FRAME";

#[derive(Debug, Clone, Default)]
struct ReasonCounter {
    counts: HashMap<String, u64>,
}

impl ReasonCounter {
    fn record<I: IntoIterator<Item = String>>(&mut self, codes: I) {
        for code in codes {
            *self.counts.entry(code).or_insert(0) += 1;
        }
    }

    fn top(&self, limit: usize) -> Vec<ucf::v1::ReasonCodeCount> {
        let mut pairs: Vec<_> = self.counts.iter().collect();
        pairs.sort_by(|(a_code, a_count), (b_code, b_count)| {
            b_count
                .cmp(a_count)
                .then_with(|| a_code.as_str().cmp(b_code.as_str()))
        });

        pairs
            .into_iter()
            .take(limit)
            .map(|(code, count)| ucf::v1::ReasonCodeCount {
                code: code.clone(),
                count: *count,
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct WindowState {
    window_index: u64,
    event_count: u64,
    policy_counts: PolicyCounts,
    exec_counts: ExecCounts,
    policy_reasons: ReasonCounter,
    exec_reasons: ReasonCounter,
    receipt_counts: ReceiptCounts,
    receipt_reasons: ReasonCounter,
    integrity_state: ucf::v1::IntegrityState,
}

impl WindowState {
    fn new(window_index: u64) -> Self {
        Self {
            window_index,
            event_count: 0,
            policy_counts: PolicyCounts::default(),
            exec_counts: ExecCounts::default(),
            policy_reasons: ReasonCounter::default(),
            exec_reasons: ReasonCounter::default(),
            receipt_counts: ReceiptCounts::default(),
            receipt_reasons: ReasonCounter::default(),
            integrity_state: ucf::v1::IntegrityState::Ok,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct PolicyCounts {
    allow: u64,
    deny: u64,
    require_approval: u64,
    require_simulation: u64,
}

#[derive(Debug, Clone, Default)]
struct ExecCounts {
    success: u64,
    failure: u64,
    timeout: u64,
    partial: u64,
    tool_unavailable: u64,
}

#[derive(Debug, Clone, Default)]
struct ReceiptCounts {
    missing: u64,
    invalid: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ReceiptIssue {
    Missing,
    Invalid,
}

#[derive(Debug, Clone)]
pub struct ShortWindowAggregator {
    max_events: u64,
    completed_frames: Vec<ucf::v1::SignalFrame>,
    state: WindowState,
}

impl ShortWindowAggregator {
    pub fn new(max_events: u64) -> Self {
        Self {
            max_events,
            completed_frames: Vec::new(),
            state: WindowState::new(0),
        }
    }

    pub fn on_policy_decision(&mut self, form: DecisionForm, reason_codes: &[String]) {
        match form {
            DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                self.state.policy_counts.allow += 1
            }
            DecisionForm::Deny => self.state.policy_counts.deny += 1,
            DecisionForm::RequireApproval => self.state.policy_counts.require_approval += 1,
            DecisionForm::RequireSimulationFirst => {
                self.state.policy_counts.require_simulation += 1
            }
        }

        self.state
            .policy_reasons
            .record(reason_codes.iter().cloned());
        self.record_event();
    }

    pub fn on_execution_outcome(
        &mut self,
        status: ucf::v1::OutcomeStatus,
        reason_codes: &[String],
    ) {
        match status {
            ucf::v1::OutcomeStatus::Success => self.state.exec_counts.success += 1,
            ucf::v1::OutcomeStatus::Failure => self.state.exec_counts.failure += 1,
            ucf::v1::OutcomeStatus::Timeout => self.state.exec_counts.timeout += 1,
            ucf::v1::OutcomeStatus::Partial => self.state.exec_counts.partial += 1,
            ucf::v1::OutcomeStatus::ToolUnavailable => self.state.exec_counts.tool_unavailable += 1,
            ucf::v1::OutcomeStatus::Unspecified => {}
        }

        self.state.exec_reasons.record(reason_codes.iter().cloned());
        self.record_event();
    }

    pub fn on_receipt_issue(&mut self, issue: ReceiptIssue, reason_codes: &[String]) {
        match issue {
            ReceiptIssue::Missing => self.state.receipt_counts.missing += 1,
            ReceiptIssue::Invalid => self.state.receipt_counts.invalid += 1,
        }
        self.state
            .receipt_reasons
            .record(reason_codes.iter().cloned());
        self.record_event();
    }

    pub fn on_budget_event(&mut self) {
        self.record_event();
    }

    pub fn on_integrity_state(&mut self, state: ucf::v1::IntegrityState) {
        self.state.integrity_state = state;
    }

    pub fn force_flush(&mut self) -> Vec<ucf::v1::SignalFrame> {
        if self.state.event_count > 0 {
            self.finish_window();
        }
        self.completed_frames.drain(..).collect()
    }

    fn record_event(&mut self) {
        self.state.event_count += 1;
        if self.state.event_count >= self.max_events {
            self.finish_window();
        }
    }

    fn finish_window(&mut self) {
        let frame_id = format!("window-{}", self.state.window_index);
        let window_meta = ucf::v1::WindowMetadata {
            window_type: SHORT_WINDOW.to_string(),
            max_events: self.max_events,
            event_count: self.state.event_count,
            window_id: frame_id.clone(),
        };

        let policy_stats = ucf::v1::PolicyStats {
            allow_count: self.state.policy_counts.allow,
            deny_count: self.state.policy_counts.deny,
            require_approval_count: self.state.policy_counts.require_approval,
            require_simulation_count: self.state.policy_counts.require_simulation,
            top_reason_codes: self.state.policy_reasons.top(10),
        };

        let exec_stats = ucf::v1::ExecStats {
            success_count: self.state.exec_counts.success,
            failure_count: self.state.exec_counts.failure,
            timeout_count: self.state.exec_counts.timeout,
            partial_count: self.state.exec_counts.partial,
            tool_unavailable_count: self.state.exec_counts.tool_unavailable,
            top_reason_codes: self.state.exec_reasons.top(10),
        };

        let receipt_stats = ucf::v1::ReceiptStats {
            receipt_missing_count: self.state.receipt_counts.missing,
            receipt_invalid_count: self.state.receipt_counts.invalid,
            top_reason_codes: self.state.receipt_reasons.top(10),
        };

        let mut frame = ucf::v1::SignalFrame {
            frame_id: frame_id.clone(),
            window: Some(window_meta),
            integrity_state: self.state.integrity_state.into(),
            policy_stats: Some(policy_stats),
            exec_stats: Some(exec_stats),
            dlp_stats: Some(ucf::v1::DlpStats {
                top_reason_codes: Vec::new(),
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
            receipt_stats: Some(receipt_stats),
        };

        let digest = self.compute_signal_digest(&frame);
        frame.signal_frame_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        self.completed_frames.push(frame);
        let next_index = self.state.window_index + 1;
        self.state = WindowState::new(next_index);
    }

    fn compute_signal_digest(&self, frame: &ucf::v1::SignalFrame) -> [u8; 32] {
        let canonical = canonical_bytes(frame);
        digest32(SIGNAL_DIGEST_DOMAIN, "SignalFrame", "v1", &canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_reason(code: &str) -> (DecisionForm, Vec<String>) {
        (DecisionForm::Allow, vec![code.to_string()])
    }

    #[test]
    fn counts_policy_events() {
        let mut agg = ShortWindowAggregator::new(32);
        for _ in 0..10 {
            agg.on_policy_decision(DecisionForm::Allow, &[]);
        }
        for _ in 0..2 {
            agg.on_policy_decision(DecisionForm::Deny, &[]);
        }

        let frames = agg.force_flush();
        assert_eq!(frames.len(), 1);
        let policy = frames[0].policy_stats.as_ref().unwrap();
        assert_eq!(policy.allow_count, 10);
        assert_eq!(policy.deny_count, 2);
    }

    #[test]
    fn reason_codes_sorted_by_count_then_lex() {
        let mut agg = ShortWindowAggregator::new(32);
        let cases = vec![
            allow_reason("A"),
            allow_reason("B"),
            allow_reason("B"),
            allow_reason("A"),
            allow_reason("C"),
            allow_reason("C"),
        ];

        for (form, reasons) in cases {
            agg.on_policy_decision(form, &reasons);
        }

        let frames = agg.force_flush();
        let policy = frames[0].policy_stats.as_ref().unwrap();
        let codes: Vec<_> = policy
            .top_reason_codes
            .iter()
            .map(|c| (c.code.clone(), c.count))
            .collect();
        assert_eq!(
            codes,
            vec![
                ("A".to_string(), 2),
                ("B".to_string(), 2),
                ("C".to_string(), 2)
            ]
        );
    }

    #[test]
    fn window_rollover_after_max_events() {
        let mut agg = ShortWindowAggregator::new(32);
        for _ in 0..33 {
            agg.on_policy_decision(DecisionForm::Allow, &[]);
        }

        let frames = agg.force_flush();
        assert_eq!(frames.len(), 2, "expected rollover after 32 events");
        assert_eq!(frames[0].window.as_ref().unwrap().event_count, 32);
        assert_eq!(frames[1].window.as_ref().unwrap().event_count, 1);
    }
}
