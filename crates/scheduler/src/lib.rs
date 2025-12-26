#![forbid(unsafe_code)]

use frames::{TraceHealthStatus, WindowEngine};
use pvgs_client::{PvgsClientReader, TraceRunStatus};

const RC_SCORECARD_OK: &str = "RC.GV.INSPECTOR.SCORECARD_OK";
const RC_FINDING_HIGH: &str = "RC.GV.INSPECTOR.FINDING_HIGH";
const RC_REPLAY_MISMATCH: &str = "RC.RE.REPLAY.MISMATCH";
const RC_TRACE_PASS: &str = "RC.GV.TRACE.PASS";
const RC_TRACE_FAIL: &str = "RC.GV.TRACE.FAIL";
const RC_INTEGRITY_DEGRADED: &str = "RC.RE.INTEGRITY.DEGRADED";

#[derive(Debug, Clone)]
pub struct ScheduleState {
    pub tick_counter: u64,
    pub scorecard_every_ticks: u64,
    pub spotcheck_every_ticks: u64,
    pub trace_poll_every_ticks: u64,
    pub last_seen_trace_run_digest: Option<[u8; 32]>,
}

impl ScheduleState {
    pub fn new(
        scorecard_every_ticks: u64,
        spotcheck_every_ticks: u64,
        trace_poll_every_ticks: u64,
    ) -> Self {
        Self {
            tick_counter: 0,
            scorecard_every_ticks,
            spotcheck_every_ticks,
            trace_poll_every_ticks,
            last_seen_trace_run_digest: None,
        }
    }

    pub fn tick(
        &mut self,
        session_id: Option<&str>,
        pvgs: &mut dyn PvgsClientReader,
        frames: &mut WindowEngine,
    ) {
        if self.scorecard_every_ticks > 0
            && self.tick_counter.is_multiple_of(self.scorecard_every_ticks)
        {
            let mut scorecards = Vec::new();
            if let Ok(scorecard) = pvgs.get_scorecard_global() {
                scorecards.push(scorecard);
            }
            if let Some(session_id) = session_id {
                if let Ok(scorecard) = pvgs.get_scorecard_session(session_id) {
                    scorecards.push(scorecard);
                }
            }

            if !scorecards.is_empty() {
                let high_risk = scorecards
                    .iter()
                    .any(|scorecard| scorecard.replay_mismatch_count > 0);
                if high_risk {
                    frames.on_integrity_issue(&[RC_FINDING_HIGH.to_string()]);
                } else {
                    frames.on_integrity_signal(&[RC_SCORECARD_OK.to_string()]);
                }
            }
        }

        if self.spotcheck_every_ticks > 0
            && self.tick_counter.is_multiple_of(self.spotcheck_every_ticks)
        {
            if let Some(session_id) = session_id {
                if let Ok(report) = pvgs.run_spotcheck(session_id) {
                    if report.mismatch {
                        frames.on_integrity_issue(&[RC_REPLAY_MISMATCH.to_string()]);
                    }
                }
            }
        }

        if self.trace_poll_every_ticks > 0
            && self
                .tick_counter
                .is_multiple_of(self.trace_poll_every_ticks)
        {
            if let Ok(Some(trace)) = pvgs.get_latest_trace_run() {
                if self.last_seen_trace_run_digest != Some(trace.trace_run_digest) {
                    let reason_codes = match trace.status {
                        TraceRunStatus::Pass => vec![RC_TRACE_PASS.to_string()],
                        TraceRunStatus::Fail => {
                            vec![RC_TRACE_FAIL.to_string(), RC_INTEGRITY_DEGRADED.to_string()]
                        }
                    };
                    let status = match trace.status {
                        TraceRunStatus::Pass => TraceHealthStatus::Pass,
                        TraceRunStatus::Fail => TraceHealthStatus::Fail,
                    };
                    frames.on_trace_health(status, &reason_codes);
                    self.last_seen_trace_run_digest = Some(trace.trace_run_digest);
                }
            }
        }

        self.tick_counter = self.tick_counter.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frames::{FramesConfig, WindowKind, WindowSpec, WindowingConfig};
    use pvgs_client::{Scorecard, SpotCheckReport, TraceRunStatus, TraceRunSummary};
    use std::collections::BTreeMap;

    fn test_frames_engine() -> WindowEngine {
        let mut windows = BTreeMap::new();
        windows.insert(
            WindowKind::Short,
            WindowSpec {
                max_events: 1,
                max_records: 1,
                max_age_ms: 0,
                top_reason_limit: None,
            },
        );
        windows.insert(
            WindowKind::Medium,
            WindowSpec {
                max_events: 1,
                max_records: 1,
                max_age_ms: 0,
                top_reason_limit: None,
            },
        );
        let config = FramesConfig {
            windowing: WindowingConfig {
                epoch_id: "test-epoch".to_string(),
                top_reason_limit: 10,
                windows,
            },
            class_thresholds: frames::ClassThresholdsConfig::fallback(),
        };
        WindowEngine::new(config).expect("frames engine")
    }

    fn scorecard_with_mismatch() -> Scorecard {
        Scorecard {
            replay_mismatch_count: 1,
        }
    }

    fn scorecard_ok() -> Scorecard {
        Scorecard {
            replay_mismatch_count: 0,
        }
    }

    #[derive(Default)]
    struct TestPvgs {
        global_scorecard: Scorecard,
        session_scorecard: Scorecard,
        spotcheck: SpotCheckReport,
        latest_trace_run: Option<TraceRunSummary>,
        scorecard_global_calls: u64,
        scorecard_session_calls: u64,
        spotcheck_calls: u64,
        trace_run_calls: u64,
    }

    impl pvgs_client::PvgsClient for TestPvgs {
        fn commit_experience_record(
            &mut self,
            _record: ucf_protocol::ucf::v1::ExperienceRecord,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn commit_dlp_decision(
            &mut self,
            _dlp: ucf_protocol::ucf::v1::DlpDecision,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn commit_tool_registry(
            &mut self,
            _trc: ucf_protocol::ucf::v1::ToolRegistryContainer,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn commit_tool_onboarding_event(
            &mut self,
            _event: ucf_protocol::ucf::v1::ToolOnboardingEvent,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn commit_micro_milestone(
            &mut self,
            _micro: ucf_protocol::ucf::v1::MicroMilestone,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn commit_consistency_feedback(
            &mut self,
            _feedback: ucf_protocol::ucf::v1::ConsistencyFeedback,
        ) -> Result<ucf_protocol::ucf::v1::PvgsReceipt, pvgs_client::PvgsClientError> {
            Err(pvgs_client::PvgsClientError::CommitFailed(
                "unused".to_string(),
            ))
        }

        fn try_commit_next_micro(
            &mut self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_meso(&mut self) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn try_commit_next_macro(
            &mut self,
            _consistency_digest: Option<[u8; 32]>,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn get_pending_replay_plans(
            &mut self,
            _session_id: &str,
        ) -> Result<Vec<ucf_protocol::ucf::v1::ReplayPlan>, pvgs_client::PvgsClientError> {
            Ok(Vec::new())
        }

        fn get_pvgs_head(&self) -> pvgs_client::PvgsHead {
            pvgs_client::PvgsHead {
                head_experience_id: 0,
                head_record_digest: [0u8; 32],
            }
        }

        fn get_scorecard_global(&mut self) -> Result<Scorecard, pvgs_client::PvgsClientError> {
            self.scorecard_global_calls += 1;
            Ok(self.global_scorecard.clone())
        }

        fn get_scorecard_session(
            &mut self,
            _session_id: &str,
        ) -> Result<Scorecard, pvgs_client::PvgsClientError> {
            self.scorecard_session_calls += 1;
            Ok(self.session_scorecard.clone())
        }

        fn run_spotcheck(
            &mut self,
            _session_id: &str,
        ) -> Result<SpotCheckReport, pvgs_client::PvgsClientError> {
            self.spotcheck_calls += 1;
            Ok(self.spotcheck.clone())
        }
    }

    impl pvgs_client::PvgsReader for TestPvgs {
        fn get_latest_pev(&self) -> Option<ucf_protocol::ucf::v1::PolicyEcologyVector> {
            None
        }

        fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
            None
        }

        fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
            None
        }

        fn is_session_sealed(
            &self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn has_unlock_permit(
            &self,
            _session_id: &str,
        ) -> Result<bool, pvgs_client::PvgsClientError> {
            Ok(false)
        }

        fn get_latest_trace_run(
            &mut self,
        ) -> Result<Option<TraceRunSummary>, pvgs_client::PvgsClientError> {
            self.trace_run_calls += 1;
            Ok(self.latest_trace_run.clone())
        }
    }

    #[test]
    fn deterministic_schedule_ticks() {
        let mut scheduler = ScheduleState::new(100, 250, 0);
        let mut pvgs = TestPvgs::default();
        let mut frames = test_frames_engine();

        let mut scorecard_ticks = Vec::new();
        let mut spotcheck_ticks = Vec::new();

        for tick in 0..300 {
            let before_scorecard = pvgs.scorecard_global_calls;
            let before_spotcheck = pvgs.spotcheck_calls;
            scheduler.tick(Some("session"), &mut pvgs, &mut frames);
            if pvgs.scorecard_global_calls > before_scorecard {
                scorecard_ticks.push(tick);
            }
            if pvgs.spotcheck_calls > before_spotcheck {
                spotcheck_ticks.push(tick);
            }
        }

        assert_eq!(scorecard_ticks, vec![0, 100, 200]);
        assert_eq!(spotcheck_ticks, vec![0, 250]);
    }

    #[test]
    fn finding_propagates_reason_code() {
        let mut scheduler = ScheduleState::new(1, 0, 0);
        let mut pvgs = TestPvgs {
            global_scorecard: scorecard_with_mismatch(),
            ..TestPvgs::default()
        };
        let mut frames = test_frames_engine();

        scheduler.tick(Some("session"), &mut pvgs, &mut frames);

        let frames = frames.force_flush();
        let mut reason_codes = Vec::new();
        for frame in frames {
            if let Some(stats) = frame.integrity_stats {
                for code in stats.top_reason_codes {
                    reason_codes.push(code.code);
                }
            }
        }

        assert!(reason_codes.iter().any(|code| code == RC_FINDING_HIGH));
    }

    #[test]
    fn bounded_calls_per_tick() {
        let mut scheduler = ScheduleState::new(1, 1, 0);
        let mut pvgs = TestPvgs::default();
        let mut frames = test_frames_engine();

        for _ in 0..10 {
            let before =
                pvgs.scorecard_global_calls + pvgs.scorecard_session_calls + pvgs.spotcheck_calls;
            scheduler.tick(Some("session"), &mut pvgs, &mut frames);
            let after =
                pvgs.scorecard_global_calls + pvgs.scorecard_session_calls + pvgs.spotcheck_calls;
            assert!(after - before <= 3);
        }
    }

    #[test]
    fn deterministic_reason_code_sequence() {
        let mut scheduler = ScheduleState::new(1, 0, 0);
        let mut pvgs = TestPvgs {
            global_scorecard: scorecard_ok(),
            ..TestPvgs::default()
        };
        let mut frames = test_frames_engine();

        let mut first_run = Vec::new();
        for _ in 0..5 {
            scheduler.tick(Some("session"), &mut pvgs, &mut frames);
            for frame in frames.drain_completed() {
                if let Some(stats) = frame.integrity_stats {
                    first_run.extend(stats.top_reason_codes.into_iter().map(|code| code.code));
                }
            }
        }

        let mut scheduler = ScheduleState::new(1, 0, 0);
        let mut pvgs = TestPvgs {
            global_scorecard: scorecard_ok(),
            ..TestPvgs::default()
        };
        let mut frames = test_frames_engine();
        let mut second_run = Vec::new();
        for _ in 0..5 {
            scheduler.tick(Some("session"), &mut pvgs, &mut frames);
            for frame in frames.drain_completed() {
                if let Some(stats) = frame.integrity_stats {
                    second_run.extend(stats.top_reason_codes.into_iter().map(|code| code.code));
                }
            }
        }

        assert_eq!(first_run, second_run);
    }

    fn trace_summary(status: TraceRunStatus, digest: [u8; 32]) -> TraceRunSummary {
        TraceRunSummary {
            trace_id: "trace-1".to_string(),
            trace_run_digest: digest,
            status,
            created_at_ms: 1_700_000_000_000,
            asset_manifest_digest: None,
            circuit_config_digest: None,
        }
    }

    #[test]
    fn trace_poll_emits_pass_once() {
        let mut scheduler = ScheduleState::new(0, 0, 1);
        let mut pvgs = TestPvgs {
            latest_trace_run: Some(trace_summary(TraceRunStatus::Pass, [1u8; 32])),
            ..TestPvgs::default()
        };
        let mut frames = test_frames_engine();

        scheduler.tick(Some("session"), &mut pvgs, &mut frames);
        let frames_first = frames.drain_completed();
        assert!(!frames_first.is_empty());
        let mut found = false;
        for frame in frames_first {
            let exec_stats = frame.exec_stats.as_ref().expect("exec stats");
            found |= exec_stats
                .top_reason_codes
                .iter()
                .any(|code| code.code == RC_TRACE_PASS);
        }
        assert!(found);

        scheduler.tick(Some("session"), &mut pvgs, &mut frames);
        assert!(frames.drain_completed().is_empty());
    }

    #[test]
    fn trace_poll_emits_fail_and_degrades_integrity() {
        let mut scheduler = ScheduleState::new(0, 0, 1);
        let mut pvgs = TestPvgs {
            latest_trace_run: Some(trace_summary(TraceRunStatus::Fail, [2u8; 32])),
            ..TestPvgs::default()
        };
        let mut frames = test_frames_engine();

        scheduler.tick(Some("session"), &mut pvgs, &mut frames);
        let frames = frames.force_flush();
        assert!(!frames.is_empty());
        let mut found_fail = false;
        let mut found_integrity = false;
        let mut degraded = false;
        for frame in &frames {
            degraded |=
                frame.integrity_state == ucf_protocol::ucf::v1::IntegrityState::Degraded as i32;
            if let Some(exec_stats) = frame.exec_stats.as_ref() {
                found_fail |= exec_stats
                    .top_reason_codes
                    .iter()
                    .any(|code| code.code == RC_TRACE_FAIL);
            }
            if let Some(integrity_stats) = frame.integrity_stats.as_ref() {
                found_integrity |= integrity_stats
                    .top_reason_codes
                    .iter()
                    .any(|code| code.code == RC_INTEGRITY_DEGRADED);
            }
        }
        assert!(degraded);
        assert!(found_fail);
        assert!(found_integrity);
    }

    #[test]
    fn trace_poll_is_deterministic() {
        let mut scheduler = ScheduleState::new(0, 0, 100);
        let mut pvgs = TestPvgs::default();
        let mut frames = test_frames_engine();
        let mut trace_ticks = Vec::new();

        for tick in 0..450 {
            let before = pvgs.trace_run_calls;
            scheduler.tick(Some("session"), &mut pvgs, &mut frames);
            if pvgs.trace_run_calls > before {
                trace_ticks.push(tick);
            }
        }

        assert_eq!(trace_ticks, vec![0, 100, 200, 300, 400]);
    }
}
