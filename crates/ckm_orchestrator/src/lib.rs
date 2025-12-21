#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use frames::WindowEngine;
use geist_stub::{build_consistency_feedback, GeistSignals};
pub use pvgs_client::PvgsClient;
use pvgs_client::PvgsClientError;
use thiserror::Error;
use ucf_protocol::ucf;

const INTEGRITY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("pvgs commit failed: {0}")]
    Pvgs(#[from] PvgsClientError),
}

#[derive(Clone)]
pub struct CkmOrchestrator {
    pub micro_chunk_size: u64,
    pub max_steps_per_tick: u32,
    pub enabled: bool,
    pub geist_signals: GeistSignals,
    pub latest_consistency_digest: Option<[u8; 32]>,
    aggregator: Option<Arc<Mutex<WindowEngine>>>,
    records_since_micro: u64,
    consistency_tick: u64,
}

impl std::fmt::Debug for CkmOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkmOrchestrator")
            .field("micro_chunk_size", &self.micro_chunk_size)
            .field("max_steps_per_tick", &self.max_steps_per_tick)
            .field("enabled", &self.enabled)
            .field("latest_consistency_digest", &self.latest_consistency_digest)
            .field("records_since_micro", &self.records_since_micro)
            .finish()
    }
}

impl Default for CkmOrchestrator {
    fn default() -> Self {
        Self {
            micro_chunk_size: 256,
            max_steps_per_tick: 3,
            enabled: true,
            geist_signals: GeistSignals::default(),
            latest_consistency_digest: None,
            aggregator: None,
            records_since_micro: 0,
            consistency_tick: 0,
        }
    }
}

impl CkmOrchestrator {
    pub fn with_aggregator(aggregator: Arc<Mutex<WindowEngine>>) -> Self {
        Self {
            aggregator: Some(aggregator),
            ..Self::default()
        }
    }

    pub fn set_aggregator(&mut self, aggregator: Arc<Mutex<WindowEngine>>) {
        self.aggregator = Some(aggregator);
    }

    pub fn set_geist_signals(&mut self, signals: GeistSignals) {
        self.geist_signals = signals;
    }

    fn log_integrity_issue(&self) {
        if let Some(agg) = self.aggregator.as_ref() {
            if let Ok(mut guard) = agg.lock() {
                guard.on_integrity_issue(&[INTEGRITY_REASON.to_string()]);
            }
        }
    }

    fn on_commit_failure(&mut self) {
        self.geist_signals.receipt_failures = self.geist_signals.receipt_failures.saturating_add(1);
        self.geist_signals.integrity_state = ucf::v1::IntegrityState::Degraded;
        self.log_integrity_issue();
    }

    fn commit_consistency_feedback(
        &mut self,
        pvgs: &mut dyn PvgsClient,
        session_id: &str,
    ) -> Result<ucf::v1::ConsistencyFeedback, PvgsClientError> {
        let feedback =
            build_consistency_feedback(session_id, self.consistency_tick, &self.geist_signals);
        self.consistency_tick = self.consistency_tick.saturating_add(1);

        let receipt = pvgs.commit_consistency_feedback(feedback.clone())?;
        let accepted = ucf::v1::ReceiptStatus::try_from(receipt.status)
            == Ok(ucf::v1::ReceiptStatus::Accepted);
        if !accepted {
            return Err(PvgsClientError::CommitFailed(
                "consistency feedback rejected".to_string(),
            ));
        }

        self.latest_consistency_digest = feedback
            .cf_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok());

        Ok(feedback)
    }

    pub fn on_record_committed(&mut self, pvgs: &mut dyn PvgsClient, session_id: &str) {
        if !self.enabled {
            return;
        }

        self.records_since_micro = self.records_since_micro.saturating_add(1);
        let mut steps: u32 = 0;
        let mut committed_micro = false;

        let should_attempt_micro =
            self.micro_chunk_size > 0 && self.records_since_micro >= self.micro_chunk_size;

        if should_attempt_micro && steps < self.max_steps_per_tick {
            steps += 1;
            match pvgs.try_commit_next_micro(session_id) {
                Ok(true) => {
                    self.records_since_micro = 0;
                    committed_micro = true;
                }
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!("micro commit failed: {err:?}");
                    self.on_commit_failure();
                    return;
                }
            }
        }

        if !committed_micro || steps >= self.max_steps_per_tick {
            return;
        }

        if steps < self.max_steps_per_tick {
            steps += 1;
            match pvgs.try_commit_next_meso() {
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!("meso commit failed: {err:?}");
                    self.on_commit_failure();
                    return;
                }
            }
        }

        if steps < self.max_steps_per_tick {
            match self.commit_consistency_feedback(pvgs, session_id) {
                Ok(feedback) => {
                    if feedback.consistency_class == ucf::v1::ConsistencyClass::Low as i32 {
                        return;
                    }

                    if let Err(err) = pvgs.try_commit_next_macro(self.latest_consistency_digest) {
                        tracing::warn!("macro commit failed: {err:?}");
                        self.on_commit_failure();
                    }
                }
                Err(err) => {
                    tracing::warn!("consistency feedback commit failed: {err:?}");
                    self.on_commit_failure();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use frames::{FramesConfig, WindowEngine};
    use pvgs_client::{MockCommitStage, MockPvgsClient};
    use ucf_protocol::ucf;

    use super::CkmOrchestrator;

    fn aggregator() -> Arc<Mutex<WindowEngine>> {
        Arc::new(Mutex::new(
            WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
        ))
    }

    #[test]
    fn micro_commit_triggered_after_threshold() {
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 2,
            ..Default::default()
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");
        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert_eq!(pvgs.micro_calls, 1);
        assert!(pvgs.last_call_order.contains(&MockCommitStage::Micro));
    }

    #[test]
    fn bounded_steps_respected() {
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 1,
            max_steps_per_tick: 3,
            ..Default::default()
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            meso_commit_every: Some(1),
            macro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert_eq!(
            pvgs.last_call_order,
            vec![
                MockCommitStage::Micro,
                MockCommitStage::Meso,
                MockCommitStage::Consistency,
                MockCommitStage::Macro,
            ]
        );
    }

    #[test]
    fn order_micro_then_meso_then_macro() {
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 1,
            ..Default::default()
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            meso_commit_every: Some(1),
            macro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert_eq!(
            pvgs.last_call_order,
            vec![
                MockCommitStage::Micro,
                MockCommitStage::Meso,
                MockCommitStage::Consistency,
                MockCommitStage::Macro,
            ]
        );
    }

    #[test]
    fn reject_stops_sequence_and_logs_integrity() {
        let agg = aggregator();
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 1,
            ..CkmOrchestrator::with_aggregator(agg.clone())
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            reject_stage: Some(MockCommitStage::Meso),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert_eq!(
            pvgs.last_call_order,
            vec![MockCommitStage::Micro, MockCommitStage::Meso]
        );

        let frames = agg.lock().expect("aggregator lock").force_flush();
        let integrity_issue_count = frames
            .first()
            .and_then(|frame| frame.integrity_stats.as_ref())
            .map(|stats| stats.integrity_issue_count)
            .unwrap_or_default();
        assert_eq!(integrity_issue_count, 1);
    }

    #[test]
    fn disabled_orchestrator_noops() {
        let mut orchestrator = CkmOrchestrator {
            enabled: false,
            ..Default::default()
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");
        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert!(pvgs.last_call_order.is_empty());
    }

    #[test]
    fn commits_consistency_feedback_before_macro() {
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 1,
            ..Default::default()
        };
        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            meso_commit_every: Some(1),
            macro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert!(!pvgs.committed_consistency_feedback.is_empty());
        assert_eq!(
            pvgs.last_call_order,
            vec![
                MockCommitStage::Micro,
                MockCommitStage::Meso,
                MockCommitStage::Consistency,
                MockCommitStage::Macro,
            ]
        );
        assert_eq!(
            pvgs.macro_consistency_digests.last().copied().flatten(),
            orchestrator.latest_consistency_digest
        );
    }

    #[test]
    fn macro_commit_skipped_when_consistency_low() {
        let mut orchestrator = CkmOrchestrator {
            micro_chunk_size: 1,
            ..Default::default()
        };
        orchestrator.geist_signals.deny_count_medium_window = 25;

        let mut pvgs = MockPvgsClient {
            micro_commit_every: Some(1),
            meso_commit_every: Some(1),
            macro_commit_every: Some(1),
            ..Default::default()
        };

        orchestrator.on_record_committed(&mut pvgs, "sess");

        assert_eq!(pvgs.macro_calls, 0);
        assert_eq!(
            pvgs.last_call_order,
            vec![
                MockCommitStage::Micro,
                MockCommitStage::Meso,
                MockCommitStage::Consistency,
            ]
        );
        let class = pvgs
            .committed_consistency_feedback
            .first()
            .map(|cf| cf.consistency_class);
        assert_eq!(class, Some(ucf::v1::ConsistencyClass::Low as i32));
    }
}
