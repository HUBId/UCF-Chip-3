#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use frames::WindowEngine;
pub use pvgs_client::PvgsClient;
use pvgs_client::PvgsClientError;
use thiserror::Error;

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
    aggregator: Option<Arc<Mutex<WindowEngine>>>,
    records_since_micro: u64,
}

impl std::fmt::Debug for CkmOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CkmOrchestrator")
            .field("micro_chunk_size", &self.micro_chunk_size)
            .field("max_steps_per_tick", &self.max_steps_per_tick)
            .field("enabled", &self.enabled)
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
            aggregator: None,
            records_since_micro: 0,
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

    fn log_integrity_issue(&self) {
        if let Some(agg) = self.aggregator.as_ref() {
            if let Ok(mut guard) = agg.lock() {
                guard.on_integrity_issue(&[INTEGRITY_REASON.to_string()]);
            }
        }
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
                    self.log_integrity_issue();
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
                    self.log_integrity_issue();
                    return;
                }
            }
        }

        if steps < self.max_steps_per_tick {
            if let Err(err) = pvgs.try_commit_next_macro() {
                tracing::warn!("macro commit failed: {err:?}");
                self.log_integrity_issue();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use frames::{FramesConfig, WindowEngine};
    use pvgs_client::{MockCommitStage, MockPvgsClient};

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
}
