#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use frames::WindowEngine;
use pvgs_client::{PvgsClient, PvgsClientError};
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const MAX_REPLAY_PLANS_PER_TICK: usize = 3;
const CORE_FRAME_DOMAIN: &str = "UCF:HASH:CORE_FRAME";
const GOVERNANCE_FRAME_DOMAIN: &str = "UCF:HASH:GOVERNANCE_FRAME";
const INTEGRITY_REASON: &str = "RC.RE.INTEGRITY.DEGRADED";
const REPLAY_REASON_CODE: &str = "RC.GV.REPLAY.PLANNED";

#[derive(Debug, Error)]
pub enum Error {
    #[error("pvgs client error: {0}")]
    Pvgs(#[from] PvgsClientError),
}

#[derive(Clone)]
pub struct ReplayOrchestrator {
    pub seen_replay_ids: HashSet<String>,
    pub enabled: bool,
    pub max_plans_per_tick: usize,
    pub consume_enabled: bool,
    aggregator: Option<Arc<Mutex<WindowEngine>>>,
}

impl Default for ReplayOrchestrator {
    fn default() -> Self {
        Self {
            seen_replay_ids: HashSet::new(),
            enabled: true,
            max_plans_per_tick: MAX_REPLAY_PLANS_PER_TICK,
            consume_enabled: true,
            aggregator: None,
        }
    }
}

impl ReplayOrchestrator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_aggregator(aggregator: Arc<Mutex<WindowEngine>>) -> Self {
        Self {
            aggregator: Some(aggregator),
            ..Self::default()
        }
    }

    pub fn set_aggregator(&mut self, aggregator: Arc<Mutex<WindowEngine>>) {
        self.aggregator = Some(aggregator);
    }

    pub fn tick(
        &mut self,
        pvgs: &mut dyn PvgsClient,
        session_id: &str,
        commit: &mut dyn PvgsClient,
    ) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }

        let mut plans = pvgs.get_pending_replay_plans(session_id)?;
        plans.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));

        let mut processed_this_tick = 0usize;
        let mut sequence = self.seen_replay_ids.len() as u64;

        for plan in plans {
            if processed_this_tick >= self.max_plans_per_tick {
                break;
            }

            if self.seen_replay_ids.contains(&plan.replay_id) {
                continue;
            }

            sequence = sequence.saturating_add(1);
            let step_id = format!("replay-tick-{sequence}");
            let record = build_replay_record(session_id, &step_id, &plan, None);

            let accepted = match commit.commit_experience_record(record) {
                Ok(receipt) => {
                    ucf::v1::ReceiptStatus::try_from(receipt.status)
                        == Ok(ucf::v1::ReceiptStatus::Accepted)
                }
                Err(err) => {
                    self.log_integrity_issue();
                    return Err(err.into());
                }
            };

            if !accepted {
                self.log_integrity_issue();
                break;
            }

            self.seen_replay_ids.insert(plan.replay_id.clone());
            processed_this_tick += 1;

            if self.consume_enabled {
                let _ = pvgs.consume_replay_plan(&plan.replay_id);
            }
        }

        Ok(())
    }

    fn log_integrity_issue(&self) {
        if let Some(agg) = self.aggregator.as_ref() {
            if let Ok(mut guard) = agg.lock() {
                guard.on_integrity_issue(&[INTEGRITY_REASON.to_string()]);
            }
        }
    }
}

fn build_replay_record(
    session_id: &str,
    step_id: &str,
    plan: &ucf::v1::ReplayPlan,
    ruleset_digest: Option<[u8; 32]>,
) -> ucf::v1::ExperienceRecord {
    let core_frame = ucf::v1::CoreFrame {
        session_id: session_id.to_string(),
        step_id: step_id.to_string(),
        input_packet_refs: Vec::new(),
        intent_refs: Vec::new(),
        candidate_refs: Vec::new(),
        workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
    };

    let governance_frame = ucf::v1::GovernanceFrame {
        policy_decision_refs: Vec::new(),
        grant_refs: Vec::new(),
        dlp_refs: Vec::new(),
        budget_snapshot_ref: None,
        pvgs_receipt_ref: None,
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: vec![REPLAY_REASON_CODE.to_string()],
        }),
    };

    let core_frame_ref = digest_proto(CORE_FRAME_DOMAIN, &canonical_bytes(&core_frame));
    let governance_frame_ref =
        digest_proto(GOVERNANCE_FRAME_DOMAIN, &canonical_bytes(&governance_frame));

    let mut related_refs = vec![ucf::v1::RelatedRef {
        id: "replay_plan".to_string(),
        digest: plan.replay_digest.clone(),
    }];

    if let Some(digest) = ruleset_digest {
        related_refs.push(ucf::v1::RelatedRef {
            id: "ruleset".to_string(),
            digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
        });
    }

    ucf::v1::ExperienceRecord {
        record_type: ucf::v1::RecordType::Replay.into(),
        core_frame: Some(core_frame),
        metabolic_frame: None,
        governance_frame: Some(governance_frame),
        core_frame_ref: Some(ucf::v1::Digest32 {
            value: core_frame_ref.to_vec(),
        }),
        metabolic_frame_ref: None,
        governance_frame_ref: Some(ucf::v1::Digest32 {
            value: governance_frame_ref.to_vec(),
        }),
        related_refs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frames::FramesConfig;
    use pvgs_client::MockPvgsClient;

    fn replay_plan(id: &str) -> ucf::v1::ReplayPlan {
        let digest = digest_proto("UCF:HASH:REPLAY_PLAN", id.as_bytes());
        ucf::v1::ReplayPlan {
            replay_id: id.to_string(),
            replay_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
        }
    }

    #[test]
    fn commits_each_plan_once_across_ticks() {
        let mut orchestrator = ReplayOrchestrator::default();
        let mut pvgs = MockPvgsClient {
            pending_replay_plans: vec![replay_plan("plan-b"), replay_plan("plan-a")],
            ..Default::default()
        };
        let mut commit = MockPvgsClient::default();

        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();
        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();

        assert_eq!(commit.local.committed_records.len(), 2);
        assert_eq!(orchestrator.seen_replay_ids.len(), 2);
    }

    #[test]
    fn bounded_to_three_per_tick() {
        let mut orchestrator = ReplayOrchestrator::default();
        let mut pvgs = MockPvgsClient {
            pending_replay_plans: (0..10).map(|i| replay_plan(&format!("plan-{i}"))).collect(),
            ..Default::default()
        };
        let mut commit = MockPvgsClient::default();

        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();

        assert_eq!(
            commit.local.committed_records.len(),
            MAX_REPLAY_PLANS_PER_TICK
        );
        assert_eq!(
            orchestrator.seen_replay_ids.len(),
            MAX_REPLAY_PLANS_PER_TICK
        );
    }

    #[test]
    fn consumes_committed_plans_when_enabled() {
        let mut orchestrator = ReplayOrchestrator::default();
        let mut pvgs = MockPvgsClient {
            pending_replay_plans: vec![replay_plan("plan-1"), replay_plan("plan-2")],
            ..Default::default()
        };
        let mut commit = MockPvgsClient::default();

        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();

        assert_eq!(
            pvgs.consumed_replay_ids,
            vec!["plan-1".to_string(), "plan-2".to_string()]
        );
    }

    #[test]
    fn rejection_stops_processing_and_logs_integrity() {
        let aggregator = Arc::new(Mutex::new(
            WindowEngine::new(FramesConfig::fallback()).expect("window engine"),
        ));
        let mut orchestrator = ReplayOrchestrator::with_aggregator(aggregator.clone());
        let mut pvgs = MockPvgsClient {
            pending_replay_plans: vec![
                replay_plan("plan-1"),
                replay_plan("plan-2"),
                replay_plan("plan-3"),
            ],
            ..Default::default()
        };
        let mut commit = MockPvgsClient {
            experience_commit_statuses: vec![
                ucf::v1::ReceiptStatus::Accepted,
                ucf::v1::ReceiptStatus::Rejected,
            ],
            ..Default::default()
        };

        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();

        assert_eq!(commit.local.committed_records.len(), 2);
        assert_eq!(orchestrator.seen_replay_ids.len(), 1);

        let frames = aggregator.lock().unwrap().force_flush();
        let integrity_issue_count = frames
            .first()
            .and_then(|frame| frame.integrity_stats.as_ref())
            .map(|stats| stats.integrity_issue_count)
            .unwrap_or_default();
        assert_eq!(integrity_issue_count, 1);

        let reason_codes: Vec<String> = frames
            .first()
            .and_then(|frame| frame.integrity_stats.as_ref())
            .map(|stats| {
                stats
                    .top_reason_codes
                    .iter()
                    .map(|rc| rc.code.clone())
                    .collect()
            })
            .unwrap_or_default();
        assert!(reason_codes.contains(&INTEGRITY_REASON.to_string()));
    }

    #[test]
    fn commits_in_sorted_replay_id_order() {
        let mut orchestrator = ReplayOrchestrator::default();
        let mut pvgs = MockPvgsClient {
            pending_replay_plans: vec![
                replay_plan("plan-c"),
                replay_plan("plan-a"),
                replay_plan("plan-b"),
            ],
            ..Default::default()
        };
        let mut commit = MockPvgsClient::default();

        orchestrator.tick(&mut pvgs, "sess", &mut commit).unwrap();

        let committed_order: Vec<Vec<u8>> = commit
            .local
            .committed_records
            .iter()
            .filter_map(|record| record.related_refs.first())
            .filter_map(|related| related.digest.as_ref())
            .map(|digest| digest.value.clone())
            .collect();

        let expected_order: Vec<Vec<u8>> = ["plan-a", "plan-b", "plan-c"]
            .iter()
            .map(|id| digest_proto("UCF:HASH:REPLAY_PLAN", id.as_bytes()).to_vec())
            .collect();

        assert_eq!(committed_order, expected_order);
    }
}
