#![forbid(unsafe_code)]

use pvgs_client::{PvgsClient, PvgsClientError};
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

#[derive(Debug, Clone)]
pub struct MicroPlanner {
    pub chunk_size: u64,
    pub last_micro_end: u64,
}

impl Default for MicroPlanner {
    fn default() -> Self {
        Self {
            chunk_size: 256,
            last_micro_end: 0,
        }
    }
}

impl MicroPlanner {
    pub fn next_range(&self, current_head_experience_id: u64) -> Option<(u64, u64)> {
        if self.chunk_size == 0 {
            return None;
        }

        let available = current_head_experience_id.saturating_sub(self.last_micro_end);
        if available < self.chunk_size {
            return None;
        }

        let start = self.last_micro_end.saturating_add(1);
        let end = start.saturating_add(self.chunk_size - 1);
        Some((start, end))
    }

    pub fn try_commit_next_micro(
        &mut self,
        pvgs: &mut dyn PvgsClient,
        session_id: &str,
    ) -> Result<Option<ucf::v1::PvgsReceipt>, MicroPlannerError> {
        let head = pvgs.get_pvgs_head();
        let Some((start, end)) = self.next_range(head.head_experience_id) else {
            return Ok(None);
        };

        let micro = build_micro(session_id, start, end, head.head_record_digest);
        let receipt = pvgs
            .commit_micro_milestone(micro)
            .map_err(MicroPlannerError::Commit)?;

        if let Ok(ucf::v1::ReceiptStatus::Accepted) =
            ucf::v1::ReceiptStatus::try_from(receipt.status)
        {
            self.last_micro_end = end;
        }

        Ok(Some(receipt))
    }
}

#[derive(Debug, Error)]
pub enum MicroPlannerError {
    #[error("pvgs commit failed: {0}")]
    Commit(#[from] PvgsClientError),
}

pub fn build_micro(
    session_id: &str,
    start: u64,
    end: u64,
    head_record_digest: [u8; 32],
) -> ucf::v1::MicroMilestone {
    let summary_preimage = [
        start.to_le_bytes().as_slice(),
        end.to_le_bytes().as_slice(),
        session_id.as_bytes(),
    ]
    .concat();
    let summary_digest = digest_proto("UCF:HASH:MICRO_SUMMARY", &summary_preimage);

    let experience_range = ucf::v1::ExperienceRange {
        start,
        end,
        head_record_digest: Some(ucf::v1::Digest32 {
            value: head_record_digest.to_vec(),
        }),
    };

    let mut micro = ucf::v1::MicroMilestone {
        micro_id: format!("micro:{session_id}:{start}:{end}"),
        experience_range: Some(experience_range),
        summary_digest: Some(ucf::v1::Digest32 {
            value: summary_digest.to_vec(),
        }),
        hormone_profile: ucf::v1::HormoneClass::Low.into(),
        priority_class: ucf::v1::PriorityClass::Medium.into(),
        micro_digest: None,
        state: ucf::v1::MicroMilestoneState::Sealed.into(),
        vrf_proof_ref: None,
        proof_receipt_ref: None,
    };

    let micro_digest = digest_proto("UCF:HASH:MICRO_MILESTONE", &canonical_bytes(&micro));
    micro.micro_digest = Some(ucf::v1::Digest32 {
        value: micro_digest.to_vec(),
    });

    micro
}

#[cfg(test)]
mod tests {
    use super::*;
    use pvgs_client::MockPvgsClient;

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn no_micro_when_insufficient_records() {
        let mut planner = MicroPlanner::default();
        let mut pvgs = MockPvgsClient::default();
        pvgs.local.set_head(128, digest(1));

        let result = planner
            .try_commit_next_micro(&mut pvgs, "session")
            .expect("call succeeds");

        assert!(result.is_none());
        assert_eq!(planner.last_micro_end, 0);
        assert!(pvgs.local.committed_micro_milestones.is_empty());
    }

    #[test]
    fn micro_committed_when_threshold_reached() {
        let mut planner = MicroPlanner::default();
        let mut pvgs = MockPvgsClient::default();
        pvgs.local.set_head(256, digest(2));

        let receipt = planner
            .try_commit_next_micro(&mut pvgs, "sess")
            .expect("commit result")
            .expect("receipt");

        assert_eq!(pvgs.local.committed_micro_milestones.len(), 1);
        assert_eq!(planner.last_micro_end, 256);
        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status).ok(),
            Some(ucf::v1::ReceiptStatus::Accepted)
        );
    }

    #[test]
    fn deterministic_micro_digest() {
        let micro_a = build_micro("sess", 1, 256, digest(3));
        let micro_b = build_micro("sess", 1, 256, digest(3));

        assert_eq!(micro_a.micro_id, micro_b.micro_id);
        assert_eq!(micro_a.micro_digest, micro_b.micro_digest);
    }

    #[test]
    fn reject_path_does_not_advance_state() {
        let mut planner = MicroPlanner::default();
        let mut pvgs = MockPvgsClient::rejecting(vec!["RC.REJECT".to_string()]);
        pvgs.local.set_head(512, digest(4));

        let receipt = planner
            .try_commit_next_micro(&mut pvgs, "sess")
            .expect("call succeeds")
            .expect("receipt returned");

        assert_eq!(planner.last_micro_end, 0);
        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status).ok(),
            Some(ucf::v1::ReceiptStatus::Rejected)
        );
    }
}
