#![allow(dead_code)]

use std::sync::Arc;

use chip4_pvgs::{ingest_published_epochs, LocalPvgs};
use pvgs_verify::PvgsKeyEpochStore;
use ucf_protocol::ucf;

#[derive(Debug, Clone)]
pub struct PvgsHandle {
    pub pvgs: LocalPvgs,
    pub key_epoch_store: Arc<PvgsKeyEpochStore>,
}

impl PvgsHandle {
    pub fn publish_key_epoch(&mut self, epoch_id: u64) -> ucf::v1::PvgsKeyEpoch {
        let epoch = self.pvgs.publish_key_epoch(epoch_id);
        let store = Arc::get_mut(&mut self.key_epoch_store)
            .expect("key epoch store should be uniquely owned during ingest");
        store
            .ingest_key_epoch(epoch.clone())
            .expect("ingest key epoch");
        epoch
    }

    pub fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> ucf::v1::PvgsReceipt {
        self.pvgs.commit_tool_registry(trc)
    }

    pub fn get_current_ruleset_digest(&self) -> [u8; 32] {
        self.pvgs
            .get_current_ruleset_digest()
            .expect("ruleset digest available")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_receipt_for_action(
        &self,
        action_digest: [u8; 32],
        decision_digest: [u8; 32],
        profile_digest: ucf::v1::Digest32,
        tool_profile_digest: ucf::v1::Digest32,
        grant_id: Option<String>,
    ) -> ucf::v1::PvgsReceipt {
        self.pvgs.issue_receipt_for_action(
            action_digest,
            decision_digest,
            profile_digest,
            tool_profile_digest,
            grant_id,
        )
    }
}

pub fn spawn_local_pvgs() -> PvgsHandle {
    let pvgs = LocalPvgs::new();
    let mut store = PvgsKeyEpochStore::new();
    ingest_published_epochs(&pvgs, &mut store).expect("ingest published epochs");

    PvgsHandle {
        pvgs,
        key_epoch_store: Arc::new(store),
    }
}
