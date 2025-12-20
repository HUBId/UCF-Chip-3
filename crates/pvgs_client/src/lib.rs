#![forbid(unsafe_code)]

use pvgs_verify::{IngestError, PvgsKeyEpochStore};
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

// TODO: Bind commit/receipt messages to ucf-protocol definitions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEpochSyncEvent {
    Accepted { epoch_id: u64 },
    Rejected { epoch_id: u64 },
}

pub struct KeyEpochSync {
    store: PvgsKeyEpochStore,
}

impl KeyEpochSync {
    pub fn new(store: PvgsKeyEpochStore) -> Self {
        Self { store }
    }

    pub fn sync_from_list(&mut self, epochs: Vec<ucf::v1::PvgsKeyEpoch>) -> Result<(), SyncError> {
        let mut sorted_epochs = epochs;
        sorted_epochs.sort_by_key(|e| e.epoch_id);

        let mut last_epoch_id: Option<u64> = None;
        for epoch in sorted_epochs {
            if let Some(prev) = last_epoch_id {
                if epoch.epoch_id < prev {
                    self.on_keyepoch_sync_event(KeyEpochSyncEvent::Rejected {
                        epoch_id: epoch.epoch_id,
                    });
                    return Err(SyncError::NonMonotonic {
                        epoch_id: epoch.epoch_id,
                        previous: prev,
                    });
                }
            }

            last_epoch_id = Some(epoch.epoch_id);
            match self.store.ingest_key_epoch(epoch) {
                Ok(()) => self.on_keyepoch_sync_event(KeyEpochSyncEvent::Accepted {
                    epoch_id: last_epoch_id.expect("epoch id set"),
                }),
                Err(source) => {
                    let epoch_id = last_epoch_id.expect("epoch id set");
                    self.on_keyepoch_sync_event(KeyEpochSyncEvent::Rejected { epoch_id });
                    return Err(SyncError::Ingest { epoch_id, source });
                }
            }
        }

        Ok(())
    }

    pub fn store(&self) -> &PvgsKeyEpochStore {
        &self.store
    }

    fn on_keyepoch_sync_event(&self, _event: KeyEpochSyncEvent) {
        // TODO: integrate PVGS sync logging
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncError {
    #[error("epoch ids must be monotonic: {epoch_id} after {previous}")]
    NonMonotonic { epoch_id: u64, previous: u64 },
    #[error("failed to ingest epoch {epoch_id}: {source}")]
    Ingest {
        epoch_id: u64,
        #[source]
        source: IngestError,
    },
}

#[derive(Debug, Error)]
pub enum PvgsClientError {
    #[error("pvgs commit failed: {0}")]
    CommitFailed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PvgsHead {
    pub head_experience_id: u64,
    pub head_record_digest: [u8; 32],
}

pub trait PvgsClient: Send + Sync {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn try_commit_next_micro(&mut self, session_id: &str) -> Result<bool, PvgsClientError>;

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError>;

    fn try_commit_next_macro(&mut self) -> Result<bool, PvgsClientError>;

    fn get_pending_replay_plans(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError>;

    fn consume_replay_plan(&mut self, _replay_id: &str) -> Result<(), PvgsClientError> {
        Ok(())
    }

    fn get_pvgs_head(&self) -> PvgsHead;
}

pub trait PvgsReader: Send + Sync {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector>;
    fn get_latest_pev_digest(&self) -> Option<[u8; 32]>;
    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]>;

    fn get_pending_replay_plans(
        &self,
        _session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        Ok(Vec::new())
    }
}

#[cfg(any(test, feature = "local-e2e"))]
#[derive(Clone)]
pub struct Chip4LocalPvgsClient {
    pub pvgs: chip4_pvgs::LocalPvgs,
    pub last_proof_receipt: Option<ucf::v1::ProofReceipt>,
}

#[cfg(any(test, feature = "local-e2e"))]
impl Chip4LocalPvgsClient {
    pub fn new(pvgs: chip4_pvgs::LocalPvgs) -> Self {
        Self {
            pvgs,
            last_proof_receipt: None,
        }
    }
}

#[cfg(any(test, feature = "local-e2e"))]
impl PvgsClient for Chip4LocalPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let (receipt, proof_receipt) = self.pvgs.append_experience_record(record);
        self.last_proof_receipt = Some(proof_receipt);
        Ok(receipt)
    }

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let (receipt, proof_receipt) = self.pvgs.append_dlp_decision(dlp);
        self.last_proof_receipt = Some(proof_receipt);
        Ok(receipt)
    }

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Ok(self.pvgs.commit_tool_registry(trc))
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let receipt = self.pvgs.append_micro_milestone(micro);
        Ok(receipt)
    }

    fn try_commit_next_micro(&mut self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn try_commit_next_macro(&mut self) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn get_pending_replay_plans(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        Ok(self.pvgs.get_pending_replay_plans(session_id))
    }

    fn consume_replay_plan(&mut self, replay_id: &str) -> Result<(), PvgsClientError> {
        self.pvgs.consume_replay_plan(replay_id);
        Ok(())
    }

    fn get_pvgs_head(&self) -> PvgsHead {
        let (head_experience_id, head_record_digest) = self.pvgs.head();
        PvgsHead {
            head_experience_id,
            head_record_digest,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalPvgsClient {
    receipt_epoch: String,
    grant_id: String,
    default_status: ucf::v1::ReceiptStatus,
    reject_reason_codes: Vec<String>,
    head_experience_id: u64,
    head_record_digest: [u8; 32],
    pub committed_records: Vec<ucf::v1::ExperienceRecord>,
    pub committed_bytes: Vec<Vec<u8>>,
    pub committed_dlp_decisions: Vec<ucf::v1::DlpDecision>,
    pub committed_dlp_bytes: Vec<Vec<u8>>,
    pub committed_tool_registries: Vec<ucf::v1::ToolRegistryContainer>,
    pub committed_registry_bytes: Vec<Vec<u8>>,
    pub committed_micro_milestones: Vec<ucf::v1::MicroMilestone>,
    pub committed_micro_bytes: Vec<Vec<u8>>,
    pub micro_chunk_size: u64,
    pub micro_last_end: u64,
    pub try_commit_meso_outcome: Option<bool>,
    pub try_commit_macro_outcome: Option<bool>,
}

impl Default for LocalPvgsClient {
    fn default() -> Self {
        Self {
            receipt_epoch: "local-epoch".to_string(),
            grant_id: "local-grant".to_string(),
            default_status: ucf::v1::ReceiptStatus::Accepted,
            reject_reason_codes: Vec::new(),
            head_experience_id: 0,
            head_record_digest: [0u8; 32],
            committed_records: Vec::new(),
            committed_bytes: Vec::new(),
            committed_dlp_decisions: Vec::new(),
            committed_dlp_bytes: Vec::new(),
            committed_tool_registries: Vec::new(),
            committed_registry_bytes: Vec::new(),
            committed_micro_milestones: Vec::new(),
            committed_micro_bytes: Vec::new(),
            micro_chunk_size: 256,
            micro_last_end: 0,
            try_commit_meso_outcome: None,
            try_commit_macro_outcome: None,
        }
    }
}

impl LocalPvgsClient {
    pub fn rejecting(reason_codes: Vec<String>) -> Self {
        Self {
            default_status: ucf::v1::ReceiptStatus::Rejected,
            reject_reason_codes: reason_codes,
            ..Self::default()
        }
    }

    pub fn with_status(status: ucf::v1::ReceiptStatus) -> Self {
        Self {
            default_status: status,
            ..Self::default()
        }
    }

    pub fn set_head(&mut self, head_experience_id: u64, head_record_digest: [u8; 32]) {
        self.head_experience_id = head_experience_id;
        self.head_record_digest = head_record_digest;
    }

    pub fn committed_tool_registries(&self) -> &[ucf::v1::ToolRegistryContainer] {
        &self.committed_tool_registries
    }
}

impl PvgsClient for LocalPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let bytes = ucf_protocol::canonical_bytes(&record);
        let record_digest = ucf_protocol::digest_proto("UCF:HASH:EXPERIENCE_RECORD", &bytes);
        let has_governance =
            record.governance_frame.is_some() || record.governance_frame_ref.is_some();

        let mut status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if !has_governance {
            status = ucf::v1::ReceiptStatus::Rejected;
            if reject_reason_codes.is_empty() {
                reject_reason_codes.push("RC.GV.MISSING".to_string());
            }
        }

        self.committed_records.push(record.clone());
        self.committed_bytes.push(bytes);

        let prev_record_digest = if self.head_experience_id > 0 {
            Some(ucf::v1::Digest32 {
                value: self.head_record_digest.to_vec(),
            })
        } else {
            None
        };

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!("pvgs-local-{}", self.committed_records.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: record_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: record
                .core_frame
                .as_ref()
                .and_then(|cf| cf.candidate_refs.first())
                .cloned(),
            decision_digest: record.governance_frame_ref.clone(),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest,
            profile_digest: record
                .metabolic_frame
                .as_ref()
                .and_then(|mf| mf.control_frame_ref.clone()),
            tool_profile_digest: None,
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                reject_reason_codes
            } else {
                Vec::new()
            },
            signer: None,
        };

        if status == ucf::v1::ReceiptStatus::Accepted {
            self.head_experience_id += 1;
            self.head_record_digest = record_digest;
        }

        Ok(receipt)
    }

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let mut canonical = dlp.clone();
        if let Some(rc) = canonical.reason_codes.as_mut() {
            rc.codes.sort();
            rc.codes.dedup();
        }

        let bytes = ucf_protocol::canonical_bytes(&canonical);
        let dlp_digest = ucf_protocol::digest_proto("UCF:HASH:DLP_DECISION", &bytes);

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if status == ucf::v1::ReceiptStatus::Rejected && reject_reason_codes.is_empty() {
            reject_reason_codes.push("RC.RE.SCHEMA.INVALID".to_string());
        }

        self.committed_dlp_decisions.push(dlp.clone());
        self.committed_dlp_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!("pvgs-local-dlp-{}", self.committed_dlp_decisions.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: dlp_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: dlp.artifact_ref.clone(),
            decision_digest: Some(ucf::v1::Digest32 {
                value: dlp_digest.to_vec(),
            }),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                reject_reason_codes
            } else {
                Vec::new()
            },
            signer: None,
        };

        Ok(receipt)
    }

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let bytes = ucf_protocol::canonical_bytes(&trc);
        let registry_digest = ucf_protocol::digest_proto("UCF:HASH:TOOL_REGISTRY", &bytes);

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();

        self.committed_tool_registries.push(trc.clone());
        self.committed_registry_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-tool-registry-{}",
                self.committed_tool_registries.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: registry_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: trc.registry_digest.clone(),
            decision_digest: None,
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                if reject_reason_codes.is_empty() {
                    reject_reason_codes.push("RC.GV.TOOL_REGISTRY.REJECTED".to_string());
                }
                reject_reason_codes
            } else {
                Vec::new()
            },
            signer: None,
        };

        Ok(receipt)
    }

    fn commit_micro_milestone(
        &mut self,
        mut micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        if micro.micro_digest.is_none() {
            let bytes = ucf_protocol::canonical_bytes(&micro);
            let micro_digest = ucf_protocol::digest_proto("UCF:HASH:MICRO_MILESTONE", &bytes);
            micro.micro_digest = Some(ucf::v1::Digest32 {
                value: micro_digest.to_vec(),
            });
        }

        let bytes = ucf_protocol::canonical_bytes(&micro);
        let micro_digest: [u8; 32] = micro
            .micro_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if status == ucf::v1::ReceiptStatus::Rejected && reject_reason_codes.is_empty() {
            reject_reason_codes.push("RC.RE.SCHEMA.INVALID".to_string());
        }

        self.committed_micro_milestones.push(micro.clone());
        self.committed_micro_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!("pvgs-local-micro-{}", self.committed_micro_milestones.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: micro_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: micro.micro_digest.clone(),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                reject_reason_codes
            } else {
                Vec::new()
            },
            signer: None,
        };

        Ok(receipt)
    }

    fn try_commit_next_micro(&mut self, session_id: &str) -> Result<bool, PvgsClientError> {
        if self.micro_chunk_size == 0 {
            return Ok(false);
        }

        let available = self.head_experience_id.saturating_sub(self.micro_last_end);
        if available < self.micro_chunk_size {
            return Ok(false);
        }

        let start = self.micro_last_end.saturating_add(1);
        let end = start.saturating_add(self.micro_chunk_size - 1);
        let micro = build_micro_milestone(session_id, start, end, self.head_record_digest);
        let receipt = self.commit_micro_milestone(micro)?;
        let accepted = ucf::v1::ReceiptStatus::try_from(receipt.status)
            == Ok(ucf::v1::ReceiptStatus::Accepted);

        if accepted {
            self.micro_last_end = end;
        }

        Ok(accepted)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError> {
        Ok(self.try_commit_meso_outcome.unwrap_or(false))
    }

    fn try_commit_next_macro(&mut self) -> Result<bool, PvgsClientError> {
        Ok(self.try_commit_macro_outcome.unwrap_or(false))
    }

    fn get_pending_replay_plans(
        &mut self,
        _session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        Ok(Vec::new())
    }

    fn get_pvgs_head(&self) -> PvgsHead {
        PvgsHead {
            head_experience_id: self.head_experience_id,
            head_record_digest: self.head_record_digest,
        }
    }
}

fn build_micro_milestone(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockCommitStage {
    Micro,
    Meso,
    Macro,
}

#[derive(Debug, Default, Clone)]
pub struct MockPvgsClient {
    pub local: LocalPvgsClient,
    pub micro_commit_every: Option<u64>,
    pub meso_commit_every: Option<u64>,
    pub macro_commit_every: Option<u64>,
    pub reject_stage: Option<MockCommitStage>,
    pub reject_reason: String,
    pub micro_calls: u64,
    pub meso_calls: u64,
    pub macro_calls: u64,
    pub last_call_order: Vec<MockCommitStage>,
    pub pending_replay_plans: Vec<ucf::v1::ReplayPlan>,
    pub consumed_replay_ids: Vec<String>,
    pub pending_replay_plan_calls: u64,
    pub experience_commit_statuses: Vec<ucf::v1::ReceiptStatus>,
}

impl MockPvgsClient {
    pub fn rejecting(reason_codes: Vec<String>) -> Self {
        Self {
            local: LocalPvgsClient::rejecting(reason_codes),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockPvgsReader {
    pev: Option<ucf::v1::PolicyEcologyVector>,
    pev_digest: Option<[u8; 32]>,
    ruleset_digest: Option<[u8; 32]>,
}

impl Default for MockPvgsReader {
    fn default() -> Self {
        let mut pev = ucf::v1::PolicyEcologyVector {
            conservatism_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            novelty_penalty_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            reversibility_bias: ucf::v1::PolicyEcologyBias::Medium.into(),
            pev_digest: None,
        };
        let digest = digest_pev(&pev);
        pev.pev_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        Self {
            pev: Some(pev),
            pev_digest: Some(digest),
            ruleset_digest: None,
        }
    }
}

impl MockPvgsReader {
    pub fn new(pev: Option<ucf::v1::PolicyEcologyVector>) -> Self {
        let pev_digest = pev
            .as_ref()
            .and_then(|vector| vector.pev_digest.as_ref())
            .and_then(digest32_to_array)
            .or_else(|| pev.as_ref().map(digest_pev));

        let mut pev_with_digest = pev;
        if let (Some(digest), Some(ref mut vector)) = (pev_digest, pev_with_digest.as_mut()) {
            if vector.pev_digest.is_none() {
                vector.pev_digest = Some(ucf::v1::Digest32 {
                    value: digest.to_vec(),
                });
            }
        }

        Self {
            pev: pev_with_digest,
            pev_digest,
            ruleset_digest: None,
        }
    }

    pub fn with_pev_digest(mut self, pev_digest: [u8; 32]) -> Self {
        self.pev_digest = Some(pev_digest);
        if let Some(ref mut vector) = self.pev {
            vector.pev_digest = Some(ucf::v1::Digest32 {
                value: pev_digest.to_vec(),
            });
        }
        self
    }

    pub fn with_ruleset_digest(mut self, ruleset_digest: [u8; 32]) -> Self {
        self.ruleset_digest = Some(ruleset_digest);
        self
    }
}

impl PvgsReader for MockPvgsReader {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        self.pev.clone()
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        self.pev_digest.or_else(|| {
            self.pev
                .as_ref()
                .and_then(|pev| pev.pev_digest.as_ref())
                .and_then(digest32_to_array)
        })
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.ruleset_digest
    }
}

impl PvgsClient for MockPvgsClient {
    fn commit_experience_record(
        &mut self,
        record: ucf::v1::ExperienceRecord,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let original_status = self.local.default_status;
        if let Some(status) = self.experience_commit_statuses.first().copied() {
            self.local.default_status = status;
        }

        let receipt = self.local.commit_experience_record(record);
        if !self.experience_commit_statuses.is_empty() {
            self.experience_commit_statuses.remove(0);
        }

        self.local.default_status = original_status;
        receipt
    }

    fn commit_dlp_decision(
        &mut self,
        dlp: ucf::v1::DlpDecision,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_dlp_decision(dlp)
    }

    fn commit_tool_registry(
        &mut self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_tool_registry(trc)
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_micro_milestone(micro)
    }

    fn try_commit_next_micro(&mut self, session_id: &str) -> Result<bool, PvgsClientError> {
        self.micro_calls = self.micro_calls.saturating_add(1);
        self.last_call_order.push(MockCommitStage::Micro);
        if self.reject_stage == Some(MockCommitStage::Micro) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        let committed = should_commit(self.micro_calls, self.micro_commit_every);
        if committed {
            let _ = self.local.try_commit_next_micro(session_id);
        }
        Ok(committed)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError> {
        self.meso_calls = self.meso_calls.saturating_add(1);
        self.last_call_order.push(MockCommitStage::Meso);
        if self.reject_stage == Some(MockCommitStage::Meso) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        Ok(should_commit(self.meso_calls, self.meso_commit_every))
    }

    fn try_commit_next_macro(&mut self) -> Result<bool, PvgsClientError> {
        self.macro_calls = self.macro_calls.saturating_add(1);
        self.last_call_order.push(MockCommitStage::Macro);
        if self.reject_stage == Some(MockCommitStage::Macro) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        Ok(should_commit(self.macro_calls, self.macro_commit_every))
    }

    fn get_pending_replay_plans(
        &mut self,
        _session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        self.pending_replay_plan_calls = self.pending_replay_plan_calls.saturating_add(1);
        Ok(self.pending_replay_plans.clone())
    }

    fn consume_replay_plan(&mut self, replay_id: &str) -> Result<(), PvgsClientError> {
        self.consumed_replay_ids.push(replay_id.to_string());
        Ok(())
    }

    fn get_pvgs_head(&self) -> PvgsHead {
        self.local.get_pvgs_head()
    }
}

fn should_commit(call_count: u64, every: Option<u64>) -> bool {
    match every {
        Some(value) if value > 0 => call_count.is_multiple_of(value),
        _ => false,
    }
}

fn digest_pev(pev: &ucf::v1::PolicyEcologyVector) -> [u8; 32] {
    ucf_protocol::digest_proto(
        "UCF:HASH:POLICY_ECOLOGY_VECTOR",
        &ucf_protocol::canonical_bytes(pev),
    )
}

fn digest32_to_array(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    digest.value.clone().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pvgs_verify::{
        pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
        verify_pvgs_receipt, VerifyError,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::convert::TryFrom;

    use crate::Chip4LocalPvgsClient;

    fn sample_digest(seed: u8) -> ucf::v1::Digest32 {
        ucf::v1::Digest32 {
            value: vec![seed; 32],
        }
    }

    fn sample_receipt_template() -> ucf::v1::PvgsReceipt {
        ucf::v1::PvgsReceipt {
            receipt_epoch: "epoch-1".to_string(),
            receipt_id: "receipt-abc".to_string(),
            receipt_digest: Some(sample_digest(1)),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: Some(sample_digest(2)),
            decision_digest: Some(sample_digest(3)),
            grant_id: "grant-1".to_string(),
            charter_version_digest: Some(sample_digest(4)),
            policy_version_digest: Some(sample_digest(5)),
            prev_record_digest: Some(sample_digest(6)),
            profile_digest: Some(sample_digest(7)),
            tool_profile_digest: Some(sample_digest(8)),
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    fn signing_key(seed: u64, key_id_suffix: u8) -> (SigningKey, String) {
        let mut bytes = [0u8; 32];
        StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        (sk, format!("pvgs-key-{key_id_suffix}"))
    }

    fn signed_key_epoch_with_timestamp(
        signing_key: &SigningKey,
        epoch_id: u64,
        key_id: &str,
        timestamp_ms: u64,
    ) -> ucf::v1::PvgsKeyEpoch {
        let mut key_epoch = ucf::v1::PvgsKeyEpoch {
            epoch_id,
            attestation_key_id: key_id.to_string(),
            attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            announcement_digest: None,
            signature: None,
            timestamp_ms,
            vrf_key_id: Some("pvgs-vrf-1".to_string()),
        };

        let digest = pvgs_key_epoch_digest(&key_epoch);
        key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });
        let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
        key_epoch.signature = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_epoch.attestation_key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        key_epoch
    }

    fn signed_key_epoch(
        signing_key: &SigningKey,
        epoch_id: u64,
        key_id: &str,
    ) -> ucf::v1::PvgsKeyEpoch {
        signed_key_epoch_with_timestamp(signing_key, epoch_id, key_id, 1_700_000_000_000)
    }

    fn sign_receipt(
        mut receipt: ucf::v1::PvgsReceipt,
        signing_key: &SigningKey,
        key_id: &str,
    ) -> ucf::v1::PvgsReceipt {
        let sig = signing_key.sign(&pvgs_receipt_signing_preimage(&receipt));
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: key_id.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        });
        receipt
    }

    #[test]
    fn sync_sorts_and_ingests() {
        let (signing_key, key_id) = signing_key(7, 1);
        let epoch_one = signed_key_epoch(&signing_key, 1, &key_id);
        let epoch_two = signed_key_epoch(&signing_key, 2, &key_id);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        sync.sync_from_list(vec![epoch_two, epoch_one]).unwrap();

        assert_eq!(sync.store().latest_epoch(), Some(2));
        assert_eq!(
            sync.store().pubkey_for_key_id(&key_id),
            Some(signing_key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn mock_reader_exposes_pev_and_digest() {
        let reader = MockPvgsReader::default();
        let pev = reader.get_latest_pev().expect("pev available");
        assert_eq!(
            ucf::v1::PolicyEcologyBias::try_from(pev.conservatism_bias),
            Ok(ucf::v1::PolicyEcologyBias::Medium)
        );

        let digest = reader
            .get_latest_pev_digest()
            .expect("pev digest available");
        assert_eq!(
            pev.pev_digest.as_ref().and_then(digest32_to_array),
            Some(digest)
        );
    }

    #[test]
    fn mock_reader_exposes_ruleset_digest() {
        let ruleset_digest = [7u8; 32];
        let reader = MockPvgsReader::default().with_ruleset_digest(ruleset_digest);

        assert_eq!(reader.get_current_ruleset_digest(), Some(ruleset_digest));
    }

    fn experience_record(include_governance: bool) -> ucf::v1::ExperienceRecord {
        let core_frame = ucf::v1::CoreFrame {
            session_id: "s".to_string(),
            step_id: "step".to_string(),
            input_packet_refs: Vec::new(),
            intent_refs: Vec::new(),
            candidate_refs: vec![sample_digest(9)],
            workspace_mode: ucf::v1::WorkspaceMode::ExecPlan.into(),
        };
        let metabolic_frame = ucf::v1::MetabolicFrame {
            profile_state: ucf::v1::ControlFrameProfile::M0Baseline.into(),
            control_frame_ref: Some(sample_digest(8)),
            hormone_classes: vec![ucf::v1::HormoneClass::Low.into()],
            noise_class: ucf::v1::NoiseClass::Medium.into(),
            priority_class: ucf::v1::PriorityClass::Medium.into(),
        };

        let governance_frame = include_governance.then(|| ucf::v1::GovernanceFrame {
            policy_decision_refs: vec![sample_digest(7)],
            grant_refs: Vec::new(),
            dlp_refs: Vec::new(),
            budget_snapshot_ref: Some(sample_digest(6)),
            pvgs_receipt_ref: None,
            reason_codes: None,
        });

        let governance_frame_ref = governance_frame.as_ref().map(|gf| ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:GOVERNANCE_FRAME",
                &ucf_protocol::canonical_bytes(gf),
            )
            .to_vec(),
        });

        let core_frame_ref = ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:CORE_FRAME",
                &ucf_protocol::canonical_bytes(&core_frame),
            )
            .to_vec(),
        };

        let metabolic_frame_ref = ucf::v1::Digest32 {
            value: ucf_protocol::digest_proto(
                "TEST:METABOLIC_FRAME",
                &ucf_protocol::canonical_bytes(&metabolic_frame),
            )
            .to_vec(),
        };

        ucf::v1::ExperienceRecord {
            record_type: ucf::v1::RecordType::ActionExec.into(),
            core_frame: Some(core_frame),
            metabolic_frame: Some(metabolic_frame),
            governance_frame,
            core_frame_ref: Some(core_frame_ref),
            metabolic_frame_ref: Some(metabolic_frame_ref),
            governance_frame_ref,
            related_refs: Vec::new(),
        }
    }

    #[test]
    fn local_client_rejects_missing_governance() {
        let mut client = LocalPvgsClient::default();
        let receipt = client
            .commit_experience_record(experience_record(false))
            .expect("receipt returned");

        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Rejected)
        );
        assert!(receipt
            .reject_reason_codes
            .iter()
            .any(|rc| rc == "RC.GV.MISSING"));
    }

    #[test]
    fn local_client_serializes_deterministically() {
        let mut client = LocalPvgsClient::default();
        let record = experience_record(true);

        let _ = client
            .commit_experience_record(record.clone())
            .expect("first receipt");
        let _ = client
            .commit_experience_record(record)
            .expect("second receipt");

        assert_eq!(client.committed_bytes.len(), 2);
        assert_eq!(client.committed_bytes[0], client.committed_bytes[1]);
    }

    #[test]
    fn local_client_serializes_tool_registry_deterministically() {
        let mut client = LocalPvgsClient::default();
        let registry = trm::registry_fixture();
        let trc = registry.build_registry_container("registry", "v1", 123);

        let _ = client
            .commit_tool_registry(trc.clone())
            .expect("first receipt");
        let _ = client.commit_tool_registry(trc).expect("second receipt");

        assert_eq!(client.committed_registry_bytes.len(), 2);
        assert_eq!(
            client.committed_registry_bytes[0],
            client.committed_registry_bytes[1]
        );
    }

    #[test]
    fn rejecting_client_flags_rejected_status() {
        let mut client = LocalPvgsClient::rejecting(vec!["RC.RE.INTEGRITY.DEGRADED".to_string()]);
        let receipt = client
            .commit_experience_record(experience_record(true))
            .expect("receipt returned");

        assert_eq!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Rejected)
        );
        assert!(receipt
            .reject_reason_codes
            .iter()
            .any(|rc| rc == "RC.RE.INTEGRITY.DEGRADED"));
    }

    #[test]
    fn sync_rejects_invalid_signature() {
        let (signing_key, key_id) = signing_key(11, 2);
        let mut invalid_epoch = signed_key_epoch(&signing_key, 2, &key_id);
        invalid_epoch
            .signature
            .as_mut()
            .expect("signature")
            .signature
            .reverse();

        let valid_epoch = signed_key_epoch(&signing_key, 1, &key_id);
        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());

        let err = sync
            .sync_from_list(vec![invalid_epoch, valid_epoch])
            .unwrap_err();

        assert!(matches!(
            err,
            SyncError::Ingest {
                epoch_id: 2,
                source: IngestError::InvalidSignature
            }
        ));
        assert_eq!(sync.store().latest_epoch(), Some(1));
    }

    #[test]
    fn sync_rejects_conflicting_duplicate_epoch() {
        let (signing_key, key_id) = signing_key(21, 3);
        let epoch = signed_key_epoch_with_timestamp(&signing_key, 3, &key_id, 1_700_000_000_000);
        let conflicting =
            signed_key_epoch_with_timestamp(&signing_key, 3, &key_id, 1_700_100_000_000);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        let err = sync
            .sync_from_list(vec![epoch.clone(), conflicting])
            .unwrap_err();

        assert!(matches!(
            err,
            SyncError::Ingest {
                epoch_id: 3,
                source: IngestError::ConflictingEpoch
            }
        ));
        assert_eq!(sync.store().latest_epoch(), Some(3));
    }

    #[test]
    fn receipt_verify_after_sync() {
        let (epoch_one_key, epoch_one_id) = signing_key(31, 4);
        let (epoch_two_key, epoch_two_id) = signing_key(41, 5);

        let epochs = vec![
            signed_key_epoch(&epoch_one_key, 1, &epoch_one_id),
            signed_key_epoch(&epoch_two_key, 2, &epoch_two_id),
        ];

        let receipt = sign_receipt(sample_receipt_template(), &epoch_two_key, &epoch_two_id);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        let err = verify_pvgs_receipt(&receipt, sync.store()).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownKeyId(_)));

        sync.sync_from_list(epochs).unwrap();

        assert_eq!(verify_pvgs_receipt(&receipt, sync.store()), Ok(()));
    }

    #[test]
    fn store_consistency_after_sync() {
        let (signing_key, key_id) = signing_key(51, 6);
        let epoch_one = signed_key_epoch(&signing_key, 1, &key_id);
        let epoch_two =
            signed_key_epoch_with_timestamp(&signing_key, 2, &key_id, 1_700_200_000_000);

        let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
        sync.sync_from_list(vec![epoch_two, epoch_one]).unwrap();

        assert_eq!(sync.store().latest_epoch(), Some(2));
        assert_eq!(
            sync.store().pubkey_for_key_id(&key_id),
            Some(signing_key.verifying_key().to_bytes())
        );
    }

    #[test]
    fn chip4_client_appends_and_advances_head() {
        let pvgs = chip4_pvgs::LocalPvgs::new();
        pvgs.publish_key_epoch(1);
        let before_head = pvgs.head_record_digest();
        let mut client = Chip4LocalPvgsClient::new(pvgs.clone());

        let record = experience_record(true);
        let receipt = client
            .commit_experience_record(record)
            .expect("receipt returned");

        assert_ne!(pvgs.head_record_digest(), before_head);
        assert_eq!(pvgs.head_id(), 1);
        assert!(matches!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Accepted)
        ));
        assert!(pvgs.validate_chain());
        assert!(pvgs
            .sep_events()
            .last()
            .is_some_and(|ev| ev.status == ucf::v1::ReceiptStatus::Accepted));

        let proof = client
            .last_proof_receipt
            .as_ref()
            .expect("proof receipt present");
        assert!(proof
            .receipt_digest
            .as_ref()
            .is_some_and(|d| !d.value.iter().all(|b| *b == 0)));
    }

    #[test]
    fn chip4_client_rejects_missing_governance() {
        let pvgs = chip4_pvgs::LocalPvgs::new();
        pvgs.publish_key_epoch(1);
        let before_head = pvgs.head_record_digest();
        let mut client = Chip4LocalPvgsClient::new(pvgs.clone());

        let mut record = experience_record(false);
        record.governance_frame_ref = None;
        record.governance_frame = None;

        let receipt = client
            .commit_experience_record(record)
            .expect("receipt returned");

        assert_eq!(pvgs.head_record_digest(), before_head);
        assert_eq!(pvgs.head_id(), 0);
        assert!(matches!(
            ucf::v1::ReceiptStatus::try_from(receipt.status),
            Ok(ucf::v1::ReceiptStatus::Rejected)
        ));
        assert!(pvgs
            .sep_events()
            .last()
            .is_some_and(|ev| ev.status == ucf::v1::ReceiptStatus::Rejected));
    }
}
