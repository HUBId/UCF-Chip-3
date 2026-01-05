#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use prost::Message;
use pvgs_verify::{IngestError, PvgsKeyEpochStore};
use rpp_checker::{compute_accumulator_digest, RppCheckInputs};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RppHeadMeta {
    pub head_id: u64,
    pub head_record_digest: [u8; 32],
    pub prev_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub prev_acc_digest: [u8; 32],
    pub acc_digest: [u8; 32],
    pub ruleset_digest: [u8; 32],
    pub asset_manifest_digest: Option<[u8; 32]>,
    pub payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbvDigest {
    pub epoch: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceRunStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRunSummary {
    pub trace_id: String,
    pub trace_run_digest: [u8; 32],
    pub status: TraceRunStatus,
    pub created_at_ms: u64,
    pub asset_manifest_digest: Option<[u8; 32]>,
    pub circuit_config_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scorecard {
    pub replay_mismatch_count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpotCheckReport {
    pub mismatch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedMacroInfo {
    pub macro_id: String,
    pub macro_digest: Option<[u8; 32]>,
    pub session_id: Option<String>,
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

    fn commit_tool_onboarding_event(
        &mut self,
        event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_consistency_feedback(
        &mut self,
        feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError>;

    fn commit_proposal_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let _ = payload_bytes;
        Err(PvgsClientError::CommitFailed(
            "proposal evidence not supported".to_string(),
        ))
    }

    fn commit_proposal_activation(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let _ = payload_bytes;
        Err(PvgsClientError::CommitFailed(
            "proposal activation not supported".to_string(),
        ))
    }

    fn commit_trace_run_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let _ = payload_bytes;
        Err(PvgsClientError::CommitFailed(
            "trace run evidence not supported".to_string(),
        ))
    }

    fn try_commit_next_micro(&mut self, session_id: &str) -> Result<bool, PvgsClientError>;

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError>;

    fn try_commit_next_macro(
        &mut self,
        consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, PvgsClientError>;

    fn try_propose_next_macro(&mut self) -> Result<Option<ProposedMacroInfo>, PvgsClientError> {
        let _ = self;
        Ok(None)
    }

    fn finalize_macro(
        &mut self,
        _macro_id: &str,
        _consistency_digest: [u8; 32],
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Err(PvgsClientError::CommitFailed("not implemented".to_string()))
    }

    fn get_pending_replay_plans(
        &mut self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError>;

    fn consume_replay_plan(&mut self, _replay_id: &str) -> Result<(), PvgsClientError> {
        Ok(())
    }

    fn get_pvgs_head(&self) -> PvgsHead;

    fn get_scorecard_global(&mut self) -> Result<Scorecard, PvgsClientError> {
        Err(PvgsClientError::CommitFailed(
            "scorecard not implemented".to_string(),
        ))
    }

    fn get_scorecard_session(&mut self, _session_id: &str) -> Result<Scorecard, PvgsClientError> {
        Err(PvgsClientError::CommitFailed(
            "scorecard not implemented".to_string(),
        ))
    }

    fn run_spotcheck(&mut self, _session_id: &str) -> Result<SpotCheckReport, PvgsClientError> {
        Err(PvgsClientError::CommitFailed(
            "spotcheck not implemented".to_string(),
        ))
    }
}

pub trait PvgsReader: Send + Sync {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector>;
    fn get_latest_pev_digest(&self) -> Option<[u8; 32]>;
    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]>;
    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        let _ = module;
        Ok(None)
    }
    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(Vec::new())
    }

    fn get_recovery_state(&self, session_id: &str) -> Result<Option<String>, PvgsClientError> {
        let _ = session_id;
        Ok(None)
    }

    fn is_session_sealed(&self, session_id: &str) -> Result<bool, PvgsClientError>;

    fn has_unlock_permit(&self, session_id: &str) -> Result<bool, PvgsClientError>;

    fn get_unlock_permit_digest(
        &self,
        session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        let _ = session_id;
        Ok(None)
    }

    fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        let _ = session_id;
        None
    }

    fn get_latest_cbv_digest(&self) -> Option<CbvDigest> {
        None
    }

    fn get_latest_trace_run(&mut self) -> Result<Option<TraceRunSummary>, PvgsClientError> {
        Ok(None)
    }

    fn get_latest_rpp_head_meta(&mut self) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(None)
    }

    fn get_rpp_head_meta(&mut self, _head_id: u64) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(None)
    }

    fn get_pending_replay_plans(
        &self,
        _session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        Ok(Vec::new())
    }
}

pub trait PvgsClientReader: PvgsClient + PvgsReader {}

impl<T> PvgsClientReader for T where T: PvgsClient + PvgsReader {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectorReplayPlan {
    pub replay_id: String,
    pub replay_digest: Option<[u8; 32]>,
    pub last_signalframe_digest: Option<[u8; 32]>,
}

impl From<ucf::v1::ReplayPlan> for InspectorReplayPlan {
    fn from(plan: ucf::v1::ReplayPlan) -> Self {
        Self {
            replay_id: plan.replay_id,
            replay_digest: plan.replay_digest.as_ref().and_then(digest32_to_array),
            last_signalframe_digest: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InspectorDump {
    pub ruleset_digest: Option<[u8; 32]>,
    pub sealed: bool,
    pub unlock_permit: bool,
    pub recovery_state: Option<String>,
    pub cbv_digest: Option<CbvDigest>,
    pub pev_digest: Option<[u8; 32]>,
    pub microcircuit_configs: Vec<ucf::v1::MicrocircuitConfigEvidence>,
    pub replay_plans: Vec<InspectorReplayPlan>,
}

pub struct InspectorClient<'a, T>
where
    T: PvgsClient + PvgsReader,
{
    pvgs: &'a mut T,
}

impl<'a, T> InspectorClient<'a, T>
where
    T: PvgsClient + PvgsReader,
{
    pub fn new(pvgs: &'a mut T) -> Self {
        Self { pvgs }
    }

    pub fn collect_dump(&mut self, session_id: &str) -> Result<InspectorDump, PvgsClientError> {
        let mut replay_plans: Vec<InspectorReplayPlan> = self
            .pvgs
            .get_pending_replay_plans(session_id)?
            .into_iter()
            .map(InspectorReplayPlan::from)
            .collect();
        replay_plans.sort_by(|a, b| a.replay_id.cmp(&b.replay_id));

        let mut microcircuit_configs = self.pvgs.list_microcircuit_configs()?;
        microcircuit_configs.sort_by(|a, b| {
            let module_cmp = a.module.cmp(&b.module);
            if module_cmp != std::cmp::Ordering::Equal {
                return module_cmp;
            }
            let version_cmp = a.version.cmp(&b.version);
            if version_cmp != std::cmp::Ordering::Equal {
                return version_cmp;
            }
            let a_digest = a
                .config_digest
                .as_ref()
                .map(|digest| digest.value.as_slice())
                .unwrap_or_default();
            let b_digest = b
                .config_digest
                .as_ref()
                .map(|digest| digest.value.as_slice())
                .unwrap_or_default();
            a_digest.cmp(b_digest)
        });

        Ok(InspectorDump {
            ruleset_digest: self.pvgs.get_current_ruleset_digest(),
            sealed: self.pvgs.is_session_sealed(session_id)?,
            unlock_permit: self.pvgs.has_unlock_permit(session_id)?,
            recovery_state: self.pvgs.get_recovery_state(session_id)?,
            cbv_digest: self.pvgs.get_latest_cbv_digest(),
            pev_digest: self.pvgs.get_latest_pev_digest(),
            microcircuit_configs,
            replay_plans,
        })
    }

    pub fn format_dump(dump: &InspectorDump) -> String {
        let ruleset_digest = format_optional_digest(dump.ruleset_digest);
        let recovery_state = dump.recovery_state.as_deref().unwrap_or("NONE").to_string();
        let cbv_epoch = dump
            .cbv_digest
            .as_ref()
            .map(|cbv| cbv.epoch.to_string())
            .unwrap_or_else(|| "NONE".to_string());
        let cbv_digest = dump
            .cbv_digest
            .as_ref()
            .map(|cbv| format_optional_digest(Some(cbv.digest)))
            .unwrap_or_else(|| "NONE".to_string());
        let pev_digest = format_optional_digest(dump.pev_digest);

        let mut lines = vec![
            format!("ruleset_digest: {ruleset_digest}"),
            format!("sealed: {}", dump.sealed),
            format!("unlock_permit: {}", dump.unlock_permit),
            format!("recovery_state: {recovery_state}"),
            format!("cbv: epoch={cbv_epoch} digest={cbv_digest}"),
            format!("pev_digest: {pev_digest}"),
            format!("microcircuit_configs: {}", dump.microcircuit_configs.len()),
        ];

        for config in &dump.microcircuit_configs {
            let module = match ucf::v1::MicroModule::try_from(config.module) {
                Ok(ucf::v1::MicroModule::Lc) => "LC",
                Ok(ucf::v1::MicroModule::Sn) => "SN",
                _ => "UNSPECIFIED",
            };
            let digest = config.config_digest.as_ref().and_then(digest32_to_array);
            let digest = format_optional_digest(digest);
            lines.push(format!(
                "- {module}: version={} digest={digest}",
                config.version
            ));
        }

        lines.push(format!("pending_replay_plans: {}", dump.replay_plans.len()));

        for plan in &dump.replay_plans {
            let replay_digest = format_optional_digest(plan.replay_digest);
            let last_signalframe_digest = format_optional_digest(plan.last_signalframe_digest);
            lines.push(format!("- {} digest={replay_digest}", plan.replay_id));
            lines.push(format!(
                "  last_signalframe_digest: {last_signalframe_digest}"
            ));
        }

        lines.join("\n") + "\n"
    }

    pub fn inspect_dump(&mut self, session_id: &str) -> Result<String, PvgsClientError> {
        let dump = self.collect_dump(session_id)?;
        Ok(Self::format_dump(&dump))
    }
}

fn format_optional_digest(digest: Option<[u8; 32]>) -> String {
    digest
        .map(hex::encode)
        .unwrap_or_else(|| "NONE".to_string())
}

#[cfg(any(test, feature = "local-e2e"))]
#[derive(Clone)]
pub struct Chip4LocalPvgsClient {
    pub pvgs: chip4_pvgs::LocalPvgs,
    pub last_proof_receipt: Option<ucf::v1::ProofReceipt>,
    pub proposed_macros: VecDeque<ProposedMacroInfo>,
    pub finalized_macros: Vec<(String, [u8; 32])>,
}

#[cfg(any(test, feature = "local-e2e"))]
impl Chip4LocalPvgsClient {
    pub fn new(pvgs: chip4_pvgs::LocalPvgs) -> Self {
        Self {
            pvgs,
            last_proof_receipt: None,
            proposed_macros: VecDeque::new(),
            finalized_macros: Vec::new(),
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

    fn commit_tool_onboarding_event(
        &mut self,
        _event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Err(PvgsClientError::CommitFailed(
            "tool onboarding events not supported".to_string(),
        ))
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let receipt = self.pvgs.append_micro_milestone(micro);
        Ok(receipt)
    }

    fn commit_consistency_feedback(
        &mut self,
        feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let (receipt, proof_receipt) = self.pvgs.append_consistency_feedback(feedback);
        self.last_proof_receipt = Some(proof_receipt);
        Ok(receipt)
    }

    fn commit_proposal_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Ok(self.pvgs.append_proposal_evidence(payload_bytes))
    }

    fn commit_proposal_activation(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Ok(self.pvgs.append_proposal_evidence(payload_bytes))
    }

    fn commit_trace_run_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        Ok(self.pvgs.append_trace_run_evidence(payload_bytes))
    }

    fn try_commit_next_micro(&mut self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn try_commit_next_meso(&mut self) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn try_commit_next_macro(
        &mut self,
        _consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, PvgsClientError> {
        Ok(false)
    }

    fn try_propose_next_macro(&mut self) -> Result<Option<ProposedMacroInfo>, PvgsClientError> {
        Ok(self.proposed_macros.pop_front())
    }

    fn finalize_macro(
        &mut self,
        macro_id: &str,
        consistency_digest: [u8; 32],
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.finalized_macros
            .push((macro_id.to_string(), consistency_digest));

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: "chip4-local-epoch".to_string(),
            receipt_id: format!("macro-{macro_id}"),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: consistency_digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: consistency_digest.to_vec(),
            }),
            grant_id: "chip4-local-grant".to_string(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        Ok(receipt)
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

    fn get_scorecard_global(&mut self) -> Result<Scorecard, PvgsClientError> {
        Ok(Scorecard::default())
    }

    fn get_scorecard_session(&mut self, _session_id: &str) -> Result<Scorecard, PvgsClientError> {
        Ok(Scorecard::default())
    }

    fn run_spotcheck(&mut self, _session_id: &str) -> Result<SpotCheckReport, PvgsClientError> {
        Ok(SpotCheckReport::default())
    }
}

#[cfg(any(test, feature = "local-e2e"))]
impl PvgsReader for Chip4LocalPvgsClient {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        None
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        None
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        None
    }

    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(self.pvgs.get_microcircuit_config(module))
    }

    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(self.pvgs.list_microcircuit_configs())
    }

    fn get_recovery_state(&self, _session_id: &str) -> Result<Option<String>, PvgsClientError> {
        Ok(None)
    }

    fn get_latest_cbv_digest(&self) -> Option<CbvDigest> {
        None
    }

    fn get_latest_trace_run(&mut self) -> Result<Option<TraceRunSummary>, PvgsClientError> {
        Ok(self
            .pvgs
            .get_latest_trace_run()
            .map(|trace| TraceRunSummary {
                trace_id: trace.trace_id,
                trace_run_digest: trace.trace_run_digest,
                status: match trace.status {
                    chip4_pvgs::TraceRunStatus::Pass => TraceRunStatus::Pass,
                    chip4_pvgs::TraceRunStatus::Fail => TraceRunStatus::Fail,
                },
                created_at_ms: trace.created_at_ms,
                asset_manifest_digest: trace.asset_manifest_digest,
                circuit_config_digest: trace.circuit_config_digest,
            }))
    }

    fn is_session_sealed(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.pvgs.is_session_sealed(session_id))
    }

    fn has_unlock_permit(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.pvgs.has_unlock_permit(session_id))
    }

    fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        self.pvgs.get_session_seal_digest(session_id)
    }

    fn get_unlock_permit_digest(
        &self,
        session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        Ok(self.pvgs.get_unlock_permit_digest(session_id))
    }

    fn get_latest_rpp_head_meta(&mut self) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self
            .pvgs
            .get_latest_rpp_head_meta()
            .map(rpp_head_meta_from_chip4))
    }

    fn get_rpp_head_meta(&mut self, head_id: u64) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self
            .pvgs
            .get_rpp_head_meta(head_id)
            .map(rpp_head_meta_from_chip4))
    }
}

fn default_rpp_head_meta() -> RppHeadMeta {
    let inputs = RppCheckInputs {
        prev_acc: [1u8; 32],
        prev_root: [2u8; 32],
        new_root: [3u8; 32],
        payload_digest: [4u8; 32],
        ruleset_digest: [5u8; 32],
        asset_manifest_digest: None,
    };
    let acc_digest = compute_accumulator_digest(&inputs);
    RppHeadMeta {
        head_id: 1,
        head_record_digest: [9u8; 32],
        prev_state_root: inputs.prev_root,
        state_root: inputs.new_root,
        prev_acc_digest: inputs.prev_acc,
        acc_digest,
        ruleset_digest: inputs.ruleset_digest,
        asset_manifest_digest: inputs.asset_manifest_digest,
        payload_digest: Some(inputs.payload_digest),
    }
}

#[cfg(any(test, feature = "local-e2e"))]
fn rpp_head_meta_from_chip4(meta: chip4_pvgs::RppHeadMeta) -> RppHeadMeta {
    RppHeadMeta {
        head_id: meta.head_id,
        head_record_digest: meta.head_record_digest,
        prev_state_root: meta.prev_state_root,
        state_root: meta.state_root,
        prev_acc_digest: meta.prev_acc_digest,
        acc_digest: meta.acc_digest,
        ruleset_digest: meta.ruleset_digest,
        asset_manifest_digest: meta.asset_manifest_digest,
        payload_digest: meta.payload_digest,
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
    rpp_head_meta: Option<RppHeadMeta>,
    rpp_heads: HashMap<u64, RppHeadMeta>,
    pub committed_records: Vec<ucf::v1::ExperienceRecord>,
    pub committed_bytes: Vec<Vec<u8>>,
    pub committed_dlp_decisions: Vec<ucf::v1::DlpDecision>,
    pub committed_dlp_bytes: Vec<Vec<u8>>,
    pub committed_tool_registries: Vec<ucf::v1::ToolRegistryContainer>,
    pub committed_registry_bytes: Vec<Vec<u8>>,
    pub committed_tool_onboarding_events: Vec<ucf::v1::ToolOnboardingEvent>,
    pub committed_tool_onboarding_bytes: Vec<Vec<u8>>,
    pub committed_micro_milestones: Vec<ucf::v1::MicroMilestone>,
    pub committed_micro_bytes: Vec<Vec<u8>>,
    pub committed_consistency_feedback: Vec<ucf::v1::ConsistencyFeedback>,
    pub committed_consistency_bytes: Vec<Vec<u8>>,
    pub committed_proposal_evidence_bytes: Vec<Vec<u8>>,
    pub committed_proposal_activation_bytes: Vec<Vec<u8>>,
    pub committed_trace_run_bytes: Vec<Vec<u8>>,
    pub micro_chunk_size: u64,
    pub micro_last_end: u64,
    pub try_commit_meso_outcome: Option<bool>,
    pub try_commit_macro_outcome: Option<bool>,
    pub proposed_macros: VecDeque<ProposedMacroInfo>,
    pub finalized_macros: Vec<(String, [u8; 32])>,
    pub scorecard_global: Scorecard,
    pub scorecard_session: Scorecard,
    pub spotcheck_report: SpotCheckReport,
    sealed_sessions: HashMap<String, Option<[u8; 32]>>,
    unlock_permits: HashMap<String, Option<[u8; 32]>>,
    recovery_states: HashMap<String, Option<String>>,
    microcircuit_configs: Vec<ucf::v1::MicrocircuitConfigEvidence>,
}

impl Default for LocalPvgsClient {
    fn default() -> Self {
        let default_rpp_head = default_rpp_head_meta();
        Self {
            receipt_epoch: "local-epoch".to_string(),
            grant_id: "local-grant".to_string(),
            default_status: ucf::v1::ReceiptStatus::Accepted,
            reject_reason_codes: Vec::new(),
            head_experience_id: 0,
            head_record_digest: [0u8; 32],
            rpp_head_meta: Some(default_rpp_head),
            rpp_heads: HashMap::from([(default_rpp_head.head_id, default_rpp_head)]),
            committed_records: Vec::new(),
            committed_bytes: Vec::new(),
            committed_dlp_decisions: Vec::new(),
            committed_dlp_bytes: Vec::new(),
            committed_tool_registries: Vec::new(),
            committed_registry_bytes: Vec::new(),
            committed_tool_onboarding_events: Vec::new(),
            committed_tool_onboarding_bytes: Vec::new(),
            committed_micro_milestones: Vec::new(),
            committed_micro_bytes: Vec::new(),
            committed_consistency_feedback: Vec::new(),
            committed_consistency_bytes: Vec::new(),
            committed_proposal_evidence_bytes: Vec::new(),
            committed_proposal_activation_bytes: Vec::new(),
            committed_trace_run_bytes: Vec::new(),
            micro_chunk_size: 256,
            micro_last_end: 0,
            try_commit_meso_outcome: None,
            try_commit_macro_outcome: None,
            proposed_macros: VecDeque::new(),
            finalized_macros: Vec::new(),
            scorecard_global: Scorecard::default(),
            scorecard_session: Scorecard::default(),
            spotcheck_report: SpotCheckReport::default(),
            sealed_sessions: HashMap::new(),
            unlock_permits: HashMap::new(),
            recovery_states: HashMap::new(),
            microcircuit_configs: Vec::new(),
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

    pub fn set_session_sealed(&mut self, session_id: impl Into<String>, digest: Option<[u8; 32]>) {
        self.sealed_sessions.insert(session_id.into(), digest);
    }

    pub fn set_unlock_permit(&mut self, session_id: impl Into<String>, digest: Option<[u8; 32]>) {
        self.unlock_permits.insert(session_id.into(), digest);
    }

    pub fn set_recovery_state(&mut self, session_id: impl Into<String>, state: Option<String>) {
        self.recovery_states.insert(session_id.into(), state);
    }

    pub fn set_microcircuit_config(&mut self, config: ucf::v1::MicrocircuitConfigEvidence) {
        self.microcircuit_configs
            .retain(|existing| existing.module != config.module);
        self.microcircuit_configs.push(config);
    }

    pub fn set_latest_rpp_head_meta(&mut self, meta: RppHeadMeta) {
        self.rpp_heads.insert(meta.head_id, meta);
        self.rpp_head_meta = Some(meta);
    }

    pub fn set_rpp_head_meta(&mut self, meta: RppHeadMeta) {
        self.rpp_heads.insert(meta.head_id, meta);
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

    fn commit_tool_onboarding_event(
        &mut self,
        mut event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        if event.event_digest.is_none() {
            let digest = ucf_protocol::digest_proto(
                "UCF:HASH:TOOL_ONBOARDING_EVENT",
                &ucf_protocol::canonical_bytes(&event),
            );
            event.event_digest = Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            });
        }

        let bytes = ucf_protocol::canonical_bytes(&event);
        let event_digest: [u8; 32] = event
            .event_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if status == ucf::v1::ReceiptStatus::Rejected && reject_reason_codes.is_empty() {
            reject_reason_codes.push("RC.RE.SCHEMA.INVALID".to_string());
        }

        self.committed_tool_onboarding_events.push(event.clone());
        self.committed_tool_onboarding_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-tool-onboarding-{}",
                self.committed_tool_onboarding_events.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: event_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: event.event_digest.clone(),
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

    fn commit_consistency_feedback(
        &mut self,
        mut feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        if feedback.cf_digest.is_none() {
            let digest = ucf_protocol::digest_proto(
                "UCF:HASH:CONSISTENCY_FEEDBACK",
                &ucf_protocol::canonical_bytes(&feedback),
            );
            feedback.cf_digest = Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            });
        }

        let bytes = ucf_protocol::canonical_bytes(&feedback);
        let cf_digest: [u8; 32] = feedback
            .cf_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if status == ucf::v1::ReceiptStatus::Rejected && reject_reason_codes.is_empty() {
            reject_reason_codes.push("RC.RE.SCHEMA.INVALID".to_string());
        }

        self.committed_consistency_feedback.push(feedback.clone());
        self.committed_consistency_bytes.push(bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-cf-{}",
                self.committed_consistency_feedback.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: cf_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: feedback.cf_digest.clone(),
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

    fn commit_proposal_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let digest = ucf_protocol::digest_proto("UCF:HASH:PROPOSAL_EVIDENCE", &payload_bytes);
        let evidence_valid = proposal_evidence_digest_valid(&payload_bytes);
        self.committed_proposal_evidence_bytes.push(payload_bytes);

        let mut status = self.default_status;
        let mut reject_reason_codes = if status == ucf::v1::ReceiptStatus::Rejected {
            self.reject_reason_codes.clone()
        } else {
            Vec::new()
        };
        if !evidence_valid {
            status = ucf::v1::ReceiptStatus::Rejected;
            if reject_reason_codes.is_empty() {
                reject_reason_codes.push("RC.GV.DIGEST_MISMATCH".to_string());
            }
        }

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-proposal-evidence-{}",
                self.committed_proposal_evidence_bytes.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes,
            signer: None,
        };

        Ok(receipt)
    }

    fn commit_proposal_activation(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let digest = ucf_protocol::digest_proto("UCF:HASH:PROPOSAL_ACTIVATION", &payload_bytes);
        let evidence_valid = activation_evidence_digest_valid(&payload_bytes);
        self.committed_proposal_activation_bytes.push(payload_bytes);

        let mut status = self.default_status;
        let mut reject_reason_codes = if status == ucf::v1::ReceiptStatus::Rejected {
            self.reject_reason_codes.clone()
        } else {
            Vec::new()
        };
        if !evidence_valid {
            status = ucf::v1::ReceiptStatus::Rejected;
            if reject_reason_codes.is_empty() {
                reject_reason_codes.push("RC.GV.DIGEST_MISMATCH".to_string());
            }
        }

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-proposal-activation-{}",
                self.committed_proposal_activation_bytes.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes,
            signer: None,
        };

        Ok(receipt)
    }

    fn commit_trace_run_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        let digest = ucf_protocol::digest_proto("UCF:HASH:TRACE_RUN_EVIDENCE", &payload_bytes);
        let evidence_valid = trace_run_evidence_digest_valid(&payload_bytes);
        self.committed_trace_run_bytes.push(payload_bytes);

        let mut status = self.default_status;
        let mut reject_reason_codes = if status == ucf::v1::ReceiptStatus::Rejected {
            self.reject_reason_codes.clone()
        } else {
            Vec::new()
        };
        if !evidence_valid {
            status = ucf::v1::ReceiptStatus::Rejected;
            if reject_reason_codes.is_empty() {
                reject_reason_codes.push("RC.GV.DIGEST_MISMATCH".to_string());
            }
        }

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!(
                "pvgs-local-trace-run-{}",
                self.committed_trace_run_bytes.len()
            ),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: self.grant_id.clone(),
            charter_version_digest: None,
            policy_version_digest: None,
            prev_record_digest: None,
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes,
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

    fn try_commit_next_macro(
        &mut self,
        _consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, PvgsClientError> {
        Ok(self.try_commit_macro_outcome.unwrap_or(false))
    }

    fn try_propose_next_macro(&mut self) -> Result<Option<ProposedMacroInfo>, PvgsClientError> {
        Ok(self.proposed_macros.pop_front())
    }

    fn finalize_macro(
        &mut self,
        macro_id: &str,
        consistency_digest: [u8; 32],
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.finalized_macros
            .push((macro_id.to_string(), consistency_digest));

        let status = self.default_status;
        let mut reject_reason_codes = self.reject_reason_codes.clone();
        if status == ucf::v1::ReceiptStatus::Rejected && reject_reason_codes.is_empty() {
            reject_reason_codes.push("RC.RE.SCHEMA.INVALID".to_string());
        }

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: self.receipt_epoch.clone(),
            receipt_id: format!("pvgs-local-macro-{}", self.finalized_macros.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: consistency_digest.to_vec(),
            }),
            status: status.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: consistency_digest.to_vec(),
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

    fn get_scorecard_global(&mut self) -> Result<Scorecard, PvgsClientError> {
        Ok(self.scorecard_global.clone())
    }

    fn get_scorecard_session(&mut self, _session_id: &str) -> Result<Scorecard, PvgsClientError> {
        Ok(self.scorecard_session.clone())
    }

    fn run_spotcheck(&mut self, _session_id: &str) -> Result<SpotCheckReport, PvgsClientError> {
        Ok(self.spotcheck_report.clone())
    }
}

fn proposal_evidence_digest_valid(payload_bytes: &[u8]) -> bool {
    let mut evidence = match ucf::v1::ProposalEvidence::decode(payload_bytes) {
        Ok(evidence) => evidence,
        Err(_) => return false,
    };
    let digest = evidence
        .proposal_digest
        .as_ref()
        .and_then(digest_bytes)
        .unwrap_or([0u8; 32]);
    evidence.proposal_digest = Some(ucf::v1::Digest32 {
        value: vec![0u8; 32],
    });
    let recomputed = ucf_protocol::digest_proto(
        "UCF:PROPOSAL_EVIDENCE",
        &ucf_protocol::canonical_bytes(&evidence),
    );
    digest == recomputed
}

fn activation_evidence_digest_valid(payload_bytes: &[u8]) -> bool {
    let mut evidence = match ucf::v1::ProposalActivationEvidence::decode(payload_bytes) {
        Ok(evidence) => evidence,
        Err(_) => return false,
    };
    let digest = evidence
        .activation_digest
        .as_ref()
        .and_then(digest_bytes)
        .unwrap_or([0u8; 32]);
    evidence.activation_digest = Some(ucf::v1::Digest32 {
        value: vec![0u8; 32],
    });
    let recomputed = ucf_protocol::digest_proto(
        "UCF:ACTIVATION_EVIDENCE",
        &ucf_protocol::canonical_bytes(&evidence),
    );
    digest == recomputed
}

fn trace_run_evidence_digest_valid(payload_bytes: &[u8]) -> bool {
    let mut evidence = match ucf::v1::TraceRunEvidence::decode(payload_bytes) {
        Ok(evidence) => evidence,
        Err(_) => return false,
    };
    let digest = evidence
        .trace_digest
        .as_ref()
        .and_then(digest_bytes)
        .unwrap_or([0u8; 32]);
    evidence.trace_digest = Some(ucf::v1::Digest32 {
        value: vec![0u8; 32],
    });
    let recomputed = ucf_protocol::digest_proto(
        "UCF:TRACE_RUN_EVIDENCE",
        &ucf_protocol::canonical_bytes(&evidence),
    );
    digest == recomputed
}

fn digest_bytes(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    digest.value.as_slice().try_into().ok()
}

impl PvgsReader for LocalPvgsClient {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        None
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        None
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        None
    }

    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        let module = module as i32;
        Ok(self
            .microcircuit_configs
            .iter()
            .find(|config| config.module == module)
            .cloned())
    }

    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(self.microcircuit_configs.clone())
    }

    fn get_recovery_state(&self, session_id: &str) -> Result<Option<String>, PvgsClientError> {
        Ok(self.recovery_states.get(session_id).cloned().flatten())
    }

    fn get_latest_cbv_digest(&self) -> Option<CbvDigest> {
        None
    }

    fn get_latest_trace_run(&mut self) -> Result<Option<TraceRunSummary>, PvgsClientError> {
        Ok(None)
    }

    fn get_latest_rpp_head_meta(&mut self) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self.rpp_head_meta)
    }

    fn get_rpp_head_meta(&mut self, head_id: u64) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self.rpp_heads.get(&head_id).copied())
    }

    fn is_session_sealed(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.sealed_sessions.contains_key(session_id))
    }

    fn has_unlock_permit(&self, session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.unlock_permits.contains_key(session_id))
    }

    fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        self.sealed_sessions
            .get(session_id)
            .and_then(|digest| *digest)
    }

    fn get_unlock_permit_digest(
        &self,
        session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        Ok(self
            .unlock_permits
            .get(session_id)
            .and_then(|digest| *digest))
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
    ToolOnboarding,
    Consistency,
    MacroPropose,
    MacroFinalize,
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
    pub macro_finalize_calls: u64,
    pub last_call_order: Vec<MockCommitStage>,
    pub pending_replay_plans: Vec<ucf::v1::ReplayPlan>,
    pub consumed_replay_ids: Vec<String>,
    pub pending_replay_plan_calls: u64,
    pub experience_commit_statuses: Vec<ucf::v1::ReceiptStatus>,
    pub committed_tool_onboarding_events: Vec<ucf::v1::ToolOnboardingEvent>,
    pub committed_consistency_feedback: Vec<ucf::v1::ConsistencyFeedback>,
    pub macro_consistency_digests: Vec<Option<[u8; 32]>>,
    pub proposed_macros: VecDeque<ProposedMacroInfo>,
    pub finalized_macros: Vec<(String, [u8; 32])>,
    pub pev_digest: Option<[u8; 32]>,
    pub ruleset_digest: Option<[u8; 32]>,
    pub latest_cbv_digest: Option<CbvDigest>,
    pub session_sealed: bool,
    pub session_seal_digest: Option<[u8; 32]>,
    pub unlock_permit: bool,
    pub unlock_permit_digest: Option<[u8; 32]>,
    pub recovery_state: Option<String>,
    pub microcircuit_configs: Vec<ucf::v1::MicrocircuitConfigEvidence>,
    pub scorecard_global: Scorecard,
    pub scorecard_session: Scorecard,
    pub spotcheck_report: SpotCheckReport,
    pub scorecard_global_calls: u64,
    pub scorecard_session_calls: u64,
    pub spotcheck_calls: u64,
    pub trace_run_summary: Option<TraceRunSummary>,
    pub committed_trace_run_bytes: Vec<Vec<u8>>,
}

impl MockPvgsClient {
    pub fn rejecting(reason_codes: Vec<String>) -> Self {
        Self {
            local: LocalPvgsClient::rejecting(reason_codes),
            ..Self::default()
        }
    }
}

impl PvgsReader for MockPvgsClient {
    fn get_latest_pev(&self) -> Option<ucf::v1::PolicyEcologyVector> {
        None
    }

    fn get_latest_pev_digest(&self) -> Option<[u8; 32]> {
        self.pev_digest
    }

    fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.ruleset_digest
    }

    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        let module = module as i32;
        Ok(self
            .microcircuit_configs
            .iter()
            .find(|config| config.module == module)
            .cloned())
    }

    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(self.microcircuit_configs.clone())
    }

    fn get_recovery_state(&self, _session_id: &str) -> Result<Option<String>, PvgsClientError> {
        Ok(self.recovery_state.clone())
    }

    fn get_latest_cbv_digest(&self) -> Option<CbvDigest> {
        self.latest_cbv_digest
    }

    fn get_latest_trace_run(&mut self) -> Result<Option<TraceRunSummary>, PvgsClientError> {
        Ok(self.trace_run_summary.clone())
    }

    fn get_latest_rpp_head_meta(&mut self) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        self.local.get_latest_rpp_head_meta()
    }

    fn get_rpp_head_meta(&mut self, head_id: u64) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        self.local.get_rpp_head_meta(head_id)
    }

    fn is_session_sealed(&self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.session_sealed)
    }

    fn has_unlock_permit(&self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.unlock_permit)
    }

    fn get_session_seal_digest(&self, _session_id: &str) -> Option<[u8; 32]> {
        self.session_seal_digest
    }

    fn get_unlock_permit_digest(
        &self,
        _session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        Ok(self.unlock_permit_digest)
    }

    fn get_pending_replay_plans(
        &self,
        session_id: &str,
    ) -> Result<Vec<ucf::v1::ReplayPlan>, PvgsClientError> {
        if session_id.is_empty() {
            return Ok(Vec::new());
        }

        Ok(self.pending_replay_plans.clone())
    }
}

#[derive(Debug, Clone)]
pub struct MockPvgsReader {
    pev: Option<ucf::v1::PolicyEcologyVector>,
    pev_digest: Option<[u8; 32]>,
    ruleset_digest: Option<[u8; 32]>,
    rpp_head_meta: Option<RppHeadMeta>,
    rpp_heads: HashMap<u64, RppHeadMeta>,
    session_sealed: bool,
    session_seal_digest: Option<[u8; 32]>,
    unlock_permit: bool,
    unlock_permit_digest: Option<[u8; 32]>,
    recovery_state: Option<String>,
    microcircuit_configs: Vec<ucf::v1::MicrocircuitConfigEvidence>,
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

        let default_rpp_head = default_rpp_head_meta();
        Self {
            pev: Some(pev),
            pev_digest: Some(digest),
            ruleset_digest: None,
            rpp_head_meta: Some(default_rpp_head),
            rpp_heads: HashMap::from([(default_rpp_head.head_id, default_rpp_head)]),
            session_sealed: false,
            session_seal_digest: None,
            unlock_permit: false,
            unlock_permit_digest: None,
            recovery_state: None,
            microcircuit_configs: Vec::new(),
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

        let default_rpp_head = default_rpp_head_meta();
        Self {
            pev: pev_with_digest,
            pev_digest,
            ruleset_digest: None,
            rpp_head_meta: Some(default_rpp_head),
            rpp_heads: HashMap::from([(default_rpp_head.head_id, default_rpp_head)]),
            session_sealed: false,
            session_seal_digest: None,
            unlock_permit: false,
            unlock_permit_digest: None,
            recovery_state: None,
            microcircuit_configs: Vec::new(),
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

    pub fn with_session_sealed(mut self, digest: Option<[u8; 32]>) -> Self {
        self.session_sealed = true;
        self.session_seal_digest = digest;
        self
    }

    pub fn with_unlock_permit(mut self, digest: Option<[u8; 32]>) -> Self {
        self.unlock_permit = true;
        self.unlock_permit_digest = digest;
        self
    }

    pub fn with_recovery_state(mut self, state: Option<String>) -> Self {
        self.recovery_state = state;
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

    fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Result<Option<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        let module = module as i32;
        Ok(self
            .microcircuit_configs
            .iter()
            .find(|config| config.module == module)
            .cloned())
    }

    fn list_microcircuit_configs(
        &self,
    ) -> Result<Vec<ucf::v1::MicrocircuitConfigEvidence>, PvgsClientError> {
        Ok(self.microcircuit_configs.clone())
    }

    fn get_recovery_state(&self, _session_id: &str) -> Result<Option<String>, PvgsClientError> {
        Ok(self.recovery_state.clone())
    }

    fn get_latest_rpp_head_meta(&mut self) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self.rpp_head_meta)
    }

    fn get_rpp_head_meta(&mut self, head_id: u64) -> Result<Option<RppHeadMeta>, PvgsClientError> {
        Ok(self.rpp_heads.get(&head_id).copied())
    }

    fn is_session_sealed(&self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.session_sealed)
    }

    fn has_unlock_permit(&self, _session_id: &str) -> Result<bool, PvgsClientError> {
        Ok(self.unlock_permit)
    }

    fn get_session_seal_digest(&self, _session_id: &str) -> Option<[u8; 32]> {
        self.session_seal_digest
    }

    fn get_unlock_permit_digest(
        &self,
        _session_id: &str,
    ) -> Result<Option<[u8; 32]>, PvgsClientError> {
        Ok(self.unlock_permit_digest)
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

    fn commit_tool_onboarding_event(
        &mut self,
        event: ucf::v1::ToolOnboardingEvent,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.last_call_order.push(MockCommitStage::ToolOnboarding);
        if self.reject_stage == Some(MockCommitStage::ToolOnboarding) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        self.committed_tool_onboarding_events.push(event.clone());
        self.local.commit_tool_onboarding_event(event)
    }

    fn commit_micro_milestone(
        &mut self,
        micro: ucf::v1::MicroMilestone,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_micro_milestone(micro)
    }

    fn commit_consistency_feedback(
        &mut self,
        feedback: ucf::v1::ConsistencyFeedback,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.last_call_order.push(MockCommitStage::Consistency);
        if self.reject_stage == Some(MockCommitStage::Consistency) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        self.committed_consistency_feedback.push(feedback.clone());
        self.local.commit_consistency_feedback(feedback)
    }

    fn commit_proposal_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_proposal_evidence(payload_bytes)
    }

    fn commit_proposal_activation(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.local.commit_proposal_activation(payload_bytes)
    }

    fn commit_trace_run_evidence(
        &mut self,
        payload_bytes: Vec<u8>,
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.committed_trace_run_bytes.push(payload_bytes.clone());
        self.local.commit_trace_run_evidence(payload_bytes)
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

    fn try_commit_next_macro(
        &mut self,
        consistency_digest: Option<[u8; 32]>,
    ) -> Result<bool, PvgsClientError> {
        self.macro_calls = self.macro_calls.saturating_add(1);
        self.last_call_order.push(MockCommitStage::MacroFinalize);
        if self.reject_stage == Some(MockCommitStage::MacroFinalize) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        self.macro_consistency_digests.push(consistency_digest);

        Ok(should_commit(self.macro_calls, self.macro_commit_every))
    }

    fn try_propose_next_macro(&mut self) -> Result<Option<ProposedMacroInfo>, PvgsClientError> {
        self.last_call_order.push(MockCommitStage::MacroPropose);
        if self.reject_stage == Some(MockCommitStage::MacroPropose) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        Ok(self.proposed_macros.pop_front())
    }

    fn finalize_macro(
        &mut self,
        macro_id: &str,
        consistency_digest: [u8; 32],
    ) -> Result<ucf::v1::PvgsReceipt, PvgsClientError> {
        self.macro_finalize_calls = self.macro_finalize_calls.saturating_add(1);
        self.last_call_order.push(MockCommitStage::MacroFinalize);
        if self.reject_stage == Some(MockCommitStage::MacroFinalize) {
            return Err(PvgsClientError::CommitFailed(
                if self.reject_reason.is_empty() {
                    "RC.RE.INTEGRITY.DEGRADED".to_string()
                } else {
                    self.reject_reason.clone()
                },
            ));
        }

        self.macro_consistency_digests
            .push(Some(consistency_digest));
        self.finalized_macros
            .push((macro_id.to_string(), consistency_digest));

        self.local
            .finalize_macro(macro_id, consistency_digest)
            .map_err(|err| match err {
                PvgsClientError::CommitFailed(reason) => PvgsClientError::CommitFailed(reason),
            })
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

    fn get_scorecard_global(&mut self) -> Result<Scorecard, PvgsClientError> {
        self.scorecard_global_calls = self.scorecard_global_calls.saturating_add(1);
        Ok(self.scorecard_global.clone())
    }

    fn get_scorecard_session(&mut self, _session_id: &str) -> Result<Scorecard, PvgsClientError> {
        self.scorecard_session_calls = self.scorecard_session_calls.saturating_add(1);
        Ok(self.scorecard_session.clone())
    }

    fn run_spotcheck(&mut self, _session_id: &str) -> Result<SpotCheckReport, PvgsClientError> {
        self.spotcheck_calls = self.spotcheck_calls.saturating_add(1);
        Ok(self.spotcheck_report.clone())
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
    fn tool_onboarding_commit_is_idempotent_per_tool() {
        use std::collections::HashSet;

        let mut client = MockPvgsClient::default();
        let mut seen = HashSet::new();

        let event = ucf::v1::ToolOnboardingEvent {
            event_id: "mock.read".to_string(),
            event_digest: None,
            reason_codes: None,
        };

        let mut commit_if_new = |ev: ucf::v1::ToolOnboardingEvent| {
            if seen.insert(ev.event_id.clone()) {
                client
                    .commit_tool_onboarding_event(ev)
                    .expect("commit accepted");
            }
        };

        commit_if_new(event.clone());
        commit_if_new(event);

        assert_eq!(client.committed_tool_onboarding_events.len(), 1);
        assert_eq!(
            client
                .committed_tool_onboarding_events
                .first()
                .expect("event recorded")
                .event_id,
            "mock.read"
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

    #[test]
    fn formats_inspector_dump() {
        let mut client = MockPvgsClient {
            ruleset_digest: Some([0x11; 32]),
            pev_digest: Some([0x22; 32]),
            latest_cbv_digest: Some(CbvDigest {
                epoch: 7,
                digest: [0x33; 32],
            }),
            session_sealed: true,
            recovery_state: Some("R1_STABILIZED".to_string()),
            microcircuit_configs: vec![
                ucf::v1::MicrocircuitConfigEvidence {
                    module: ucf::v1::MicroModule::Sn.into(),
                    version: 2,
                    config_digest: Some(ucf::v1::Digest32 {
                        value: vec![0x77; 32],
                    }),
                },
                ucf::v1::MicrocircuitConfigEvidence {
                    module: ucf::v1::MicroModule::Lc.into(),
                    version: 1,
                    config_digest: Some(ucf::v1::Digest32 {
                        value: vec![0x66; 32],
                    }),
                },
            ],
            pending_replay_plans: vec![
                replay_plan_with_digest("b-replay", 0x44),
                replay_plan_with_digest("a-replay", 0x55),
            ],
            ..Default::default()
        };

        let mut inspector = InspectorClient::new(&mut client);
        let output = inspector
            .inspect_dump("session-abc")
            .expect("inspect dump succeeds");

        let expected = format!(
            "ruleset_digest: {ruleset}\nsealed: true\nunlock_permit: false\nrecovery_state: R1_STABILIZED\ncbv: epoch=7 digest={cbv}\npev_digest: {pev}\n\
microcircuit_configs: 2\n\
- LC: version=1 digest={lc_cfg}\n\
- SN: version=2 digest={sn_cfg}\n\
pending_replay_plans: 2\n\
- a-replay digest={a_digest}\n  last_signalframe_digest: NONE\n\
- b-replay digest={b_digest}\n  last_signalframe_digest: NONE\n",
            ruleset = hex::encode([0x11; 32]),
            cbv = hex::encode([0x33; 32]),
            pev = hex::encode([0x22; 32]),
            lc_cfg = hex::encode([0x66; 32]),
            sn_cfg = hex::encode([0x77; 32]),
            a_digest = hex::encode([0x55; 32]),
            b_digest = hex::encode([0x44; 32]),
        );

        assert_eq!(output, expected);
    }

    fn replay_plan_with_digest(id: &str, value: u8) -> ucf::v1::ReplayPlan {
        ucf::v1::ReplayPlan {
            replay_id: id.to_string(),
            replay_digest: Some(ucf::v1::Digest32 {
                value: vec![value; 32],
            }),
            trigger_reason_codes: None,
        }
    }
}
