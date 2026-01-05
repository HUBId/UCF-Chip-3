#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    convert::TryInto,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{Signer, SigningKey};
use pvgs_verify::{pvgs_receipt_signing_preimage, PvgsKeyEpochStore};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rpp_checker::{compute_accumulator_digest, RppCheckInputs};
use ucf_protocol::{canonical_bytes, digest32, digest_proto, ucf};
use ucf_test_utils::{make_pvgs_key_epoch, make_pvgs_receipt_accepted};

const RECEIPT_DOMAIN: &str = "UCF:HASH:PVGS_RECEIPT";

#[derive(Debug, Clone)]
pub struct SepEvent {
    pub record_digest: [u8; 32],
    pub status: ucf::v1::ReceiptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug)]
struct LocalPvgsState {
    signing_key: SigningKey,
    attestation_key_id: String,
    key_epochs: Vec<ucf::v1::PvgsKeyEpoch>,
    latest_ruleset_digest: Option<[u8; 32]>,
    registry_commit_count: usize,
    head_id: u64,
    head_record_digest: Option<[u8; 32]>,
    latest_rpp_head_id: Option<u64>,
    rpp_heads: HashMap<u64, RppHeadMeta>,
    sep_events: Vec<SepEvent>,
    proof_receipts: Vec<ucf::v1::ProofReceipt>,
    micro_milestones: Vec<ucf::v1::MicroMilestone>,
    consistency_feedback: Vec<ucf::v1::ConsistencyFeedback>,
    proposal_evidence: Vec<Vec<u8>>,
    trace_run_evidence: Vec<Vec<u8>>,
    replay_plans: Vec<ucf::v1::ReplayPlan>,
    latest_trace_run: Option<TraceRunSummary>,
    sealed_sessions: HashMap<String, Option<[u8; 32]>>,
    unlock_permits: HashMap<String, Option<[u8; 32]>>,
    microcircuit_configs: Vec<ucf::v1::MicrocircuitConfigEvidence>,
}

#[derive(Clone, Debug)]
pub struct LocalPvgs {
    inner: Arc<Mutex<LocalPvgsState>>,
}

impl Default for LocalPvgs {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPvgs {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        // Deterministic seed keeps tests stable.
        StdRng::seed_from_u64(7).fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let attestation_key_id = "pvgs-key-test".to_string();

        let default_rpp_head = default_rpp_head_meta();
        Self {
            inner: Arc::new(Mutex::new(LocalPvgsState {
                signing_key,
                attestation_key_id,
                key_epochs: Vec::new(),
                latest_ruleset_digest: None,
                registry_commit_count: 0,
                head_id: 0,
                head_record_digest: None,
                latest_rpp_head_id: Some(default_rpp_head.head_id),
                rpp_heads: HashMap::from([(default_rpp_head.head_id, default_rpp_head)]),
                sep_events: Vec::new(),
                proof_receipts: Vec::new(),
                micro_milestones: Vec::new(),
                consistency_feedback: Vec::new(),
                proposal_evidence: Vec::new(),
                trace_run_evidence: Vec::new(),
                replay_plans: Vec::new(),
                latest_trace_run: None,
                sealed_sessions: HashMap::new(),
                unlock_permits: HashMap::new(),
                microcircuit_configs: Vec::new(),
            })),
        }
    }

    pub fn publish_key_epoch(&self, epoch_id: u64) -> ucf::v1::PvgsKeyEpoch {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let key_epoch = make_pvgs_key_epoch(epoch_id, &guard.signing_key);
        guard.attestation_key_id = key_epoch.attestation_key_id.clone();
        guard.key_epochs.push(key_epoch.clone());
        key_epoch
    }

    pub fn key_epochs(&self) -> Vec<ucf::v1::PvgsKeyEpoch> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.key_epochs.clone()
    }

    pub fn add_replay_plan(&self, plan: ucf::v1::ReplayPlan) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard.replay_plans.push(plan);
    }

    pub fn get_pending_replay_plans(&self, _session_id: &str) -> Vec<ucf::v1::ReplayPlan> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.replay_plans.clone()
    }

    pub fn set_microcircuit_config(&self, config: ucf::v1::MicrocircuitConfigEvidence) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard
            .microcircuit_configs
            .retain(|existing| existing.module != config.module);
        guard.microcircuit_configs.push(config);
    }

    pub fn set_rpp_head_meta(&self, meta: RppHeadMeta) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard.latest_rpp_head_id = Some(meta.head_id);
        guard.rpp_heads.insert(meta.head_id, meta);
    }

    pub fn get_latest_rpp_head_meta(&self) -> Option<RppHeadMeta> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard
            .latest_rpp_head_id
            .and_then(|head_id| guard.rpp_heads.get(&head_id).copied())
    }

    pub fn get_rpp_head_meta(&self, head_id: u64) -> Option<RppHeadMeta> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.rpp_heads.get(&head_id).copied()
    }

    pub fn get_microcircuit_config(
        &self,
        module: ucf::v1::MicroModule,
    ) -> Option<ucf::v1::MicrocircuitConfigEvidence> {
        let guard = self.inner.lock().expect("pvgs state lock");
        let module = module as i32;
        guard
            .microcircuit_configs
            .iter()
            .find(|config| config.module == module)
            .cloned()
    }

    pub fn list_microcircuit_configs(&self) -> Vec<ucf::v1::MicrocircuitConfigEvidence> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.microcircuit_configs.clone()
    }

    pub fn consume_replay_plan(&self, replay_id: &str) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard
            .replay_plans
            .retain(|plan| plan.replay_id != replay_id);
    }

    pub fn set_latest_trace_run(&self, summary: TraceRunSummary) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard.latest_trace_run = Some(summary);
    }

    pub fn get_latest_trace_run(&self) -> Option<TraceRunSummary> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.latest_trace_run.clone()
    }

    pub fn seal_session(&self, session_id: &str, seal_digest: Option<[u8; 32]>) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard
            .sealed_sessions
            .insert(session_id.to_string(), seal_digest);
    }

    pub fn unseal_session(&self, session_id: &str) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard.sealed_sessions.remove(session_id);
    }

    pub fn grant_unlock_permit(&self, session_id: &str, permit_digest: Option<[u8; 32]>) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard
            .unlock_permits
            .insert(session_id.to_string(), permit_digest);
    }

    pub fn revoke_unlock_permit(&self, session_id: &str) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        guard.unlock_permits.remove(session_id);
    }

    pub fn is_session_sealed(&self, session_id: &str) -> bool {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.sealed_sessions.contains_key(session_id)
    }

    pub fn get_session_seal_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard
            .sealed_sessions
            .get(session_id)
            .and_then(|digest| *digest)
    }

    pub fn has_unlock_permit(&self, session_id: &str) -> bool {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard.unlock_permits.contains_key(session_id)
    }

    pub fn get_unlock_permit_digest(&self, session_id: &str) -> Option<[u8; 32]> {
        let guard = self.inner.lock().expect("pvgs state lock");
        guard
            .unlock_permits
            .get(session_id)
            .and_then(|digest| *digest)
    }

    pub fn commit_tool_registry(
        &self,
        trc: ucf::v1::ToolRegistryContainer,
    ) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&trc);
        let registry_digest = digest_proto("UCF:HASH:TOOL_REGISTRY", &bytes);
        guard.latest_ruleset_digest = Some(registry_digest);
        guard.registry_commit_count += 1;

        let mut receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.registry_commit_count),
            receipt_id: format!("registry-{}", guard.registry_commit_count),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: registry_digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: trc.registry_digest.clone(),
            decision_digest: None,
            grant_id: "grant-registry".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        let preimage = pvgs_receipt_signing_preimage(&receipt);
        let signature = guard.signing_key.sign(&preimage);
        receipt.signer = Some(ucf::v1::Signature {
            algorithm: "ed25519".to_string(),
            signer: guard.attestation_key_id.as_bytes().to_vec(),
            signature: signature.to_bytes().to_vec(),
        });

        receipt
    }

    pub fn append_micro_milestone(
        &self,
        mut micro: ucf::v1::MicroMilestone,
    ) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        if micro.micro_digest.is_none() {
            let digest = digest_proto("UCF:HASH:MICRO_MILESTONE", &canonical_bytes(&micro));
            micro.micro_digest = Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            });
        }

        let digest: [u8; 32] = micro
            .micro_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);
        guard.micro_milestones.push(micro.clone());

        ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-micro-{}", guard.micro_milestones.len()),
            receipt_id: format!("micro-{}", guard.micro_milestones.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: micro.micro_digest.clone(),
            grant_id: "grant-micro".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    pub fn append_consistency_feedback(
        &self,
        mut feedback: ucf::v1::ConsistencyFeedback,
    ) -> (ucf::v1::PvgsReceipt, ucf::v1::ProofReceipt) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        if feedback.cf_digest.is_none() {
            let digest = digest_proto("UCF:HASH:CONSISTENCY_FEEDBACK", &canonical_bytes(&feedback));
            feedback.cf_digest = Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            });
        }

        let digest: [u8; 32] = feedback
            .cf_digest
            .as_ref()
            .and_then(|d| d.value.clone().try_into().ok())
            .unwrap_or([0u8; 32]);
        guard.consistency_feedback.push(feedback.clone());

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-cf-{}", guard.consistency_feedback.len()),
            receipt_id: format!("cf-{}", guard.consistency_feedback.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: feedback.cf_digest.clone(),
            grant_id: "grant-cf".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        let proof_receipt = ucf::v1::ProofReceipt {
            status: receipt.status,
            receipt_digest: receipt.receipt_digest.clone(),
            validator: Some(ucf::v1::Signature {
                algorithm: "local-proof".to_string(),
                signer: b"pvgs-proof".to_vec(),
                signature: vec![3u8; 64],
            }),
        };

        guard.proof_receipts.push(proof_receipt.clone());
        (receipt, proof_receipt)
    }

    pub fn append_proposal_evidence(&self, payload_bytes: Vec<u8>) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let digest = digest_proto("UCF:HASH:PROPOSAL_EVIDENCE", &payload_bytes);
        guard.proposal_evidence.push(payload_bytes);

        ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-proposal-{}", guard.proposal_evidence.len()),
            receipt_id: format!("proposal-{}", guard.proposal_evidence.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: "grant-proposal".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    pub fn append_trace_run_evidence(&self, payload_bytes: Vec<u8>) -> ucf::v1::PvgsReceipt {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let digest = digest_proto("UCF:HASH:TRACE_RUN_EVIDENCE", &payload_bytes);
        guard.trace_run_evidence.push(payload_bytes);

        ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-trace-{}", guard.trace_run_evidence.len()),
            receipt_id: format!("trace-{}", guard.trace_run_evidence.len()),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: None,
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: "grant-trace".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        }
    }

    pub fn append_experience_record(
        &self,
        record: ucf::v1::ExperienceRecord,
    ) -> (ucf::v1::PvgsReceipt, ucf::v1::ProofReceipt) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&record);
        let digest = digest_proto("UCF:HASH:EXPERIENCE_RECORD", &bytes);
        let has_governance =
            record.governance_frame.is_some() || record.governance_frame_ref.is_some();

        let status = if has_governance {
            ucf::v1::ReceiptStatus::Accepted
        } else {
            ucf::v1::ReceiptStatus::Rejected
        };

        let action_digest = record.core_frame_ref.clone().or_else(|| {
            record
                .core_frame
                .as_ref()
                .and_then(|cf| cf.candidate_refs.first().cloned())
        });

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.head_id + 1),
            receipt_id: format!("record-{}", guard.head_id + 1),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: status.into(),
            action_digest,
            decision_digest: record.governance_frame_ref.clone(),
            grant_id: "grant-local".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: record
                .metabolic_frame
                .as_ref()
                .and_then(|m| m.control_frame_ref.clone())
                .or_else(|| record.metabolic_frame_ref.clone()),
            tool_profile_digest: record
                .governance_frame
                .as_ref()
                .and_then(|g| g.policy_decision_refs.first().cloned())
                .or_else(|| record.governance_frame_ref.clone()),
            reject_reason_codes: if status == ucf::v1::ReceiptStatus::Rejected {
                vec!["RC.RE.SCHEMA.INVALID".to_string()]
            } else {
                Vec::new()
            },
            signer: None,
        };

        if status == ucf::v1::ReceiptStatus::Accepted {
            guard.head_id += 1;
            guard.head_record_digest = Some(digest);
        }

        let proof_receipt = ucf::v1::ProofReceipt {
            status: receipt.status,
            receipt_digest: receipt.receipt_digest.clone(),
            validator: Some(ucf::v1::Signature {
                algorithm: "local-proof".to_string(),
                signer: b"pvgs-proof".to_vec(),
                signature: vec![1u8; 64],
            }),
        };

        let event = SepEvent {
            record_digest: digest,
            status,
        };
        guard.sep_events.push(event);
        guard.proof_receipts.push(proof_receipt.clone());

        (receipt, proof_receipt)
    }

    pub fn head(&self) -> (u64, [u8; 32]) {
        let guard = self.inner.lock().expect("pvgs state lock");
        (guard.head_id, guard.head_record_digest.unwrap_or([0u8; 32]))
    }

    pub fn append_dlp_decision(
        &self,
        dlp: ucf::v1::DlpDecision,
    ) -> (ucf::v1::PvgsReceipt, ucf::v1::ProofReceipt) {
        let mut guard = self.inner.lock().expect("pvgs state lock");
        let bytes = canonical_bytes(&dlp);
        let digest = digest_proto("UCF:HASH:DLP_DECISION", &bytes);

        let receipt = ucf::v1::PvgsReceipt {
            receipt_epoch: format!("epoch-{}", guard.head_id + 1),
            receipt_id: format!("dlp-{}", guard.head_id + 1),
            receipt_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            status: ucf::v1::ReceiptStatus::Accepted.into(),
            action_digest: dlp.artifact_ref.clone(),
            decision_digest: Some(ucf::v1::Digest32 {
                value: digest.to_vec(),
            }),
            grant_id: "grant-local".to_string(),
            charter_version_digest: Some(ucf::v1::Digest32 {
                value: vec![1u8; 32],
            }),
            policy_version_digest: Some(ucf::v1::Digest32 {
                value: vec![2u8; 32],
            }),
            prev_record_digest: guard
                .head_record_digest
                .as_ref()
                .map(|digest| ucf::v1::Digest32 {
                    value: digest.to_vec(),
                }),
            profile_digest: None,
            tool_profile_digest: None,
            reject_reason_codes: Vec::new(),
            signer: None,
        };

        guard.head_id += 1;
        guard.head_record_digest = Some(digest);

        let proof_receipt = ucf::v1::ProofReceipt {
            status: receipt.status,
            receipt_digest: receipt.receipt_digest.clone(),
            validator: Some(ucf::v1::Signature {
                algorithm: "local-proof".to_string(),
                signer: b"pvgs-proof".to_vec(),
                signature: vec![2u8; 64],
            }),
        };

        guard.sep_events.push(SepEvent {
            record_digest: digest,
            status: ucf::v1::ReceiptStatus::Accepted,
        });
        guard.proof_receipts.push(proof_receipt.clone());

        (receipt, proof_receipt)
    }

    pub fn get_current_ruleset_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .latest_ruleset_digest
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
        let guard = self.inner.lock().expect("pvgs state lock");
        let key_epoch = guard
            .key_epochs
            .last()
            .expect("publish a key epoch before issuing receipts");

        make_pvgs_receipt_accepted(
            action_digest,
            decision_digest,
            profile_digest,
            tool_profile_digest,
            &guard.signing_key,
            key_epoch,
            grant_id,
        )
    }

    pub fn attestation_key_id(&self) -> String {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .attestation_key_id
            .clone()
    }

    pub fn head_record_digest(&self) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .head_record_digest
    }

    pub fn head_id(&self) -> u64 {
        self.inner.lock().expect("pvgs state lock").head_id
    }

    pub fn sep_events(&self) -> Vec<SepEvent> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .sep_events
            .clone()
    }

    pub fn proof_receipts(&self) -> Vec<ucf::v1::ProofReceipt> {
        self.inner
            .lock()
            .expect("pvgs state lock")
            .proof_receipts
            .clone()
    }

    pub fn validate_chain(&self) -> bool {
        let guard = self.inner.lock().expect("pvgs state lock");
        match (guard.head_id, guard.head_record_digest.as_ref()) {
            (0, None) => true,
            (id, Some(_)) => id as usize == guard.sep_events.len(),
            _ => false,
        }
    }
}

pub fn ingest_published_epochs(
    pvgs: &LocalPvgs,
    store: &mut PvgsKeyEpochStore,
) -> Result<(), pvgs_verify::IngestError> {
    for epoch in pvgs.key_epochs() {
        store.ingest_key_epoch(epoch)?;
    }
    Ok(())
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

pub fn receipt_digest(receipt: &ucf::v1::PvgsReceipt) -> [u8; 32] {
    let mut canonical = receipt.clone();
    canonical.receipt_digest = None;
    canonical.signer = None;
    let bytes = canonical_bytes(&canonical);
    digest32(RECEIPT_DOMAIN, "PvgsReceipt", "v1", &bytes)
}
