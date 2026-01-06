#![forbid(unsafe_code)]

use lnss_core::{BiophysFeedbackSnapshot, CoreContextDigestPack, FeatureToBrainMap, RlmDirective};
use lnss_evolve::{build_proposal, Proposal, ProposalKind, ProposalPayload};
use lnss_lifecycle::{LifecycleIndex, LifecycleKey};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_TRIGGERS: usize = 8;
const DROPS_THRESH: u64 = 50;
const MISMATCH_THRESH: u32 = 20;
const INJECTION_SPIKE_FACTOR_NUM: u32 = 8;
const INJECTION_SPIKE_FACTOR_DEN: u32 = 10;
const INJECTION_FANOUT_FACTOR_NUM: u32 = 9;
const INJECTION_FANOUT_FACTOR_DEN: u32 = 10;
const MAPPING_AMPLITUDE_FACTOR_NUM: u32 = 9;
const MAPPING_AMPLITUDE_FACTOR_DEN: u32 = 10;
const MAPPING_FANOUT_FACTOR_NUM: u32 = 9;
const MAPPING_FANOUT_FACTOR_DEN: u32 = 10;
const LIQUID_DT_FACTOR_NUM: u32 = 9;
const LIQUID_DT_FACTOR_DEN: u32 = 10;
const LIQUID_PARAMS_DOMAIN: &str = "lnss.liquid.params.v1";

const RC_TRIGGER_BIO_OVERLOAD: &str = "RC.GV.PROPOSAL.TRIGGER.BIO_OVERLOAD";
const RC_TRIGGER_WM_CRITICAL: &str = "RC.GV.PROPOSAL.TRIGGER.WM_CRITICAL";
const RC_TRIGGER_WM_HIGH: &str = "RC.GV.PROPOSAL.TRIGGER.WM_HIGH";
const RC_RLM_RISK_SCAN: &str = "RC.GV.PROPOSAL.RLM_ASSIST.RISK_SCAN";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trigger {
    WmPredErrorHigh { bucket: u8 },
    WmPredErrorCritical { bucket: u8 },
    BioOverflow,
    BioDropsHigh { drops: u32 },
    BioInjectionMismatch { recv: u32, applied: u32 },
    PolicyClampActive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TriggerSet {
    pub triggers: Vec<Trigger>,
}

impl TriggerSet {
    pub fn contains(&self, target: &Trigger) -> bool {
        self.triggers.iter().any(|trig| trig == target)
    }

    pub fn has_bio_overflow(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| matches!(trigger, Trigger::BioOverflow))
    }

    pub fn has_bio_drops_high(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| matches!(trigger, Trigger::BioDropsHigh { .. }))
    }

    pub fn has_wm_pred_error_critical(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| matches!(trigger, Trigger::WmPredErrorCritical { .. }))
    }

    pub fn has_wm_pred_error_high(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| matches!(trigger, Trigger::WmPredErrorHigh { .. }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActiveConstraints {
    pub cooldown_active: bool,
    pub modulation_active: bool,
}

impl ActiveConstraints {
    pub fn policy_clamp_active(&self) -> bool {
        self.cooldown_active || self.modulation_active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidParamsSnapshot {
    pub dt_ms_q: u16,
    pub steps_per_call: u16,
}

impl Default for LiquidParamsSnapshot {
    fn default() -> Self {
        Self {
            dt_ms_q: 1000,
            steps_per_call: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActiveCfg {
    pub created_at_ms: u64,
    pub base_evidence_digest: [u8; 32],
    pub active_cfg_root_digest: [u8; 32],
    pub core_context_digest_pack: CoreContextDigestPack,
    pub mapping: FeatureToBrainMap,
    pub max_spikes_per_tick: u32,
    pub max_targets_per_spike: u32,
    pub liquid_params: LiquidParamsSnapshot,
    pub rlm_directives: Vec<RlmDirective>,
    pub allow_followup: bool,
    pub artifacts_dir: Option<PathBuf>,
}

pub fn extract_triggers(
    ctx: &CoreContextDigestPack,
    fb: Option<&BiophysFeedbackSnapshot>,
    constraints: &ActiveConstraints,
) -> TriggerSet {
    let mut triggers = Vec::new();

    let bucket = ctx.wm_pred_error_bucket;
    let (mut drops, mut recv, mut applied, mut overflow) = (0u32, 0u32, 0u32, false);
    if let Some(snapshot) = fb {
        overflow = snapshot.event_queue_overflowed;
        drops = snapshot.events_dropped.min(u64::from(u32::MAX)) as u32;
        recv = snapshot.events_injected;
        applied = snapshot.injected_total.min(u64::from(u32::MAX)) as u32;
    }

    if overflow {
        triggers.push(Trigger::BioOverflow);
    }
    if bucket >= 3 {
        triggers.push(Trigger::WmPredErrorCritical { bucket });
    }
    if drops >= DROPS_THRESH as u32 {
        triggers.push(Trigger::BioDropsHigh { drops });
    }
    if bucket >= 2 {
        triggers.push(Trigger::WmPredErrorHigh { bucket });
    }
    if recv > applied.saturating_add(MISMATCH_THRESH) {
        triggers.push(Trigger::BioInjectionMismatch { recv, applied });
    }
    if constraints.policy_clamp_active() {
        triggers.push(Trigger::PolicyClampActive);
    }

    triggers.sort_by_key(trigger_priority);
    triggers.truncate(MAX_TRIGGERS);

    TriggerSet { triggers }
}

pub fn propose_from_triggers(
    triggers: &TriggerSet,
    active_cfg: &ActiveCfg,
    context_digest: [u8; 32],
) -> Option<Proposal> {
    if active_cfg.core_context_digest_pack.digest() != context_digest {
        return None;
    }

    let mut reason_codes = Vec::new();

    let payload = if triggers.has_bio_overflow() || triggers.has_bio_drops_high() {
        reason_codes.push(RC_TRIGGER_BIO_OVERLOAD.to_string());
        let (max_spikes, max_targets) = compute_injection_limits_update(active_cfg);
        ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick: max_spikes,
            max_targets_per_spike: max_targets,
        }
    } else if triggers.has_wm_pred_error_critical() {
        reason_codes.push(RC_TRIGGER_WM_CRITICAL.to_string());
        let plan = mapping_update_plan(active_cfg);
        plan.payload
    } else if triggers.has_wm_pred_error_high() {
        reason_codes.push(RC_TRIGGER_WM_HIGH.to_string());
        let (payload, _snapshot) = liquid_params_update_payload(active_cfg);
        payload
    } else {
        return None;
    };

    if active_cfg.allow_followup
        && active_cfg
            .rlm_directives
            .contains(&RlmDirective::FollowUpRiskScan)
    {
        reason_codes.push(RC_RLM_RISK_SCAN.to_string());
    }

    let kind = match payload {
        ProposalPayload::MappingUpdate { .. } => ProposalKind::MappingUpdate,
        ProposalPayload::SaePackUpdate { .. } => ProposalKind::SaePackUpdate,
        ProposalPayload::LiquidParamsUpdate { .. } => ProposalKind::LiquidParamsUpdate,
        ProposalPayload::InjectionLimitsUpdate { .. } => ProposalKind::InjectionLimitsUpdate,
    };

    build_proposal(
        kind,
        active_cfg.created_at_ms,
        active_cfg.base_evidence_digest,
        Some(active_cfg.active_cfg_root_digest),
        active_cfg.core_context_digest_pack.clone(),
        payload,
        reason_codes,
    )
    .ok()
}

pub fn proposal_is_duplicate(index: &LifecycleIndex, proposal: &Proposal) -> bool {
    let key = LifecycleKey {
        proposal_digest: proposal.proposal_digest,
        context_digest: proposal.core_context_digest,
        active_cfg_root_digest: proposal.base_active_cfg_digest,
    };
    index.state_for(&key).is_some()
}

pub fn mapping_update_plan(active_cfg: &ActiveCfg) -> MappingUpdatePlan {
    let map = tightened_mapping(active_cfg);
    let map_digest = map.map_digest;
    let map_path = map_path_for(active_cfg.artifacts_dir.as_ref(), &map);
    let change_summary = vec![
        format!(
            "amplitude_q scaled by {}/{}",
            MAPPING_AMPLITUDE_FACTOR_NUM, MAPPING_AMPLITUDE_FACTOR_DEN
        ),
        format!(
            "fanout capped to {}/{} per feature",
            MAPPING_FANOUT_FACTOR_NUM, MAPPING_FANOUT_FACTOR_DEN
        ),
    ];
    let payload = ProposalPayload::MappingUpdate {
        new_map_path: map_path,
        map_digest,
        change_summary,
    };
    MappingUpdatePlan { payload, map }
}

#[derive(Debug, Clone)]
pub struct MappingUpdatePlan {
    pub payload: ProposalPayload,
    pub map: FeatureToBrainMap,
}

pub fn liquid_params_update_payload(
    active_cfg: &ActiveCfg,
) -> (ProposalPayload, LiquidParamsSnapshot) {
    let mut dt_ms_q = active_cfg.liquid_params.dt_ms_q as u32;
    dt_ms_q = dt_ms_q.saturating_mul(LIQUID_DT_FACTOR_NUM);
    dt_ms_q /= LIQUID_DT_FACTOR_DEN;
    let dt_ms_q = dt_ms_q.max(1).min(u16::MAX as u32) as u16;
    let steps_per_call = active_cfg
        .liquid_params
        .steps_per_call
        .saturating_sub(1)
        .max(1);
    let params = vec![
        ("dt_ms_q".to_string(), dt_ms_q.to_string()),
        ("steps_per_call".to_string(), steps_per_call.to_string()),
    ];
    let params_digest = liquid_params_digest(&params);
    let payload = ProposalPayload::LiquidParamsUpdate {
        param_set: params,
        params_digest,
    };
    (
        payload,
        LiquidParamsSnapshot {
            dt_ms_q,
            steps_per_call,
        },
    )
}

pub fn compute_injection_limits_update(active_cfg: &ActiveCfg) -> (u32, u32) {
    let mut max_spikes = active_cfg.max_spikes_per_tick;
    max_spikes = max_spikes.saturating_mul(INJECTION_SPIKE_FACTOR_NUM);
    max_spikes /= INJECTION_SPIKE_FACTOR_DEN;
    let max_spikes = max_spikes.max(1);

    let mut max_targets = active_cfg.max_targets_per_spike;
    max_targets = max_targets.saturating_mul(INJECTION_FANOUT_FACTOR_NUM);
    max_targets /= INJECTION_FANOUT_FACTOR_DEN;
    let max_targets = max_targets.max(1);

    (max_spikes, max_targets)
}

pub fn tightened_mapping(active_cfg: &ActiveCfg) -> FeatureToBrainMap {
    let mut entries = active_cfg.mapping.entries.clone();
    entries.sort_by(|(a_id, a_target), (b_id, b_target)| {
        let base = a_id.cmp(b_id);
        if base != Ordering::Equal {
            return base;
        }
        a_target
            .region
            .cmp(&b_target.region)
            .then_with(|| a_target.population.cmp(&b_target.population))
            .then_with(|| a_target.neuron_group.cmp(&b_target.neuron_group))
            .then_with(|| a_target.syn_kind.cmp(&b_target.syn_kind))
            .then_with(|| a_target.amplitude_q.cmp(&b_target.amplitude_q))
    });

    let mut tightened = Vec::new();
    let mut idx = 0usize;
    while idx < entries.len() {
        let feature_id = entries[idx].0;
        let start = idx;
        while idx < entries.len() && entries[idx].0 == feature_id {
            idx += 1;
        }
        let group = &entries[start..idx];
        let mut limit = (group.len() as u32).saturating_mul(MAPPING_FANOUT_FACTOR_NUM)
            / MAPPING_FANOUT_FACTOR_DEN;
        if limit == 0 {
            limit = 1;
        }
        for (feature_id, target) in group.iter().take(limit as usize) {
            let mut amplitude_q = target.amplitude_q as u32;
            amplitude_q = amplitude_q.saturating_mul(MAPPING_AMPLITUDE_FACTOR_NUM);
            amplitude_q /= MAPPING_AMPLITUDE_FACTOR_DEN;
            let amplitude_q = amplitude_q.clamp(1, 1000) as u16;
            let adjusted = lnss_core::BrainTarget::new(
                &target.region,
                &target.population,
                target.neuron_group,
                &target.syn_kind,
                amplitude_q,
            );
            tightened.push((*feature_id, adjusted));
        }
    }

    let map_version = active_cfg.mapping.map_version.saturating_add(1);
    FeatureToBrainMap::new(map_version, tightened)
}

fn map_path_for(artifacts_dir: Option<&PathBuf>, map: &FeatureToBrainMap) -> String {
    let filename = format!("map_{}.json", hex::encode(map.map_digest));
    match artifacts_dir {
        Some(dir) => {
            if let Err(err) = fs::create_dir_all(dir) {
                eprintln!("lnss_triggers: failed to create map dir: {err}");
                return format!("generated://{filename}");
            }
            let path = dir.join(filename);
            if let Err(err) = write_map_file(&path, map) {
                eprintln!("lnss_triggers: failed to write map file: {err}");
            }
            path.to_string_lossy().to_string()
        }
        None => format!("generated://{filename}"),
    }
}

fn write_map_file(path: &Path, map: &FeatureToBrainMap) -> Result<(), std::io::Error> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(map).unwrap_or_default();
    fs::write(path, bytes)
}

fn liquid_params_digest(kv_pairs: &[(String, String)]) -> [u8; 32] {
    let mut pairs = kv_pairs.to_vec();
    pairs.sort_by(|(a_key, a_val), (b_key, b_val)| a_key.cmp(b_key).then_with(|| a_val.cmp(b_val)));
    let mut buf = Vec::new();
    write_u32(&mut buf, pairs.len() as u32);
    for (key, value) in pairs {
        write_string(&mut buf, &key);
        write_string(&mut buf, &value);
    }
    lnss_core::digest(LIQUID_PARAMS_DOMAIN, &buf)
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn trigger_priority(trigger: &Trigger) -> u8 {
    match trigger {
        Trigger::BioOverflow => 0,
        Trigger::WmPredErrorCritical { .. } => 1,
        Trigger::BioDropsHigh { .. } => 2,
        Trigger::WmPredErrorHigh { .. } => 3,
        Trigger::BioInjectionMismatch { .. } => 4,
        Trigger::PolicyClampActive => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_core::CoreContextDigestPack;

    fn ctx_with_bucket(bucket: u8) -> CoreContextDigestPack {
        CoreContextDigestPack {
            world_state_digest: [1u8; 32],
            self_state_digest: [2u8; 32],
            control_frame_digest: [3u8; 32],
            policy_digest: None,
            last_feedback_digest: None,
            wm_pred_error_bucket: bucket,
            rlm_followup_executed: false,
        }
    }

    fn active_cfg() -> ActiveCfg {
        let map = FeatureToBrainMap::new(
            1,
            vec![
                (1, lnss_core::BrainTarget::new("r", "p", 1, "syn", 1000)),
                (1, lnss_core::BrainTarget::new("r", "p", 2, "syn", 900)),
                (2, lnss_core::BrainTarget::new("r", "p", 3, "syn", 800)),
            ],
        );
        ActiveCfg {
            created_at_ms: 100,
            base_evidence_digest: [9u8; 32],
            active_cfg_root_digest: [4u8; 32],
            core_context_digest_pack: ctx_with_bucket(2),
            mapping: map,
            max_spikes_per_tick: 100,
            max_targets_per_spike: 20,
            liquid_params: LiquidParamsSnapshot::default(),
            rlm_directives: vec![RlmDirective::FollowUpRiskScan],
            allow_followup: true,
            artifacts_dir: None,
        }
    }

    #[test]
    fn overflow_triggers_injection_limits_update() {
        let ctx = ctx_with_bucket(0);
        let feedback = BiophysFeedbackSnapshot {
            tick: 1,
            snapshot_digest: [1u8; 32],
            event_queue_overflowed: true,
            events_dropped: 0,
            events_injected: 0,
            injected_total: 0,
        };
        let triggers = extract_triggers(&ctx, Some(&feedback), &ActiveConstraints::default());
        let mut cfg = active_cfg();
        cfg.core_context_digest_pack = ctx.clone();
        let proposal = propose_from_triggers(&triggers, &cfg, ctx.digest()).expect("proposal");
        assert_eq!(proposal.kind, ProposalKind::InjectionLimitsUpdate);
        if let ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick,
            max_targets_per_spike,
        } = proposal.payload
        {
            assert_eq!(max_spikes_per_tick, 80);
            assert_eq!(max_targets_per_spike, 18);
        } else {
            panic!("expected injection limits update");
        }
    }

    #[test]
    fn wm_bucket_critical_triggers_mapping_update() {
        let ctx = ctx_with_bucket(3);
        let triggers = extract_triggers(&ctx, None, &ActiveConstraints::default());
        let mut cfg = active_cfg();
        cfg.core_context_digest_pack = ctx.clone();
        let proposal = propose_from_triggers(&triggers, &cfg, ctx.digest()).expect("proposal");
        assert_eq!(proposal.kind, ProposalKind::MappingUpdate);
    }

    #[test]
    fn wm_bucket_high_triggers_liquid_update() {
        let ctx = ctx_with_bucket(2);
        let triggers = extract_triggers(&ctx, None, &ActiveConstraints::default());
        let mut cfg = active_cfg();
        cfg.core_context_digest_pack = ctx.clone();
        let proposal = propose_from_triggers(&triggers, &cfg, ctx.digest()).expect("proposal");
        assert_eq!(proposal.kind, ProposalKind::LiquidParamsUpdate);
    }

    #[test]
    fn trigger_order_is_deterministic() {
        let ctx = ctx_with_bucket(3);
        let feedback = BiophysFeedbackSnapshot {
            tick: 1,
            snapshot_digest: [1u8; 32],
            event_queue_overflowed: true,
            events_dropped: 100,
            events_injected: 100,
            injected_total: 0,
        };
        let constraints = ActiveConstraints {
            cooldown_active: true,
            modulation_active: true,
        };
        let triggers = extract_triggers(&ctx, Some(&feedback), &constraints);
        assert_eq!(
            triggers.triggers,
            vec![
                Trigger::BioOverflow,
                Trigger::WmPredErrorCritical { bucket: 3 },
                Trigger::BioDropsHigh { drops: 100 },
                Trigger::WmPredErrorHigh { bucket: 3 },
                Trigger::BioInjectionMismatch {
                    recv: 100,
                    applied: 0
                },
                Trigger::PolicyClampActive,
            ]
        );
    }

    #[test]
    fn lifecycle_index_prevents_duplicates() {
        let ctx = ctx_with_bucket(2);
        let triggers = extract_triggers(&ctx, None, &ActiveConstraints::default());
        let mut cfg = active_cfg();
        cfg.core_context_digest_pack = ctx.clone();
        let proposal = propose_from_triggers(&triggers, &cfg, ctx.digest()).expect("proposal");
        let mut index = LifecycleIndex::default();
        assert!(!proposal_is_duplicate(&index, &proposal));
        let key = LifecycleKey {
            proposal_digest: proposal.proposal_digest,
            context_digest: proposal.core_context_digest,
            active_cfg_root_digest: proposal.base_active_cfg_digest,
        };
        index.note_proposal(key, 1);
        assert!(proposal_is_duplicate(&index, &proposal));
    }

    #[test]
    fn proposals_bind_context_digest() {
        let ctx = ctx_with_bucket(2);
        let triggers = extract_triggers(&ctx, None, &ActiveConstraints::default());
        let mut cfg = active_cfg();
        cfg.core_context_digest_pack = ctx.clone();
        let proposal = propose_from_triggers(&triggers, &cfg, ctx.digest()).expect("proposal");
        assert_eq!(proposal.core_context_digest, ctx.digest());
        assert_eq!(proposal.core_context_digest_pack.digest(), ctx.digest());
    }
}
