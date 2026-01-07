#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

use lnss_core::{CoreContextDigestPack, MAX_REASON_CODES, MAX_STRING_LEN};
pub mod trace_encoding;
#[cfg(feature = "lnss-legacy-evidence")]
pub use trace_encoding::encode_trace;
pub use trace_encoding::TraceVerdict;
pub use trace_encoding::{
    build_trace_run_evidence_pb, compute_trace_digest, TraceRunEvidenceLocal,
};

const MAX_CHANGE_SUMMARY: usize = 32;
const MAX_PARAM_ENTRIES: usize = 64;
const MAX_METRIC_ENTRIES: usize = 32;
const MAX_REASON_CODE_LEN: usize = MAX_STRING_LEN;
const MAX_PATH_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    MappingUpdate,
    SaePackUpdate,
    LiquidParamsUpdate,
    InjectionLimitsUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub proposal_id: String,
    pub proposal_digest: [u8; 32],
    pub kind: ProposalKind,
    pub created_at_ms: u64,
    pub base_evidence_digest: [u8; 32],
    pub base_active_cfg_digest: Option<[u8; 32]>,
    pub core_context_digest_pack: CoreContextDigestPack,
    pub core_context_digest: [u8; 32],
    pub payload: ProposalPayload,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProposalPayload {
    MappingUpdate {
        new_map_path: String,
        map_digest: [u8; 32],
        change_summary: Vec<String>,
    },
    SaePackUpdate {
        pack_path: String,
        pack_digest: [u8; 32],
    },
    LiquidParamsUpdate {
        param_set: Vec<(String, String)>,
        params_digest: [u8; 32],
    },
    InjectionLimitsUpdate {
        max_spikes_per_tick: u32,
        max_targets_per_spike: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalContext {
    pub latest_feedback_digest: Option<[u8; 32]>,
    pub trace_run_digest: Option<[u8; 32]>,
    pub metrics: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalResult {
    pub score: i32,
    pub verdict: EvalVerdict,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalEvidence {
    pub proposal_id: String,
    pub proposal_digest: [u8; 32],
    pub kind: ProposalKind,
    pub base_evidence_digest: [u8; 32],
    pub core_context_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub created_at_ms: u64,
    pub score: i32,
    pub verdict: EvalVerdict,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvalVerdict {
    Promising,
    Neutral,
    Risky,
}

#[derive(Debug, Error)]
pub enum LnssEvolveError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Deserialize)]
struct ProposalInput {
    #[serde(default)]
    proposal_id: Option<String>,
    kind: ProposalKind,
    created_at_ms: u64,
    base_evidence_digest: [u8; 32],
    #[serde(default)]
    base_active_cfg_digest: Option<[u8; 32]>,
    core_context_digest_pack: CoreContextDigestPack,
    core_context_digest: [u8; 32],
    payload: ProposalPayload,
    #[serde(default)]
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalCanonical<'a> {
    proposal_id: &'a str,
    kind: &'a ProposalKind,
    created_at_ms: u64,
    base_evidence_digest: [u8; 32],
    base_active_cfg_digest: Option<[u8; 32]>,
    payload: &'a ProposalPayload,
    reason_codes: &'a [String],
}

pub fn load_proposals(dir: &Path) -> Result<Vec<Proposal>, LnssEvolveError> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map(|ext| ext == "json").unwrap_or(false))
        .collect();

    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .cmp(b.file_name().unwrap_or_default())
    });

    let mut proposals = Vec::new();
    for path in entries {
        let bytes = fs::read(&path)?;
        let input: ProposalInput = serde_json::from_slice(&bytes)?;
        let proposal = normalize_proposal(input)?;
        proposals.push(proposal);
    }

    Ok(proposals)
}

pub fn evaluate(proposal: &Proposal, ctx: &EvalContext) -> EvalResult {
    let metrics = normalize_metrics(&ctx.metrics);
    let mut score = 0i32;
    let mut reasons = Vec::new();

    let events_dropped = metric_value(&metrics, "events_dropped").unwrap_or(0);
    let overflow = metric_value(&metrics, "event_queue_overflowed").unwrap_or(0);
    let trace_pass = metric_value(&metrics, "trace_pass").unwrap_or(0);

    match &proposal.payload {
        ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick,
            max_targets_per_spike,
        } => {
            let reduced_limits = *max_spikes_per_tick < 2048 || *max_targets_per_spike < 64;
            if reduced_limits && overflow > 0 {
                score += 5;
                reasons.push("limit_reduction_overflow".to_string());
            }
            if reduced_limits && events_dropped > 0 {
                score += 3;
                reasons.push("limit_reduction_drops".to_string());
            }
        }
        ProposalPayload::MappingUpdate { .. } => {
            if events_dropped >= 100 {
                score += 5;
                reasons.push("mapping_update_drops".to_string());
            } else if events_dropped == 0 {
                score -= 2;
                reasons.push("mapping_update_no_drops".to_string());
            }
        }
        ProposalPayload::SaePackUpdate { .. } => {
            if is_zero_digest(&proposal.base_evidence_digest) {
                score -= 5;
                reasons.push("sae_pack_missing_evidence".to_string());
            } else if ctx.latest_feedback_digest.is_some() {
                score += 2;
                reasons.push("sae_pack_with_feedback".to_string());
            }
        }
        ProposalPayload::LiquidParamsUpdate { .. } => {
            if ctx.trace_run_digest.is_some() && trace_pass > 0 {
                score += 4;
                reasons.push("liquid_params_trace_pass".to_string());
            } else if ctx.trace_run_digest.is_none() {
                score -= 3;
                reasons.push("liquid_params_no_trace".to_string());
            }
        }
    }

    let verdict = if score >= 8 {
        EvalVerdict::Promising
    } else if score >= 0 {
        EvalVerdict::Neutral
    } else {
        EvalVerdict::Risky
    };

    let mut reason_codes = normalize_reason_codes(reasons);
    reason_codes.truncate(MAX_REASON_CODES);

    EvalResult {
        score,
        verdict,
        reason_codes,
    }
}

pub fn proposal_payload_digest(payload: &ProposalPayload) -> Result<[u8; 32], LnssEvolveError> {
    let value = serde_json::to_value(payload)?;
    let bytes = canonical_json_bytes(value);
    Ok(domain_digest("UCF:PROPOSAL_PAYLOAD", &bytes))
}

pub fn build_proposal_evidence_pb(pe: &ProposalEvidence) -> ucf::v1::ProposalEvidence {
    let mut reason_codes = pe
        .reason_codes
        .iter()
        .map(|code| bound_string(code, MAX_REASON_CODE_LEN).to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_REASON_CODES);

    let mut evidence = ucf::v1::ProposalEvidence {
        proposal_id: bound_string(&pe.proposal_id, MAX_STRING_LEN).to_uppercase(),
        proposal_digest: Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        }),
        kind: proposal_kind_proto(&pe.kind) as i32,
        base_evidence_digest: Some(ucf::v1::Digest32 {
            value: pe.base_evidence_digest.to_vec(),
        }),
        payload_digest: Some(ucf::v1::Digest32 {
            value: pe.payload_digest.to_vec(),
        }),
        created_at_ms: pe.created_at_ms,
        score: pe.score,
        verdict: proposal_verdict_proto(&pe.verdict) as i32,
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: reason_codes,
        }),
        context_digest: Some(ucf::v1::Digest32 {
            value: pe.core_context_digest.to_vec(),
        }),
    };

    let digest = digest_proto("UCF:PROPOSAL_EVIDENCE", &canonical_bytes(&evidence));
    evidence.proposal_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    evidence
}

#[cfg(feature = "lnss-legacy-evidence")]
pub fn encode_proposal_evidence(pe: &ProposalEvidence) -> Vec<u8> {
    let mut buf = Vec::new();

    let proposal_id = bound_string(&pe.proposal_id, MAX_STRING_LEN).to_uppercase();
    let proposal_id_bytes = proposal_id.as_bytes();
    let proposal_id_len = u16::try_from(proposal_id_bytes.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&proposal_id_len.to_le_bytes());
    buf.extend_from_slice(&proposal_id_bytes[..proposal_id_len as usize]);

    buf.extend_from_slice(&pe.proposal_digest);
    buf.push(proposal_kind_tag(&pe.kind));
    buf.extend_from_slice(&pe.base_evidence_digest);
    buf.extend_from_slice(&pe.core_context_digest);
    buf.extend_from_slice(&pe.payload_digest);
    buf.extend_from_slice(&pe.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&pe.score.to_le_bytes());
    buf.push(eval_verdict_tag(&pe.verdict));

    let mut reason_codes = normalize_reason_codes(pe.reason_codes.clone())
        .into_iter()
        .map(|code| code.to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_REASON_CODES);
    let reason_count = u16::try_from(reason_codes.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&reason_count.to_le_bytes());

    for code in reason_codes.into_iter().take(reason_count as usize) {
        let code = bound_string(&code, MAX_REASON_CODE_LEN);
        let code_bytes = code.as_bytes();
        let code_len = u16::try_from(code_bytes.len()).unwrap_or(u16::MAX);
        buf.extend_from_slice(&code_len.to_le_bytes());
        buf.extend_from_slice(&code_bytes[..code_len as usize]);
    }

    buf
}

pub fn build_proposal(
    kind: ProposalKind,
    created_at_ms: u64,
    base_evidence_digest: [u8; 32],
    base_active_cfg_digest: Option<[u8; 32]>,
    core_context_digest_pack: CoreContextDigestPack,
    payload: ProposalPayload,
    reason_codes: Vec<String>,
) -> Result<Proposal, LnssEvolveError> {
    let payload = normalize_payload(payload)?;
    let reason_codes = normalize_reason_codes(reason_codes);
    let proposal_id = generate_proposal_id(
        &kind,
        created_at_ms,
        base_evidence_digest,
        base_active_cfg_digest,
        &payload,
        &reason_codes,
    );
    let canonical = ProposalCanonical {
        proposal_id: &proposal_id,
        kind: &kind,
        created_at_ms,
        base_evidence_digest,
        base_active_cfg_digest,
        payload: &payload,
        reason_codes: &reason_codes,
    };
    let proposal_digest = proposal_digest(&canonical)?;
    let core_context_digest = core_context_digest_pack.digest();

    Ok(Proposal {
        proposal_id,
        proposal_digest,
        kind,
        created_at_ms,
        base_evidence_digest,
        base_active_cfg_digest,
        core_context_digest_pack,
        core_context_digest,
        payload,
        reason_codes,
    })
}

fn normalize_proposal(input: ProposalInput) -> Result<Proposal, LnssEvolveError> {
    let mut reason_codes = normalize_reason_codes(input.reason_codes);
    reason_codes.truncate(MAX_REASON_CODES);

    let payload = normalize_payload(input.payload)?;
    let proposal_id = match input.proposal_id {
        Some(id) if !id.trim().is_empty() => bound_string(&id, MAX_STRING_LEN),
        _ => generate_proposal_id(
            &input.kind,
            input.created_at_ms,
            input.base_evidence_digest,
            input.base_active_cfg_digest,
            &payload,
            &reason_codes,
        ),
    };
    if is_zero_digest(&input.core_context_digest_pack.world_state_digest)
        || is_zero_digest(&input.core_context_digest_pack.self_state_digest)
    {
        return Err(LnssEvolveError::Validation(
            "missing core context digest components".to_string(),
        ));
    }
    let expected_context_digest = input.core_context_digest_pack.digest();
    if expected_context_digest != input.core_context_digest {
        return Err(LnssEvolveError::Validation(
            "core context digest mismatch".to_string(),
        ));
    }

    let canonical = ProposalCanonical {
        proposal_id: &proposal_id,
        kind: &input.kind,
        created_at_ms: input.created_at_ms,
        base_evidence_digest: input.base_evidence_digest,
        base_active_cfg_digest: input.base_active_cfg_digest,
        payload: &payload,
        reason_codes: &reason_codes,
    };

    let digest_bytes = proposal_digest(&canonical)?;

    Ok(Proposal {
        proposal_id,
        proposal_digest: digest_bytes,
        kind: input.kind,
        created_at_ms: input.created_at_ms,
        base_evidence_digest: input.base_evidence_digest,
        base_active_cfg_digest: input.base_active_cfg_digest,
        core_context_digest_pack: input.core_context_digest_pack,
        core_context_digest: input.core_context_digest,
        payload,
        reason_codes,
    })
}

fn normalize_payload(payload: ProposalPayload) -> Result<ProposalPayload, LnssEvolveError> {
    match payload {
        ProposalPayload::MappingUpdate {
            new_map_path,
            map_digest,
            change_summary,
        } => {
            let mut summary = change_summary
                .into_iter()
                .map(|s| bound_string(&s, MAX_STRING_LEN))
                .collect::<Vec<_>>();
            summary.sort();
            summary.dedup();
            summary.truncate(MAX_CHANGE_SUMMARY);
            Ok(ProposalPayload::MappingUpdate {
                new_map_path: bound_string(&new_map_path, MAX_PATH_LEN),
                map_digest,
                change_summary: summary,
            })
        }
        ProposalPayload::SaePackUpdate {
            pack_path,
            pack_digest,
        } => Ok(ProposalPayload::SaePackUpdate {
            pack_path: bound_string(&pack_path, MAX_PATH_LEN),
            pack_digest,
        }),
        ProposalPayload::LiquidParamsUpdate {
            param_set,
            params_digest,
        } => {
            let mut params = param_set
                .into_iter()
                .map(|(k, v)| {
                    (
                        bound_string(&k, MAX_STRING_LEN),
                        bound_string(&v, MAX_STRING_LEN),
                    )
                })
                .collect::<Vec<_>>();
            params.sort_by(|(a_key, a_val), (b_key, b_val)| {
                a_key.cmp(b_key).then_with(|| a_val.cmp(b_val))
            });
            params.dedup();
            params.truncate(MAX_PARAM_ENTRIES);
            Ok(ProposalPayload::LiquidParamsUpdate {
                param_set: params,
                params_digest,
            })
        }
        ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick,
            max_targets_per_spike,
        } => Ok(ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick,
            max_targets_per_spike,
        }),
    }
}

fn normalize_reason_codes(reason_codes: Vec<String>) -> Vec<String> {
    let mut codes = reason_codes
        .into_iter()
        .map(|s| bound_string(&s, MAX_REASON_CODE_LEN))
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    codes
}

#[cfg(feature = "lnss-legacy-evidence")]
fn proposal_kind_tag(kind: &ProposalKind) -> u8 {
    match kind {
        ProposalKind::MappingUpdate => 1,
        ProposalKind::SaePackUpdate => 2,
        ProposalKind::LiquidParamsUpdate => 3,
        ProposalKind::InjectionLimitsUpdate => 4,
    }
}

fn proposal_kind_proto(kind: &ProposalKind) -> ucf::v1::ProposalKind {
    match kind {
        ProposalKind::MappingUpdate => ucf::v1::ProposalKind::MappingUpdate,
        ProposalKind::SaePackUpdate => ucf::v1::ProposalKind::SaePackUpdate,
        ProposalKind::LiquidParamsUpdate => ucf::v1::ProposalKind::LiquidParamsUpdate,
        ProposalKind::InjectionLimitsUpdate => ucf::v1::ProposalKind::InjectionLimitsUpdate,
    }
}

#[cfg(feature = "lnss-legacy-evidence")]
fn eval_verdict_tag(verdict: &EvalVerdict) -> u8 {
    match verdict {
        EvalVerdict::Promising => 1,
        EvalVerdict::Neutral => 2,
        EvalVerdict::Risky => 3,
    }
}

fn proposal_verdict_proto(verdict: &EvalVerdict) -> ucf::v1::ProposalVerdict {
    match verdict {
        EvalVerdict::Promising => ucf::v1::ProposalVerdict::Promising,
        EvalVerdict::Neutral => ucf::v1::ProposalVerdict::Neutral,
        EvalVerdict::Risky => ucf::v1::ProposalVerdict::Risky,
    }
}

fn normalize_metrics(metrics: &[(String, i64)]) -> BTreeMap<String, i64> {
    let mut map = BTreeMap::new();
    for (key, value) in metrics.iter().take(MAX_METRIC_ENTRIES) {
        let key = bound_string(key, MAX_STRING_LEN);
        map.insert(key, *value);
    }
    map
}

fn metric_value(metrics: &BTreeMap<String, i64>, key: &str) -> Option<i64> {
    metrics.get(key).copied()
}

fn generate_proposal_id(
    kind: &ProposalKind,
    created_at_ms: u64,
    base_evidence_digest: [u8; 32],
    base_active_cfg_digest: Option<[u8; 32]>,
    payload: &ProposalPayload,
    reason_codes: &[String],
) -> String {
    let seed = ProposalCanonical {
        proposal_id: "",
        kind,
        created_at_ms,
        base_evidence_digest,
        base_active_cfg_digest,
        payload,
        reason_codes,
    };
    let bytes = canonical_json_bytes(serde_json::to_value(seed).expect("seed json"));
    let digest = domain_digest("UCF:LNSS:PROPOSAL:ID", &bytes);
    hex::encode(digest)
}

fn proposal_digest(canonical: &ProposalCanonical<'_>) -> Result<[u8; 32], LnssEvolveError> {
    let value = serde_json::to_value(canonical)?;
    let bytes = canonical_json_bytes(value);
    Ok(domain_digest("UCF:LNSS:PROPOSAL", &bytes))
}

fn domain_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn bound_string(value: &str, limit: usize) -> String {
    let mut out = value.trim().to_string();
    out.truncate(limit);
    out
}

fn canonical_json_bytes(value: Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical_json(&value, &mut buf);
    buf
}

fn write_canonical_json(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(value) => {
            if *value {
                buf.extend_from_slice(b"true");
            } else {
                buf.extend_from_slice(b"false");
            }
        }
        Value::Number(num) => buf.extend_from_slice(num.to_string().as_bytes()),
        Value::String(s) => {
            buf.extend_from_slice(serde_json::to_string(s).expect("json string").as_bytes())
        }
        Value::Array(values) => {
            buf.push(b'[');
            for (idx, value) in values.iter().enumerate() {
                if idx > 0 {
                    buf.push(b',');
                }
                write_canonical_json(value, buf);
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    buf.push(b',');
                }
                buf.extend_from_slice(serde_json::to_string(key).expect("json key").as_bytes());
                buf.push(b':');
                write_canonical_json(&map[*key], buf);
            }
            buf.push(b'}');
        }
    }
}

fn is_zero_digest(digest: &[u8; 32]) -> bool {
    digest.iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}_{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_json(path: &Path, value: Value) {
        fs::write(path, serde_json::to_vec(&value).expect("json")).expect("write json");
    }

    fn core_context_pack(seed: u8) -> CoreContextDigestPack {
        CoreContextDigestPack {
            world_state_digest: [seed; 32],
            self_state_digest: [seed.wrapping_add(1); 32],
            control_frame_digest: [seed.wrapping_add(2); 32],
            policy_digest: None,
            last_feedback_digest: None,
            wm_pred_error_bucket: 2,
            rlm_followup_executed: false,
        }
    }

    fn core_context_json(seed: u8) -> Value {
        let pack = core_context_pack(seed);
        serde_json::json!({
            "core_context_digest_pack": {
                "world_state_digest": pack.world_state_digest.to_vec(),
                "self_state_digest": pack.self_state_digest.to_vec(),
                "control_frame_digest": pack.control_frame_digest.to_vec(),
                "policy_digest": Value::Null,
                "last_feedback_digest": Value::Null,
                "wm_pred_error_bucket": pack.wm_pred_error_bucket,
                "rlm_followup_executed": pack.rlm_followup_executed,
            },
            "core_context_digest": pack.digest().to_vec(),
        })
    }

    #[test]
    fn load_proposals_orders_and_hashes_deterministically() {
        let dir = temp_dir("lnss_prop");
        let context_a = core_context_json(10);
        let context_b = core_context_json(11);
        let context_c = core_context_json(12);
        let proposal_a = serde_json::json!({
            "proposal_id": "p-a",
            "kind": "mapping_update",
            "created_at_ms": 10,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": context_a["core_context_digest_pack"].clone(),
            "core_context_digest": context_a["core_context_digest"].clone(),
            "payload": {
                "type": "mapping_update",
                "new_map_path": "maps/a.json",
                "map_digest": vec![2; 32],
                "change_summary": ["b", "a"]
            },
            "reason_codes": ["z", "a"]
        });
        let proposal_b = serde_json::json!({
            "proposal_id": "p-b",
            "kind": "injection_limits_update",
            "created_at_ms": 11,
            "base_evidence_digest": vec![2; 32],
            "core_context_digest_pack": context_b["core_context_digest_pack"].clone(),
            "core_context_digest": context_b["core_context_digest"].clone(),
            "payload": {
                "type": "injection_limits_update",
                "max_spikes_per_tick": 100,
                "max_targets_per_spike": 4
            },
            "reason_codes": ["c"]
        });
        let proposal_c = serde_json::json!({
            "proposal_id": "p-c",
            "kind": "sae_pack_update",
            "created_at_ms": 12,
            "base_evidence_digest": vec![3; 32],
            "core_context_digest_pack": context_c["core_context_digest_pack"].clone(),
            "core_context_digest": context_c["core_context_digest"].clone(),
            "payload": {
                "type": "sae_pack_update",
                "pack_path": "packs/p.safetensors",
                "pack_digest": vec![4; 32]
            },
            "reason_codes": []
        });

        write_json(&dir.join("b.json"), proposal_b);
        write_json(&dir.join("c.json"), proposal_c);
        write_json(&dir.join("a.json"), proposal_a);

        let first = load_proposals(&dir).expect("load proposals");
        let second = load_proposals(&dir).expect("load proposals");

        assert_eq!(first[0].proposal_id, "p-a");
        assert_eq!(first[1].proposal_id, "p-b");
        assert_eq!(first[2].proposal_id, "p-c");
        assert_eq!(
            first.iter().map(|p| p.proposal_digest).collect::<Vec<_>>(),
            second.iter().map(|p| p.proposal_digest).collect::<Vec<_>>()
        );
    }

    #[test]
    fn proposal_missing_context_is_rejected() {
        let dir = temp_dir("lnss_prop_missing_context");
        let mut pack = core_context_pack(20);
        pack.world_state_digest = [0u8; 32];
        let proposal = serde_json::json!({
            "proposal_id": "p-missing",
            "kind": "mapping_update",
            "created_at_ms": 10,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": {
                "world_state_digest": pack.world_state_digest.to_vec(),
                "self_state_digest": pack.self_state_digest.to_vec(),
                "control_frame_digest": pack.control_frame_digest.to_vec(),
                "policy_digest": Value::Null,
                "last_feedback_digest": Value::Null,
                "wm_pred_error_bucket": pack.wm_pred_error_bucket,
                "rlm_followup_executed": pack.rlm_followup_executed,
            },
            "core_context_digest": pack.digest().to_vec(),
            "payload": {
                "type": "mapping_update",
                "new_map_path": "maps/a.json",
                "map_digest": vec![2; 32],
                "change_summary": ["b", "a"]
            },
            "reason_codes": ["z", "a"]
        });
        write_json(&dir.join("a.json"), proposal);
        assert!(load_proposals(&dir).is_err());
    }

    #[test]
    fn proposal_context_digest_mismatch_is_rejected() {
        let dir = temp_dir("lnss_prop_context_mismatch");
        let pack = core_context_pack(21);
        let proposal = serde_json::json!({
            "proposal_id": "p-mismatch",
            "kind": "mapping_update",
            "created_at_ms": 10,
            "base_evidence_digest": vec![1; 32],
            "core_context_digest_pack": {
                "world_state_digest": pack.world_state_digest.to_vec(),
                "self_state_digest": pack.self_state_digest.to_vec(),
                "control_frame_digest": pack.control_frame_digest.to_vec(),
                "policy_digest": Value::Null,
                "last_feedback_digest": Value::Null,
                "wm_pred_error_bucket": pack.wm_pred_error_bucket,
                "rlm_followup_executed": pack.rlm_followup_executed,
            },
            "core_context_digest": vec![0u8; 32],
            "payload": {
                "type": "mapping_update",
                "new_map_path": "maps/a.json",
                "map_digest": vec![2; 32],
                "change_summary": ["b", "a"]
            },
            "reason_codes": ["z", "a"]
        });
        write_json(&dir.join("a.json"), proposal);
        assert!(load_proposals(&dir).is_err());
    }

    #[test]
    fn evaluation_is_deterministic() {
        let proposal = Proposal {
            proposal_id: "p".to_string(),
            proposal_digest: [0; 32],
            kind: ProposalKind::InjectionLimitsUpdate,
            created_at_ms: 1,
            base_evidence_digest: [0; 32],
            base_active_cfg_digest: None,
            core_context_digest_pack: core_context_pack(1),
            core_context_digest: core_context_pack(1).digest(),
            payload: ProposalPayload::InjectionLimitsUpdate {
                max_spikes_per_tick: 32,
                max_targets_per_spike: 4,
            },
            reason_codes: vec![],
        };
        let ctx = EvalContext {
            latest_feedback_digest: Some([1; 32]),
            trace_run_digest: None,
            metrics: vec![("event_queue_overflowed".to_string(), 1)],
        };

        let first = evaluate(&proposal, &ctx);
        let second = evaluate(&proposal, &ctx);
        assert_eq!(first, second);
    }

    #[test]
    fn encoding_is_deterministic() {
        let payload = ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick: 32,
            max_targets_per_spike: 4,
        };
        let payload_digest = proposal_payload_digest(&payload).expect("payload digest");
        let context_digest = core_context_pack(2).digest();
        let evidence = ProposalEvidence {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: [9; 32],
            kind: ProposalKind::InjectionLimitsUpdate,
            base_evidence_digest: [0; 32],
            core_context_digest: context_digest,
            payload_digest,
            created_at_ms: 123,
            score: 7,
            verdict: EvalVerdict::Neutral,
            reason_codes: vec!["rc.beta".to_string(), "RC.ALPHA".to_string()],
        };

        let first = canonical_bytes(&build_proposal_evidence_pb(&evidence));
        let second = canonical_bytes(&build_proposal_evidence_pb(&evidence));
        assert_eq!(first, second);
    }

    #[test]
    fn proposal_evidence_digest_matches() {
        let payload = ProposalPayload::InjectionLimitsUpdate {
            max_spikes_per_tick: 32,
            max_targets_per_spike: 4,
        };
        let payload_digest = proposal_payload_digest(&payload).expect("payload digest");
        let context_digest = core_context_pack(3).digest();
        let evidence = ProposalEvidence {
            proposal_id: "proposal-1".to_string(),
            proposal_digest: [9; 32],
            kind: ProposalKind::InjectionLimitsUpdate,
            base_evidence_digest: [0; 32],
            core_context_digest: context_digest,
            payload_digest,
            created_at_ms: 123,
            score: 7,
            verdict: EvalVerdict::Neutral,
            reason_codes: vec!["rc.beta".to_string(), "RC.ALPHA".to_string()],
        };

        let mut pb = build_proposal_evidence_pb(&evidence);
        let digest = pb
            .proposal_digest
            .as_ref()
            .and_then(digest_bytes)
            .expect("proposal digest");
        pb.proposal_digest = Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        });
        let recomputed = digest_proto("UCF:PROPOSAL_EVIDENCE", &canonical_bytes(&pb));
        assert_eq!(digest, recomputed);
    }

    fn digest_bytes(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
        digest.value.as_slice().try_into().ok()
    }
}
