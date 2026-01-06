#![forbid(unsafe_code)]

use lnss_core::MAX_STRING_LEN;
use ucf_protocol::{canonical_bytes, digest_proto, ucf};

const TRACE_DOMAIN: &str = "UCF:TRACE_RUN_EVIDENCE";
const MAX_TRACE_ID_LEN: usize = 64;
const MAX_REASON_CODES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceVerdict {
    Promising,
    Neutral,
    Risky,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRunEvidenceLocal {
    pub trace_id: String,
    pub active_cfg_digest: [u8; 32],
    pub shadow_cfg_digest: [u8; 32],
    pub active_feedback_digest: [u8; 32],
    pub shadow_feedback_digest: [u8; 32],
    pub active_context_digest: [u8; 32],
    pub shadow_context_digest: [u8; 32],
    pub score_active: i32,
    pub score_shadow: i32,
    pub delta: i32,
    pub verdict: TraceVerdict,
    pub created_at_ms: u64,
    pub reason_codes: Vec<String>,
    pub trace_digest: [u8; 32],
}

pub fn build_trace_run_evidence_pb(ev: &TraceRunEvidenceLocal) -> ucf::v1::TraceRunEvidence {
    let mut reason_codes = ev
        .reason_codes
        .iter()
        .map(|code| bound_string(code).to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_REASON_CODES);

    let mut evidence = ucf::v1::TraceRunEvidence {
        trace_id: bound_string_with_limit(&ev.trace_id, MAX_TRACE_ID_LEN)
            .trim()
            .to_uppercase(),
        active_cfg_digest: Some(ucf::v1::Digest32 {
            value: ev.active_cfg_digest.to_vec(),
        }),
        shadow_cfg_digest: Some(ucf::v1::Digest32 {
            value: ev.shadow_cfg_digest.to_vec(),
        }),
        active_feedback_digest: Some(ucf::v1::Digest32 {
            value: ev.active_feedback_digest.to_vec(),
        }),
        shadow_feedback_digest: Some(ucf::v1::Digest32 {
            value: ev.shadow_feedback_digest.to_vec(),
        }),
        active_context_digest: Some(ucf::v1::Digest32 {
            value: ev.active_context_digest.to_vec(),
        }),
        shadow_context_digest: Some(ucf::v1::Digest32 {
            value: ev.shadow_context_digest.to_vec(),
        }),
        score_active: ev.score_active,
        score_shadow: ev.score_shadow,
        delta: ev.delta,
        verdict: trace_verdict_proto(&ev.verdict) as i32,
        created_at_ms: ev.created_at_ms,
        reason_codes: Some(ucf::v1::ReasonCodes {
            codes: reason_codes,
        }),
        trace_digest: Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        }),
    };

    let digest = digest_proto(TRACE_DOMAIN, &canonical_bytes(&evidence));
    evidence.trace_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    evidence
}

#[cfg(feature = "lnss-legacy-evidence")]
pub fn encode_trace(ev: &TraceRunEvidenceLocal) -> Vec<u8> {
    let mut buf = Vec::new();

    let trace_id = bound_string_with_limit(&ev.trace_id, MAX_TRACE_ID_LEN)
        .trim()
        .to_uppercase();
    write_string_u16(&mut buf, &trace_id);

    buf.extend_from_slice(&ev.active_cfg_digest);
    buf.extend_from_slice(&ev.shadow_cfg_digest);
    buf.extend_from_slice(&ev.active_feedback_digest);
    buf.extend_from_slice(&ev.shadow_feedback_digest);
    buf.extend_from_slice(&ev.active_context_digest);
    buf.extend_from_slice(&ev.shadow_context_digest);
    write_i32(&mut buf, ev.score_active);
    write_i32(&mut buf, ev.score_shadow);
    write_i32(&mut buf, ev.delta);
    buf.push(trace_verdict_tag(&ev.verdict));
    write_u64(&mut buf, ev.created_at_ms);

    let mut reason_codes = ev
        .reason_codes
        .iter()
        .map(|code| bound_string(code).to_uppercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    reason_codes.truncate(MAX_REASON_CODES);
    write_u16(&mut buf, reason_codes.len() as u16);
    for code in reason_codes {
        write_string_u16(&mut buf, &code);
    }

    buf.extend_from_slice(&ev.trace_digest);
    buf
}

pub fn compute_trace_digest(ev: &mut TraceRunEvidenceLocal) -> [u8; 32] {
    let evidence = build_trace_run_evidence_pb(ev);
    let digest_bytes = evidence
        .trace_digest
        .as_ref()
        .and_then(digest_bytes)
        .unwrap_or([0u8; 32]);
    ev.trace_digest = digest_bytes;
    digest_bytes
}

#[cfg(feature = "lnss-legacy-evidence")]
fn trace_verdict_tag(verdict: &TraceVerdict) -> u8 {
    match verdict {
        TraceVerdict::Promising => 1,
        TraceVerdict::Neutral => 2,
        TraceVerdict::Risky => 3,
    }
}

fn trace_verdict_proto(verdict: &TraceVerdict) -> ucf::v1::TraceVerdict {
    match verdict {
        TraceVerdict::Promising => ucf::v1::TraceVerdict::Promising,
        TraceVerdict::Neutral => ucf::v1::TraceVerdict::Neutral,
        TraceVerdict::Risky => ucf::v1::TraceVerdict::Risky,
    }
}

fn bound_string(value: &str) -> String {
    bound_string_with_limit(value, MAX_STRING_LEN)
}

fn bound_string_with_limit(value: &str, limit: usize) -> String {
    let mut out = value.trim().to_string();
    out.truncate(limit);
    out
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_string_u16(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "lnss-legacy-evidence")]
fn write_i32(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn digest_bytes(digest: &ucf::v1::Digest32) -> Option<[u8; 32]> {
    digest.value.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_encoding_is_deterministic() {
        let mut evidence = TraceRunEvidenceLocal {
            trace_id: "trace:aa:bb:1".to_string(),
            active_cfg_digest: [1u8; 32],
            shadow_cfg_digest: [2u8; 32],
            active_feedback_digest: [3u8; 32],
            shadow_feedback_digest: [4u8; 32],
            active_context_digest: [5u8; 32],
            shadow_context_digest: [6u8; 32],
            score_active: 10,
            score_shadow: 15,
            delta: 5,
            verdict: TraceVerdict::Promising,
            created_at_ms: 20,
            reason_codes: vec!["rc.beta".to_string(), "rc.alpha".to_string()],
            trace_digest: [0u8; 32],
        };

        let first_digest = compute_trace_digest(&mut evidence);
        let first_bytes = canonical_bytes(&build_trace_run_evidence_pb(&evidence));

        let mut evidence_clone = evidence.clone();
        evidence_clone.trace_digest = [0u8; 32];
        let second_digest = compute_trace_digest(&mut evidence_clone);
        let second_bytes = canonical_bytes(&build_trace_run_evidence_pb(&evidence_clone));

        assert_eq!(first_digest, second_digest);
        assert_eq!(first_bytes, second_bytes);
    }

    #[test]
    fn trace_digest_matches() {
        let evidence = TraceRunEvidenceLocal {
            trace_id: "trace:aa:bb:1".to_string(),
            active_cfg_digest: [1u8; 32],
            shadow_cfg_digest: [2u8; 32],
            active_feedback_digest: [3u8; 32],
            shadow_feedback_digest: [4u8; 32],
            active_context_digest: [5u8; 32],
            shadow_context_digest: [6u8; 32],
            score_active: 10,
            score_shadow: 15,
            delta: 5,
            verdict: TraceVerdict::Promising,
            created_at_ms: 20,
            reason_codes: vec!["rc.beta".to_string(), "rc.alpha".to_string()],
            trace_digest: [0u8; 32],
        };

        let mut pb = build_trace_run_evidence_pb(&evidence);
        let digest = pb
            .trace_digest
            .as_ref()
            .and_then(digest_bytes)
            .expect("trace digest");
        pb.trace_digest = Some(ucf::v1::Digest32 {
            value: vec![0u8; 32],
        });
        let recomputed = digest_proto(TRACE_DOMAIN, &canonical_bytes(&pb));
        assert_eq!(digest, recomputed);
    }
}
