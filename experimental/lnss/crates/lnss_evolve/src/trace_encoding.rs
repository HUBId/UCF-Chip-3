#![forbid(unsafe_code)]

use lnss_core::{digest, MAX_STRING_LEN};

const TRACE_DOMAIN: &str = "UCF:LNSS:TRACE_RUN";
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
    pub score_active: i32,
    pub score_shadow: i32,
    pub delta: i32,
    pub verdict: TraceVerdict,
    pub created_at_ms: u64,
    pub reason_codes: Vec<String>,
    pub trace_digest: [u8; 32],
}

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
    let mut canonical = ev.clone();
    canonical.trace_digest = [0u8; 32];
    let bytes = encode_trace(&canonical);
    let digest_bytes = digest(TRACE_DOMAIN, &bytes);
    ev.trace_digest = digest_bytes;
    digest_bytes
}

fn trace_verdict_tag(verdict: &TraceVerdict) -> u8 {
    match verdict {
        TraceVerdict::Promising => 1,
        TraceVerdict::Neutral => 2,
        TraceVerdict::Risky => 3,
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

fn write_string_u16(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_i32(buf: &mut Vec<u8>, value: i32) {
    buf.extend_from_slice(&value.to_le_bytes());
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
            score_active: 10,
            score_shadow: 15,
            delta: 5,
            verdict: TraceVerdict::Promising,
            created_at_ms: 20,
            reason_codes: vec!["rc.beta".to_string(), "rc.alpha".to_string()],
            trace_digest: [0u8; 32],
        };

        let first_digest = compute_trace_digest(&mut evidence);
        let first_bytes = encode_trace(&evidence);

        let mut evidence_clone = evidence.clone();
        evidence_clone.trace_digest = [0u8; 32];
        let second_digest = compute_trace_digest(&mut evidence_clone);
        let second_bytes = encode_trace(&evidence_clone);

        assert_eq!(first_digest, second_digest);
        assert_eq!(first_bytes, second_bytes);
    }
}
