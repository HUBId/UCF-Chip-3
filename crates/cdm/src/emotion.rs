#![forbid(unsafe_code)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use ucf_protocol::ucf;

const PURPOSE_BINDING: &str = "metabolic_modulation";
const DEFAULT_REASON_LIMIT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmotionField {
    pub noise_class: String,
    pub priority_class: String,
    pub recursion_depth_class: String,
    pub dwm: String,
    pub profile_state: String,
    pub overlays: Vec<String>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmotionFieldPacket {
    pub purpose_binding: String,
    pub noise_class: String,
    pub priority_class: String,
    pub recursion_depth_class: String,
    pub dwm: String,
    pub profile_state: String,
    pub overlays: Vec<String>,
    pub top_reason_codes: Vec<String>,
    pub payload_digest: Option<[u8; 32]>,
}

impl EmotionFieldPacket {
    pub fn from_field(field: &EmotionField, reason_limit: Option<usize>) -> Self {
        let mut reason_codes = field.reason_codes.clone();
        reason_codes.sort();
        reason_codes.dedup();

        let capped = reason_limit.unwrap_or(DEFAULT_REASON_LIMIT);
        let top_reason_codes = reason_codes.into_iter().take(capped).collect();

        Self {
            purpose_binding: PURPOSE_BINDING.to_string(),
            noise_class: field.noise_class.clone(),
            priority_class: field.priority_class.clone(),
            recursion_depth_class: field.recursion_depth_class.clone(),
            dwm: field.dwm.clone(),
            profile_state: field.profile_state.clone(),
            overlays: field.overlays.clone(),
            top_reason_codes,
            payload_digest: None,
        }
    }

    pub fn encode(&self) -> (Vec<u8>, [u8; 32]) {
        let mut canonical = self.clone();
        canonical.payload_digest = None;

        let canonical_bytes =
            serde_json::to_vec(&canonical).expect("emotion packet canonical json");
        let mut hasher = Hasher::new();
        hasher.update(&canonical_bytes);
        let digest = hasher.finalize();
        let digest_bytes: [u8; 32] = digest.into();

        let mut with_digest = self.clone();
        with_digest.payload_digest = Some(digest_bytes);
        let payload = serde_json::to_vec(&with_digest).expect("emotion packet json");

        (payload, digest_bytes)
    }
}

pub fn emotion_field_to_input_packet(
    window_index: u64,
    field: &EmotionField,
    reason_limit: Option<usize>,
) -> ucf::v1::InputPacket {
    let packet = EmotionFieldPacket::from_field(field, reason_limit);
    let (payload, _embedded_digest) = packet.encode();

    let mut payload_hasher = Hasher::new();
    payload_hasher.update(&payload);
    let payload_digest = payload_hasher.finalize();

    ucf::v1::InputPacket {
        request_id: format!("emotion-field:{window_index}"),
        payload,
        payload_digest: Some(ucf::v1::Digest32 {
            value: (*payload_digest.as_bytes()).to_vec(),
        }),
        data_class: ucf::v1::DataClass::Public as i32,
    }
}

pub fn purpose_binding() -> &'static str {
    PURPOSE_BINDING
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_field(reason_codes: Vec<&str>) -> EmotionField {
        EmotionField {
            noise_class: "calm".to_string(),
            priority_class: "low".to_string(),
            recursion_depth_class: "shallow".to_string(),
            dwm: "baseline".to_string(),
            profile_state: "stable".to_string(),
            overlays: vec!["overlay-a".to_string()],
            reason_codes: reason_codes.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn sorts_and_caps_reason_codes() {
        let field = sample_field(vec!["b", "a", "b", "c"]);
        let packet = EmotionFieldPacket::from_field(&field, Some(2));

        assert_eq!(packet.top_reason_codes, vec!["a", "b"]);
    }

    #[test]
    fn encode_sets_embedded_digest() {
        let field = sample_field(vec!["b", "a"]);
        let packet = EmotionFieldPacket::from_field(&field, None);
        let (payload, digest) = packet.encode();

        let decoded: EmotionFieldPacket = serde_json::from_slice(&payload).expect("decode payload");
        assert_eq!(decoded.payload_digest, Some(digest));
    }
}
