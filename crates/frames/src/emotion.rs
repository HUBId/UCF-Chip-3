#![forbid(unsafe_code)]

use cdm::emotion::emotion_field_to_input_packet;
use chip2_client::Chip2Reader;
use ucf_protocol::ucf;

const DEFAULT_REASON_LIMIT: usize = 16;

#[derive(Debug, Clone)]
pub struct EmotionSnapshotEmitter<R: Chip2Reader> {
    reader: R,
    reason_limit: usize,
    last_window_index: Option<u64>,
}

impl<R: Chip2Reader> EmotionSnapshotEmitter<R> {
    pub fn new(reader: R) -> Self {
        Self::with_reason_limit(reader, DEFAULT_REASON_LIMIT)
    }

    pub fn with_reason_limit(reader: R, reason_limit: usize) -> Self {
        Self {
            reader,
            reason_limit,
            last_window_index: None,
        }
    }

    pub fn tick(&mut self, window_index: u64) -> Option<ucf::v1::InputPacket> {
        if self.last_window_index == Some(window_index) {
            return None;
        }

        self.last_window_index = Some(window_index);
        let field = self.reader.get_latest_emotion_field()?;

        Some(emotion_field_to_input_packet(
            window_index,
            &field,
            Some(self.reason_limit),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::hash;
    use blake3::Hash;
    use cdm::emotion::{purpose_binding, EmotionField, EmotionFieldPacket};
    use chip2_client::MockChip2Reader;

    fn field(reason_codes: Vec<&str>) -> EmotionField {
        EmotionField {
            noise_class: "steady".to_string(),
            priority_class: "high".to_string(),
            recursion_depth_class: "deep".to_string(),
            dwm: "engaged".to_string(),
            profile_state: "active".to_string(),
            overlays: vec!["overlay-1".to_string(), "overlay-2".to_string()],
            reason_codes: reason_codes.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn translates_emotion_field() {
        let mut emitter = EmotionSnapshotEmitter::new(MockChip2Reader::new(Some(field(vec![
            "rc.c", "rc.a", "rc.b", "rc.a",
        ]))));

        let packet = emitter.tick(10).expect("packet emitted");
        let decoded: EmotionFieldPacket =
            serde_json::from_slice(&packet.payload).expect("decode emotion payload");

        assert_eq!(decoded.purpose_binding, purpose_binding());
        assert_eq!(decoded.top_reason_codes, vec!["rc.a", "rc.b", "rc.c"]);

        let mut canonical = decoded.clone();
        canonical.payload_digest = None;
        let canonical_bytes = serde_json::to_vec(&canonical).expect("canonical emotion packet");
        let embedded_digest: [u8; 32] = hash(&canonical_bytes).into();
        assert_eq!(decoded.payload_digest, Some(embedded_digest));

        let envelope_digest = packet
            .payload_digest
            .as_ref()
            .expect("payload digest set")
            .value
            .clone();
        let payload_digest: [u8; 32] = hash(&packet.payload).into();
        assert_eq!(envelope_digest, payload_digest.to_vec());
    }

    #[test]
    fn bounded_to_single_packet_per_window() {
        let mut emitter =
            EmotionSnapshotEmitter::new(MockChip2Reader::new(Some(field(vec!["rc"]))));

        let first = emitter.tick(1);
        let second = emitter.tick(1);

        assert!(first.is_some());
        assert!(second.is_none());
    }

    #[test]
    fn deterministic_encoding() {
        let reader = MockChip2Reader::new(Some(field(vec!["rc.a", "rc.b"])));
        let mut emitter_a = EmotionSnapshotEmitter::new(reader.clone());
        let mut emitter_b = EmotionSnapshotEmitter::new(reader);

        let packet_a = emitter_a.tick(2).expect("first packet");
        let packet_b = emitter_b.tick(2).expect("second packet");

        let digest_a: Hash = hash(&packet_a.payload);
        let digest_b: Hash = hash(&packet_b.payload);

        assert_eq!(digest_a.as_bytes(), digest_b.as_bytes());
    }
}
