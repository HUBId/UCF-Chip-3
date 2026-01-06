#![forbid(unsafe_code)]

use blake3::Hasher;
use lnss_core::{WorldModelCfgSnapshot, WorldModelCore, WorldModelInput, WorldModelOutput};

#[derive(Debug, Default)]
pub struct WorldModelCoreStub;

impl WorldModelCore for WorldModelCoreStub {
    fn step(&mut self, input: &WorldModelInput) -> WorldModelOutput {
        let world_state_digest =
            digest_concat("WM:ENC", &[&input.input_digest, &input.prev_world_digest]);
        let pred_world_digest =
            digest_concat("WM:PRED", &[&world_state_digest, &input.action_digest]);
        let prediction_error_score =
            hamming_distance(&world_state_digest, &pred_world_digest).min(1024) as i32;
        WorldModelOutput {
            world_state_digest,
            prediction_error_score,
            world_taps: None,
        }
    }

    fn cfg_snapshot(&self) -> WorldModelCfgSnapshot {
        WorldModelCfgSnapshot {
            mode: "stub".to_string(),
            encoder_id: "stub-encoder".to_string(),
            predictor_id: "stub-predictor".to_string(),
            constants: vec![("pred_error_cap".to_string(), 1024)],
        }
    }
}

fn digest_concat(domain: &str, parts: &[&[u8; 32]]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update(*part);
    }
    *hasher.finalize().as_bytes()
}

fn hamming_distance(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(left, right)| (left ^ right).count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_core::WorldModelInput;

    #[test]
    fn deterministic_world_model_outputs() {
        let mut core = WorldModelCoreStub;
        let input = WorldModelInput {
            input_digest: [1; 32],
            prev_world_digest: [2; 32],
            action_digest: [3; 32],
        };
        let out_a = core.step(&input);
        let out_b = core.step(&input);
        assert_eq!(out_a.world_state_digest, out_b.world_state_digest);
        assert_eq!(out_a.prediction_error_score, out_b.prediction_error_score);
    }
}
