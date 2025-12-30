#![forbid(unsafe_code)]

use std::path::PathBuf;

use lnss_core::{FeatureEvent, TapFrame, MAX_TOP_FEATURES};
use lnss_runtime::SaeBackend;
#[derive(Debug, Clone)]
pub struct SaeWeightsRef {
    pub path: PathBuf,
}

pub struct StubSaeBackend {
    pub top_k: usize,
}

impl StubSaeBackend {
    pub fn new(top_k: usize) -> Self {
        Self { top_k }
    }

    fn pseudo_features(&self, digest: &[u8; 32]) -> Vec<(u32, u16)> {
        let mut features = Vec::new();
        let base = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        for idx in 0..self.top_k.min(MAX_TOP_FEATURES) {
            let feature_id = base.wrapping_add(idx as u32);
            let strength = (digest[(idx * 2) % digest.len()] as u16) % 1001;
            features.push((feature_id, strength));
        }
        features
    }
}

impl SaeBackend for StubSaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent {
        let features = self.pseudo_features(&tap.activation_digest);
        FeatureEvent::new(
            "session-stub",
            "step-stub",
            &tap.hook_id,
            features,
            0,
            vec!["stub".to_string()],
        )
    }
}

#[cfg(feature = "lnss-candle")]
pub struct CandleSaeLoader;

#[cfg(feature = "lnss-candle")]
impl CandleSaeLoader {
    pub fn load_weights(path: PathBuf) -> SaeWeightsRef {
        SaeWeightsRef { path }
    }
}
