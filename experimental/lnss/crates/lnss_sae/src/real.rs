#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
};

use candle_core::{Device, Tensor};
use half::f16;
use lnss_core::{FeatureEvent, TapFrame, MAX_TOP_FEATURES};
use lnss_runtime::SaeBackend;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_INPUT_DIM: usize = 4096;
const MAX_FEATURE_DIM: usize = 65536;
const MAX_TOP_K: usize = 256;
const MAX_CACHE_PACKS: usize = 8;

#[derive(Debug, Error)]
pub enum SaePackError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("candle error: {0}")]
    Candle(#[from] candle_core::Error),
    #[error("invalid pack metadata: {0}")]
    InvalidMeta(String),
    #[error("invalid pack weights: {0}")]
    InvalidWeights(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaePackMeta {
    pub version: u32,
    pub hook_id: String,
    pub input_dim: usize,
    pub feature_dim: usize,
    pub top_k: usize,
    pub scaling_q: u32,
}

#[derive(Debug)]
pub struct SaePack {
    pub meta: SaePackMeta,
    pub w_enc: Tensor,
    pub b_enc: Tensor,
}

#[derive(Debug, Clone, Copy)]
pub enum SaeNonlinearity {
    Relu,
    Abs,
}

#[derive(Debug)]
struct CacheEntry {
    hook_id: String,
    pack: SaePack,
}

#[derive(Debug)]
pub struct RealSaeBackend {
    pack_root: PathBuf,
    cache: VecDeque<CacheEntry>,
    nonlinearity: SaeNonlinearity,
}

impl RealSaeBackend {
    pub fn new(pack_root: PathBuf, nonlinearity: SaeNonlinearity) -> Self {
        Self {
            pack_root,
            cache: VecDeque::new(),
            nonlinearity,
        }
    }

    fn resolve_pack_dir(&self, hook_id: &str) -> PathBuf {
        let root_meta = self.pack_root.join("meta.json");
        if root_meta.exists() {
            return self.pack_root.clone();
        }
        self.pack_root.join(hook_id)
    }

    fn load_pack_for_hook(&mut self, hook_id: &str) -> Result<&SaePack, SaePackError> {
        if let Some(pos) = self.cache.iter().position(|entry| entry.hook_id == hook_id) {
            return Ok(&self.cache[pos].pack);
        }

        let pack_dir = self.resolve_pack_dir(hook_id);
        let pack = load_pack(&pack_dir)?;

        if pack.meta.hook_id != hook_id {
            return Err(SaePackError::InvalidMeta(format!(
                "hook id mismatch: expected {hook_id}, got {}",
                pack.meta.hook_id
            )));
        }

        if self.cache.len() >= MAX_CACHE_PACKS {
            self.cache.pop_front();
        }
        self.cache.push_back(CacheEntry {
            hook_id: hook_id.to_string(),
            pack,
        });
        Ok(&self.cache.back().expect("pack cached").pack)
    }

    fn sample_to_input(sample: &[u8], input_dim: usize) -> Vec<f32> {
        let mut input = vec![0.0f32; input_dim];
        for (idx, chunk) in sample.chunks_exact(2).enumerate() {
            if idx >= input_dim {
                break;
            }
            let value = i16::from_le_bytes([chunk[0], chunk[1]]) as f32;
            input[idx] = value;
        }
        input
    }

    fn activation_values(
        nonlinearity: SaeNonlinearity,
        pack: &SaePack,
        input: &[f32],
    ) -> Result<Vec<f32>, SaePackError> {
        let device = Device::Cpu;
        let x = Tensor::from_vec(input.to_vec(), (pack.meta.input_dim, 1), &device)?;
        let z = pack.w_enc.matmul(&x)?;
        let z = z.add(&pack.b_enc)?;
        let z = match nonlinearity {
            SaeNonlinearity::Relu => z.relu()?,
            SaeNonlinearity::Abs => z.abs()?,
        };
        let z = z.reshape((pack.meta.feature_dim,))?;
        let mut values = z.to_vec1::<f32>()?;
        for value in &mut values {
            if !value.is_finite() {
                *value = 0.0;
            }
        }
        Ok(values)
    }

    fn select_top_features(pack: &SaePack, values: &[f32]) -> Vec<(u32, u16)> {
        let mut pairs: Vec<(u32, f32)> = values
            .iter()
            .enumerate()
            .map(|(idx, value)| (idx as u32, *value))
            .collect();
        pairs.sort_by(|(id_a, val_a), (id_b, val_b)| {
            val_b
                .partial_cmp(val_a)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| id_a.cmp(id_b))
        });
        let top_k = pack
            .meta
            .top_k
            .min(MAX_TOP_K)
            .min(MAX_TOP_FEATURES)
            .min(pack.meta.feature_dim);
        let scale = pack.meta.scaling_q as f32;
        pairs
            .into_iter()
            .take(top_k)
            .map(|(feature_id, value)| {
                let scaled = (value * scale).round();
                let strength = scaled.clamp(0.0, 1000.0) as u16;
                (feature_id, strength)
            })
            .collect()
    }
}

impl SaeBackend for RealSaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent {
        let nonlinearity = self.nonlinearity;
        let pack = match self.load_pack_for_hook(&tap.hook_id) {
            Ok(pack) => pack,
            Err(_) => {
                return FeatureEvent::new(
                    "session-stub",
                    "step-stub",
                    &tap.hook_id,
                    Vec::new(),
                    0,
                    vec!["sae-error".to_string()],
                );
            }
        };
        let input = Self::sample_to_input(&tap.activation_bytes, pack.meta.input_dim);
        let values = match Self::activation_values(nonlinearity, pack, &input) {
            Ok(values) => values,
            Err(_) => {
                return FeatureEvent::new(
                    "session-stub",
                    "step-stub",
                    &pack.meta.hook_id,
                    Vec::new(),
                    0,
                    vec!["sae-error".to_string()],
                );
            }
        };
        let features = Self::select_top_features(pack, &values);
        FeatureEvent::new(
            "session-stub",
            "step-stub",
            &pack.meta.hook_id,
            features,
            0,
            vec!["sae-real".to_string()],
        )
    }
}

pub fn load_pack(dir: &Path) -> Result<SaePack, SaePackError> {
    let meta_path = dir.join("meta.json");
    let meta_bytes = fs::read_to_string(&meta_path)?;
    let meta: SaePackMeta = serde_json::from_str(&meta_bytes)?;

    if meta.input_dim == 0 || meta.input_dim > MAX_INPUT_DIM {
        return Err(SaePackError::InvalidMeta(format!(
            "input_dim {} exceeds bounds",
            meta.input_dim
        )));
    }
    if meta.feature_dim == 0 || meta.feature_dim > MAX_FEATURE_DIM {
        return Err(SaePackError::InvalidMeta(format!(
            "feature_dim {} exceeds bounds",
            meta.feature_dim
        )));
    }
    if meta.top_k == 0 || meta.top_k > MAX_TOP_K {
        return Err(SaePackError::InvalidMeta(format!(
            "top_k {} exceeds bounds",
            meta.top_k
        )));
    }
    if meta.top_k > meta.feature_dim {
        return Err(SaePackError::InvalidMeta(
            "top_k exceeds feature_dim".to_string(),
        ));
    }

    let w_path = dir.join("w_enc.bin");
    let b_path = dir.join("b_enc.bin");
    let w_bytes = fs::read(&w_path)?;
    let b_bytes = fs::read(&b_path)?;

    let w_len = meta.feature_dim * meta.input_dim;
    let b_len = meta.feature_dim;
    let expected_f16 = w_len
        .checked_mul(2)
        .ok_or_else(|| SaePackError::InvalidWeights("w_enc size overflow".to_string()))?;
    let expected_f32 = w_len
        .checked_mul(4)
        .ok_or_else(|| SaePackError::InvalidWeights("w_enc size overflow".to_string()))?;

    let expected_b_f16 = b_len
        .checked_mul(2)
        .ok_or_else(|| SaePackError::InvalidWeights("b_enc size overflow".to_string()))?;
    let expected_b_f32 = b_len
        .checked_mul(4)
        .ok_or_else(|| SaePackError::InvalidWeights("b_enc size overflow".to_string()))?;

    let use_f16 = if w_bytes.len() == expected_f16 && b_bytes.len() == expected_b_f16 {
        true
    } else if w_bytes.len() == expected_f32 && b_bytes.len() == expected_b_f32 {
        false
    } else {
        return Err(SaePackError::InvalidWeights(format!(
            "unexpected weight sizes: w_enc {} bytes, b_enc {} bytes",
            w_bytes.len(),
            b_bytes.len()
        )));
    };

    let w_vals = if use_f16 {
        w_bytes
            .chunks_exact(2)
            .map(|chunk| {
                let bits = u16::from_le_bytes([chunk[0], chunk[1]]);
                f16::from_bits(bits).to_f32()
            })
            .collect::<Vec<f32>>()
    } else {
        w_bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<f32>>()
    };

    let b_vals = if use_f16 {
        b_bytes
            .chunks_exact(2)
            .map(|chunk| {
                let bits = u16::from_le_bytes([chunk[0], chunk[1]]);
                f16::from_bits(bits).to_f32()
            })
            .collect::<Vec<f32>>()
    } else {
        b_bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<f32>>()
    };

    let device = Device::Cpu;
    let w_enc = Tensor::from_vec(w_vals, (meta.feature_dim, meta.input_dim), &device)?;
    let b_enc = Tensor::from_vec(b_vals, (meta.feature_dim, 1), &device)?;

    Ok(SaePack { meta, w_enc, b_enc })
}
