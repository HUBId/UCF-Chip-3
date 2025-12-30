#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use lnss_core::{TapFrame, TapKind, TapSpec, MAX_STRING_LEN, MAX_TAP_SPECS};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HookError {
    #[error("failed to load tap plan: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse tap plan: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct TapPlan {
    pub specs: Vec<TapSpec>,
}

impl TapPlan {
    pub fn new(mut specs: Vec<TapSpec>) -> Self {
        specs.sort_by(|a, b| {
            a.hook_id
                .cmp(&b.hook_id)
                .then_with(|| a.layer_index.cmp(&b.layer_index))
        });
        specs.truncate(MAX_TAP_SPECS);
        Self { specs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredTap {
    pub hook_id: String,
    pub tensor_name: String,
    pub layer_index: u16,
}

impl RegisteredTap {
    pub fn new(hook_id: &str, tensor_name: &str, layer_index: u16) -> Self {
        Self {
            hook_id: bound_string(hook_id),
            tensor_name: bound_string(tensor_name),
            layer_index,
        }
    }
}

#[derive(Debug, Default)]
pub struct TapRegistry {
    registered: Vec<RegisteredTap>,
    frames: Vec<TapFrame>,
}

impl TapRegistry {
    pub fn new() -> Self {
        Self {
            registered: Vec::new(),
            frames: Vec::new(),
        }
    }

    pub fn register_tap(&mut self, hook_id: &str, tensor_name: &str, layer_index: u16) {
        let candidate = RegisteredTap::new(hook_id, tensor_name, layer_index);
        if self.registered.contains(&candidate) {
            return;
        }
        if self.registered.len() >= MAX_TAP_SPECS {
            return;
        }
        self.registered.push(candidate);
        self.registered.sort_by(|a, b| {
            a.hook_id
                .cmp(&b.hook_id)
                .then_with(|| a.layer_index.cmp(&b.layer_index))
        });
    }

    pub fn registered(&self) -> Vec<RegisteredTap> {
        self.registered.clone()
    }

    pub fn record_frame(&mut self, frame: TapFrame) {
        if self.frames.len() >= MAX_TAP_SPECS {
            return;
        }
        self.frames.push(frame);
    }

    pub fn collect(&mut self) -> Vec<TapFrame> {
        let mut frames = std::mem::take(&mut self.frames);
        frames.truncate(MAX_TAP_SPECS);
        frames
    }
}

#[derive(Debug, Deserialize)]
struct TapSpecJson {
    hook_id: String,
    tap_kind: String,
    layer_index: u16,
    tensor_name: String,
}

pub struct TransformerLensPlanImport;

impl TransformerLensPlanImport {
    pub fn from_path(path: impl AsRef<Path>) -> Result<TapPlan, HookError> {
        let data = fs::read_to_string(path)?;
        let specs: Vec<TapSpecJson> = serde_json::from_str(&data)?;
        let mut tap_specs = Vec::new();
        for spec in specs {
            let tap_kind = match spec.tap_kind.as_str() {
                "residual_stream" => TapKind::ResidualStream,
                "mlp_post" => TapKind::MlpPost,
                "attn_out" => TapKind::AttnOut,
                "embedding" => TapKind::Embedding,
                "liquid_state" => TapKind::LiquidState,
                _ => TapKind::ResidualStream,
            };
            tap_specs.push(TapSpec::new(
                &spec.hook_id,
                tap_kind,
                spec.layer_index,
                &spec.tensor_name,
            ));
        }
        Ok(TapPlan::new(tap_specs))
    }
}

fn bound_string(value: &str) -> String {
    let mut out = value.to_string();
    out.truncate(MAX_STRING_LEN);
    out
}
