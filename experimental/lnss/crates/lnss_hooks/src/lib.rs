#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use lnss_core::{TapKind, TapSpec, MAX_TAP_SPECS};
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
