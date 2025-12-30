#![forbid(unsafe_code)]
#![cfg(feature = "lnss-sae-real")]

use std::{
    fs,
    path::{Path, PathBuf},
};

use lnss_core::{digest, TapFrame};
use lnss_runtime::SaeBackend;
use lnss_sae::{load_pack, RealSaeBackend, SaeNonlinearity};

fn write_pack(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir).expect("create pack dir");
    let meta = serde_json::json!({
        "version": 1,
        "hook_id": "liquid-state",
        "input_dim": 4,
        "feature_dim": 4,
        "top_k": 2,
        "scaling_q": 10
    });
    fs::write(
        dir.join("meta.json"),
        serde_json::to_string(&meta).expect("meta json"),
    )
    .expect("write meta");
    let mut w_bytes = Vec::new();
    for i in 0..4 {
        for j in 0..4 {
            let value = if i == j { 1.0f32 } else { 0.0f32 };
            w_bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    fs::write(dir.join("w_enc.bin"), &w_bytes).expect("write w_enc");
    let mut b_bytes = Vec::new();
    for _ in 0..4 {
        b_bytes.extend_from_slice(&0.0f32.to_le_bytes());
    }
    fs::write(dir.join("b_enc.bin"), &b_bytes).expect("write b_enc");
    dir.to_path_buf()
}

fn tap_frame(bytes: &[u8]) -> TapFrame {
    TapFrame {
        hook_id: "liquid-state".to_string(),
        activation_digest: digest("test", bytes),
        activation_bytes: bytes.to_vec(),
    }
}

fn i16_bytes(values: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn real_sae_inference_is_deterministic() {
    let pack_dir = std::env::temp_dir().join("lnss_sae_pack_small");
    let mut backend = RealSaeBackend::new(write_pack(&pack_dir), SaeNonlinearity::Relu);
    let tap = tap_frame(&i16_bytes(&[2, -1, 3, 0]));
    let event_a = backend.infer_features(&tap);
    let event_b = backend.infer_features(&tap);
    assert_eq!(event_a.top_features, event_b.top_features);
    assert_eq!(event_a.top_features, vec![(2, 30), (0, 20)]);
}

#[test]
fn real_sae_tie_breaks_on_feature_id() {
    let pack_dir = std::env::temp_dir().join("lnss_sae_pack_small_tie");
    let mut backend = RealSaeBackend::new(write_pack(&pack_dir), SaeNonlinearity::Relu);
    let tap = tap_frame(&i16_bytes(&[5, 5, 0, 0]));
    let event = backend.infer_features(&tap);
    assert_eq!(event.top_features, vec![(0, 50), (1, 50)]);
}

#[test]
fn load_pack_rejects_bounds() {
    let temp_root = std::env::temp_dir().join("lnss_sae_pack_bounds");
    let _ = std::fs::create_dir_all(&temp_root);
    let meta = serde_json::json!({
        "version": 1,
        "hook_id": "liquid-state",
        "input_dim": 5000,
        "feature_dim": 4,
        "top_k": 2,
        "scaling_q": 10
    });
    std::fs::write(
        temp_root.join("meta.json"),
        serde_json::to_string(&meta).expect("meta json"),
    )
    .expect("write meta");
    let err = load_pack(&temp_root).expect_err("expected bounds error");
    let err_text = err.to_string();
    assert!(err_text.contains("input_dim"));
}
