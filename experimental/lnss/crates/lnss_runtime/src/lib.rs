#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use lnss_core::{
    digest, BrainTarget, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap, TapFrame, TapSpec,
    MAX_ACTIVATION_BYTES, MAX_MAPPING_ENTRIES, MAX_TOP_FEATURES,
};
use lnss_hooks::TapRegistry;

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 4096;
pub const DEFAULT_MAX_SPIKES: usize = 2048;
pub const DEFAULT_MAX_TAPS: usize = 128;
pub const DEFAULT_MAX_MECHINT_BYTES: usize = 8192;
pub const MAX_TAP_SAMPLE_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum LnssRuntimeError {
    #[error("mechint writer error: {0}")]
    MechInt(String),
    #[error("rig client error: {0}")]
    Rig(String),
}

pub trait LlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8>;
    fn supports_hooks(&self) -> bool;
}

pub trait HookProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame>;
}

pub trait SaeBackend {
    fn infer_features(&mut self, tap: &TapFrame) -> FeatureEvent;
}

pub trait MechIntWriter {
    fn write_step(&mut self, rec: &MechIntRecord) -> Result<(), LnssRuntimeError>;
}

pub trait RigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError>;
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_output_bytes: usize,
    pub max_taps: usize,
    pub max_spikes: usize,
    pub max_mechint_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_taps: DEFAULT_MAX_TAPS,
            max_spikes: DEFAULT_MAX_SPIKES,
            max_mechint_bytes: DEFAULT_MAX_MECHINT_BYTES,
        }
    }
}

pub struct LnssRuntime {
    pub llm: Box<dyn LlmBackend>,
    pub hooks: Box<dyn HookProvider>,
    pub sae: Box<dyn SaeBackend>,
    pub mechint: Box<dyn MechIntWriter>,
    pub rig: Box<dyn RigClient>,
    pub mapper: FeatureToBrainMap,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrainSpike {
    pub target: BrainTarget,
    pub tick: u64,
    pub amplitude_q: u16,
}

impl BrainSpike {
    pub fn new(target: BrainTarget, tick: u64, amplitude_q: u16) -> Self {
        Self {
            target,
            tick,
            amplitude_q: amplitude_q.min(1000),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechIntRecord {
    pub session_id: String,
    pub step_id: String,
    pub token_digest: [u8; 32],
    pub tap_digests: Vec<[u8; 32]>,
    pub tap_summaries: Vec<TapSummary>,
    pub feature_event_digests: Vec<[u8; 32]>,
    pub mapping_digest: [u8; 32],
    pub record_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapSummary {
    pub hook_id: String,
    pub activation_digest: [u8; 32],
    pub sample_len: u32,
}

impl TapSummary {
    pub fn from_tap(tap: &TapFrame) -> Self {
        Self {
            hook_id: tap.hook_id.clone(),
            activation_digest: tap.activation_digest,
            sample_len: tap.activation_bytes.len() as u32,
        }
    }
}

impl MechIntRecord {
    pub fn new(
        session_id: &str,
        step_id: &str,
        token_digest: [u8; 32],
        mut tap_summaries: Vec<TapSummary>,
        mut feature_event_digests: Vec<[u8; 32]>,
        mapping_digest: [u8; 32],
    ) -> Self {
        tap_summaries.sort_by(|a, b| {
            a.hook_id
                .cmp(&b.hook_id)
                .then_with(|| a.activation_digest.cmp(&b.activation_digest))
        });
        let mut tap_digests: Vec<[u8; 32]> = tap_summaries
            .iter()
            .map(|summary| summary.activation_digest)
            .collect();
        tap_digests.sort();
        feature_event_digests.sort();
        let record_digest = record_digest(
            session_id,
            step_id,
            token_digest,
            &tap_summaries,
            &feature_event_digests,
            mapping_digest,
        );
        Self {
            session_id: session_id.to_string(),
            step_id: step_id.to_string(),
            token_digest,
            tap_digests,
            tap_summaries,
            feature_event_digests,
            mapping_digest,
            record_digest,
        }
    }
}

fn record_digest(
    session_id: &str,
    step_id: &str,
    token_digest: [u8; 32],
    tap_summaries: &[TapSummary],
    feature_event_digests: &[[u8; 32]],
    mapping_digest: [u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(session_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(step_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&token_digest);
    buf.extend_from_slice(&mapping_digest);
    buf.extend_from_slice(&(tap_summaries.len() as u32).to_le_bytes());
    for summary in tap_summaries {
        write_string(&mut buf, &summary.hook_id);
        buf.extend_from_slice(&summary.activation_digest);
        buf.extend_from_slice(&summary.sample_len.to_le_bytes());
    }
    buf.extend_from_slice(&(feature_event_digests.len() as u32).to_le_bytes());
    for digest_bytes in feature_event_digests {
        buf.extend_from_slice(digest_bytes);
    }
    digest("lnss.mechint.record.v1", &buf)
}

#[derive(Debug, Clone)]
pub struct RuntimeOutput {
    pub output_bytes: Vec<u8>,
    pub taps: Vec<TapFrame>,
    pub feature_events: Vec<FeatureEvent>,
    pub spikes: Vec<BrainSpike>,
    pub mechint_record: MechIntRecord,
}

impl LnssRuntime {
    pub fn run_step(
        &mut self,
        session_id: &str,
        step_id: &str,
        input: &[u8],
        mods: &EmotionFieldSnapshot,
        tap_specs: &[TapSpec],
    ) -> Result<RuntimeOutput, LnssRuntimeError> {
        let mut output_bytes = self.llm.infer_step(input, mods);
        output_bytes.truncate(self.limits.max_output_bytes);
        let token_digest = digest("lnss.token_bytes.v1", &output_bytes);

        let taps = if self.llm.supports_hooks() {
            let mut frames = self.hooks.collect_taps(tap_specs);
            frames.truncate(self.limits.max_taps);
            frames
        } else {
            Vec::new()
        };

        let mut feature_events = Vec::new();
        for tap in &taps {
            let event = self.sae.infer_features(tap);
            feature_events.push(event);
        }

        let mut spikes = map_features_to_spikes(&self.mapper, &feature_events);
        spikes.truncate(self.limits.max_spikes);
        self.rig.send_spikes(&spikes)?;

        let tap_summaries = taps.iter().map(TapSummary::from_tap).collect();
        let feature_event_digests = feature_events
            .iter()
            .map(|event| event.event_digest)
            .collect();
        let mechint_record = MechIntRecord::new(
            session_id,
            step_id,
            token_digest,
            tap_summaries,
            feature_event_digests,
            self.mapper.map_digest,
        );
        self.mechint.write_step(&mechint_record)?;

        Ok(RuntimeOutput {
            output_bytes,
            taps,
            feature_events,
            spikes,
            mechint_record,
        })
    }
}

pub fn map_features_to_spikes(
    mapper: &FeatureToBrainMap,
    feature_events: &[FeatureEvent],
) -> Vec<BrainSpike> {
    let mut spikes = Vec::new();
    let mut entries = mapper.entries.clone();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    entries.truncate(MAX_MAPPING_ENTRIES);

    for event in feature_events {
        for (feature_id, strength_q) in event.top_features.iter().take(MAX_TOP_FEATURES) {
            if let Some((_, target)) = entries.iter().find(|(id, _)| id == feature_id) {
                let scaled = ((*strength_q as u32) * (target.amplitude_q as u32) / 1000) as u16;
                spikes.push(BrainSpike::new(target.clone(), 0, scaled));
            }
        }
    }

    spikes
}

pub struct StubLlmBackend;

impl LlmBackend for StubLlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(input);
        buf.extend_from_slice(mods.noise.as_bytes());
        buf.extend_from_slice(mods.priority.as_bytes());
        let digest_bytes = digest("lnss.stub.llm.v1", &buf);
        digest_bytes.to_vec()
    }

    fn supports_hooks(&self) -> bool {
        true
    }
}

pub struct StubHookProvider {
    pub taps: Vec<TapFrame>,
}

impl HookProvider for StubHookProvider {
    fn collect_taps(&mut self, _specs: &[TapSpec]) -> Vec<TapFrame> {
        let mut taps = self.taps.clone();
        taps.truncate(DEFAULT_MAX_TAPS);
        taps
    }
}

pub struct StubRigClient {
    pub sent: Vec<BrainSpike>,
}

impl StubRigClient {
    pub fn new() -> Self {
        Self { sent: Vec::new() }
    }
}

impl Default for StubRigClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RigClient for StubRigClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        self.sent.extend_from_slice(spikes);
        Ok(())
    }
}

pub fn ensure_bounded_bytes(bytes: &mut Vec<u8>, limit: usize) {
    bytes.truncate(limit.min(MAX_ACTIVATION_BYTES));
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

pub struct TapRegistryProvider {
    registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>,
    enabled: bool,
}

impl TapRegistryProvider {
    pub fn new(registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>, enabled: bool) -> Self {
        Self { registry, enabled }
    }
}

impl HookProvider for TapRegistryProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame> {
        if !self.enabled {
            return Vec::new();
        }
        let mut registry = match self.registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let frames = registry.collect();
        if specs.is_empty() {
            return frames;
        }
        let allowed: std::collections::HashSet<&str> =
            specs.iter().map(|spec| spec.hook_id.as_str()).collect();
        frames
            .into_iter()
            .filter(|frame| allowed.contains(frame.hook_id.as_str()))
            .collect()
    }
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug, Clone)]
pub struct CandleConfig {
    pub model_dir: String,
    pub max_new_tokens: u32,
    pub seed: u64,
    pub device: String,
    pub hooks_enabled: bool,
}

#[cfg(feature = "lnss-candle")]
impl Default for CandleConfig {
    fn default() -> Self {
        Self {
            model_dir: ".".to_string(),
            max_new_tokens: 1,
            seed: 0,
            device: "cpu".to_string(),
            hooks_enabled: false,
        }
    }
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug)]
pub struct CandleLlmBackend {
    cfg: CandleConfig,
    loaded: bool,
    registry: Option<std::sync::Arc<std::sync::Mutex<TapRegistry>>>,
}

#[cfg(feature = "lnss-candle")]
#[derive(Debug, Error)]
pub enum CandleLoadError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(feature = "lnss-candle")]
impl CandleLlmBackend {
    pub fn new(cfg: CandleConfig) -> Self {
        Self {
            cfg,
            loaded: false,
            registry: None,
        }
    }

    pub fn with_registry(
        cfg: CandleConfig,
        registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>,
    ) -> Self {
        Self {
            cfg,
            loaded: false,
            registry: Some(registry),
        }
    }

    pub fn set_registry(&mut self, registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>) {
        self.registry = Some(registry);
    }

    pub fn try_load(&mut self) -> Result<(), CandleLoadError> {
        let readme_path = std::path::Path::new(&self.cfg.model_dir).join("README");
        if readme_path.exists() {
            self.loaded = true;
        } else {
            self.loaded = false;
        }
        Ok(())
    }

    fn record_taps(&self, input: &[u8], mods: &EmotionFieldSnapshot) {
        let registry = match &self.registry {
            Some(registry) => registry,
            None => return,
        };
        let registered = match registry.lock() {
            Ok(guard) => guard.registered(),
            Err(poisoned) => poisoned.into_inner().registered(),
        };
        if registered.is_empty() {
            return;
        }
        let seed_bytes = candle_seed_bytes(input, mods, self.cfg.seed);
        let mut frames = Vec::new();
        for tap in registered {
            let sample = candle_sample_bytes(&seed_bytes, &tap, self.cfg.max_new_tokens);
            let activation_digest = candle_activation_digest(&tap, &sample);
            let frame = TapFrame {
                hook_id: tap.hook_id.clone(),
                activation_digest,
                activation_bytes: sample,
            };
            frames.push(frame);
        }
        let mut registry = match registry.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for frame in frames {
            registry.record_frame(frame);
        }
    }
}

#[cfg(feature = "lnss-candle")]
impl LlmBackend for CandleLlmBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let mut seed_bytes = candle_seed_bytes(input, mods, self.cfg.seed);
        seed_bytes.extend_from_slice(self.cfg.device.as_bytes());
        let output = if self.loaded {
            digest("lnss.candle.infer.v1", &seed_bytes).to_vec()
        } else {
            digest("lnss.candle.fallback.v1", &seed_bytes).to_vec()
        };
        if self.loaded && self.cfg.hooks_enabled {
            self.record_taps(input, mods);
        }
        output
    }

    fn supports_hooks(&self) -> bool {
        self.loaded && self.cfg.hooks_enabled
    }
}

#[cfg(feature = "lnss-candle")]
fn candle_seed_bytes(input: &[u8], mods: &EmotionFieldSnapshot, seed: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(input);
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(mods.noise.as_bytes());
    buf.extend_from_slice(mods.priority.as_bytes());
    buf.extend_from_slice(mods.recursion_depth.as_bytes());
    buf.extend_from_slice(mods.dwm.as_bytes());
    buf.extend_from_slice(mods.profile.as_bytes());
    for overlay in &mods.overlays {
        buf.extend_from_slice(overlay.as_bytes());
    }
    for code in &mods.top_reason_codes {
        buf.extend_from_slice(code.as_bytes());
    }
    buf
}

#[cfg(feature = "lnss-candle")]
fn candle_sample_bytes(
    seed_bytes: &[u8],
    tap: &lnss_hooks::RegisteredTap,
    max_new_tokens: u32,
) -> Vec<u8> {
    let mut sample = Vec::new();
    let mut base = Vec::new();
    base.extend_from_slice(seed_bytes);
    base.extend_from_slice(tap.hook_id.as_bytes());
    base.extend_from_slice(tap.tensor_name.as_bytes());
    base.extend_from_slice(&tap.layer_index.to_le_bytes());
    base.extend_from_slice(&max_new_tokens.to_le_bytes());
    let values = 128;
    for idx in 0..values {
        let mut chunk_seed = base.clone();
        chunk_seed.extend_from_slice(&(idx as u32).to_le_bytes());
        let chunk = digest("lnss.candle.tap.sample.v1", &chunk_seed);
        let raw = u16::from_le_bytes([chunk[0], chunk[1]]);
        let f = (raw as f32 / u16::MAX as f32) * 2.0 - 1.0;
        let q = (f * 32767.0)
            .round()
            .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        sample.extend_from_slice(&q.to_le_bytes());
    }
    sample.truncate(MAX_TAP_SAMPLE_BYTES);
    sample
}

#[cfg(feature = "lnss-candle")]
fn candle_activation_digest(tap: &lnss_hooks::RegisteredTap, sample: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(tap.hook_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(tap.tensor_name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&tap.layer_index.to_le_bytes());
    buf.extend_from_slice(sample);
    digest("lnss.tap.summary.v1", &buf)
}
