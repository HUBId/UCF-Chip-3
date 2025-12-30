#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use lnss_core::BiophysFeedbackSnapshot;
#[cfg(feature = "lnss-liquid-ode")]
use lnss_core::TapKind;
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
    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        None
    }
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
    pub feedback: FeedbackConsumer,
    pub adaptation: MappingAdaptationConfig,
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
    pub feedback: Option<FeedbackSummary>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
    pub record_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechIntRecordParts {
    pub session_id: String,
    pub step_id: String,
    pub token_digest: [u8; 32],
    pub tap_summaries: Vec<TapSummary>,
    pub feature_event_digests: Vec<[u8; 32]>,
    pub mapping_digest: [u8; 32],
    pub feedback: Option<FeedbackSummary>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapSummary {
    pub hook_id: String,
    pub activation_digest: [u8; 32],
    pub sample_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackSummary {
    pub tick: u64,
    pub snapshot_digest: [u8; 32],
    pub event_queue_overflowed: bool,
    pub events_dropped: u64,
    pub events_injected: u32,
    pub injected_total: u64,
}

impl FeedbackSummary {
    pub fn from_snapshot(snapshot: &BiophysFeedbackSnapshot) -> Self {
        Self {
            tick: snapshot.tick,
            snapshot_digest: snapshot.snapshot_digest,
            event_queue_overflowed: snapshot.event_queue_overflowed,
            events_dropped: snapshot.events_dropped,
            events_injected: snapshot.events_injected,
            injected_total: snapshot.injected_total,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingAdaptationSuggestion {
    pub amplitude_q_factor: u16,
    pub max_targets_per_feature: u16,
}

#[derive(Debug, Clone)]
pub struct MappingAdaptationConfig {
    pub enabled: bool,
    pub events_dropped_threshold: u64,
    pub amplitude_q_factor: u16,
    pub max_targets_per_feature: u16,
}

impl Default for MappingAdaptationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            events_dropped_threshold: 1,
            amplitude_q_factor: 900,
            max_targets_per_feature: 8,
        }
    }
}

impl MappingAdaptationConfig {
    pub fn suggest(
        &self,
        feedback: Option<&BiophysFeedbackSnapshot>,
    ) -> Option<MappingAdaptationSuggestion> {
        if !self.enabled {
            return None;
        }
        let feedback = feedback?;
        let dropped_high = feedback.events_dropped >= self.events_dropped_threshold;
        if !(feedback.event_queue_overflowed || dropped_high) {
            return None;
        }
        Some(MappingAdaptationSuggestion {
            amplitude_q_factor: self.amplitude_q_factor.clamp(1, 1000),
            max_targets_per_feature: self.max_targets_per_feature.max(1),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct FeedbackConsumer {
    pub last: Option<BiophysFeedbackSnapshot>,
}

impl FeedbackConsumer {
    pub fn ingest(&mut self, snap: BiophysFeedbackSnapshot) {
        self.last = Some(snap);
    }
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
    pub fn new(mut parts: MechIntRecordParts) -> Self {
        parts.tap_summaries.sort_by(|a, b| {
            a.hook_id
                .cmp(&b.hook_id)
                .then_with(|| a.activation_digest.cmp(&b.activation_digest))
        });
        let mut tap_digests: Vec<[u8; 32]> = parts
            .tap_summaries
            .iter()
            .map(|summary| summary.activation_digest)
            .collect();
        tap_digests.sort();
        parts.feature_event_digests.sort();
        let record_digest = record_digest(&parts);
        Self {
            session_id: parts.session_id,
            step_id: parts.step_id,
            token_digest: parts.token_digest,
            tap_digests,
            tap_summaries: parts.tap_summaries,
            feature_event_digests: parts.feature_event_digests,
            mapping_digest: parts.mapping_digest,
            feedback: parts.feedback,
            mapping_suggestion: parts.mapping_suggestion,
            record_digest,
        }
    }
}

fn record_digest(parts: &MechIntRecordParts) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(parts.session_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(parts.step_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(&parts.token_digest);
    buf.extend_from_slice(&parts.mapping_digest);
    buf.extend_from_slice(&(parts.tap_summaries.len() as u32).to_le_bytes());
    for summary in &parts.tap_summaries {
        write_string(&mut buf, &summary.hook_id);
        buf.extend_from_slice(&summary.activation_digest);
        buf.extend_from_slice(&summary.sample_len.to_le_bytes());
    }
    buf.extend_from_slice(&(parts.feature_event_digests.len() as u32).to_le_bytes());
    for digest_bytes in &parts.feature_event_digests {
        buf.extend_from_slice(digest_bytes);
    }
    write_optional_feedback(&mut buf, parts.feedback.as_ref());
    write_optional_suggestion(&mut buf, parts.mapping_suggestion.as_ref());
    digest("lnss.mechint.record.v1", &buf)
}

#[derive(Debug, Clone)]
pub struct RuntimeOutput {
    pub output_bytes: Vec<u8>,
    pub taps: Vec<TapFrame>,
    pub feature_events: Vec<FeatureEvent>,
    pub spikes: Vec<BrainSpike>,
    pub feedback_snapshot: Option<BiophysFeedbackSnapshot>,
    pub mapping_suggestion: Option<MappingAdaptationSuggestion>,
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
        if let Some(snapshot) = self.rig.poll_feedback() {
            self.feedback.ingest(snapshot);
        }
        let feedback_snapshot = self.feedback.last.clone();
        let feedback_summary = feedback_snapshot
            .as_ref()
            .map(FeedbackSummary::from_snapshot);
        let mapping_suggestion = self.adaptation.suggest(feedback_snapshot.as_ref());

        let tap_summaries = taps.iter().map(TapSummary::from_tap).collect();
        let feature_event_digests = feature_events
            .iter()
            .map(|event| event.event_digest)
            .collect();
        let mechint_record = MechIntRecord::new(MechIntRecordParts {
            session_id: session_id.to_string(),
            step_id: step_id.to_string(),
            token_digest,
            tap_summaries,
            feature_event_digests,
            mapping_digest: self.mapper.map_digest,
            feedback: feedback_summary,
            mapping_suggestion: mapping_suggestion.clone(),
        });
        self.mechint.write_step(&mechint_record)?;

        Ok(RuntimeOutput {
            output_bytes,
            taps,
            feature_events,
            spikes,
            feedback_snapshot,
            mapping_suggestion,
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

fn write_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn write_optional_feedback(buf: &mut Vec<u8>, feedback: Option<&FeedbackSummary>) {
    match feedback {
        Some(summary) => {
            write_bool(buf, true);
            write_u64(buf, summary.tick);
            buf.extend_from_slice(&summary.snapshot_digest);
            write_bool(buf, summary.event_queue_overflowed);
            write_u64(buf, summary.events_dropped);
            write_u32(buf, summary.events_injected);
            write_u64(buf, summary.injected_total);
        }
        None => write_bool(buf, false),
    }
}

fn write_optional_suggestion(buf: &mut Vec<u8>, suggestion: Option<&MappingAdaptationSuggestion>) {
    match suggestion {
        Some(suggestion) => {
            write_bool(buf, true);
            write_u16(buf, suggestion.amplitude_q_factor);
            write_u16(buf, suggestion.max_targets_per_feature);
        }
        None => write_bool(buf, false),
    }
}

pub struct TapRegistryProvider {
    registry: std::sync::Arc<std::sync::Mutex<TapRegistry>>,
    enabled: bool,
}

#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_Q_SHIFT: i32 = 16;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_Q_ONE: i32 = 1 << LIQUID_Q_SHIFT;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_WEIGHT_SCALE: i64 = 64;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_OUTPUT_SAMPLE_DIMS: usize = 16;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_TAP_SAMPLE_DIMS: usize = 64;
#[cfg(feature = "lnss-liquid-ode")]
const LIQUID_STATE_CLAMP_Q: i32 = LIQUID_Q_ONE * 8;

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
pub struct LiquidOdeConfig {
    pub state_dim: u32,
    pub dt_ms_q: u16,
    pub steps_per_call: u16,
    pub seed: u64,
    pub input_proj_dim: u32,
    pub mods_gain_q: u16,
}

#[cfg(feature = "lnss-liquid-ode")]
impl Default for LiquidOdeConfig {
    fn default() -> Self {
        Self {
            state_dim: 256,
            dt_ms_q: 1000,
            steps_per_call: 1,
            seed: 0,
            input_proj_dim: 64,
            mods_gain_q: 100,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
pub struct LiquidOdeState {
    pub x_q: Vec<i32>,
    pub step_count: u64,
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug, Clone)]
struct LiquidWeights {
    w_in: Vec<i16>,
    w_rec: Vec<i16>,
    bias_q: Vec<i32>,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidWeights {
    fn new(cfg: &LiquidOdeConfig) -> Self {
        let state_dim = cfg.state_dim.max(1) as usize;
        let input_dim = cfg.input_proj_dim.max(1) as usize;
        let mut w_in = Vec::with_capacity(state_dim * input_dim);
        for idx in 0..(state_dim * input_dim) {
            w_in.push(derive_weight(cfg.seed, idx as u64, "w_in"));
        }
        let mut w_rec = Vec::with_capacity(state_dim * state_dim);
        for idx in 0..(state_dim * state_dim) {
            w_rec.push(derive_weight(cfg.seed, idx as u64, "w_rec"));
        }
        let mut bias_q = Vec::with_capacity(state_dim);
        for idx in 0..state_dim {
            bias_q.push(derive_bias(cfg.seed, idx as u64));
        }
        Self {
            w_in,
            w_rec,
            bias_q,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug)]
pub struct LiquidOdeBackend {
    cfg: LiquidOdeConfig,
    state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
    weights: LiquidWeights,
    dt_q: i32,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidOdeBackend {
    pub fn new(mut cfg: LiquidOdeConfig) -> Self {
        cfg.state_dim = cfg.state_dim.max(1);
        cfg.input_proj_dim = cfg.input_proj_dim.max(1);
        cfg.steps_per_call = cfg.steps_per_call.max(1);
        let state_dim = cfg.state_dim as usize;
        let state = LiquidOdeState {
            x_q: vec![0; state_dim],
            step_count: 0,
        };
        let dt_q =
            ((cfg.dt_ms_q as i64) * (LIQUID_Q_ONE as i64) / 1000).clamp(1, i32::MAX as i64) as i32;
        let weights = LiquidWeights::new(&cfg);
        Self {
            cfg,
            state: std::sync::Arc::new(std::sync::Mutex::new(state)),
            weights,
            dt_q,
        }
    }

    pub fn tap_provider(&self) -> LiquidTapProvider {
        LiquidTapProvider::new(self.state.clone(), self.cfg.clone())
    }

    pub fn state_len(&self) -> usize {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.x_q.len()
    }

    fn step_state(&mut self, input_proj: &[i32], gain_q: i32) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state_dim = self.cfg.state_dim as usize;
        if guard.x_q.len() != state_dim {
            guard.x_q.resize(state_dim, 0);
        }
        let mut tanh_vals = Vec::with_capacity(state_dim);
        for &x_q in &guard.x_q {
            tanh_vals.push(tanh_approx_q(x_q));
        }
        let mut next = vec![0; state_dim];
        let alpha_q = LIQUID_Q_ONE / 8;
        let input_dim = self.cfg.input_proj_dim as usize;
        for (i, next_val) in next.iter_mut().enumerate().take(state_dim) {
            let x_q = guard.x_q[i];
            let leak = -((alpha_q as i64 * x_q as i64) >> LIQUID_Q_SHIFT);
            let mut sum_in = 0i64;
            let w_in_offset = i * input_dim;
            for (j, u_q) in input_proj.iter().enumerate() {
                let w = self.weights.w_in[w_in_offset + j] as i64;
                sum_in += w * (*u_q as i64);
            }
            let mut sum_rec = 0i64;
            let w_rec_offset = i * state_dim;
            for (j, tanh_q) in tanh_vals.iter().enumerate() {
                let w = self.weights.w_rec[w_rec_offset + j] as i64;
                sum_rec += w * (*tanh_q as i64);
            }
            let input_term = sum_in / LIQUID_WEIGHT_SCALE;
            let rec_term = sum_rec / LIQUID_WEIGHT_SCALE;
            let mut drive = input_term + rec_term + self.weights.bias_q[i] as i64;
            drive = (drive * gain_q as i64) >> LIQUID_Q_SHIFT;
            let f_q = leak + drive;
            let delta = ((self.dt_q as i64) * f_q) >> LIQUID_Q_SHIFT;
            let updated = (x_q as i64 + delta)
                .clamp(-(LIQUID_STATE_CLAMP_Q as i64), LIQUID_STATE_CLAMP_Q as i64);
            *next_val = updated as i32;
        }
        guard.x_q = next;
        guard.step_count = guard.step_count.saturating_add(1);
    }
}

#[cfg(feature = "lnss-liquid-ode")]
impl LlmBackend for LiquidOdeBackend {
    fn infer_step(&mut self, input: &[u8], mods: &EmotionFieldSnapshot) -> Vec<u8> {
        let input_proj = encode_input_projection(input, &self.cfg);
        let gain_q = modulation_gain_q(mods, self.cfg.mods_gain_q);
        for _ in 0..self.cfg.steps_per_call {
            self.step_state(&input_proj, gain_q);
        }
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let sample = sample_state_bytes(&guard.x_q, LIQUID_OUTPUT_SAMPLE_DIMS);
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.cfg.seed.to_le_bytes());
        buf.extend_from_slice(&guard.step_count.to_le_bytes());
        buf.extend_from_slice(&sample);
        let digest_bytes = digest("lnss.liquid.output.v1", &buf);
        let mut output = Vec::new();
        output.extend_from_slice(&digest_bytes);
        output.extend_from_slice(&sample);
        output
    }

    fn supports_hooks(&self) -> bool {
        true
    }
}

#[cfg(feature = "lnss-liquid-ode")]
#[derive(Debug)]
pub struct LiquidTapProvider {
    state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
    cfg: LiquidOdeConfig,
}

#[cfg(feature = "lnss-liquid-ode")]
impl LiquidTapProvider {
    pub fn new(
        state: std::sync::Arc<std::sync::Mutex<LiquidOdeState>>,
        cfg: LiquidOdeConfig,
    ) -> Self {
        Self { state, cfg }
    }

    fn tap_frame(&self, hook_id: &str) -> TapFrame {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut state_bytes = Vec::with_capacity(guard.x_q.len() * 4);
        for x_q in &guard.x_q {
            state_bytes.extend_from_slice(&x_q.to_le_bytes());
        }
        let activation_digest = digest("lnss.liquid.tap.v1", &state_bytes);
        let sample_dims = (self.cfg.state_dim as usize).min(LIQUID_TAP_SAMPLE_DIMS);
        let activation_bytes = sample_state_bytes(&guard.x_q, sample_dims);
        TapFrame {
            hook_id: hook_id.to_string(),
            activation_digest,
            activation_bytes,
        }
    }
}

#[cfg(feature = "lnss-liquid-ode")]
impl HookProvider for LiquidTapProvider {
    fn collect_taps(&mut self, specs: &[TapSpec]) -> Vec<TapFrame> {
        let liquid_specs: Vec<&TapSpec> = specs
            .iter()
            .filter(|spec| spec.tap_kind == TapKind::LiquidState)
            .collect();
        let targets: Vec<String> = if liquid_specs.is_empty() {
            vec!["liquid-state".to_string()]
        } else {
            liquid_specs
                .iter()
                .map(|spec| spec.hook_id.clone())
                .collect()
        };
        targets
            .iter()
            .map(|hook_id| self.tap_frame(hook_id))
            .collect()
    }
}

#[cfg(feature = "lnss-liquid-ode")]
fn derive_weight(seed: u64, index: u64, tag: &str) -> i16 {
    let mut buf = Vec::new();
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    let digest_bytes = digest("lnss.liquid.weight.v1", &buf);
    let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
    let bounded = raw.rem_euclid(129) - 64;
    bounded as i16
}

#[cfg(feature = "lnss-liquid-ode")]
fn derive_bias(seed: u64, index: u64) -> i32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(&index.to_le_bytes());
    let digest_bytes = digest("lnss.liquid.bias.v1", &buf);
    let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
    let bounded = raw.rem_euclid(257) - 128;
    bounded * (LIQUID_Q_ONE / 128)
}

#[cfg(feature = "lnss-liquid-ode")]
fn encode_input_projection(input: &[u8], cfg: &LiquidOdeConfig) -> Vec<i32> {
    let mut base = Vec::new();
    base.extend_from_slice(&cfg.seed.to_le_bytes());
    base.extend_from_slice(input);
    let input_dim = cfg.input_proj_dim.max(1) as usize;
    let mut proj = Vec::with_capacity(input_dim);
    for idx in 0..input_dim {
        let mut buf = base.clone();
        buf.extend_from_slice(&(idx as u32).to_le_bytes());
        let digest_bytes = digest("lnss.liquid.input.v1", &buf);
        let raw = i16::from_le_bytes([digest_bytes[0], digest_bytes[1]]) as i32;
        let scaled = raw / 256;
        let u_q = scaled * (LIQUID_Q_ONE / 128);
        proj.push(u_q);
    }
    proj
}

#[cfg(feature = "lnss-liquid-ode")]
fn modulation_gain_q(mods: &EmotionFieldSnapshot, base_gain: u16) -> i32 {
    let mut gain = base_gain as i32;
    if mods.noise.eq_ignore_ascii_case("high") {
        gain = gain * 90 / 100;
    } else if mods.noise.eq_ignore_ascii_case("low") {
        gain = gain * 110 / 100;
    }
    if mods.priority.eq_ignore_ascii_case("high") {
        gain = gain * 110 / 100;
    } else if mods.priority.eq_ignore_ascii_case("low") {
        gain = gain * 90 / 100;
    }
    let gain = gain.clamp(10, 200);
    (gain * LIQUID_Q_ONE) / 100
}

#[cfg(feature = "lnss-liquid-ode")]
fn tanh_approx_q(x_q: i32) -> i32 {
    let abs = x_q.abs();
    if abs >= 3 * LIQUID_Q_ONE {
        return if x_q >= 0 {
            LIQUID_Q_ONE
        } else {
            -LIQUID_Q_ONE
        };
    }
    if abs <= LIQUID_Q_ONE {
        return x_q;
    }
    let base = LIQUID_Q_ONE * 4 / 5;
    let extra = (abs - LIQUID_Q_ONE) / 10;
    let value = base + extra;
    if x_q >= 0 {
        value
    } else {
        -value
    }
}

#[cfg(feature = "lnss-liquid-ode")]
fn sample_state_bytes(x_q: &[i32], dims: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &value in x_q.iter().take(dims) {
        let quantized = (value >> 8).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        bytes.extend_from_slice(&quantized.to_le_bytes());
    }
    bytes.truncate(MAX_TAP_SAMPLE_BYTES);
    bytes
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
        self.loaded = readme_path.exists();
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
