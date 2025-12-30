#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use lnss_core::{
    digest, BrainTarget, EmotionFieldSnapshot, FeatureEvent, FeatureToBrainMap, TapFrame, TapSpec,
    MAX_ACTIVATION_BYTES, MAX_MAPPING_ENTRIES, MAX_TOP_FEATURES,
};

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 4096;
pub const DEFAULT_MAX_SPIKES: usize = 2048;
pub const DEFAULT_MAX_TAPS: usize = 128;
pub const DEFAULT_MAX_MECHINT_BYTES: usize = 8192;

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
    pub feature_event_digests: Vec<[u8; 32]>,
    pub mapping_digest: [u8; 32],
    pub record_digest: [u8; 32],
}

impl MechIntRecord {
    pub fn new(
        session_id: &str,
        step_id: &str,
        token_digest: [u8; 32],
        mut tap_digests: Vec<[u8; 32]>,
        mut feature_event_digests: Vec<[u8; 32]>,
        mapping_digest: [u8; 32],
    ) -> Self {
        tap_digests.sort();
        feature_event_digests.sort();
        let record_digest = record_digest(
            session_id,
            step_id,
            token_digest,
            &tap_digests,
            &feature_event_digests,
            mapping_digest,
        );
        Self {
            session_id: session_id.to_string(),
            step_id: step_id.to_string(),
            token_digest,
            tap_digests,
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
    tap_digests: &[[u8; 32]],
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
    buf.extend_from_slice(&(tap_digests.len() as u32).to_le_bytes());
    for digest_bytes in tap_digests {
        buf.extend_from_slice(digest_bytes);
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

        let tap_digests = taps.iter().map(|tap| tap.activation_digest).collect();
        let feature_event_digests = feature_events
            .iter()
            .map(|event| event.event_digest)
            .collect();
        let mechint_record = MechIntRecord::new(
            session_id,
            step_id,
            token_digest,
            tap_digests,
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
