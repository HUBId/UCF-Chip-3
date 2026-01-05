#![forbid(unsafe_code)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_STRING_LEN: usize = 128;
pub const MAX_REASON_CODES: usize = 16;
pub const MAX_TOP_FEATURES: usize = 64;
pub const MAX_TAP_SPECS: usize = 128;
pub const MAX_ACTIVATION_BYTES: usize = 1024 * 1024;
pub const MAX_MAPPING_ENTRIES: usize = 4096;
pub const MAX_OVERLAYS: usize = 16;
pub const MAX_RLM_DIRECTIVES: usize = 3;

#[derive(Debug, Error)]
pub enum LnssCoreError {
    #[error("string length exceeded limit")]
    StringTooLong,
}

pub fn digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(bytes);
    let digest = hasher.finalize();
    *digest.as_bytes()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiophysFeedbackSnapshot {
    pub tick: u64,
    pub snapshot_digest: [u8; 32],
    pub event_queue_overflowed: bool,
    pub events_dropped: u64,
    pub events_injected: u32,
    pub injected_total: u64,
}

fn bound_string(value: &str) -> String {
    let mut out = value.to_string();
    out.truncate(MAX_STRING_LEN);
    out
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureEvent {
    pub event_id: String,
    pub event_digest: [u8; 32],
    pub session_id: String,
    pub step_id: String,
    pub hook_id: String,
    pub top_features: Vec<(u32, u16)>,
    pub timestamp_ms: u64,
    pub reason_codes: Vec<String>,
}

impl FeatureEvent {
    pub fn new(
        session_id: &str,
        step_id: &str,
        hook_id: &str,
        mut top_features: Vec<(u32, u16)>,
        timestamp_ms: u64,
        mut reason_codes: Vec<String>,
    ) -> Self {
        for (_, strength) in &mut top_features {
            *strength = (*strength).min(1000);
        }

        top_features.sort_by(|(id_a, strength_a), (id_b, strength_b)| {
            strength_b.cmp(strength_a).then_with(|| id_a.cmp(id_b))
        });
        top_features.truncate(MAX_TOP_FEATURES);

        reason_codes.iter_mut().for_each(|s| *s = bound_string(s));
        reason_codes.sort();
        reason_codes.dedup();
        reason_codes.truncate(MAX_REASON_CODES);

        let session_id = bound_string(session_id);
        let step_id = bound_string(step_id);
        let hook_id = bound_string(hook_id);

        let event_digest = feature_event_digest(
            &session_id,
            &step_id,
            &hook_id,
            &top_features,
            timestamp_ms,
            &reason_codes,
        );
        let event_id = hex::encode(event_digest);

        Self {
            event_id,
            event_digest,
            session_id,
            step_id,
            hook_id,
            top_features,
            timestamp_ms,
            reason_codes,
        }
    }
}

fn feature_event_digest(
    session_id: &str,
    step_id: &str,
    hook_id: &str,
    top_features: &[(u32, u16)],
    timestamp_ms: u64,
    reason_codes: &[String],
) -> [u8; 32] {
    let mut buf = Vec::new();
    write_string(&mut buf, session_id);
    write_string(&mut buf, step_id);
    write_string(&mut buf, hook_id);
    write_u64(&mut buf, timestamp_ms);
    write_u32(&mut buf, top_features.len() as u32);
    for (feature_id, strength_q) in top_features {
        write_u32(&mut buf, *feature_id);
        write_u16(&mut buf, *strength_q);
    }
    write_u32(&mut buf, reason_codes.len() as u32);
    for code in reason_codes {
        write_string(&mut buf, code);
    }
    digest("lnss.feature_event.v1", &buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TapKind {
    ResidualStream,
    MlpPost,
    AttnOut,
    Embedding,
    LiquidState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapSpec {
    pub hook_id: String,
    pub tap_kind: TapKind,
    pub layer_index: u16,
    pub tensor_name: String,
}

impl TapSpec {
    pub fn new(hook_id: &str, tap_kind: TapKind, layer_index: u16, tensor_name: &str) -> Self {
        Self {
            hook_id: bound_string(hook_id),
            tap_kind,
            layer_index,
            tensor_name: bound_string(tensor_name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapFrame {
    pub hook_id: String,
    pub activation_digest: [u8; 32],
    pub activation_bytes: Vec<u8>,
}

impl TapFrame {
    pub fn new(hook_id: &str, activation_bytes: Vec<u8>) -> Self {
        let mut bytes = activation_bytes;
        bytes.truncate(MAX_ACTIVATION_BYTES);
        let activation_digest = digest("lnss.tap_frame.v1", &bytes);
        Self {
            hook_id: bound_string(hook_id),
            activation_digest,
            activation_bytes: bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrainTarget {
    pub region: String,
    pub population: String,
    pub neuron_group: u32,
    pub syn_kind: String,
    pub amplitude_q: u16,
}

impl BrainTarget {
    pub fn new(
        region: &str,
        population: &str,
        neuron_group: u32,
        syn_kind: &str,
        amplitude_q: u16,
    ) -> Self {
        Self {
            region: bound_string(region),
            population: bound_string(population),
            neuron_group,
            syn_kind: bound_string(syn_kind),
            amplitude_q: amplitude_q.min(1000),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureToBrainMap {
    pub map_version: u32,
    pub map_digest: [u8; 32],
    pub entries: Vec<(u32, BrainTarget)>,
}

impl FeatureToBrainMap {
    pub fn new(map_version: u32, mut entries: Vec<(u32, BrainTarget)>) -> Self {
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries.truncate(MAX_MAPPING_ENTRIES);
        let map_digest = mapping_digest(map_version, &entries);
        Self {
            map_version,
            map_digest,
            entries,
        }
    }
}

fn mapping_digest(map_version: u32, entries: &[(u32, BrainTarget)]) -> [u8; 32] {
    let mut buf = Vec::new();
    write_u32(&mut buf, map_version);
    write_u32(&mut buf, entries.len() as u32);
    for (feature_id, target) in entries {
        write_u32(&mut buf, *feature_id);
        write_string(&mut buf, &target.region);
        write_string(&mut buf, &target.population);
        write_u32(&mut buf, target.neuron_group);
        write_string(&mut buf, &target.syn_kind);
        write_u16(&mut buf, target.amplitude_q);
    }
    digest("lnss.feature_map.v1", &buf)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmotionFieldSnapshot {
    pub noise: String,
    pub priority: String,
    pub recursion_depth: String,
    pub dwm: String,
    pub profile: String,
    pub overlays: Vec<String>,
    pub top_reason_codes: Vec<String>,
}

pub type CoreTapFrame = TapFrame;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreStepOutput {
    pub output_bytes: Vec<u8>,
    pub taps: Vec<CoreTapFrame>,
}

pub trait CognitiveCore {
    fn step(&mut self, input: &[u8], context: &ContextBundle) -> CoreStepOutput;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBundle {
    pub control_frame_digest: [u8; 32],
    pub policy_digest: Option<[u8; 32]>,
    pub constraints_digest: Option<[u8; 32]>,
    pub world_state_digest: [u8; 32],
    pub last_self_state_digest: [u8; 32],
    pub emotion_snapshot_digest: Option<[u8; 32]>,
}

impl ContextBundle {
    pub fn new(
        control_frame_digest: [u8; 32],
        policy_digest: Option<[u8; 32]>,
        constraints_digest: Option<[u8; 32]>,
        world_state_digest: [u8; 32],
        last_self_state_digest: [u8; 32],
        emotion_snapshot_digest: Option<[u8; 32]>,
    ) -> Self {
        Self {
            control_frame_digest,
            policy_digest,
            constraints_digest,
            world_state_digest,
            last_self_state_digest,
            emotion_snapshot_digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlIntentClass {
    Monitor,
    Explore,
    Execute,
    Reflect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyMode {
    Open,
    Guarded,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FeedbackAnomalyFlags {
    pub event_queue_overflowed: bool,
    pub events_dropped: bool,
}

impl FeedbackAnomalyFlags {
    pub fn any(&self) -> bool {
        self.event_queue_overflowed || self.events_dropped
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModelInput {
    pub input_digest: [u8; 32],
    pub prev_world_digest: [u8; 32],
    pub action_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModelOutput {
    pub world_state_digest: [u8; 32],
    pub prediction_error_score: i32,
    pub world_taps: Option<Vec<CoreTapFrame>>,
}

pub trait WorldModelCore {
    fn step(&mut self, input: &WorldModelInput) -> WorldModelOutput;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecursionDirectiveKind {
    Followup,
    Reflect,
    Hold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursionDirective {
    pub kind: RecursionDirectiveKind,
    pub description: String,
}

impl RecursionDirective {
    pub fn new(kind: RecursionDirectiveKind, description: &str) -> Self {
        Self {
            kind,
            description: bound_string(description),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlmInput {
    pub control_frame_digest: [u8; 32],
    pub policy_mode: PolicyMode,
    pub control_intent: ControlIntentClass,
    pub feedback_flags: FeedbackAnomalyFlags,
    pub current_depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RlmOutput {
    pub recursion_directives: Vec<RecursionDirective>,
    pub self_state_digest: [u8; 32],
}

pub trait RlmCore {
    fn step(&mut self, input: &RlmInput) -> RlmOutput;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursionPolicy {
    pub allow_followup: bool,
    pub max_depth: u8,
}

impl Default for RecursionPolicy {
    fn default() -> Self {
        Self {
            allow_followup: true,
            max_depth: 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OrchestratorOutput {
    pub world_output: WorldModelOutput,
    pub language_output: CoreStepOutput,
    pub rlm_output: RlmOutput,
    pub followup_output: Option<CoreStepOutput>,
    pub recursion_used: bool,
    pub recursion_blocked: bool,
}

#[derive(Debug, Default)]
pub struct CoreOrchestrator;

impl CoreOrchestrator {
    pub fn run_tick<W, L, R>(
        &mut self,
        worldmodel: &mut W,
        language: &mut L,
        rlm: &mut R,
        input: &[u8],
        mut context: ContextBundle,
        world_input: &WorldModelInput,
        rlm_input: &RlmInput,
        policy: RecursionPolicy,
    ) -> OrchestratorOutput
    where
        W: WorldModelCore + ?Sized,
        L: CognitiveCore + ?Sized,
        R: RlmCore + ?Sized,
    {
        let world_output = worldmodel.step(world_input);
        context.world_state_digest = world_output.world_state_digest;
        let language_output = language.step(input, &context);
        let rlm_output = rlm.step(rlm_input);

        let wants_followup = rlm_output
            .recursion_directives
            .iter()
            .any(|directive| directive.kind == RecursionDirectiveKind::Followup);
        let depth_ok = rlm_input.current_depth < policy.max_depth;
        let allow_followup = policy.allow_followup && depth_ok;
        let followup_output = if wants_followup && allow_followup {
            context.last_self_state_digest = rlm_output.self_state_digest;
            Some(language.step(input, &context))
        } else {
            None
        };
        OrchestratorOutput {
            world_output,
            language_output,
            rlm_output,
            followup_output,
            recursion_used: wants_followup && allow_followup,
            recursion_blocked: wants_followup && !allow_followup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct TestWorldModel {
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl WorldModelCore for TestWorldModel {
        fn step(&mut self, _input: &WorldModelInput) -> WorldModelOutput {
            self.log.lock().expect("log lock").push("world");
            WorldModelOutput {
                world_state_digest: [1; 32],
                prediction_error_score: 0,
                world_taps: None,
            }
        }
    }

    struct TestLanguage {
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl CognitiveCore for TestLanguage {
        fn step(&mut self, _input: &[u8], _context: &ContextBundle) -> CoreStepOutput {
            self.log.lock().expect("log lock").push("language");
            CoreStepOutput {
                output_bytes: vec![1],
                taps: Vec::new(),
            }
        }
    }

    struct TestRlm {
        log: Arc<Mutex<Vec<&'static str>>>,
        directives: Vec<RecursionDirective>,
    }

    impl RlmCore for TestRlm {
        fn step(&mut self, _input: &RlmInput) -> RlmOutput {
            self.log.lock().expect("log lock").push("rlm");
            RlmOutput {
                recursion_directives: self.directives.clone(),
                self_state_digest: [2; 32],
            }
        }
    }

    #[test]
    fn orchestrator_order_is_fixed() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut world = TestWorldModel { log: log.clone() };
        let mut language = TestLanguage { log: log.clone() };
        let mut rlm = TestRlm {
            log: log.clone(),
            directives: vec![RecursionDirective::new(
                RecursionDirectiveKind::Hold,
                "hold",
            )],
        };
        let mut orchestrator = CoreOrchestrator::default();
        let context = ContextBundle::new([0; 32], None, None, [0; 32], [0; 32], None);
        let world_input = WorldModelInput {
            input_digest: [0; 32],
            prev_world_digest: [0; 32],
            action_digest: [0; 32],
        };
        let rlm_input = RlmInput {
            control_frame_digest: [0; 32],
            policy_mode: PolicyMode::Open,
            control_intent: ControlIntentClass::Monitor,
            feedback_flags: FeedbackAnomalyFlags::default(),
            current_depth: 0,
        };
        orchestrator.run_tick(
            &mut world,
            &mut language,
            &mut rlm,
            b"input",
            context,
            &world_input,
            &rlm_input,
            RecursionPolicy::default(),
        );

        let steps = log.lock().expect("log lock").clone();
        assert_eq!(steps, vec!["world", "language", "rlm"]);
    }

    #[test]
    fn recursion_is_blocked_when_depth_exceeds_policy() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut world = TestWorldModel { log: log.clone() };
        let mut language = TestLanguage { log: log.clone() };
        let mut rlm = TestRlm {
            log: log.clone(),
            directives: vec![RecursionDirective::new(
                RecursionDirectiveKind::Followup,
                "FOLLOWUP",
            )],
        };
        let mut orchestrator = CoreOrchestrator::default();
        let context = ContextBundle::new([0; 32], None, None, [0; 32], [0; 32], None);
        let world_input = WorldModelInput {
            input_digest: [0; 32],
            prev_world_digest: [0; 32],
            action_digest: [0; 32],
        };
        let rlm_input = RlmInput {
            control_frame_digest: [0; 32],
            policy_mode: PolicyMode::Open,
            control_intent: ControlIntentClass::Explore,
            feedback_flags: FeedbackAnomalyFlags::default(),
            current_depth: 2,
        };
        let output = orchestrator.run_tick(
            &mut world,
            &mut language,
            &mut rlm,
            b"input",
            context,
            &world_input,
            &rlm_input,
            RecursionPolicy {
                allow_followup: true,
                max_depth: 2,
            },
        );

        assert!(output.followup_output.is_none());
        assert!(output.recursion_blocked);
    }
}

impl EmotionFieldSnapshot {
    pub fn new(
        noise: &str,
        priority: &str,
        recursion_depth: &str,
        dwm: &str,
        profile: &str,
        overlays: Vec<String>,
        top_reason_codes: Vec<String>,
    ) -> Self {
        let mut overlays = overlays;
        overlays.iter_mut().for_each(|s| *s = bound_string(s));
        overlays.truncate(MAX_OVERLAYS);

        let mut reasons = top_reason_codes;
        reasons.iter_mut().for_each(|s| *s = bound_string(s));
        reasons.sort();
        reasons.dedup();
        reasons.truncate(MAX_REASON_CODES);

        Self {
            noise: bound_string(noise),
            priority: bound_string(priority),
            recursion_depth: bound_string(recursion_depth),
            dwm: bound_string(dwm),
            profile: bound_string(profile),
            overlays,
            top_reason_codes: reasons,
        }
    }
}
