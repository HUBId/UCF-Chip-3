#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub mod emotion;

use lnss_frames_bridge::LnssGovEvent;
use pbm::DecisionForm;
use serde::{de::DeserializeOwned, Deserialize};
use thiserror::Error;
use ucf_protocol::{canonical_bytes, digest32, ucf};

const SIGNAL_DIGEST_DOMAIN: &str = "UCF:HASH:SIGNAL_FRAME";
const DEFAULT_EPOCH_ID: &str = "epoch-0";
const DEFAULT_TOP_REASON_CODES: usize = 10;

#[derive(Debug, Error)]
pub enum FramesError {
    #[error("failed to read config at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse config at {path:?}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("missing window config for {0}")]
    MissingWindow(WindowKind),
    #[error("unknown window kind {0}")]
    UnknownWindowKind(String),
}

pub trait Clock: Clone {
    type Instant: Copy;

    fn now(&self) -> Self::Instant;
    fn elapsed_ms(&self, from: Self::Instant) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::now()
    }

    fn elapsed_ms(&self, from: Self::Instant) -> u64 {
        from.elapsed().as_millis() as u64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowKind {
    Short,
    Medium,
    Long,
}

impl WindowKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            WindowKind::Short => "short",
            WindowKind::Medium => "medium",
            WindowKind::Long => "long",
        }
    }
}

impl std::fmt::Display for WindowKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for WindowKind {
    type Err = FramesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "short" => Ok(WindowKind::Short),
            "medium" => Ok(WindowKind::Medium),
            "long" => Ok(WindowKind::Long),
            other => Err(FramesError::UnknownWindowKind(other.to_string())),
        }
    }
}

impl<'de> Deserialize<'de> for WindowKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn default_top_reason_limit() -> usize {
    DEFAULT_TOP_REASON_CODES
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowSpec {
    pub max_events: u64,
    pub max_records: u64,
    pub max_age_ms: u64,
    #[serde(default)]
    pub top_reason_limit: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowingConfig {
    pub epoch_id: String,
    #[serde(default = "default_top_reason_limit")]
    pub top_reason_limit: usize,
    pub windows: BTreeMap<WindowKind, WindowSpec>,
}

impl WindowingConfig {
    pub fn fallback() -> Self {
        let mut windows = BTreeMap::new();
        windows.insert(
            WindowKind::Short,
            WindowSpec {
                max_events: 32,
                max_records: 32,
                max_age_ms: 0,
                top_reason_limit: None,
            },
        );
        windows.insert(
            WindowKind::Medium,
            WindowSpec {
                max_events: 128,
                max_records: 128,
                max_age_ms: 0,
                top_reason_limit: None,
            },
        );
        Self {
            epoch_id: DEFAULT_EPOCH_ID.to_string(),
            top_reason_limit: DEFAULT_TOP_REASON_CODES,
            windows,
        }
    }

    pub fn spec(&self, kind: &WindowKind) -> Option<&WindowSpec> {
        self.windows.get(kind)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdBands {
    pub thresholds: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassThresholdsConfig {
    pub short: ThresholdBands,
    #[serde(default)]
    pub medium: Option<ThresholdBands>,
    #[serde(default)]
    pub long: Option<ThresholdBands>,
}

impl ClassThresholdsConfig {
    pub fn fallback() -> Self {
        let band = ThresholdBands {
            thresholds: vec![1, 4],
        };

        Self {
            short: band.clone(),
            medium: Some(band),
            long: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FramesConfig {
    pub windowing: WindowingConfig,
    pub class_thresholds: ClassThresholdsConfig,
}

impl FramesConfig {
    pub fn load_from_dir<P: AsRef<Path>>(root: P) -> Result<Self, FramesError> {
        let root = root.as_ref().join("config");
        let windowing =
            load_or_fallback(&root.join("windowing.yaml"), WindowingConfig::fallback())?;
        let class_thresholds = load_or_fallback(
            &root.join("class_thresholds.yaml"),
            ClassThresholdsConfig::fallback(),
        )?;

        Ok(Self {
            windowing,
            class_thresholds,
        })
    }

    pub fn fallback() -> Self {
        Self {
            windowing: WindowingConfig::fallback(),
            class_thresholds: ClassThresholdsConfig::fallback(),
        }
    }
}

fn load_or_fallback<T: DeserializeOwned + Clone>(
    path: &Path,
    fallback: T,
) -> Result<T, FramesError> {
    match File::open(path) {
        Ok(file) => serde_yaml::from_reader(file).map_err(|source| FramesError::Parse {
            path: path.to_path_buf(),
            source,
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(fallback),
        Err(source) => Err(FramesError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[derive(Debug, Clone, Default)]
struct ReasonCounter {
    counts: HashMap<String, u64>,
}

impl ReasonCounter {
    fn record<I: IntoIterator<Item = String>>(&mut self, codes: I) {
        for code in codes {
            *self.counts.entry(code).or_insert(0) += 1;
        }
    }

    fn top(&self, limit: usize) -> Vec<ucf::v1::ReasonCodeCount> {
        let mut pairs: Vec<_> = self.counts.iter().collect();
        pairs.sort_by(|(a_code, a_count), (b_code, b_count)| {
            b_count
                .cmp(a_count)
                .then_with(|| a_code.as_str().cmp(b_code.as_str()))
        });

        pairs
            .into_iter()
            .take(limit)
            .map(|(code, count)| ucf::v1::ReasonCodeCount {
                code: code.clone(),
                count: *count,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
struct PolicyCounts {
    allow: u64,
    deny: u64,
    require_approval: u64,
    require_simulation: u64,
}

#[derive(Debug, Clone, Default)]
struct ExecCounts {
    success: u64,
    failure: u64,
    timeout: u64,
    partial: u64,
    tool_unavailable: u64,
}

#[derive(Debug, Clone, Default)]
struct DlpCounts {
    allow: u64,
    block: u64,
    redact: u64,
    classify_upgrade: u64,
}

#[derive(Debug, Clone, Default)]
struct ReceiptCounts {
    missing: u64,
    invalid: u64,
}

#[derive(Debug, Clone, Default)]
struct HumanCounts {
    approval_denied_count: u64,
    stop: bool,
}

#[derive(Debug, Clone, Default)]
struct IntegrityCounts {
    issues: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum ReceiptIssue {
    Missing,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
pub enum DlpDecision {
    Allow,
    Block,
    Redact,
    ClassifyUpgrade,
}

#[derive(Debug, Clone, Copy)]
pub enum TraceHealthStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
struct WindowState<C: Clock> {
    window_index: u64,
    event_count: u64,
    record_count: u64,
    policy_counts: PolicyCounts,
    exec_counts: ExecCounts,
    dlp_counts: DlpCounts,
    receipt_counts: ReceiptCounts,
    human_counts: HumanCounts,
    policy_reasons: ReasonCounter,
    exec_reasons: ReasonCounter,
    dlp_reasons: ReasonCounter,
    receipt_reasons: ReasonCounter,
    integrity_counts: IntegrityCounts,
    integrity_reasons: ReasonCounter,
    integrity_state: ucf::v1::IntegrityState,
    opened_at: C::Instant,
}

impl<C: Clock> WindowState<C> {
    fn new(clock: &C) -> Self {
        Self {
            window_index: 0,
            event_count: 0,
            record_count: 0,
            policy_counts: PolicyCounts::default(),
            exec_counts: ExecCounts::default(),
            dlp_counts: DlpCounts::default(),
            receipt_counts: ReceiptCounts::default(),
            human_counts: HumanCounts::default(),
            policy_reasons: ReasonCounter::default(),
            exec_reasons: ReasonCounter::default(),
            dlp_reasons: ReasonCounter::default(),
            receipt_reasons: ReasonCounter::default(),
            integrity_counts: IntegrityCounts::default(),
            integrity_reasons: ReasonCounter::default(),
            integrity_state: ucf::v1::IntegrityState::Ok,
            opened_at: clock.now(),
        }
    }

    fn record_event(&mut self) {
        self.event_count += 1;
        self.record_count += 1;
    }

    fn should_close(&self, spec: &WindowSpec, clock: &C) -> bool {
        self.event_count >= spec.max_events
            || self.record_count >= spec.max_records
            || (spec.max_age_ms > 0 && clock.elapsed_ms(self.opened_at) >= spec.max_age_ms)
    }

    fn reset(&mut self, index: u64, clock: &C) {
        self.window_index = index;
        self.event_count = 0;
        self.record_count = 0;
        self.policy_counts = PolicyCounts::default();
        self.exec_counts = ExecCounts::default();
        self.dlp_counts = DlpCounts::default();
        self.receipt_counts = ReceiptCounts::default();
        self.human_counts = HumanCounts::default();
        self.policy_reasons = ReasonCounter::default();
        self.exec_reasons = ReasonCounter::default();
        self.dlp_reasons = ReasonCounter::default();
        self.receipt_reasons = ReasonCounter::default();
        self.integrity_counts = IntegrityCounts::default();
        self.integrity_reasons = ReasonCounter::default();
        self.integrity_state = ucf::v1::IntegrityState::Ok;
        self.opened_at = clock.now();
    }
}

pub struct WindowEngine<C: Clock = SystemClock> {
    config: FramesConfig,
    specs: BTreeMap<WindowKind, WindowSpec>,
    windows: BTreeMap<WindowKind, WindowState<C>>,
    completed_frames: Vec<ucf::v1::SignalFrame>,
    clock: C,
}

impl WindowEngine<SystemClock> {
    pub fn new(config: FramesConfig) -> Result<Self, FramesError> {
        WindowEngine::with_clock(config, SystemClock)
    }

    pub fn from_default_configs() -> Result<Self, FramesError> {
        WindowEngine::new(FramesConfig::load_from_dir(".")?)
    }
}

impl<C: Clock> WindowEngine<C> {
    pub fn with_clock(config: FramesConfig, clock: C) -> Result<Self, FramesError> {
        let specs = config.windowing.windows.clone();
        for required in [WindowKind::Short, WindowKind::Medium] {
            if !specs.contains_key(&required) {
                return Err(FramesError::MissingWindow(required));
            }
        }

        let mut windows = BTreeMap::new();
        for kind in specs.keys() {
            windows.insert(*kind, WindowState::new(&clock));
        }

        Ok(Self {
            config,
            specs,
            windows,
            completed_frames: Vec::new(),
            clock,
        })
    }

    pub fn class_thresholds(&self) -> &ClassThresholdsConfig {
        &self.config.class_thresholds
    }

    pub fn on_policy_decision(&mut self, form: DecisionForm, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            match form {
                DecisionForm::Allow | DecisionForm::AllowWithConstraints => {
                    state.policy_counts.allow += 1;
                }
                DecisionForm::Deny => state.policy_counts.deny += 1,
                DecisionForm::RequireApproval => state.policy_counts.require_approval += 1,
                DecisionForm::RequireSimulationFirst => {
                    state.policy_counts.require_simulation += 1;
                }
            }
            state.policy_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_execution_outcome(
        &mut self,
        status: ucf::v1::OutcomeStatus,
        reason_codes: &[String],
    ) {
        self.apply_to_windows(|state| {
            match status {
                ucf::v1::OutcomeStatus::Success => state.exec_counts.success += 1,
                ucf::v1::OutcomeStatus::Failure => state.exec_counts.failure += 1,
                ucf::v1::OutcomeStatus::Timeout => state.exec_counts.timeout += 1,
                ucf::v1::OutcomeStatus::Partial => state.exec_counts.partial += 1,
                ucf::v1::OutcomeStatus::ToolUnavailable => state.exec_counts.tool_unavailable += 1,
                ucf::v1::OutcomeStatus::Unspecified => {}
            }

            state.exec_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_dlp_decision(&mut self, decision: DlpDecision, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            match decision {
                DlpDecision::Allow => state.dlp_counts.allow += 1,
                DlpDecision::Block => state.dlp_counts.block += 1,
                DlpDecision::Redact => state.dlp_counts.redact += 1,
                DlpDecision::ClassifyUpgrade => state.dlp_counts.classify_upgrade += 1,
            }
            state.dlp_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_receipt_issue(&mut self, issue: ReceiptIssue, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            match issue {
                ReceiptIssue::Missing => state.receipt_counts.missing += 1,
                ReceiptIssue::Invalid => state.receipt_counts.invalid += 1,
            }
            state.receipt_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_integrity_issue(&mut self, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            state.integrity_counts.issues += 1;
            state.integrity_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_integrity_signal(&mut self, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            state.integrity_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn ingest_lnss_event(&mut self, ev: LnssGovEvent) {
        let reason_code = ev.reason_code().map(str::to_string);
        self.apply_to_windows(|state| {
            if let Some(code) = reason_code.clone() {
                state.integrity_reasons.record([code]);
                state.integrity_counts.issues += 1;
            }
            state.record_event();
        });
    }

    pub fn on_suspension(&mut self, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            state.exec_counts.tool_unavailable += 1;
            state.exec_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn on_human_denied(&mut self, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            state.human_counts.approval_denied_count += 1;
            state.policy_reasons.record(reason_codes.iter().cloned());
            state.record_event();
        });
    }

    pub fn set_stop(&mut self) {
        self.apply_to_windows(|state| {
            state.human_counts.stop = true;
            state.record_event();
        });
    }

    pub fn on_budget_event(&mut self) {
        self.apply_to_windows(|state| {
            state.record_event();
        });
    }

    pub fn on_integrity_state(&mut self, state: ucf::v1::IntegrityState) {
        for window in self.windows.values_mut() {
            window.integrity_state = state;
        }
    }

    pub fn on_trace_health(&mut self, status: TraceHealthStatus, reason_codes: &[String]) {
        self.apply_to_windows(|state| {
            state.exec_reasons.record(reason_codes.iter().cloned());
            state.record_event();
            if matches!(status, TraceHealthStatus::Fail) {
                state.integrity_state = ucf::v1::IntegrityState::Degraded;
                state.integrity_counts.issues += 1;
                state.integrity_reasons.record(reason_codes.iter().cloned());
            }
        });
    }

    pub fn force_flush(&mut self) -> Vec<ucf::v1::SignalFrame> {
        self.flush_active_windows();
        self.drain_completed()
    }

    pub fn drain_completed(&mut self) -> Vec<ucf::v1::SignalFrame> {
        self.completed_frames.drain(..).collect()
    }

    fn flush_active_windows(&mut self) {
        let kinds: Vec<_> = self
            .windows
            .iter()
            .filter(|(_, state)| state.event_count > 0)
            .map(|(kind, _)| *kind)
            .collect();

        for kind in kinds {
            self.finish_window(kind);
        }
    }

    fn apply_to_windows<F>(&mut self, mut update: F)
    where
        F: FnMut(&mut WindowState<C>),
    {
        let mut to_close = Vec::new();

        for (kind, state) in self.windows.iter_mut() {
            update(state);
            if let Some(spec) = self.specs.get(kind) {
                if state.should_close(spec, &self.clock) {
                    to_close.push(*kind);
                }
            }
        }

        for kind in to_close {
            self.finish_window(kind);
        }
    }

    fn finish_window(&mut self, kind: WindowKind) {
        let Some(spec) = self.specs.get(&kind).cloned() else {
            return;
        };

        let (mut frame, next_index) = {
            let Some(state) = self.windows.get_mut(&kind) else {
                return;
            };

            if state.event_count == 0 {
                return;
            }

            let top_limit = spec
                .top_reason_limit
                .unwrap_or(self.config.windowing.top_reason_limit);
            let frame_id = format!(
                "{}:{}:{}",
                kind.as_str(),
                self.config.windowing.epoch_id,
                state.window_index
            );
            let window_meta = ucf::v1::WindowMetadata {
                window_type: kind.as_str().to_string(),
                max_events: spec.max_events,
                event_count: state.event_count,
                window_id: frame_id.clone(),
            };

            let policy_stats = ucf::v1::PolicyStats {
                allow_count: state.policy_counts.allow,
                deny_count: state.policy_counts.deny,
                require_approval_count: state.policy_counts.require_approval,
                require_simulation_count: state.policy_counts.require_simulation,
                top_reason_codes: state.policy_reasons.top(top_limit),
            };

            let exec_stats = ucf::v1::ExecStats {
                success_count: state.exec_counts.success,
                failure_count: state.exec_counts.failure,
                timeout_count: state.exec_counts.timeout,
                partial_count: state.exec_counts.partial,
                tool_unavailable_count: state.exec_counts.tool_unavailable,
                top_reason_codes: state.exec_reasons.top(top_limit),
            };

            let dlp_stats = ucf::v1::DlpStats {
                top_reason_codes: state.dlp_reasons.top(top_limit),
                allow_count: state.dlp_counts.allow,
                block_count: state.dlp_counts.block,
                redact_count: state.dlp_counts.redact,
                classify_upgrade_count: state.dlp_counts.classify_upgrade,
            };

            let receipt_stats = ucf::v1::ReceiptStats {
                receipt_missing_count: state.receipt_counts.missing,
                receipt_invalid_count: state.receipt_counts.invalid,
                top_reason_codes: state.receipt_reasons.top(top_limit),
            };

            let integrity_stats = ucf::v1::IntegrityStats {
                integrity_issue_count: state.integrity_counts.issues,
                top_reason_codes: state.integrity_reasons.top(top_limit),
            };

            let human_stats = ucf::v1::HumanStats {
                approval_denied_count: state.human_counts.approval_denied_count,
                stop: state.human_counts.stop,
            };

            (
                ucf::v1::SignalFrame {
                    frame_id: frame_id.clone(),
                    window: Some(window_meta),
                    integrity_state: state.integrity_state.into(),
                    policy_stats: Some(policy_stats),
                    exec_stats: Some(exec_stats),
                    dlp_stats: Some(dlp_stats),
                    budget_stats: Some(ucf::v1::BudgetStats {
                        budget_exhausted_count: 0,
                        top_reason_codes: Vec::new(),
                    }),
                    human_stats: Some(human_stats),
                    signal_frame_digest: None,
                    signature: None,
                    receipt_stats: Some(receipt_stats),
                    integrity_stats: Some(integrity_stats),
                },
                state.window_index + 1,
            )
        };

        let digest = compute_signal_digest(&frame);
        frame.signal_frame_digest = Some(ucf::v1::Digest32 {
            value: digest.to_vec(),
        });

        self.completed_frames.push(frame);
        if let Some(state) = self.windows.get_mut(&kind) {
            state.reset(next_index, &self.clock);
        }
    }
}

fn compute_signal_digest(frame: &ucf::v1::SignalFrame) -> [u8; 32] {
    let canonical = canonical_bytes(frame);
    digest32(SIGNAL_DIGEST_DOMAIN, "SignalFrame", "v1", &canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lnss_frames_bridge::LnssGovEvent;
    use std::fs;
    use tempfile::tempdir;

    fn write_windowing_config(dir: &Path, content: &str) {
        let config_dir = dir.join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(config_dir.join("windowing.yaml"), content).expect("write windowing config");
    }

    fn write_class_thresholds_config(dir: &Path, content: &str) {
        let config_dir = dir.join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(config_dir.join("class_thresholds.yaml"), content)
            .expect("write class thresholds config");
    }

    fn engine_with_config(config: FramesConfig) -> WindowEngine {
        WindowEngine::new(config).expect("window engine")
    }

    #[test]
    fn loads_valid_configs() {
        let temp = tempdir().expect("tempdir");
        write_windowing_config(
            temp.path(),
            r#"epoch_id: "epoch-demo"
top_reason_limit: 5
windows:
  short:
    max_events: 4
    max_records: 4
    max_age_ms: 0
    top_reason_limit: 3
  medium:
    max_events: 8
    max_records: 8
    max_age_ms: 0
"#,
        );

        write_class_thresholds_config(
            temp.path(),
            r#"short:
  thresholds: [2, 5]
medium:
  thresholds: [1, 3]
"#,
        );

        let config = FramesConfig::load_from_dir(temp.path()).expect("load config");
        assert_eq!(config.windowing.epoch_id, "epoch-demo");
        assert_eq!(config.windowing.top_reason_limit, 5);
        assert_eq!(
            config
                .windowing
                .spec(&WindowKind::Short)
                .unwrap()
                .max_events,
            4
        );
        assert_eq!(
            config.class_thresholds.medium.as_ref().unwrap().thresholds,
            vec![1, 3]
        );
    }

    #[test]
    fn missing_field_fails() {
        let temp = tempdir().expect("tempdir");
        write_windowing_config(
            temp.path(),
            r#"epoch_id: "epoch-demo"
windows:
  short:
    max_events: 4
    max_age_ms: 0
"#,
        );

        let err =
            FramesConfig::load_from_dir(temp.path()).expect_err("missing max_records should fail");
        match err {
            FramesError::Parse { .. } => {}
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn window_closes_on_max_records() {
        let temp = tempdir().expect("tempdir");
        write_windowing_config(
            temp.path(),
            r#"epoch_id: "epoch-demo"
windows:
  short:
    max_events: 50
    max_records: 3
    max_age_ms: 0
  medium:
    max_events: 100
    max_records: 100
    max_age_ms: 0
"#,
        );

        write_class_thresholds_config(temp.path(), "short:\n  thresholds: [1, 4]\n");

        let mut engine = engine_with_config(FramesConfig::load_from_dir(temp.path()).unwrap());
        for _ in 0..3 {
            engine.on_policy_decision(DecisionForm::Allow, &["rc".to_string()]);
        }

        let frames = engine.drain_completed();
        assert_eq!(frames.len(), 1, "expected single short window frame");
        let window = frames[0].window.as_ref().unwrap();
        assert_eq!(window.window_type, WindowKind::Short.as_str());
        assert_eq!(window.event_count, 3);
    }

    #[test]
    fn deterministic_reason_code_ordering() {
        let mut engine = engine_with_config(FramesConfig::fallback());
        let reasons = vec![
            vec!["B".to_string()],
            vec!["A".to_string()],
            vec!["B".to_string()],
            vec!["A".to_string()],
        ];

        for codes in reasons {
            engine.on_policy_decision(DecisionForm::Allow, &codes);
        }

        let frames = engine.force_flush();
        let policy = frames[0].policy_stats.as_ref().unwrap();
        let codes: Vec<_> = policy
            .top_reason_codes
            .iter()
            .map(|c| (c.code.clone(), c.count))
            .collect();
        assert_eq!(codes, vec![("A".to_string(), 2), ("B".to_string(), 2),]);
    }

    #[test]
    fn receipt_stats_are_recorded() {
        let mut engine = engine_with_config(FramesConfig::fallback());
        engine.on_receipt_issue(ReceiptIssue::Missing, &["miss".to_string()]);
        engine.on_receipt_issue(ReceiptIssue::Missing, &["miss".to_string()]);
        engine.on_receipt_issue(ReceiptIssue::Invalid, &["bad".to_string()]);

        let frames = engine.force_flush();
        let receipt = frames[0].receipt_stats.as_ref().unwrap();
        assert_eq!(receipt.receipt_missing_count, 2);
        assert_eq!(receipt.receipt_invalid_count, 1);
    }

    #[test]
    fn suspension_events_are_reflected_in_exec_stats() {
        let mut engine = engine_with_config(FramesConfig::fallback());
        let reason = "RC.GV.TOOL.SUSPENDED".to_string();

        engine.on_suspension(std::slice::from_ref(&reason));

        let frames = engine.force_flush();
        for frame in frames {
            let exec_stats = frame.exec_stats.as_ref().expect("exec stats present");
            assert_eq!(exec_stats.tool_unavailable_count, 1);
            assert!(exec_stats
                .top_reason_codes
                .iter()
                .any(|code| code.code == reason));
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let config = FramesConfig::fallback();
        let mut engine_a = engine_with_config(config.clone());
        let mut engine_b = engine_with_config(config);

        for _ in 0..5 {
            engine_a.on_policy_decision(DecisionForm::Allow, &["rc".to_string()]);
            engine_b.on_policy_decision(DecisionForm::Allow, &["rc".to_string()]);
        }

        let digest_a = engine_a.force_flush()[0]
            .signal_frame_digest
            .as_ref()
            .unwrap()
            .value
            .clone();
        let digest_b = engine_b.force_flush()[0]
            .signal_frame_digest
            .as_ref()
            .unwrap()
            .value
            .clone();
        assert_eq!(digest_a, digest_b);
    }

    #[test]
    fn fallback_config_used_when_files_missing() {
        let temp = tempdir().expect("tempdir");
        let mut engine = engine_with_config(FramesConfig::load_from_dir(temp.path()).unwrap());
        for _ in 0..32 {
            engine.on_policy_decision(DecisionForm::Allow, &["rc".to_string()]);
        }

        let frames = engine.drain_completed();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].window.as_ref().unwrap().window_type, "short");
        assert_eq!(frames[0].window.as_ref().unwrap().event_count, 32);
    }

    #[test]
    fn ingest_lnss_event_activation_applied_records_reason() {
        let mut engine = engine_with_config(FramesConfig::fallback());
        engine.ingest_lnss_event(LnssGovEvent::ActivationApplied {
            activation_digest: [9u8; 32],
        });

        let frames = engine.force_flush();
        assert!(!frames.is_empty());
        assert!(frames.iter().any(|frame| {
            frame
                .integrity_stats
                .as_ref()
                .expect("integrity stats")
                .top_reason_codes
                .iter()
                .any(|code| code.code == "RC.GV.PROPOSAL.ACTIVATED")
        }));
    }

    #[test]
    fn ingest_lnss_event_is_bounded() {
        let mut config = FramesConfig::fallback();
        config.windowing.top_reason_limit = 1;
        let mut engine = engine_with_config(config);
        engine.ingest_lnss_event(LnssGovEvent::ActivationApplied {
            activation_digest: [1u8; 32],
        });
        engine.ingest_lnss_event(LnssGovEvent::ActivationRejected {
            activation_digest: [2u8; 32],
        });
        engine.ingest_lnss_event(LnssGovEvent::SaePackUpdated {
            new_digest: [3u8; 32],
        });

        let frames = engine.force_flush();
        for frame in frames {
            let integrity = frame.integrity_stats.as_ref().expect("integrity stats");
            assert!(integrity.top_reason_codes.len() <= 1);
        }
    }

    #[test]
    fn ingest_lnss_event_is_deterministic() {
        let config = FramesConfig::fallback();
        let mut engine_a = engine_with_config(config.clone());
        let mut engine_b = engine_with_config(config);
        let sequence = vec![
            LnssGovEvent::ActivationApplied {
                activation_digest: [4u8; 32],
            },
            LnssGovEvent::ActivationRejected {
                activation_digest: [5u8; 32],
            },
            LnssGovEvent::SaePackUpdated {
                new_digest: [6u8; 32],
            },
        ];

        for event in sequence.clone() {
            engine_a.ingest_lnss_event(event);
        }
        for event in sequence {
            engine_b.ingest_lnss_event(event);
        }

        let frames_a = engine_a.force_flush();
        let frames_b = engine_b.force_flush();
        assert_eq!(frames_a, frames_b);
    }
}
