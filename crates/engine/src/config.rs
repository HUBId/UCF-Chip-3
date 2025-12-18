use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::{EngineError, IntegrityStateClass, SeverityClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowKind {
    Short,
    Medium,
    Long,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowSpec {
    pub min_records: u64,
    pub max_records: u64,
    pub max_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowingConfig {
    pub short: WindowSpec,
    pub medium: WindowSpec,
    pub long: WindowSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdBands {
    pub medium: u64,
    pub high: u64,
}

impl ThresholdBands {
    pub fn classify(&self, count: u64) -> SeverityClass {
        if count >= self.high {
            SeverityClass::High
        } else if count >= self.medium {
            SeverityClass::Medium
        } else {
            SeverityClass::Low
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowThresholds {
    pub short: ThresholdBands,
    pub medium: ThresholdBands,
    pub long: ThresholdBands,
}

impl WindowThresholds {
    pub fn classify(&self, window: WindowKind, count: u64) -> SeverityClass {
        match window {
            WindowKind::Short => self.short.classify(count),
            WindowKind::Medium => self.medium.classify(count),
            WindowKind::Long => self.long.classify(count),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdConfig {
    pub policy_pressure: WindowThresholds,
    pub receipt_failures: WindowThresholds,
    pub exec_reliability: WindowThresholds,
    pub dlp_severity: WindowThresholds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlProfileId {
    M0,
    M1,
    M2,
    M3,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolClassMaskConfig {
    pub enable_read: bool,
    pub enable_transform: bool,
    pub enable_export: bool,
    pub enable_write: bool,
    pub enable_execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GainProfileConfig {
    pub novelty: String,
    pub abstraction: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetClasses {
    pub k1: String,
    pub k2: String,
    pub k3: String,
    pub k4: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPolicy {
    pub max_chain: u32,
    pub max_concurrency: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPolicy {
    pub export_lock_default: bool,
    pub allowed_output_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeescalationPolicy {
    pub lock: bool,
    pub cooldown_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatorProfile {
    pub control_profile: ControlProfileId,
    pub note: String,
    pub toolclass_mask: ToolClassMaskConfig,
    pub approval_mode: String,
    pub gain_profile: GainProfileConfig,
    pub budgets: BudgetClasses,
    pub chain_policy: ChainPolicy,
    pub export_policy: ExportPolicy,
    pub deescalation: DeescalationPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatorProfilesConfig {
    pub profiles: HashMap<String, RegulatorProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayEffects {
    pub ovl_simulate_first: bool,
    pub ovl_export_lock: bool,
    pub ovl_novelty_lock: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySpec {
    pub note: Option<String>,
    pub effects: OverlayEffects,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatorOverlaysConfig {
    pub overlays: HashMap<String, OverlaySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCondition {
    pub receipt_failures: Option<SeverityClass>,
    pub integrity_state: Option<IntegrityStateClass>,
    pub policy_pressure: Option<SeverityClass>,
}

impl UpdateCondition {
    pub fn matches(&self, classified: &crate::ClassifiedSignals) -> bool {
        if let Some(expected) = self.receipt_failures {
            if classified.receipt_failures_class != expected {
                return false;
            }
        }

        if let Some(expected) = self.integrity_state {
            if classified.integrity_state != expected {
                return false;
            }
        }

        if let Some(expected) = self.policy_pressure {
            if classified.policy_pressure_class != expected {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSwitchRule {
    pub when: UpdateCondition,
    pub profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayEnableRule {
    pub when: UpdateCondition,
    pub overlays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatorUpdateTablesConfig {
    pub profile_switch: Vec<ProfileSwitchRule>,
    pub overlay_enable: Vec<OverlayEnableRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    pub windowing: WindowingConfig,
    pub thresholds: ThresholdConfig,
    pub profiles: RegulatorProfilesConfig,
    pub overlays: RegulatorOverlaysConfig,
    pub update_tables: RegulatorUpdateTablesConfig,
}

impl EngineConfig {
    pub fn load_from_dir(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let base = path.as_ref();
        let windowing = load_yaml(base.join("windowing.yaml"))?;
        let thresholds = load_yaml(base.join("class_thresholds.yaml"))?;
        let profiles = load_yaml(base.join("regulator_profiles.yaml"))?;
        let overlays = load_yaml(base.join("regulator_overlays.yaml"))?;
        let update_tables = load_yaml(base.join("regulator_update_tables.yaml"))?;

        Ok(Self {
            windowing,
            thresholds,
            profiles,
            overlays,
            update_tables,
        })
    }
}

fn load_yaml<T: DeserializeOwned>(path: PathBuf) -> Result<T, EngineError> {
    let file = File::open(&path)?;
    serde_yaml::from_reader(file).map_err(EngineError::from)
}
