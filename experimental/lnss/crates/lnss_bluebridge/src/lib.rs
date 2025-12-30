#![forbid(unsafe_code)]

use lnss_runtime::{BiophysFeedbackSnapshot, BrainSpike, LnssRuntimeError, RigClient};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct Chip2BiophysBridge {
    pub received: Vec<BrainSpike>,
}

impl Chip2BiophysBridge {
    pub fn new() -> Self {
        Self {
            received: Vec::new(),
        }
    }

    pub fn send_spikes(&mut self, spikes: &[BrainSpike]) {
        self.received.extend_from_slice(spikes);
    }
}

#[derive(Debug, Default)]
pub struct NeuronBridgeStub;

impl NeuronBridgeStub {
    pub fn new() -> Self {
        Self
    }

    pub fn send_spikes(&self, _spikes: &[BrainSpike]) {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSpike {
    pub region: String,
    pub population: String,
    pub neuron_group: u32,
    pub syn_kind: String,
    pub amplitude_q: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTarget {
    pub region: String,
    pub population: String,
    pub neuron_group: u32,
    pub syn_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionReport {
    pub applied: Vec<AppliedTarget>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chip2RouterError;

impl std::fmt::Display for Chip2RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("chip2 router error")
    }
}

impl std::error::Error for Chip2RouterError {}

pub trait Chip2RouterAdapter: Send {
    fn inject_external_spikes(
        &mut self,
        tick: u64,
        spikes: &[ExternalSpike],
    ) -> Result<InjectionReport, Chip2RouterError>;

    fn feedback_snapshot(&mut self) -> Option<BiophysFeedbackSnapshot> {
        None
    }
}

const MAX_SPIKES_PER_TICK: usize = 256;

pub struct Chip2InjectClient {
    router: Box<dyn Chip2RouterAdapter>,
    max_spikes_per_tick: usize,
    latest_feedback: Option<BiophysFeedbackSnapshot>,
}

impl Chip2InjectClient {
    pub fn new(router: Box<dyn Chip2RouterAdapter>) -> Self {
        Self::with_max_spikes_per_tick(router, MAX_SPIKES_PER_TICK)
    }

    pub fn with_max_spikes_per_tick(
        router: Box<dyn Chip2RouterAdapter>,
        max_spikes_per_tick: usize,
    ) -> Self {
        Self {
            router,
            max_spikes_per_tick: max_spikes_per_tick.min(MAX_SPIKES_PER_TICK),
            latest_feedback: None,
        }
    }

    pub fn router_mut(&mut self) -> &mut dyn Chip2RouterAdapter {
        self.router.as_mut()
    }

    fn normalize_spikes(&self, spikes: &[BrainSpike]) -> BTreeMap<u64, Vec<ExternalSpike>> {
        if self.max_spikes_per_tick == 0 || spikes.is_empty() {
            return BTreeMap::new();
        }

        let mut per_tick: BTreeMap<u64, Vec<ExternalSpike>> = BTreeMap::new();
        for spike in spikes {
            per_tick
                .entry(spike.tick)
                .or_default()
                .push(map_external_spike(spike));
        }

        for spikes in per_tick.values_mut() {
            spikes.sort_by(|a, b| {
                a.region
                    .cmp(&b.region)
                    .then_with(|| a.population.cmp(&b.population))
                    .then_with(|| a.neuron_group.cmp(&b.neuron_group))
                    .then_with(|| a.syn_kind.cmp(&b.syn_kind))
                    .then_with(|| a.amplitude_q.cmp(&b.amplitude_q))
            });
            spikes.truncate(self.max_spikes_per_tick);
        }

        per_tick
    }
}

impl RigClient for Chip2InjectClient {
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        let per_tick = self.normalize_spikes(spikes);
        for (tick, spikes) in per_tick {
            self.router
                .inject_external_spikes(tick, &spikes)
                .map_err(|_| LnssRuntimeError::Rig("chip2 injection failed".to_string()))?;
        }
        self.latest_feedback = self.router.feedback_snapshot();
        Ok(())
    }

    fn poll_feedback(&mut self) -> Option<BiophysFeedbackSnapshot> {
        self.latest_feedback.take()
    }
}

fn map_external_spike(spike: &BrainSpike) -> ExternalSpike {
    ExternalSpike {
        region: spike.target.region.clone(),
        population: spike.target.population.clone(),
        neuron_group: spike.target.neuron_group,
        syn_kind: spike.target.syn_kind.clone(),
        amplitude_q: spike.amplitude_q,
    }
}
