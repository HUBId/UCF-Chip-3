#![forbid(unsafe_code)]

use lnss_runtime::{BrainSpike, LnssRuntimeError, RigClient, DEFAULT_MAX_SPIKES};
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
    pub tick: u64,
    pub amplitude_q: u16,
}

impl ExternalSpike {
    pub fn from_brain_spike(spike: &BrainSpike) -> Self {
        Self {
            region: spike.target.region.clone(),
            population: spike.target.population.clone(),
            neuron_group: spike.target.neuron_group,
            syn_kind: spike.target.syn_kind.clone(),
            tick: spike.tick,
            amplitude_q: spike.amplitude_q,
        }
    }
}

pub trait Chip2RuntimeHandle {
    fn inject_external_spikes(&mut self, spikes: &[ExternalSpike]) -> Result<(), String>;
}

#[derive(Debug)]
pub struct Chip2InjectClient<R> {
    runtime: R,
    max_spikes_per_tick: usize,
}

impl<R> Chip2InjectClient<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            max_spikes_per_tick: DEFAULT_MAX_SPIKES,
        }
    }

    pub fn with_max_spikes_per_tick(runtime: R, max_spikes_per_tick: usize) -> Self {
        Self {
            runtime,
            max_spikes_per_tick,
        }
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut R {
        &mut self.runtime
    }

    fn prepare_external_spikes(&self, spikes: &[BrainSpike]) -> Vec<ExternalSpike> {
        if self.max_spikes_per_tick == 0 || spikes.is_empty() {
            return Vec::new();
        }

        let mut per_tick: BTreeMap<u64, Vec<ExternalSpike>> = BTreeMap::new();
        for spike in spikes {
            per_tick
                .entry(spike.tick)
                .or_default()
                .push(ExternalSpike::from_brain_spike(spike));
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

        let mut out = Vec::new();
        for (_, spikes) in per_tick {
            out.extend(spikes);
        }
        out
    }
}

impl<R> RigClient for Chip2InjectClient<R>
where
    R: Chip2RuntimeHandle,
{
    fn send_spikes(&mut self, spikes: &[BrainSpike]) -> Result<(), LnssRuntimeError> {
        let external = self.prepare_external_spikes(spikes);
        self.runtime
            .inject_external_spikes(&external)
            .map_err(LnssRuntimeError::Rig)
    }
}
