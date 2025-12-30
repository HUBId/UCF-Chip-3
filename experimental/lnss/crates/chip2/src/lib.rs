#![forbid(unsafe_code)]

use blake3::Hasher;
use lnss_core::BiophysFeedbackSnapshot;

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

#[derive(Debug, Clone)]
pub struct L4Circuit {
    seed: u64,
}

impl L4Circuit {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }
}

#[derive(Debug, Clone)]
pub struct Chip2Runtime {
    tick: u64,
    injected_total: usize,
    digest: [u8; 32],
    last_injected: u32,
    last_dropped: u64,
    last_overflowed: bool,
}

impl Chip2Runtime {
    pub fn new(circuit: L4Circuit) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"chip2.runtime.init.v1");
        hasher.update(&circuit.seed.to_le_bytes());
        let digest = *hasher.finalize().as_bytes();
        Self {
            tick: 0,
            injected_total: 0,
            digest,
            last_injected: 0,
            last_dropped: 0,
            last_overflowed: false,
        }
    }

    pub fn tick(&self) -> u64 {
        self.tick
    }

    pub fn injected_total(&self) -> usize {
        self.injected_total
    }

    pub fn snapshot_digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn feedback_snapshot(&self) -> BiophysFeedbackSnapshot {
        BiophysFeedbackSnapshot {
            tick: self.tick,
            snapshot_digest: self.digest,
            event_queue_overflowed: self.last_overflowed,
            events_dropped: self.last_dropped,
            events_injected: self.last_injected,
            injected_total: self.injected_total as u64,
        }
    }

    fn apply_spikes(&mut self, tick: u64, spikes: &[ExternalSpike]) -> InjectionReport {
        const FEEDBACK_QUEUE_CAP: usize = 128;
        let mut hasher = Hasher::new();
        hasher.update(b"chip2.runtime.inject.v1");
        hasher.update(&self.digest);
        hasher.update(&tick.to_le_bytes());
        hasher.update(&(spikes.len() as u32).to_le_bytes());
        for spike in spikes {
            write_string(&mut hasher, &spike.region);
            write_string(&mut hasher, &spike.population);
            hasher.update(&spike.neuron_group.to_le_bytes());
            write_string(&mut hasher, &spike.syn_kind);
            hasher.update(&spike.amplitude_q.to_le_bytes());
        }
        self.digest = *hasher.finalize().as_bytes();
        self.tick = tick;
        self.injected_total = self.injected_total.saturating_add(spikes.len());
        let dropped = spikes.len().saturating_sub(FEEDBACK_QUEUE_CAP);
        self.last_dropped = dropped as u64;
        self.last_overflowed = dropped > 0;
        self.last_injected = spikes.len().min(u32::MAX as usize) as u32;
        let applied = spikes
            .iter()
            .map(|spike| AppliedTarget {
                region: spike.region.clone(),
                population: spike.population.clone(),
                neuron_group: spike.neuron_group,
                syn_kind: spike.syn_kind.clone(),
            })
            .collect();
        InjectionReport { applied }
    }
}

#[derive(Debug, Clone)]
pub struct SpikeRouter {
    runtime: Chip2Runtime,
    last_report: Option<InjectionReport>,
}

impl SpikeRouter {
    pub fn new(runtime: Chip2Runtime) -> Self {
        Self {
            runtime,
            last_report: None,
        }
    }

    pub fn runtime(&self) -> &Chip2Runtime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut Chip2Runtime {
        &mut self.runtime
    }

    pub fn last_report(&self) -> Option<&InjectionReport> {
        self.last_report.as_ref()
    }

    pub fn inject_external_spikes(
        &mut self,
        tick: u64,
        spikes: &[ExternalSpike],
    ) -> Result<InjectionReport, Chip2RouterError> {
        let report = self.runtime.apply_spikes(tick, spikes);
        self.last_report = Some(report.clone());
        Ok(report)
    }
}

#[derive(Debug, Clone)]
pub struct DefaultRouter {
    router: SpikeRouter,
}

impl DefaultRouter {
    pub fn new(runtime: Chip2Runtime) -> Self {
        Self {
            router: SpikeRouter::new(runtime),
        }
    }

    pub fn runtime(&self) -> &Chip2Runtime {
        self.router.runtime()
    }

    pub fn last_report(&self) -> Option<&InjectionReport> {
        self.router.last_report()
    }

    pub fn inject_external_spikes(
        &mut self,
        tick: u64,
        spikes: &[ExternalSpike],
    ) -> Result<InjectionReport, Chip2RouterError> {
        self.router.inject_external_spikes(tick, spikes)
    }
}

fn write_string(hasher: &mut Hasher, value: &str) {
    let len = value.len() as u32;
    hasher.update(&len.to_le_bytes());
    hasher.update(value.as_bytes());
}
