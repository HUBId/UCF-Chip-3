#![cfg(feature = "lnss-chip2-bridge")]

use std::sync::{Arc, Mutex};

use chip2::{Chip2Runtime, DefaultRouter, L4Circuit};
use lnss_bluebridge::{
    AppliedTarget, Chip2InjectClient, Chip2RouterAdapter, Chip2RouterError, ExternalSpike,
    InjectionReport,
};
use lnss_core::{BrainTarget, FeatureEvent, FeatureToBrainMap};
use lnss_runtime::{map_features_to_spikes, RigClient};

#[derive(Clone)]
struct Chip2RouterBridge {
    router: Arc<Mutex<DefaultRouter>>,
}

impl Chip2RouterBridge {
    fn new(router: DefaultRouter) -> Self {
        Self {
            router: Arc::new(Mutex::new(router)),
        }
    }

    fn handle(&self) -> Arc<Mutex<DefaultRouter>> {
        self.router.clone()
    }
}

impl Chip2RouterAdapter for Chip2RouterBridge {
    fn inject_external_spikes(
        &mut self,
        tick: u64,
        spikes: &[ExternalSpike],
    ) -> Result<InjectionReport, Chip2RouterError> {
        let mut guard = match self.router.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let chip2_spikes: Vec<chip2::ExternalSpike> = spikes
            .iter()
            .map(|spike| chip2::ExternalSpike {
                region: spike.region.clone(),
                population: spike.population.clone(),
                neuron_group: spike.neuron_group,
                syn_kind: spike.syn_kind.clone(),
                amplitude_q: spike.amplitude_q,
            })
            .collect();
        let report = guard
            .inject_external_spikes(tick, &chip2_spikes)
            .map_err(|_| Chip2RouterError)?;
        let applied = report
            .applied
            .into_iter()
            .map(|target| AppliedTarget {
                region: target.region,
                population: target.population,
                neuron_group: target.neuron_group,
                syn_kind: target.syn_kind,
            })
            .collect();
        Ok(InjectionReport { applied })
    }
}

fn sample_mapper() -> FeatureToBrainMap {
    let target_a = BrainTarget::new("rc", "pop", 1, "exc", 900);
    let target_b = BrainTarget::new("rc", "pop", 2, "inh", 700);
    let target_c = BrainTarget::new("rc", "pop", 3, "exc", 500);
    FeatureToBrainMap::new(1, vec![(7, target_a), (9, target_b), (11, target_c)])
}

fn sample_events(tick: u64) -> Vec<FeatureEvent> {
    vec![
        FeatureEvent::new(
            "session",
            &format!("step-{tick}"),
            "hook",
            vec![(7, 1000), (9, 500)],
            123 + tick,
            vec![format!("reason-{tick}")],
        ),
        FeatureEvent::new(
            "session",
            &format!("step-{tick}-b"),
            "hook",
            vec![(7, 600), (11, 800)],
            321 + tick,
            vec![format!("reason-b-{tick}")],
        ),
    ]
}

fn run_sequence(max_spikes: usize) -> (Vec<u8>, Vec<u8>, Vec<AppliedTarget>) {
    let mapper = sample_mapper();
    let circuit = L4Circuit::new(42);
    let runtime = Chip2Runtime::new(circuit);
    let router = DefaultRouter::new(runtime);
    let bridge = Chip2RouterBridge::new(router);
    let handle = bridge.handle();
    let mut client = Chip2InjectClient::with_max_spikes_per_tick(Box::new(bridge), max_spikes);

    let initial_digest = {
        let guard = handle.lock().expect("router lock");
        guard.runtime().snapshot_digest()
    };

    for tick in 0..10 {
        let events = sample_events(tick);
        let mut spikes = map_features_to_spikes(&mapper, &events);
        for spike in &mut spikes {
            spike.tick = tick;
        }
        client.send_spikes(&spikes).expect("inject spikes");
    }

    let (digest, applied) = {
        let guard = handle.lock().expect("router lock");
        let digest = guard.runtime().snapshot_digest();
        let applied = guard
            .last_report()
            .map(|report| {
                report
                    .applied
                    .iter()
                    .map(|target| AppliedTarget {
                        region: target.region.clone(),
                        population: target.population.clone(),
                        neuron_group: target.neuron_group,
                        syn_kind: target.syn_kind.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        (digest, applied)
    };

    (initial_digest.to_vec(), digest.to_vec(), applied)
}

#[test]
fn injects_deterministically_across_ticks() {
    let (initial_digest, digest, applied) = run_sequence(256);
    assert_ne!(
        initial_digest, digest,
        "digest should change after injection"
    );
    let first = applied.first().expect("expected applied targets");
    assert_eq!(first.region, "rc");
    assert_eq!(first.population, "pop");

    let (_, digest_repeat, _) = run_sequence(256);
    assert_eq!(digest, digest_repeat, "digest must be deterministic");
}

#[test]
fn respects_per_tick_cap() {
    let mapper = sample_mapper();
    let circuit = L4Circuit::new(7);
    let runtime = Chip2Runtime::new(circuit);
    let router = DefaultRouter::new(runtime);
    let bridge = Chip2RouterBridge::new(router);
    let handle = bridge.handle();
    let mut client = Chip2InjectClient::with_max_spikes_per_tick(Box::new(bridge), 2);

    let events = sample_events(0);
    let mut spikes = map_features_to_spikes(&mapper, &events);
    for spike in &mut spikes {
        spike.tick = 0;
    }

    client.send_spikes(&spikes).expect("inject spikes");

    let applied = {
        let guard = handle.lock().expect("router lock");
        guard
            .last_report()
            .map(|report| report.applied.len())
            .unwrap_or(0)
    };
    assert!(applied <= 2, "applied spikes should respect cap");
}
