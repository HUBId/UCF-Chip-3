#![cfg(all(feature = "lnss", feature = "lnss-chip2-bridge"))]

use std::sync::{Arc, Mutex};

use chip2::{Chip2Runtime, DefaultRouter, L4Circuit};
use lnss::lnss_bluebridge::{
    AppliedTarget, Chip2InjectClient, Chip2RouterAdapter, Chip2RouterError, ExternalSpike,
    InjectionReport,
};
use lnss::lnss_core::{BrainTarget, FeatureEvent, FeatureToBrainMap};
use lnss::lnss_runtime::{map_features_to_spikes, RigClient};

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
    let target_b = BrainTarget::new("rc", "pop", 2, "exc", 700);
    FeatureToBrainMap::new(1, vec![(7, target_a), (9, target_b)])
}

fn sample_events() -> Vec<FeatureEvent> {
    vec![
        FeatureEvent::new(
            "session",
            "step",
            "hook",
            vec![(7, 1000), (9, 500)],
            123,
            vec!["reason".to_string()],
        ),
        FeatureEvent::new(
            "session",
            "step",
            "hook",
            vec![(7, 600), (9, 800)],
            124,
            vec!["reason".to_string()],
        ),
    ]
}

#[test]
fn injects_external_spikes_deterministically() {
    let mapper = sample_mapper();
    let events = sample_events();
    let mut spikes = map_features_to_spikes(&mapper, &events);
    assert!(!spikes.is_empty());
    for (idx, spike) in spikes.iter_mut().enumerate() {
        spike.tick = idx as u64 % 2;
    }

    let circuit = L4Circuit::new(99);
    let runtime = Chip2Runtime::new(circuit);
    let router = DefaultRouter::new(runtime);
    let bridge = Chip2RouterBridge::new(router);
    let mut client = Chip2InjectClient::with_max_spikes_per_tick(Box::new(bridge), 2);
    client.send_spikes(&spikes).unwrap();
}
