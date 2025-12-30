use lnss_bluebridge::{Chip2InjectClient, Chip2RuntimeHandle, ExternalSpike};
use lnss_core::{BrainTarget, FeatureEvent, FeatureToBrainMap};
use lnss_runtime::{map_features_to_spikes, BrainSpike, RigClient};

#[derive(Debug, Default)]
struct TestChip2Runtime {
    injected: Vec<ExternalSpike>,
    total_injected: usize,
}

impl Chip2RuntimeHandle for TestChip2Runtime {
    fn inject_external_spikes(&mut self, spikes: &[ExternalSpike]) -> Result<(), String> {
        self.total_injected += spikes.len();
        self.injected.extend_from_slice(spikes);
        Ok(())
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

    let mut client = Chip2InjectClient::with_max_spikes_per_tick(TestChip2Runtime::default(), 2);
    client.send_spikes(&spikes).unwrap();

    let runtime = client.runtime();
    assert_eq!(runtime.injected.len(), runtime.total_injected);
    assert!(runtime.total_injected <= 4);

    let first = runtime.injected.first().expect("expected injected spikes");
    assert_eq!(first.region, "rc");
    assert_eq!(first.population, "pop");
    assert_eq!(first.syn_kind, "exc");
}

#[test]
fn drops_excess_spikes_per_tick_deterministically() {
    let mapper = sample_mapper();
    let events = sample_events();
    let spikes = map_features_to_spikes(&mapper, &events)
        .into_iter()
        .enumerate()
        .map(|(idx, mut spike)| {
            spike.tick = 0;
            spike.amplitude_q = 1000 - idx as u16;
            spike
        })
        .collect::<Vec<BrainSpike>>();

    let mut client = Chip2InjectClient::with_max_spikes_per_tick(TestChip2Runtime::default(), 1);
    client.send_spikes(&spikes).unwrap();

    let runtime = client.runtime();
    assert_eq!(runtime.total_injected, 1);
    let injected = runtime.injected.first().expect("expected injected spike");
    assert_eq!(injected.tick, 0);
}
