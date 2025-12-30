#![forbid(unsafe_code)]

use lnss_runtime::BrainSpike;

#[derive(Debug, Default)]
pub struct Chip2BiophysBridge {
    pub received: Vec<BrainSpike>,
}

impl Chip2BiophysBridge {
    pub fn new() -> Self {
        Self { received: Vec::new() }
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
