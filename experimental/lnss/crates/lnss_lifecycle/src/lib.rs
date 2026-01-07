#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const TRACE_VERDICT_PROMISING: u8 = 1;
pub const TRACE_VERDICT_NEUTRAL: u8 = 2;
pub const TRACE_VERDICT_RISKY: u8 = 3;

pub const ACTIVATION_STATUS_APPLIED: u8 = 1;
pub const ACTIVATION_STATUS_REJECTED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LifecycleKey {
    pub proposal_digest: [u8; 32],
    pub context_digest: [u8; 32],
    #[serde(default)]
    pub active_cfg_root_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LifecycleState {
    pub latest_trace_digest: Option<[u8; 32]>,
    pub latest_trace_verdict: Option<u8>,
    pub latest_aap_digest: Option<[u8; 32]>,
    pub latest_approval_digest: Option<[u8; 32]>,
    pub latest_activation_digest: Option<[u8; 32]>,
    pub latest_activation_status: Option<u8>,
    pub updated_at_tick: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleIndex {
    pub map: BTreeMap<LifecycleKey, LifecycleState>,
}

impl LifecycleIndex {
    pub fn state_for(&self, key: &LifecycleKey) -> Option<&LifecycleState> {
        self.map.get(key)
    }

    pub fn note_proposal(&mut self, key: LifecycleKey, tick: u64) -> bool {
        self.note_tick_only(key, tick)
    }

    pub fn note_trace(
        &mut self,
        key: LifecycleKey,
        trace_digest: [u8; 32],
        verdict: u8,
        tick: u64,
    ) -> bool {
        self.update_if_newer(key, tick, |state| {
            if state.latest_trace_digest == Some(trace_digest)
                && state.latest_trace_verdict == Some(verdict)
            {
                return false;
            }
            state.latest_trace_digest = Some(trace_digest);
            state.latest_trace_verdict = Some(verdict);
            true
        })
    }

    pub fn note_aap(&mut self, key: LifecycleKey, aap_digest: [u8; 32], tick: u64) -> bool {
        self.update_if_newer(key, tick, |state| {
            if state.latest_aap_digest == Some(aap_digest) {
                return false;
            }
            state.latest_aap_digest = Some(aap_digest);
            true
        })
    }

    pub fn note_approval(
        &mut self,
        key: LifecycleKey,
        approval_digest: [u8; 32],
        tick: u64,
    ) -> bool {
        self.update_if_newer(key, tick, |state| {
            if state.latest_approval_digest == Some(approval_digest) {
                return false;
            }
            state.latest_approval_digest = Some(approval_digest);
            true
        })
    }

    pub fn note_activation(
        &mut self,
        key: LifecycleKey,
        activation_digest: [u8; 32],
        status: u8,
        tick: u64,
    ) -> bool {
        self.update_if_newer(key, tick, |state| {
            if state.latest_activation_digest == Some(activation_digest)
                && state.latest_activation_status == Some(status)
            {
                return false;
            }
            state.latest_activation_digest = Some(activation_digest);
            state.latest_activation_status = Some(status);
            true
        })
    }

    fn note_tick_only(&mut self, key: LifecycleKey, tick: u64) -> bool {
        self.update_if_newer(key, tick, |_| true)
    }

    fn update_if_newer<F>(&mut self, key: LifecycleKey, tick: u64, updater: F) -> bool
    where
        F: FnOnce(&mut LifecycleState) -> bool,
    {
        let state = self.map.entry(key).or_default();
        if tick < state.updated_at_tick {
            return false;
        }
        let updated = if tick > state.updated_at_tick {
            updater(state)
        } else {
            // Same tick: only update if the field is empty or identical.
            updater(state)
        };
        if updated {
            state.updated_at_tick = tick;
        }
        updated
    }
}

pub trait EvidenceQueryClient {
    fn latest_trace_for(
        &self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)>;
    fn latest_activation_for(
        &self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)>;
}

#[derive(Debug, Clone, Default)]
pub struct MockEvidenceQueryClient {
    latest_trace: BTreeMap<LifecycleKey, ([u8; 32], u8)>,
    latest_activation: BTreeMap<LifecycleKey, ([u8; 32], u8)>,
}

impl MockEvidenceQueryClient {
    pub fn set_latest_trace(
        &mut self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
        trace_digest: [u8; 32],
        verdict: u8,
    ) {
        let key = LifecycleKey {
            proposal_digest,
            context_digest,
            active_cfg_root_digest: None,
        };
        self.latest_trace.insert(key, (trace_digest, verdict));
    }

    pub fn set_latest_activation(
        &mut self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
        activation_digest: [u8; 32],
        status: u8,
    ) {
        let key = LifecycleKey {
            proposal_digest,
            context_digest,
            active_cfg_root_digest: None,
        };
        self.latest_activation
            .insert(key, (activation_digest, status));
    }
}

impl EvidenceQueryClient for MockEvidenceQueryClient {
    fn latest_trace_for(
        &self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)> {
        let key = LifecycleKey {
            proposal_digest,
            context_digest,
            active_cfg_root_digest: None,
        };
        self.latest_trace.get(&key).copied()
    }

    fn latest_activation_for(
        &self,
        proposal_digest: [u8; 32],
        context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)> {
        let key = LifecycleKey {
            proposal_digest,
            context_digest,
            active_cfg_root_digest: None,
        };
        self.latest_activation.get(&key).copied()
    }
}

#[cfg(feature = "lnss-chip4-query")]
#[derive(Debug, Clone, Default)]
pub struct LocalChip4QueryClient {
    _private: (),
}

#[cfg(feature = "lnss-chip4-query")]
impl EvidenceQueryClient for LocalChip4QueryClient {
    fn latest_trace_for(
        &self,
        _proposal_digest: [u8; 32],
        _context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)> {
        // TODO: wire to Chip4 once context-bound query index exists.
        None
    }

    fn latest_activation_for(
        &self,
        _proposal_digest: [u8; 32],
        _context_digest: [u8; 32],
    ) -> Option<([u8; 32], u8)> {
        // TODO: wire to Chip4 once context-bound query index exists.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_index_is_deterministic() {
        let key = LifecycleKey {
            proposal_digest: [1u8; 32],
            context_digest: [2u8; 32],
            active_cfg_root_digest: None,
        };
        let mut index_a = LifecycleIndex::default();
        let mut index_b = LifecycleIndex::default();

        index_a.note_proposal(key, 1);
        index_a.note_trace(key, [3u8; 32], TRACE_VERDICT_PROMISING, 2);
        index_a.note_aap(key, [4u8; 32], 3);
        index_a.note_approval(key, [5u8; 32], 4);
        index_a.note_activation(key, [6u8; 32], ACTIVATION_STATUS_APPLIED, 5);

        index_b.note_proposal(key, 1);
        index_b.note_trace(key, [3u8; 32], TRACE_VERDICT_PROMISING, 2);
        index_b.note_aap(key, [4u8; 32], 3);
        index_b.note_approval(key, [5u8; 32], 4);
        index_b.note_activation(key, [6u8; 32], ACTIVATION_STATUS_APPLIED, 5);

        assert_eq!(index_a, index_b);
    }

    #[test]
    fn lifecycle_index_ignores_older_ticks() {
        let key = LifecycleKey {
            proposal_digest: [9u8; 32],
            context_digest: [8u8; 32],
            active_cfg_root_digest: None,
        };
        let mut index = LifecycleIndex::default();
        index.note_trace(key, [1u8; 32], TRACE_VERDICT_PROMISING, 10);
        let updated = index.note_trace(key, [2u8; 32], TRACE_VERDICT_RISKY, 5);
        assert!(!updated);
        let state = index.state_for(&key).expect("state");
        assert_eq!(state.latest_trace_digest, Some([1u8; 32]));
    }
}
