# LNSS (experimental)

Offline-first LNSS scaffolding with deterministic, bounded stubs.

## Layout

* `crates/lnss_core`: core types + digests
* `crates/lnss_runtime`: orchestrator + traits
* `crates/lnss_hooks`: tap plan parsing
* `crates/lnss_sae`: SAE stub + placeholders
* `crates/lnss_mechint`: JSONL transparency writer
* `crates/lnss_rig`: rig client stubs
* `crates/lnss_bluebridge`: Chip2/NEURON stubs
* `crates/lnss_evolve`: OpenEvolve stub
* `docs/`: architecture + determinism

## Running tests

```bash
cargo test -p lnss_runtime
```

## Feature flags

* `lnss`: enables the LNSS facade crate.
* `lnss-candle`: optional SAE inference backend.
* `lnss-burn`: optional Burn backend.
* `lnss-arrow`: optional Arrow writer.
* `lnss-pyo3`: optional Python bridge.
* `lnss-cxx`: optional C++ bridge.
* `lnss-rig-sdk`: optional rig SDK.
