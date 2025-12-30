# Roadmap

## Phase 0/1 (this scaffold)
* Core types + deterministic digests.
* Stub LLM, hooks, SAE, mechint JSONL, and rig client.
* Deterministic tests and bounded outputs.

## Phase 2 (inference backends)
* `lnss-candle`: local-only SAE inference with Candle.
* `lnss-liquid-ode`: open LiquidOdeBackend (fixed-step Euler, deterministic taps) as a substitute for the proprietary LFM.
* `lnss-burn`: optional Burn ODE backend wiring (used by LiquidOdeBackend).
* Future: replace Euler with `diffsol`/SUNDIALS behind a `lnss-diffsol` feature flag.
* Candle hooks/taps (local-only model loading, no downloads).

## Phase 3 (data & logging)
* `lnss-arrow`: Arrow writer (optional, feature-gated).
* Offline JSONL → Arrow conversion pipeline.

## Phase 4 (hooks & tooling)
* TransformerLens tap-plan import improvements.
* Tap selection catalog.

## Phase 5 (RIG & bridges)
* `lnss-rig-sdk` integration (optional).
* BlueBrain/NEURON bridges (`pyo3`/`cxx`) behind feature flags.

## Phase 6 (OpenEvolve)
* Offline proposal pipeline with evidence digests.
