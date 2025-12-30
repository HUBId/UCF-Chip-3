# Determinism

LNSS is deterministic by construction:

* All digests use domain-separated BLAKE3 with a stable byte encoding.
* Feature ordering:
  * `FeatureEvent.top_features` sorted by `strength_q` desc, then `feature_id` asc.
  * Mapping entries sorted by `feature_id` asc before digesting.
* Reason codes and overlays are sorted/deduped and bounded.
* Stub backends derive outputs from input/tap digests only.
* No RNG usage and no system-time dependence.
* JSONL writers cap line size to avoid unbounded output.

These rules ensure identical inputs yield identical outputs and stable digests.
