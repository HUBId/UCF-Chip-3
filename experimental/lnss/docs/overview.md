# LNSS Overview

```
[input bytes + EmotionFieldSnapshot]
        |
        v
  LLM Backend (stub/feature-gated)
        |
        v
    HookProvider -> TapFrame(s)
        |
        v
     SAE Backend -> FeatureEvent(s)
        |
        v
FeatureToBrainMap -> BrainSpike(s)
        |
        +--> RigClient (stub/log)
        |
        +--> MechIntWriter (JSONL)
```

LNSS Phase 0/1 focuses on deterministic, bounded, offline-friendly scaffolding with stubs. No heavy dependencies are required unless a feature flag is enabled.
