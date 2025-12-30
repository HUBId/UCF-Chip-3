# LNSS Interfaces & Bounds

## Bounds (hard caps)

* String fields: `MAX_STRING_LEN = 128`
* Reason codes: `MAX_REASON_CODES = 16`
* Feature top-k: `MAX_TOP_FEATURES = 64`
* Tap specs: `MAX_TAP_SPECS = 128`
* Tap activation bytes: `MAX_ACTIVATION_BYTES = 1_048_576` (1 MiB)
* Mapping entries: `MAX_MAPPING_ENTRIES = 4096`
* Emotion overlays: `MAX_OVERLAYS = 16`

Runtime defaults:

* Output bytes: `DEFAULT_MAX_OUTPUT_BYTES = 4096`
* Spikes: `DEFAULT_MAX_SPIKES = 2048`
* Taps: `DEFAULT_MAX_TAPS = 128`
* MechInt line bytes: `DEFAULT_MAX_MECHINT_BYTES = 8192`

## lnss_core

### Deterministic digest

`digest(domain: &str, bytes: &[u8]) -> [u8; 32]`

BLAKE3 with domain prefix + `0x00` separator.

### FeatureEvent (SAE output)

```
struct FeatureEvent {
  event_id: String
  event_digest: [u8; 32]
  session_id: String
  step_id: String
  hook_id: String
  top_features: Vec<(u32 feature_id, u16 strength_q)>
  timestamp_ms: u64
  reason_codes: Vec<String>
}
```

* `strength_q`: fixed-point `0..=1000`
* `top_features`: sorted by strength desc, then `feature_id` asc
* `reason_codes`: sorted, deduped, capped

### TapSpec / TapFrame

```
enum TapKind { ResidualStream, MlpPost, AttnOut, Embedding, LiquidState }

struct TapSpec {
  hook_id: String
  tap_kind: TapKind
  layer_index: u16
  tensor_name: String
}

struct TapFrame {
  hook_id: String
  activation_digest: [u8; 32]
  activation_bytes: Vec<u8>
}
```

### FeatureToBrainMap

```
struct BrainTarget {
  region: String
  population: String
  neuron_group: u32
  syn_kind: String
  amplitude_q: u16
}

struct FeatureToBrainMap {
  map_version: u32
  map_digest: [u8; 32]
  entries: Vec<(u32 feature_id, BrainTarget)>
}
```

Entries are sorted by `feature_id` asc before digesting.

### EmotionFieldSnapshot

```
struct EmotionFieldSnapshot {
  noise: String
  priority: String
  recursion_depth: String
  dwm: String
  profile: String
  overlays: Vec<String>
  top_reason_codes: Vec<String>
}
```

## lnss_runtime

### Traits

* `LlmBackend::infer_step(input, mods) -> Vec<u8>`
* `HookProvider::collect_taps(specs) -> Vec<TapFrame>`
* `SaeBackend::infer_features(tap) -> FeatureEvent`
* `MechIntWriter::write_step(rec) -> Result<(), Error>`
* `RigClient::send_spikes(spikes) -> Result<(), Error>`

### Outputs

```
struct BrainSpike { target: BrainTarget, tick: u64, amplitude_q: u16 }

struct MechIntRecord {
  session_id: String
  step_id: String
  token_digest: [u8; 32]
  tap_digests: Vec<[u8; 32]>
  feature_event_digests: Vec<[u8; 32]>
  mapping_digest: [u8; 32]
  record_digest: [u8; 32]
}
```
