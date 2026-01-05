# LNSS evidence encoding

LNSS emits proposal, activation, and trace evidence as protobuf messages and commits the
protobuf bytes to PVGS/Chip4. The evidence digest for each message is computed by zeroing the
digest field, serializing the protobuf bytes, then hashing `DOMAIN || bytes` with BLAKE3:

* `UCF:PROPOSAL_EVIDENCE` for `ProposalEvidence`
* `UCF:ACTIVATION_EVIDENCE` for `ProposalActivationEvidence`
* `UCF:TRACE_RUN_EVIDENCE` for `TraceRunEvidence`

## Proposal payload digest

`ProposalEvidence.payload_digest` is computed as:

`blake3("UCF:PROPOSAL_PAYLOAD" || canonical_payload_bytes)`

The canonical payload bytes are the canonical JSON encoding of `ProposalPayload` (sorted keys,
no extra whitespace), matching the LNSS canonical JSON serialization used elsewhere.

## Deterministic timestamps

Evidence timestamps are deterministic:

`created_at_ms = tick * FIXED_MS_PER_TICK`

with `FIXED_MS_PER_TICK = 10`. No wall-clock APIs are used for evidence timestamps.
