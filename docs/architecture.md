# UCF Chip 3 Workspace Scaffold

```
.
├── Cargo.toml
├── crates
│   ├── app          # Binary entry point; boots and prepares config paths
│   ├── cdm          # Curator / DLP placeholder interfaces
│   ├── frames       # SignalFrame aggregation placeholders
│   ├── gem          # Gate / PEP placeholder interfaces
│   ├── pbm          # Policy Brain placeholder interfaces
│   ├── pvgs_client  # PVGS commit / receipt client placeholder
│   ├── tam          # Tool Adapters interface placeholder
│   ├── tom          # Tool onboarding state machine placeholder
│   ├── trm          # Tool registry loader / validator placeholder
│   └── wire         # Envelope / Auth / Epoch / Nonce placeholders
├── config
│   ├── deployment_map.yaml
│   ├── receipt_gate_policy.yaml
│   └── tool_registry.yaml
└── tests            # Integration tests land here later
```

Each crate is intentionally minimal and exposes placeholder APIs marked with TODOs for future implementation. All crates forbid unsafe code, depend on `thiserror` for error scaffolding, and leave space to integrate the `ucf-protocol` prost-generated types later.
