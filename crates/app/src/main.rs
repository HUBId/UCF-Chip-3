#![forbid(unsafe_code)]

use std::{
    convert::TryFrom,
    env, process,
    sync::{Arc, Mutex},
};

use ckm_orchestrator::CkmOrchestrator;
use control::ControlFrameStore;
use ed25519_dalek::{Signer, SigningKey};
use frames::{FramesConfig, WindowEngine};
use gem::{DecisionLogStore, Gate, GateContext, GateResult};
use pbm::{DecisionForm, PolicyEngine};
use pvgs_client::{InspectorClient, KeyEpochSync, LocalPvgsClient};
use pvgs_verify::{
    pvgs_key_epoch_digest, pvgs_key_epoch_signing_preimage, pvgs_receipt_signing_preimage,
    verify_pvgs_receipt, PvgsKeyEpochStore,
};
use scheduler::ScheduleState;
use tam::MockAdapter;
use trm::registry_fixture;
use ucf_protocol::ucf;

fn main() {
    let mut args = env::args().skip(1).peekable();
    if let Some(subcommand) = args.peek() {
        if subcommand == "inspect-dump" {
            args.next();
            let session_id = match (args.next(), args.next()) {
                (Some(flag), Some(id)) if flag == "--session" => id,
                _ => {
                    eprintln!("usage: app inspect-dump --session <id>");
                    process::exit(1);
                }
            };

            if args.next().is_some() {
                eprintln!("usage: app inspect-dump --session <id>");
                process::exit(1);
            }

            run_inspect_dump(&session_id);
            return;
        }

        if subcommand == "run-scheduler" {
            args.next();
            let mut session_id: Option<String> = None;
            let mut ticks: Option<u64> = None;

            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--session" => {
                        session_id = args.next();
                    }
                    "--ticks" => {
                        ticks = args.next().and_then(|value| value.parse::<u64>().ok());
                    }
                    _ => {
                        eprintln!("usage: app run-scheduler --session <id> --ticks <n>");
                        process::exit(1);
                    }
                }
            }

            let (Some(session_id), Some(ticks)) = (session_id, ticks) else {
                eprintln!("usage: app run-scheduler --session <id> --ticks <n>");
                process::exit(1);
            };

            run_scheduler(&session_id, ticks);
            return;
        }

        if subcommand == "lnss-run" {
            args.next();
            let mut session_id: Option<String> = None;
            let mut steps: Option<u64> = None;
            let mut tap_plan: Option<String> = None;
            let mut map_path: Option<String> = None;
            let mut sae_pack: Option<String> = None;

            while let Some(flag) = args.next() {
                match flag.as_str() {
                    "--session" => session_id = args.next(),
                    "--steps" => steps = args.next().and_then(|value| value.parse::<u64>().ok()),
                    "--tap-plan" => tap_plan = args.next(),
                    "--map" => map_path = args.next(),
                    "--sae-pack" => sae_pack = args.next(),
                    _ => {
                        eprintln!(
                            "usage: app lnss-run --session <id> --steps <n> --tap-plan <file> --map <file> [--sae-pack <dir>]"
                        );
                        process::exit(1);
                    }
                }
            }

            let (Some(session_id), Some(steps), Some(tap_plan), Some(map_path)) =
                (session_id, steps, tap_plan, map_path)
            else {
                eprintln!(
                    "usage: app lnss-run --session <id> --steps <n> --tap-plan <file> --map <file> [--sae-pack <dir>]"
                );
                process::exit(1);
            };

            #[cfg(feature = "lnss")]
            {
                lnss_cli::run_lnss(
                    &session_id,
                    steps,
                    &tap_plan,
                    &map_path,
                    sae_pack.as_deref(),
                );
                return;
            }

            #[cfg(not(feature = "lnss"))]
            {
                eprintln!("lnss feature not enabled");
                process::exit(1);
            }
        }
    }

    run_demo();
}

#[cfg(feature = "lnss")]
mod lnss_cli {
    use std::fs;

    use frames::{FramesConfig, WindowEngine};
    use lnss_core::{
        BrainTarget, ControlIntentClass, CoreOrchestrator, EmotionFieldSnapshot, FeatureToBrainMap,
        PolicyMode, RecursionPolicy,
    };
    use lnss_frames_bridge::LnssGovEvent;
    use lnss_hooks::TransformerLensPlanImport;
    use lnss_lifecycle::LifecycleIndex;
    use lnss_mechint::JsonlMechIntWriter;
    use lnss_rig::LoggingRigClient;
    use lnss_rlm::RlmController;
    use lnss_runtime::{
        ActivationResult, FeedbackConsumer, Limits, LnssEventSink, LnssRuntime,
        MappingAdaptationConfig, SaeBackend, StubHookProvider, StubLlmBackend,
    };
    use lnss_sae::StubSaeBackend;
    use lnss_worldmodel::WorldModelCoreStub;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct MapEntry {
        feature_id: u32,
        target: BrainTarget,
    }

    #[derive(Debug, Deserialize)]
    struct MapFile {
        map_version: u32,
        entries: Vec<MapEntry>,
    }

    struct FramesLnssEventSink {
        frames: WindowEngine,
    }

    impl FramesLnssEventSink {
        fn new(frames: WindowEngine) -> Self {
            Self { frames }
        }
    }

    impl LnssEventSink for FramesLnssEventSink {
        fn on_activation_event(&mut self, activation_digest: [u8; 32], result: ActivationResult) {
            let event = match result {
                ActivationResult::Applied => LnssGovEvent::ActivationApplied { activation_digest },
                ActivationResult::Rejected => {
                    LnssGovEvent::ActivationRejected { activation_digest }
                }
            };
            self.frames.ingest_lnss_event(event);
        }
    }

    pub fn run_lnss(
        session_id: &str,
        steps: u64,
        tap_plan: &str,
        map_path: &str,
        sae_pack: Option<&str>,
    ) {
        let plan = TransformerLensPlanImport::from_path(tap_plan)
            .unwrap_or_else(|err| panic!("tap plan load failed: {err}"));

        let map_bytes =
            fs::read_to_string(map_path).unwrap_or_else(|err| panic!("map load failed: {err}"));
        let map_file: MapFile = serde_json::from_str(&map_bytes)
            .unwrap_or_else(|err| panic!("map parse failed: {err}"));
        let entries = map_file
            .entries
            .into_iter()
            .map(|entry| (entry.feature_id, entry.target))
            .collect();
        let mapper = FeatureToBrainMap::new(map_file.map_version, entries);

        let mechint = JsonlMechIntWriter::new("experimental/lnss/out/mechint.jsonl", Some(8192))
            .expect("mechint writer");
        let rig =
            LoggingRigClient::new("experimental/lnss/out/rig.jsonl", 8192).expect("rig writer");

        let sae: Box<dyn SaeBackend> = match sae_pack {
            Some(path) => {
                #[cfg(feature = "lnss-sae-real")]
                {
                    use lnss_sae::{RealSaeBackend, SaeNonlinearity};

                    Box::new(RealSaeBackend::new(path.into(), SaeNonlinearity::Relu))
                }
                #[cfg(not(feature = "lnss-sae-real"))]
                {
                    panic!("lnss-sae-real feature not enabled");
                }
            }
            None => Box::new(StubSaeBackend::new(8)),
        };

        let frames_config = FramesConfig::load_from_dir(".").unwrap_or_else(|err| {
            eprintln!("using fallback frames config: {err}");
            FramesConfig::fallback()
        });
        let frames = WindowEngine::new(frames_config).expect("window engine");
        let sink: Box<dyn LnssEventSink> = Box::new(FramesLnssEventSink::new(frames));

        let mut runtime = LnssRuntime {
            llm: Box::new(StubLlmBackend),
            hooks: Box::new(StubHookProvider { taps: Vec::new() }),
            worldmodel: Box::new(WorldModelCoreStub),
            rlm: Box::new(RlmController::default()),
            orchestrator: CoreOrchestrator,
            sae,
            mechint: Box::new(mechint),
            pvgs: None,
            rig: Box::new(rig),
            mapper,
            limits: Limits::default(),
            injection_limits: lnss_runtime::InjectionLimits::default(),
            active_sae_pack_digest: None,
            active_liquid_params_digest: None,
            active_cfg_root_digest: None,
            shadow_cfg_root_digest: None,
            active_liquid_params: None,
            feedback: FeedbackConsumer::default(),
            adaptation: MappingAdaptationConfig::default(),
            proposal_inbox: None,
            approval_inbox: None,
            activation_now_ms: None,
            event_sink: Some(sink),
            shadow: lnss_runtime::ShadowConfig::default(),
            shadow_rig: None,
            trace_state: None,
            seen_trace_digests: std::collections::BTreeSet::new(),
            lifecycle_index: LifecycleIndex::default(),
            evidence_query_client: None,
            lifecycle_tick: 0,
            policy_mode: PolicyMode::Open,
            control_intent_class: ControlIntentClass::Monitor,
            recursion_policy: RecursionPolicy::default(),
            world_state_digest: [0; 32],
            last_action_digest: [0; 32],
            last_self_state_digest: [0; 32],
            pred_error_threshold: 128,
            trigger_proposals_enabled: true,
        };

        let mods = EmotionFieldSnapshot::new(
            "calm",
            "low",
            "shallow",
            "baseline",
            "stable",
            vec!["overlay".to_string()],
            vec!["reason".to_string()],
        );

        for step in 0..steps {
            let input = format!("lnss-step-{step}").into_bytes();
            runtime
                .run_step(
                    session_id,
                    &format!("step-{step}"),
                    &input,
                    &mods,
                    &plan.specs,
                )
                .expect("lnss step");
        }
    }
}

fn run_inspect_dump(session_id: &str) {
    let mut pvgs = LocalPvgsClient::default();
    let mut inspector = InspectorClient::new(&mut pvgs);
    match inspector.inspect_dump(session_id) {
        Ok(output) => print!("{output}"),
        Err(err) => {
            eprintln!("inspect-dump failed: {err}");
            process::exit(1);
        }
    }
}

fn run_demo() {
    let frames_config = FramesConfig::load_from_dir(".").unwrap_or_else(|err| {
        eprintln!("using fallback frames config: {err}");
        FramesConfig::fallback()
    });
    let aggregator = Arc::new(Mutex::new(
        WindowEngine::new(frames_config).expect("window engine from config"),
    ));
    let control_store = Arc::new(Mutex::new(ControlFrameStore::new()));
    let receipt_store = bootstrap_pvgs_store();
    let gate = Gate {
        policy: PolicyEngine::new(),
        adapter: Box::new(MockAdapter),
        aggregator: aggregator.clone(),
        orchestrator: Arc::new(Mutex::new(CkmOrchestrator::with_aggregator(
            aggregator.clone(),
        ))),
        control_store: control_store.clone(),
        receipt_store: receipt_store.clone(),
        registry: Arc::new(registry_fixture()),
        pvgs_client: Arc::new(Mutex::new(
            Box::new(LocalPvgsClient::default()) as Box<dyn pvgs_client::PvgsClientReader>
        )),
        integrity_issues: Arc::new(Mutex::new(0)),
        decision_log: Arc::new(Mutex::new(DecisionLogStore::default())),
        query_decisions: Arc::new(Mutex::new(gem::QueryDecisionMap::default())),
        rpp_cache: Arc::new(Mutex::new(gem::RppMetaCache::default())),
    };

    let control_frame_m0 = control_frame_m0();
    let control_frame_m1 = control_frame_m1();

    {
        control_store
            .lock()
            .expect("control store lock")
            .update(control_frame_m0.clone())
            .expect("valid control frame");
    }

    let ctx = GateContext {
        integrity_state: "OK".to_string(),
        charter_version_digest: "charter-mvp".to_string(),
        allowed_tools: vec!["mock.read".to_string(), "mock.export".to_string()],
        control_frame: None,
        pvgs_receipt: None,
        approval_grant_id: None,
        pev: None,
        pev_digest: None,
        ruleset_digest: None,
        session_sealed: false,
        session_unlock_permit: false,
    };

    let read_action = ucf::v1::ActionSpec {
        verb: "mock.read/get".to_string(),
        resources: vec!["demo".to_string()],
    };

    let export_action = ucf::v1::ActionSpec {
        verb: "mock.export/render".to_string(),
        resources: vec!["demo".to_string()],
    };

    let result = gate.handle_action_spec("session-1", "step-1", read_action.clone(), ctx.clone());
    print_result(result);

    {
        control_store
            .lock()
            .expect("control store lock")
            .update(control_frame_m1.clone())
            .expect("valid control frame");
    }

    let result = gate.handle_action_spec("session-1", "step-2", read_action.clone(), ctx.clone());
    print_result(result);

    let result = gate.handle_action_spec("session-1", "step-3", export_action, ctx.clone());
    print_result(result);

    let frames = aggregator.lock().expect("aggregator lock").force_flush();

    for frame in frames {
        print_frame_summary(&frame);
    }
}

fn run_scheduler(session_id: &str, ticks: u64) {
    let frames_config = FramesConfig::load_from_dir(".").unwrap_or_else(|err| {
        eprintln!("using fallback frames config: {err}");
        FramesConfig::fallback()
    });
    let mut frames = WindowEngine::new(frames_config).expect("window engine from config");
    let mut pvgs = LocalPvgsClient::default();
    let mut scheduler = ScheduleState::new(100, 250, 200);

    for _ in 0..ticks {
        scheduler.tick(Some(session_id), &mut pvgs, &mut frames);
    }

    let frames = frames.force_flush();
    for frame in frames {
        print_frame_summary(&frame);
    }
}

fn bootstrap_pvgs_store() -> Arc<PvgsKeyEpochStore> {
    const EPOCH_ONE_SEED: [u8; 32] = [1; 32];
    const EPOCH_TWO_SEED: [u8; 32] = [2; 32];

    let epoch_one = key_epoch_fixture(
        1,
        "pvgs-bootstrap-1",
        &SigningKey::from_bytes(&EPOCH_ONE_SEED),
        1_700_000_000_000,
    );
    let epoch_two = key_epoch_fixture(
        2,
        "pvgs-bootstrap-2",
        &SigningKey::from_bytes(&EPOCH_TWO_SEED),
        1_700_000_500_000,
    );

    let mut sync = KeyEpochSync::new(PvgsKeyEpochStore::new());
    sync.sync_from_list(vec![epoch_two, epoch_one])
        .expect("deterministic key epoch sync");

    let receipt = receipt_fixture(&SigningKey::from_bytes(&EPOCH_TWO_SEED), "pvgs-bootstrap-2");
    verify_pvgs_receipt(&receipt, sync.store()).expect("receipt verification");
    println!("sync ok, receipt verify ok");

    Arc::new(sync.store().clone())
}

fn print_result(result: GateResult) {
    match result {
        GateResult::ValidationError { code, message } => {
            println!("DENIED validation_error code={code} message={message}");
        }
        GateResult::Denied { decision } => {
            println!(
                "DENIED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::ApprovalRequired { decision } => {
            println!(
                "APPROVAL_REQUIRED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::SimulationRequired { decision } => {
            println!(
                "SIMULATION_REQUIRED form={:?} reasons={:?}",
                decision.form,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
        GateResult::Executed { decision, outcome } => {
            let outcome_status = match ucf::v1::OutcomeStatus::try_from(outcome.status) {
                Ok(ucf::v1::OutcomeStatus::Success) => "EXECUTED",
                _ => "FAILED",
            };
            let payload_str = String::from_utf8_lossy(&outcome.payload);
            let form_str = match decision.form {
                DecisionForm::AllowWithConstraints => "ALLOW_WITH_CONSTRAINTS",
                DecisionForm::Allow => "ALLOW",
                DecisionForm::Deny => "DENY",
                DecisionForm::RequireApproval => "REQUIRE_APPROVAL",
                DecisionForm::RequireSimulationFirst => "REQUIRE_SIMULATION_FIRST",
            };
            println!(
                "{outcome_status} form={} reasons={:?} payload={payload_str}",
                form_str,
                decision.decision.reason_codes.map(|r| r.codes)
            );
        }
    }
}

fn key_epoch_fixture(
    epoch_id: u64,
    key_id: &str,
    signing_key: &SigningKey,
    timestamp_ms: u64,
) -> ucf::v1::PvgsKeyEpoch {
    let mut key_epoch = ucf::v1::PvgsKeyEpoch {
        epoch_id,
        attestation_key_id: key_id.to_string(),
        attestation_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        announcement_digest: None,
        signature: None,
        timestamp_ms,
        vrf_key_id: Some("pvgs-vrf-demo".to_string()),
    };

    let digest = pvgs_key_epoch_digest(&key_epoch);
    key_epoch.announcement_digest = Some(ucf::v1::Digest32 {
        value: digest.to_vec(),
    });
    let sig = signing_key.sign(&pvgs_key_epoch_signing_preimage(&key_epoch));
    key_epoch.signature = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_id.as_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
    });

    key_epoch
}

fn receipt_fixture(signing_key: &SigningKey, key_id: &str) -> ucf::v1::PvgsReceipt {
    let mut receipt = ucf::v1::PvgsReceipt {
        receipt_epoch: "pvgs-epoch-2".to_string(),
        receipt_id: "demo-receipt".to_string(),
        receipt_digest: Some(sample_digest(1)),
        status: ucf::v1::ReceiptStatus::Accepted.into(),
        action_digest: Some(sample_digest(2)),
        decision_digest: Some(sample_digest(3)),
        grant_id: "demo-grant".to_string(),
        charter_version_digest: Some(sample_digest(4)),
        policy_version_digest: Some(sample_digest(5)),
        prev_record_digest: Some(sample_digest(6)),
        profile_digest: Some(sample_digest(7)),
        tool_profile_digest: Some(sample_digest(8)),
        reject_reason_codes: Vec::new(),
        signer: None,
    };

    let sig = signing_key.sign(&pvgs_receipt_signing_preimage(&receipt));
    receipt.signer = Some(ucf::v1::Signature {
        algorithm: "ed25519".to_string(),
        signer: key_id.as_bytes().to_vec(),
        signature: sig.to_bytes().to_vec(),
    });
    receipt
}

fn sample_digest(seed: u8) -> ucf::v1::Digest32 {
    ucf::v1::Digest32 {
        value: vec![seed; 32],
    }
}

fn print_frame_summary(frame: &ucf::v1::SignalFrame) {
    let policy = frame.policy_stats.as_ref().unwrap();
    let exec = frame.exec_stats.as_ref().unwrap();
    let digest_hex = frame
        .signal_frame_digest
        .as_ref()
        .map(|d| hex::encode(&d.value))
        .unwrap_or_default();

    println!(
        "SIGNAL_FRAME window={} policy_allow={} policy_deny={} exec_success={} exec_failure={} top_rcs={:?} digest={}",
        frame.window.as_ref().map(|w| w.window_id.clone()).unwrap_or_default(),
        policy.allow_count,
        policy.deny_count,
        exec.success_count,
        exec.failure_count,
        policy
            .top_reason_codes
            .iter()
            .map(|rc| rc.code.clone())
            .collect::<Vec<_>>(),
        digest_hex
    );
}

fn control_frame_m0() -> ucf::v1::ControlFrame {
    ucf::v1::ControlFrame {
        frame_id: "cf-m0".to_string(),
        note: "open profile".to_string(),
        active_profile: ucf::v1::ControlFrameProfile::M0Baseline.into(),
        overlays: Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: false,
            ovl_export_lock: false,
            ovl_novelty_lock: false,
        }),
        toolclass_mask: Some(ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        }),
        deescalation_lock: false,
        reason_codes: None,
        evidence_refs: Vec::new(),
    }
}

fn control_frame_m1() -> ucf::v1::ControlFrame {
    ucf::v1::ControlFrame {
        frame_id: "cf-m1".to_string(),
        note: "restricted overlays".to_string(),
        active_profile: ucf::v1::ControlFrameProfile::M1Restricted.into(),
        overlays: Some(ucf::v1::ControlFrameOverlays {
            ovl_simulate_first: true,
            ovl_export_lock: true,
            ovl_novelty_lock: false,
        }),
        toolclass_mask: Some(ucf::v1::ToolClassMask {
            enable_read: true,
            enable_transform: true,
            enable_export: true,
            enable_write: true,
            enable_execute: true,
        }),
        deescalation_lock: true,
        reason_codes: None,
        evidence_refs: Vec::new(),
    }
}
