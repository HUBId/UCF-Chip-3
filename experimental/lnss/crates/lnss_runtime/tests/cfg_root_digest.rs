use lnss_core::{FeatureToBrainMap, RlmCore, TapKind, TapSpec, WorldModelCore};
use lnss_rlm::RlmController;
use lnss_runtime::{
    cfg_root_digest_pack, CfgRootDigestInputs, InjectionLimits, Limits, StubLlmBackend,
    DEFAULT_AMPLITUDE_CAP_Q,
};
use lnss_worldmodel::WorldModelCoreStub;

fn sample_mapping(version: u32, amplitude_q: u16) -> FeatureToBrainMap {
    let target = lnss_core::BrainTarget::new("v1", "pop", 1, "syn", amplitude_q);
    FeatureToBrainMap::new(version, vec![(1, target)])
}

fn base_inputs() -> (
    StubLlmBackend,
    Vec<TapSpec>,
    WorldModelCoreStub,
    RlmController,
    Limits,
    InjectionLimits,
) {
    let llm = StubLlmBackend;
    let tap_specs = vec![TapSpec::new("hook-a", TapKind::ResidualStream, 0, "resid")];
    let worldmodel = WorldModelCoreStub;
    let rlm = RlmController::default();
    let limits = Limits::default();
    let injection_limits = InjectionLimits::default();
    (llm, tap_specs, worldmodel, rlm, limits, injection_limits)
}

#[test]
fn cfg_root_digest_is_deterministic() {
    let (llm, tap_specs, worldmodel, rlm, limits, injection_limits) = base_inputs();
    let mapping = sample_mapping(1, 900);
    let world_cfg = worldmodel.cfg_snapshot();
    let rlm_cfg = rlm.cfg_snapshot();

    let first = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    let second = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");

    assert_eq!(first.root_cfg_digest, second.root_cfg_digest);
}

#[test]
fn cfg_root_digest_changes_with_limits_or_mapping() {
    let (llm, tap_specs, worldmodel, rlm, limits, mut injection_limits) = base_inputs();
    let mapping = sample_mapping(1, 900);
    let world_cfg = worldmodel.cfg_snapshot();
    let rlm_cfg = rlm.cfg_snapshot();
    let baseline = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");

    injection_limits.max_spikes_per_tick += 1;
    let updated_limits = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    assert_ne!(baseline.root_cfg_digest, updated_limits.root_cfg_digest);

    let mapping_changed = sample_mapping(2, 900);
    let updated_mapping = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping_changed,
        limits: &limits,
        injection_limits: &InjectionLimits::default(),
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    assert_ne!(baseline.root_cfg_digest, updated_mapping.root_cfg_digest);
}

#[test]
fn shadow_cfg_root_digest_changes_only_with_shadow_config() {
    let (llm, tap_specs, worldmodel, rlm, limits, injection_limits) = base_inputs();
    let mapping = sample_mapping(1, 900);
    let world_cfg = worldmodel.cfg_snapshot();
    let rlm_cfg = rlm.cfg_snapshot();

    let active = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    let shadow_same = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    assert_eq!(active.root_cfg_digest, shadow_same.root_cfg_digest);

    let shadow_mapping = sample_mapping(1, 800);
    let shadow_changed = cfg_root_digest_pack(CfgRootDigestInputs {
        llm: &llm,
        tap_specs: &tap_specs,
        worldmodel_cfg: &world_cfg,
        rlm_cfg: &rlm_cfg,
        sae_pack_digest: Some([7u8; 32]),
        mapping: &shadow_mapping,
        limits: &limits,
        injection_limits: &injection_limits,
        amplitude_cap_q: DEFAULT_AMPLITUDE_CAP_Q,
        policy_digest: None,
        liquid_params_digest: None,
    })
    .expect("cfg pack");
    assert_ne!(active.root_cfg_digest, shadow_changed.root_cfg_digest);
}
