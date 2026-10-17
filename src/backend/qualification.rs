//! Conservative incumbents and reusable seeds for local calibration.
//! Measurements select performance; model names never authorize fast arithmetic.
use super::{
    CpuEngine, EdTable, HashMode,
    opencl::{DeviceInfo, Tuning},
};
use crate::{
    chains::{AddressType, Chain, Profile},
    coordinator::Config,
    model::SearchStrategy,
};
fn representative(profile: Profile) -> (Chain, AddressType) {
    if profile.is_evm() {
        (Chain::Ethereum, AddressType::Eoa)
    } else {
        (profile.chain, profile.address_type)
    }
}
fn has(profiles: &[(Chain, AddressType)], profile: Profile) -> bool {
    profile.validate().is_ok() && profiles.contains(&representative(profile))
}
/// Context-free initialization stays deterministic on every computer. A resolved
/// execution plan may choose a strategy before creating a new job instead.
pub fn new_strategy(_profile: Profile) -> SearchStrategy {
    SearchStrategy::Linear
}
/// Preserve an accepted GPU enumeration as the local calibration incumbent.
/// A saved/explicit stream always wins. New jobs use the transformed seed only
/// when every selected device can run the checked-in profile/class bundle;
/// this is not a performance qualification for a new model or driver.
pub fn gpu_incumbent_strategy(
    devices: &[&DeviceInfo],
    profile: Profile,
    encoded_suffix: bool,
    fixed: Option<SearchStrategy>,
) -> SearchStrategy {
    if let Some(strategy) = fixed {
        return strategy;
    }
    let transformed = SearchStrategy::EndomorphismV1;
    if profile.address_type != AddressType::P2tr
        && !devices.is_empty()
        && devices.iter().all(|info| {
            gpu(info, profile, transformed, encoded_suffix)
                .is_some_and(|tuning| super::autotune::eligible_tuning(info, profile, &tuning))
        })
    {
        transformed
    } else {
        SearchStrategy::Linear
    }
}
/// Resolve Auto only. Explicit benchmark stages and --baseline remain independent.
pub fn cpu(config: &Config) -> (CpuEngine, HashMode) {
    if !config.batched {
        return (CpuEngine::Reference, HashMode::Scalar);
    }
    let profile = config.profile.unwrap_or_default();
    let engine = match config.cpu_engine {
        CpuEngine::Auto => CpuEngine::Reference,
        explicit => explicit,
    };
    let hash = match config.hash_mode {
        _ if engine == CpuEngine::Reference || profile.address_type == AddressType::P2tr => {
            HashMode::Scalar
        }
        HashMode::Auto => HashMode::Scalar,
        explicit => explicit,
    };
    (engine, hash)
}
/// Previously measured profile bundles are candidates, not hardware allowlists.
/// Runtime ISA dispatch and a correctness test still apply before timing/use.
pub fn cpu_incumbent(
    profile: Profile,
    strategy: SearchStrategy,
    encoded_suffix: bool,
) -> (CpuEngine, HashMode) {
    let measured = (has(CPU_FAST, profile)
        && strategy
            == if profile.address_type == AddressType::P2tr {
                SearchStrategy::Linear
            } else {
                SearchStrategy::EndomorphismV1
            })
        || (strategy == SearchStrategy::Linear
            && has(
                if encoded_suffix {
                    CPU_LINEAR_SUFFIX
                } else {
                    CPU_LINEAR_PREFIX
                },
                profile,
            ));
    if measured {
        (CpuEngine::Batched, HashMode::Simd)
    } else {
        (CpuEngine::Reference, HashMode::Scalar)
    }
}
/// All table APIs are constant-time. Unqualified alternatives stay opt-in.
pub fn ed(config: &Config, _profile: Profile) -> (EdTable, HashMode) {
    if !config.batched {
        return (EdTable::Reference, HashMode::Scalar);
    }
    let table = match config.ed_table {
        EdTable::Auto => EdTable::Reference,
        explicit => explicit,
    };
    let hash = match config.hash_mode {
        _ if table == EdTable::Reference => HashMode::Scalar,
        HashMode::Auto => HashMode::Scalar,
        explicit => explicit,
    };
    (table, hash)
}
// Exact profile/strategy/class gates from five paired20s windows.
// GPU manifest sha256:e20d5ac9429b32e2702a03739d7cd7639bd23221d0bb29e492caf1a84578b34c
const GPU_TRANSFER_FIELDS_PREFIX: &[(Chain, AddressType, SearchStrategy)] = &[
    (
        Chain::Bitcoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Bitcoin, AddressType::P2pkh, SearchStrategy::Linear),
    (Chain::Bitcoin, AddressType::P2tr, SearchStrategy::Linear),
    (
        Chain::Bitcoin,
        AddressType::P2wpkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Bitcoin, AddressType::P2wpkh, SearchStrategy::Linear),
    (
        Chain::BitcoinCash,
        AddressType::Cashaddr,
        SearchStrategy::EndomorphismV1,
    ),
    (
        Chain::BitcoinCash,
        AddressType::Cashaddr,
        SearchStrategy::Linear,
    ),
    (
        Chain::Cosmos,
        AddressType::Account,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Cosmos, AddressType::Account, SearchStrategy::Linear),
    (
        Chain::Dogecoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Dogecoin, AddressType::P2pkh, SearchStrategy::Linear),
    (
        Chain::Litecoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Litecoin, AddressType::P2pkh, SearchStrategy::Linear),
    (
        Chain::Litecoin,
        AddressType::P2wpkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Litecoin, AddressType::P2wpkh, SearchStrategy::Linear),
    (
        Chain::Warthog,
        AddressType::Account,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Warthog, AddressType::Account, SearchStrategy::Linear),
    (
        Chain::Xrp,
        AddressType::Classic,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Xrp, AddressType::Classic, SearchStrategy::Linear),
];

const GPU_TRANSFER_FIELDS_SUFFIX: &[(Chain, AddressType, SearchStrategy)] = &[
    (
        Chain::Bitcoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Bitcoin, AddressType::P2pkh, SearchStrategy::Linear),
    (Chain::Bitcoin, AddressType::P2tr, SearchStrategy::Linear),
    (
        Chain::Bitcoin,
        AddressType::P2wpkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Bitcoin, AddressType::P2wpkh, SearchStrategy::Linear),
    (
        Chain::BitcoinCash,
        AddressType::Cashaddr,
        SearchStrategy::EndomorphismV1,
    ),
    (
        Chain::BitcoinCash,
        AddressType::Cashaddr,
        SearchStrategy::Linear,
    ),
    (
        Chain::Cosmos,
        AddressType::Account,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Cosmos, AddressType::Account, SearchStrategy::Linear),
    (
        Chain::Dogecoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Dogecoin, AddressType::P2pkh, SearchStrategy::Linear),
    (
        Chain::Litecoin,
        AddressType::P2pkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Litecoin, AddressType::P2pkh, SearchStrategy::Linear),
    (
        Chain::Litecoin,
        AddressType::P2wpkh,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Litecoin, AddressType::P2wpkh, SearchStrategy::Linear),
    (
        Chain::Warthog,
        AddressType::Account,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Warthog, AddressType::Account, SearchStrategy::Linear),
    (
        Chain::Xrp,
        AddressType::Classic,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Xrp, AddressType::Classic, SearchStrategy::Linear),
];

const GPU_TRANSFER_TRON_PREFIX: &[(Chain, AddressType, SearchStrategy)] = &[
    (
        Chain::Tron,
        AddressType::Eoa,
        SearchStrategy::EndomorphismV1,
    ),
    (Chain::Tron, AddressType::Eoa, SearchStrategy::Linear),
];

const GPU_TRANSFER_TRON_SUFFIX: &[(Chain, AddressType, SearchStrategy)] =
    &[(Chain::Tron, AddressType::Eoa, SearchStrategy::Linear)];

fn gpu_transfer_has(
    rows: &[(Chain, AddressType, SearchStrategy)],
    profile: Profile,
    strategy: SearchStrategy,
) -> bool {
    // Exact validated keys. Shared EVM Linear reuse is explicit in gpu().
    profile.validate().is_ok() && rows.contains(&(profile.chain, profile.address_type, strategy))
}

pub fn gpu(
    info: &DeviceInfo,
    profile: Profile,
    strategy: SearchStrategy,
    suffix: bool,
) -> Option<Tuning> {
    if !info.nvidia_eligible() {
        return None;
    }
    // Explicit reuse proved for these six labels by the shared program/stream
    // proof and all14 runtime identity controls. Only tuning is reused; callers
    // retain their actual profile and authenticated metadata.
    if strategy == SearchStrategy::Linear
        && profile.validate().is_ok()
        && profile.address_type == AddressType::Eoa
        && matches!(
            profile.chain,
            Chain::Bnb
                | Chain::Polygon
                | Chain::Arbitrum
                | Chain::Optimism
                | Chain::Base
                | Chain::Avalanche
        )
    {
        return gpu_pre_transfer(info, Profile::default(), strategy, suffix);
    }
    let (fields, tron) = if suffix {
        (GPU_TRANSFER_FIELDS_SUFFIX, GPU_TRANSFER_TRON_SUFFIX)
    } else {
        (GPU_TRANSFER_FIELDS_PREFIX, GPU_TRANSFER_TRON_PREFIX)
    };
    let tron = gpu_transfer_has(tron, profile, strategy);
    if !tron && !gpu_transfer_has(fields, profile, strategy) {
        return gpu_pre_transfer(info, profile, strategy, suffix);
    }
    let mut tuning = super::autotune::preset(info);
    tuning.inversion_width = 64;
    tuning.fixed_hash = true;
    tuning.bounded_multiply = true;
    tuning.canonical_field = true;
    tuning.address_keccak = tron;
    tuning.ternary_keccak = tron && info.has_extension("cl_nv_compiler_options");
    tuning.word_match = false;
    if profile.address_type == AddressType::P2tr {
        tuning.max_lanes = tuning.max_lanes.min(4096);
    }
    Some(tuning)
}

// Exact previous gpu() implementation, including Ethereum Linear/Endomorphism,
// Warthog legacy255 and every class that failed or lacked a transfer gate.
fn gpu_pre_transfer(
    info: &DeviceInfo,
    profile: Profile,
    strategy: SearchStrategy,
    suffix: bool,
) -> Option<Tuning> {
    if !info.nvidia_eligible() {
        return None;
    }
    // Preserved Ethereum Linear streams: five 20s windows in both classes.
    // Manifest sha256:3a51f71b7dd43e26f15096cd6d93f58a103ac0f3083d9c81b7f2eeb454bae58f
    // Exact chain match leaves unmeasured Linear EVM labels unchanged.
    let ethereum_linear = profile.chain == Chain::Ethereum
        && profile.address_type == AddressType::Eoa
        && profile.validate().is_ok()
        && strategy == SearchStrategy::Linear;
    let qualified = ethereum_linear
        || (has(GPU_FAST, profile)
            && strategy
                == if profile.address_type == AddressType::P2tr {
                    SearchStrategy::Linear
                } else {
                    SearchStrategy::EndomorphismV1
                });
    let legacy = strategy == SearchStrategy::Linear && !suffix && has(GPU_LINEAR_PREFIX, profile);
    if !qualified && !legacy {
        return None;
    }
    let mut tuning = super::autotune::preset(info);
    tuning.inversion_width = if qualified { 64 } else { 255 };
    tuning.fixed_hash = true;
    // Ethereum full-search qualification sha256:94d4cb3ec342a3d757e4fed4b675a3fb77ffe8faabb7062b0fe286352e23db19
    tuning.address_keccak = qualified && profile.is_evm();
    // Complete-search qualification sha256:30610291afbfd40c2d3fdbfea3b9b6d3b48ccec7a3c75d490eab62e5ac19dafc
    tuning.bounded_multiply = qualified && profile.is_evm();
    tuning.canonical_field = qualified && profile.is_evm();
    tuning.word_match = qualified && profile.is_evm();
    tuning.ternary_keccak =
        qualified && profile.is_evm() && info.has_extension("cl_nv_compiler_options");
    Some(tuning)
}

// BEGIN MEASURED POLICY
// Five 20-second windows per case; every paired ratio must be >= 1.05.
// qualification-summary.json sha256:2eb227c5c071269a2ea7331605ac57efe1a0f807d697f5fa080494e6c5a5609c
// ablation-summary.json sha256:222f5af5ba410ce91ab3f31d462690057d3098686fa55a601382f1a9332e12b8
// original-release-summary.json sha256:315c124a0d37c2051d63dfee6fb3ba904de847cdd34f83c0e89d307c9b15d94e
// bch-repeat-summary.json sha256:4b3fb57036174ea7b61a7ff938c0ffbcdaab0a961dad6a05259d939e66e79cb8
const CPU_FAST: &[(Chain, AddressType)] = &[
    (Chain::Bitcoin, AddressType::P2pkh),
    (Chain::Bitcoin, AddressType::P2wpkh),
    (Chain::BitcoinCash, AddressType::Cashaddr),
    (Chain::Cosmos, AddressType::Account),
    (Chain::Dogecoin, AddressType::P2pkh),
    (Chain::Ethereum, AddressType::Eoa),
    (Chain::Litecoin, AddressType::P2pkh),
    (Chain::Litecoin, AddressType::P2wpkh),
    (Chain::Tron, AddressType::Eoa),
    (Chain::Warthog, AddressType::Account),
    (Chain::Xrp, AddressType::Classic),
];
// Saved Linear qualification manifest sha256:7cd0e37a4d2ffe14c3eb31573356563a0a50086102b54717b0a197ecdb11e70b
const CPU_LINEAR_PREFIX: &[(Chain, AddressType)] = &[
    (Chain::Bitcoin, AddressType::P2pkh),
    (Chain::Bitcoin, AddressType::P2wpkh),
    (Chain::BitcoinCash, AddressType::Cashaddr),
    (Chain::Cosmos, AddressType::Account),
    (Chain::Dogecoin, AddressType::P2pkh),
    (Chain::Ethereum, AddressType::Eoa),
    (Chain::Litecoin, AddressType::P2pkh),
    (Chain::Litecoin, AddressType::P2wpkh),
    (Chain::Tron, AddressType::Eoa),
    (Chain::Warthog, AddressType::Account),
    (Chain::Xrp, AddressType::Classic),
];
const CPU_LINEAR_SUFFIX: &[(Chain, AddressType)] = &[
    (Chain::Bitcoin, AddressType::P2pkh),
    (Chain::Bitcoin, AddressType::P2wpkh),
    (Chain::BitcoinCash, AddressType::Cashaddr),
    (Chain::Cosmos, AddressType::Account),
    (Chain::Dogecoin, AddressType::P2pkh),
    (Chain::Ethereum, AddressType::Eoa),
    (Chain::Litecoin, AddressType::P2pkh),
    (Chain::Litecoin, AddressType::P2wpkh),
    (Chain::Tron, AddressType::Eoa),
    (Chain::Warthog, AddressType::Account),
    (Chain::Xrp, AddressType::Classic),
];
const GPU_FAST: &[(Chain, AddressType)] = &[
    (Chain::Bitcoin, AddressType::P2pkh),
    (Chain::Bitcoin, AddressType::P2tr),
    (Chain::Bitcoin, AddressType::P2wpkh),
    (Chain::BitcoinCash, AddressType::Cashaddr),
    (Chain::Cosmos, AddressType::Account),
    (Chain::Dogecoin, AddressType::P2pkh),
    (Chain::Ethereum, AddressType::Eoa),
    (Chain::Litecoin, AddressType::P2pkh),
    (Chain::Litecoin, AddressType::P2wpkh),
    (Chain::Tron, AddressType::Eoa),
    (Chain::Warthog, AddressType::Account),
    (Chain::Xrp, AddressType::Classic),
];
const GPU_LINEAR_PREFIX: &[(Chain, AddressType)] = &[(Chain::Warthog, AddressType::Account)];
// END MEASURED POLICY

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gpu_incumbent_preserves_accepted_stream_only_for_common_eligible_bundles() {
        let info: DeviceInfo = serde_json::from_value(serde_json::json!({
            "index":0,"name":"unknown NVIDIA label","vendor":"diagnostic label",
            "vendor_id":0x10de,"compute_capability":null,"warp_size":null,
            "platform":"generic ICD","driver":"new driver","api":"OpenCL 3.0",
            "language":"OpenCL C 1.2","memory_bytes":8_589_934_592u64,
            "max_allocation_bytes":2_147_483_648u64,"compute_units":24,
            "max_work_group":1024,"integer_width":1,"extensions":"",
            "physical_id":null,"suitable":true,"self_test":"not run"
        }))
        .unwrap();
        let mut other = info.clone();
        other.index = 3;
        other.name = "a different diagnostic model".into();
        other.compute_capability = Some((12, 0));
        let linear = SearchStrategy::Linear;
        let transformed = SearchStrategy::EndomorphismV1;
        for row in crate::chains::registry() {
            let profile = row.profile;
            for suffix in [false, true] {
                let expected = if profile.address_type == AddressType::P2tr
                    || profile.key_family() == crate::chains::KeyFamily::Ed25519
                {
                    linear
                } else {
                    transformed
                };
                assert_eq!(
                    gpu_incumbent_strategy(&[&info, &other], profile, suffix, None),
                    expected
                );
                assert_eq!(
                    gpu_incumbent_strategy(&[&info, &other], profile, suffix, Some(linear)),
                    linear
                );
                // Existing transformed Taproot streams also retain their exact strategy.
                assert_eq!(
                    gpu_incumbent_strategy(&[&info, &other], profile, suffix, Some(transformed)),
                    transformed
                );
                assert_eq!(new_strategy(profile), linear);
            }
        }
        assert_eq!(
            gpu_incumbent_strategy(&[], Profile::default(), false, None),
            linear
        );
        other.vendor_id = 0x1002;
        assert_eq!(
            gpu_incumbent_strategy(&[&info, &other], Profile::default(), false, None),
            linear
        );
        other = info.clone();
        other.max_allocation_bytes = 0;
        assert_eq!(
            gpu_incumbent_strategy(&[&info, &other], Profile::default(), true, None),
            linear
        );
        other = info.clone();
        other.suitable = false;
        assert_eq!(
            gpu_incumbent_strategy(&[&info, &other], Profile::default(), false, None),
            linear
        );
        let invalid = Profile {
            chain: Chain::Bnb,
            address_type: AddressType::P2pkh,
            ..Profile::default()
        };
        assert_eq!(
            gpu_incumbent_strategy(&[&info], invalid, false, None),
            linear
        );
    }
    #[test]
    fn context_free_initialization_and_uncalibrated_cpu_are_portable() {
        for profile in crate::chains::registry().into_iter().map(|v| v.profile) {
            assert_eq!(new_strategy(profile), SearchStrategy::Linear);
            let config = Config {
                profile: Some(profile),
                ..Config::default()
            };
            assert_eq!(cpu(&config), (CpuEngine::Reference, HashMode::Scalar));
            assert_eq!(ed(&config, profile), (EdTable::Reference, HashMode::Scalar));
        }
        let explicit = Config {
            cpu_engine: CpuEngine::Batched,
            hash_mode: HashMode::Simd,
            ..Config::default()
        };
        assert_eq!(cpu(&explicit), (CpuEngine::Batched, HashMode::Simd));
        assert_eq!(
            cpu_incumbent(Profile::default(), SearchStrategy::Linear, false),
            (CpuEngine::Batched, HashMode::Simd)
        );
    }
    #[test]
    fn nvidia_capabilities_accept_generations_and_preserve_incumbents() {
        let mut info = DeviceInfo {
            index: 0,
            name: "NVIDIA GeForce RTX 4060".into(),
            vendor: "NVIDIA Corporation".into(),
            vendor_id: 0x10de,
            compute_capability: Some((8, 9)),
            warp_size: Some(32),
            platform: "NVIDIA CUDA".into(),
            driver: "610.88".into(),
            api: "OpenCL 3.0 CUDA".into(),
            language: "OpenCL C 1.2".into(),
            memory_bytes: 8 * 1024 * 1024 * 1024,
            max_allocation_bytes: 2 * 1024 * 1024 * 1024,
            compute_units: 24,
            max_work_group: 1024,
            integer_width: 64,
            extensions: "cl_nv_compiler_options".into(),
            physical_id: None,
            suitable: true,
            self_test: String::new(),
        };
        assert!(info.nvidia_eligible());
        {
            let strategy = SearchStrategy::EndomorphismV1;
            assert!(
                gpu(&info, Profile::default(), strategy, false)
                    .unwrap()
                    .address_keccak
            );
            let tron = Profile::new(Chain::Tron, None).unwrap();
            let tron_prefix = gpu(&info, tron, strategy, false).unwrap();
            assert!(tron_prefix.address_keccak && tron_prefix.ternary_keccak);
            assert!(tron_prefix.bounded_multiply && tron_prefix.canonical_field);
            assert!(!tron_prefix.word_match);
            // The failed suffix gate must retain the complete old tuning.
            let tron_suffix = gpu(&info, tron, strategy, true).unwrap();
            assert_eq!(
                serde_json::to_value(&tron_suffix).unwrap(),
                serde_json::to_value(gpu_pre_transfer(&info, tron, strategy, true).unwrap())
                    .unwrap()
            );
            assert!(!tron_suffix.address_keccak && !tron_suffix.bounded_multiply);
            for suffix in [false, true] {
                let tron_linear = gpu(&info, tron, SearchStrategy::Linear, suffix).unwrap();
                assert!(tron_linear.address_keccak && tron_linear.ternary_keccak);
                assert!(tron_linear.bounded_multiply && tron_linear.canonical_field);
                assert!(!tron_linear.word_match);
            }
            // A narrow but passing gate remains selected; Taproot keeps Linear.
            let bitcoin = Profile::new(Chain::Bitcoin, Some(AddressType::P2pkh)).unwrap();
            assert!(
                gpu(&info, bitcoin, strategy, true)
                    .unwrap()
                    .bounded_multiply
            );
            let taproot = Profile::new(Chain::Bitcoin, Some(AddressType::P2tr)).unwrap();
            for suffix in [false, true] {
                let tuning = gpu(&info, taproot, SearchStrategy::Linear, suffix).unwrap();
                assert_eq!(tuning.max_lanes, 4096);
                assert!(tuning.bounded_multiply && tuning.canonical_field);
                assert!(gpu(&info, taproot, strategy, suffix).is_none());
            }
            for suffix in [false, true] {
                let linear = gpu(&info, Profile::default(), SearchStrategy::Linear, suffix)
                    .expect("both Ethereum Linear pattern classes passed measured gates");
                assert_eq!(linear.inversion_width, 64);
                assert!(linear.fixed_hash && linear.fast_field && linear.interleaved_inverse);
                assert!(linear.bounded_multiply && linear.canonical_field);
                assert!(linear.address_keccak && linear.word_match && linear.ternary_keccak);
                for chain in [
                    Chain::Bnb,
                    Chain::Polygon,
                    Chain::Arbitrum,
                    Chain::Optimism,
                    Chain::Base,
                    Chain::Avalanche,
                ] {
                    let alias = Profile::new(chain, None).unwrap();
                    let shared = gpu(&info, alias, SearchStrategy::Linear, suffix).unwrap();
                    assert_eq!(
                        serde_json::to_value(&shared).unwrap(),
                        serde_json::to_value(&linear).unwrap()
                    );
                }
                let invalid_alias = Profile {
                    chain: Chain::Bnb,
                    address_type: AddressType::P2pkh,
                    ..Profile::default()
                };
                assert!(gpu(&info, invalid_alias, SearchStrategy::Linear, suffix).is_none());
                for chain in [Chain::Solana, Chain::Stellar, Chain::Algorand] {
                    assert!(
                        gpu(
                            &info,
                            Profile::new(chain, None).unwrap(),
                            SearchStrategy::Linear,
                            suffix
                        )
                        .is_none()
                    );
                }
            }
        }
        info.driver = "unmeasured driver".into();
        info.platform = "Other OpenCL platform".into();
        for (name, capability) in [
            ("RTX 3060 Laptop", Some((8, 6))),
            ("RTX 4090", Some((8, 9))),
            ("RTX 5060 Ti", Some((12, 0))),
            ("Unknown NVIDIA model", None),
        ] {
            info.name = name.into();
            info.compute_capability = capability;
            assert!(info.nvidia_eligible());
            assert!(gpu(&info, Profile::default(), SearchStrategy::Linear, false).is_some());
        }
        info.extensions.clear();
        assert!(
            !gpu(&info, Profile::default(), SearchStrategy::Linear, false)
                .unwrap()
                .ternary_keccak
        );
        info.vendor_id = 0x1002;
        assert!(!info.nvidia_eligible());
        assert!(gpu(&info, Profile::default(), SearchStrategy::Linear, false).is_none());
    }
    #[test]
    fn baseline_overrides_all_automatic_choices() {
        let config = Config {
            batched: false,
            cpu_engine: CpuEngine::Batched,
            hash_mode: HashMode::Simd,
            ed_table: EdTable::calibration_candidates().last().copied().unwrap(),
            ..Config::default()
        };
        assert_eq!(cpu(&config), (CpuEngine::Reference, HashMode::Scalar));
        assert_eq!(
            ed(&config, Profile::default()),
            (EdTable::Reference, HashMode::Scalar)
        );
    }
    #[test]
    fn reference_ed_table_reports_the_hash_path_it_actually_uses() {
        let config = Config {
            ed_table: EdTable::Reference,
            hash_mode: HashMode::Simd,
            ..Config::default()
        };
        assert_eq!(
            ed(&config, Profile::default()),
            (EdTable::Reference, HashMode::Scalar)
        );
    }
}
