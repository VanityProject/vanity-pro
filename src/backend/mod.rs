pub mod autotune;
pub mod calibration;
pub(crate) mod calibration_sampling;
pub mod cpu;
pub(crate) mod hashes;
pub mod opencl;
mod public_batch;
pub mod qualification;
/// Maximum durable interval; workers may execute it through bounded dispatches.
pub const MAX_BATCH: u32 = 16_777_216;
use crate::model::{Candidate, Interval, Job};
use anyhow::Result;
use serde::Serialize;
use std::sync::atomic::AtomicBool;

#[derive(Debug)]
pub struct CorrectnessError(pub String);
impl std::fmt::Display for CorrectnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cryptographic correctness failure: {}", self.0)
    }
}
impl std::error::Error for CorrectnessError {}
pub fn correct(condition: bool, message: impl Into<String>) -> Result<()> {
    if !condition {
        return Err(CorrectnessError(message.into()).into());
    }
    Ok(())
}

/// A cryptographic fault must never turn into an ordinary fallback because a
/// different worker failed or panicked first. Preserve the first fault of the
/// highest priority; anyhow's downcast also recognizes contextualized faults.
pub(crate) fn retain_failure(slot: &mut Option<anyhow::Error>, error: anyhow::Error) {
    let incoming_correctness = error.downcast_ref::<CorrectnessError>().is_some();
    let replace = match slot.as_ref() {
        None => true,
        Some(existing) => {
            incoming_correctness && existing.downcast_ref::<CorrectnessError>().is_none()
        }
    };
    if replace {
        *slot = Some(error);
    }
}

#[derive(Debug)]
pub struct BatchResult {
    pub completed: u32,
    pub evaluated: u32,
    pub candidate: Option<Candidate>,
    pub seconds: f64,
}
/// Every input and output is public. Implementations own their runtime resources.
pub trait Compute: Send {
    fn name(&self) -> String;
    fn diagnostics(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    fn self_test(&mut self) -> Result<()>;
    fn run(&mut self, job: &Job, range: &Interval, cancel: &AtomicBool) -> Result<BatchResult>;
}
#[derive(Debug, Clone, Serialize)]
pub struct CpuInfo {
    pub logical_processors: usize,
    pub model: String,
    /// CPUID vendor and signature are diagnostic/cache identity, never ISA gates.
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub family: Option<u32>,
    #[serde(default)]
    pub model_id: Option<u32>,
    #[serde(default)]
    pub stepping: Option<u32>,
    pub architecture: &'static str,
    pub instruction_sets: Vec<&'static str>,
    pub arithmetic: &'static str,
}
pub fn cpu_info() -> CpuInfo {
    let mut instruction_sets = vec![];
    let mut model = std::env::consts::ARCH.to_owned();
    #[cfg(target_arch = "x86_64")]
    let vendor;
    #[cfg(not(target_arch = "x86_64"))]
    let vendor = String::new();
    let mut family = None;
    let mut model_id = None;
    let mut stepping = None;
    #[cfg(target_arch = "x86_64")]
    {
        #[allow(unused_unsafe)] // CPUID became safe after the minimum supported Rust release.
        // SAFETY: x86_64 supports CPUID; extended leaves are checked first.
        unsafe {
            let basic = std::arch::x86_64::__cpuid(0);
            let mut vendor_bytes = Vec::with_capacity(12);
            for word in [basic.ebx, basic.edx, basic.ecx] {
                vendor_bytes.extend_from_slice(&word.to_le_bytes());
            }
            vendor = String::from_utf8_lossy(&vendor_bytes).into_owned();
            if basic.eax >= 1 {
                let signature = std::arch::x86_64::__cpuid(1).eax;
                let (f, m, s) = cpu_signature(signature);
                family = Some(f);
                model_id = Some(m);
                stepping = Some(s);
            }
            if std::arch::x86_64::__cpuid(0x80000000).eax >= 0x80000004 {
                let mut bytes = vec![];
                for leaf in 0x80000002..=0x80000004 {
                    let r = std::arch::x86_64::__cpuid(leaf);
                    for word in [r.eax, r.ebx, r.ecx, r.edx] {
                        bytes.extend_from_slice(&word.to_le_bytes());
                    }
                }
                model = String::from_utf8_lossy(&bytes)
                    .trim_matches('\0')
                    .trim()
                    .to_owned();
            }
        }
        for (name, available) in [
            ("sse2", std::is_x86_feature_detected!("sse2")),
            ("sha", std::is_x86_feature_detected!("sha")),
            ("avx2", std::is_x86_feature_detected!("avx2")),
            ("avx512f", std::is_x86_feature_detected!("avx512f")),
            ("bmi2", std::is_x86_feature_detected!("bmi2")),
            ("adx", std::is_x86_feature_detected!("adx")),
        ] {
            if available {
                instruction_sets.push(name);
            }
        }
    }
    CpuInfo {
        logical_processors: std::thread::available_parallelism().map_or(1, usize::from),
        model,
        vendor,
        family,
        model_id,
        stepping,
        architecture: std::env::consts::ARCH,
        instruction_sets,
        arithmetic: "public affine batching / libsecp256k1 reference; runtime hash dispatch",
    }
}

/// Architectural CPUID signature decoding; it does not execute optional ISA.
fn cpu_signature(signature: u32) -> (u32, u32, u32) {
    let base_family = (signature >> 8) & 15;
    let family = if base_family == 15 {
        base_family + ((signature >> 20) & 255)
    } else {
        base_family
    };
    let mut model = (signature >> 4) & 15;
    if base_family == 6 || base_family == 15 {
        model |= ((signature >> 16) & 15) << 4;
    }
    (family, model, signature & 15)
}

/// Diagnostic name for the actual runtime hash dispatch. Scalar tails still
/// apply when a microbatch is shorter than the selected vector width.
pub fn hash_dispatch(profile: crate::chains::Profile, simd: bool) -> &'static str {
    hash_dispatch_with_features(profile, simd, &cpu_info().instruction_sets)
}

fn hash_dispatch_with_features(
    profile: crate::chains::Profile,
    simd: bool,
    features: &[&str],
) -> &'static str {
    use crate::chains::{AddressType, Chain, KeyFamily};
    let avx2 = simd && features.contains(&"avx2");
    if profile.key_family() == KeyFamily::Ed25519 {
        if avx2 {
            "avx2-sha512-x4"
        } else {
            "library-sha512"
        }
    } else if profile.address_type == AddressType::P2tr {
        "library-taptweak-sha256"
    } else if profile.is_evm() || profile.chain == Chain::Tron {
        if avx2 {
            "avx2-keccak-x4"
        } else {
            "scalar-keccak"
        }
    } else if avx2 {
        "avx2-hash160-x8"
    } else if simd && features.contains(&"sse2") {
        "sse2-hash160-x4"
    } else {
        "scalar-or-library-hardware"
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum CpuEngine {
    #[default]
    Auto,
    Reference,
    Batched,
}
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum HashMode {
    #[default]
    Auto,
    Scalar,
    Simd,
}
impl HashMode {
    pub fn simd(self) -> bool {
        self != Self::Scalar
    }
}
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum EdTable {
    #[default]
    Auto,
    Reference,
    #[cfg(feature = "developer-tools")]
    Radix16,
    #[cfg(feature = "developer-tools")]
    Radix32,
    #[cfg(feature = "developer-tools")]
    Radix64,
    #[cfg(feature = "developer-tools")]
    Radix256,
}
impl EdTable {
    pub(crate) fn calibration_candidates() -> &'static [Self] {
        &[
            Self::Reference,
            #[cfg(feature = "developer-tools")]
            Self::Radix16,
            #[cfg(feature = "developer-tools")]
            Self::Radix32,
            #[cfg(feature = "developer-tools")]
            Self::Radix64,
            #[cfg(feature = "developer-tools")]
            Self::Radix256,
        ]
    }
}

/// Logical dispatch bounds align full point families with stable GPU geometry.
pub fn aligned_batch(job: &Job, requested: u32, gpu: bool) -> u32 {
    let width = u32::from(job.width());
    if !gpu || width == 1 || requested < width {
        return requested;
    }
    let bases = requested / width;
    let bases = 1u32 << (u32::BITS - 1 - bases.leading_zeros());
    bases * width
}

#[cfg(test)]
mod cpu_metadata_tests {
    use super::*;

    #[test]
    fn cpuid_signature_decodes_amd_and_intel_extended_fields() {
        assert_eq!(cpu_signature(0x00a20f12), (25, 33, 2));
        assert_eq!(cpu_signature(0x000b0671), (6, 183, 1));
        assert_eq!(cpu_signature(0x00000423), (4, 2, 3));
    }

    #[test]
    fn reported_instructions_are_os_usable() {
        let info = cpu_info();
        assert!(info.logical_processors > 0);
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(
                info.instruction_sets.contains(&"avx2"),
                std::is_x86_feature_detected!("avx2")
            );
            assert_eq!(
                info.instruction_sets.contains(&"sse2"),
                std::is_x86_feature_detected!("sse2")
            );
            assert!(!info.vendor.is_empty());
            assert!(info.family.is_some());
        }
    }

    #[test]
    fn masked_hash_features_choose_only_usable_implementations() {
        use crate::chains::{AddressType, Chain, Profile};
        let ethereum = Profile::default();
        let tron = Profile::new(Chain::Tron, None).unwrap();
        let bitcoin = Profile::new(Chain::Bitcoin, Some(AddressType::P2pkh)).unwrap();
        let taproot = Profile::new(Chain::Bitcoin, Some(AddressType::P2tr)).unwrap();
        let solana = Profile::new(Chain::Solana, None).unwrap();
        for features in [&[][..], &["sse2"][..]] {
            assert_eq!(
                hash_dispatch_with_features(ethereum, true, features),
                "scalar-keccak"
            );
            assert_eq!(
                hash_dispatch_with_features(tron, true, features),
                "scalar-keccak"
            );
            assert_eq!(
                hash_dispatch_with_features(solana, true, features),
                "library-sha512"
            );
            assert_eq!(
                hash_dispatch_with_features(taproot, true, features),
                "library-taptweak-sha256"
            );
        }
        assert_eq!(
            hash_dispatch_with_features(bitcoin, true, &[]),
            "scalar-or-library-hardware"
        );
        assert_eq!(
            hash_dispatch_with_features(bitcoin, true, &["sse2"]),
            "sse2-hash160-x4"
        );
        assert_eq!(
            hash_dispatch_with_features(bitcoin, true, &["sse2", "avx2"]),
            "avx2-hash160-x8"
        );
        assert_eq!(
            hash_dispatch_with_features(ethereum, true, &["sse2", "avx2"]),
            "avx2-keccak-x4"
        );
        assert_eq!(
            hash_dispatch_with_features(tron, true, &["sse2", "avx2"]),
            "avx2-keccak-x4"
        );
        assert_eq!(
            hash_dispatch_with_features(solana, true, &["sse2", "avx2"]),
            "avx2-sha512-x4"
        );
        assert_eq!(
            hash_dispatch_with_features(bitcoin, false, &["sse2", "avx2"]),
            "scalar-or-library-hardware"
        );
        assert_eq!(
            hash_dispatch_with_features(ethereum, false, &["sse2", "avx2"]),
            "scalar-keccak"
        );
        assert_eq!(
            hash_dispatch_with_features(solana, false, &["sse2", "avx2"]),
            "library-sha512"
        );
        assert_eq!(
            hash_dispatch_with_features(taproot, true, &["sse2", "avx2"]),
            "library-taptweak-sha256"
        );
    }
}
