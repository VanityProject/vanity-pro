//! Correctness-gated public-only tuning. Saved settings are data, never executable
//! GPU binaries, and every selected configuration still passes startup self-test.
#[cfg(feature = "developer-tools")]
use super::Compute;
#[cfg(any(test, feature = "developer-tools"))]
use super::CorrectnessError;
use super::opencl::{self, Curve, DeviceInfo, Opencl, Tuning};
use crate::storage;
#[cfg(feature = "developer-tools")]
use crate::{
    crypto::{Pattern, generator},
    model::{Interval, Job},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
#[cfg(feature = "developer-tools")]
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema: u32,
    key: String,
    tuning: Tuning,
    median_per_second: f64,
}
pub fn default_directory() -> Option<PathBuf> {
    crate::desktop::default_data_directory()
        .ok()
        .filter(|p| p.is_absolute())
        .map(|p| p.join("GpuTuning"))
}
pub fn fingerprint(info: &DeviceInfo) -> Result<String> {
    let mut digest = Sha256::new();
    let device = serde_json::to_string(&info.cache_identity())?;
    for text in [
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        opencl::OPTIONS,
        &device,
        env!("VANITY_OPENCL_IMPLEMENTATION"),
    ] {
        digest.update((text.len() as u64).to_be_bytes());
        digest.update(text.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}
/// Profile/strategy/matching-class namespace; cached settings never change job enumeration.
pub fn fingerprint_profile(
    info: &DeviceInfo,
    profile: crate::chains::Profile,
    strategy: crate::model::SearchStrategy,
    encoded_suffix: bool,
) -> Result<String> {
    let mut h = Sha256::new();
    h.update(fingerprint(info)?.as_bytes());
    h.update(serde_json::to_vec(&(profile, strategy, encoded_suffix))?);
    Ok(hex::encode(h.finalize()))
}
pub fn resolve_profile(
    info: &DeviceInfo,
    directory: Option<&Path>,
    profile: crate::chains::Profile,
    strategy: crate::model::SearchStrategy,
    encoded_suffix: bool,
) -> Result<(Tuning, &'static str)> {
    if let Some(dir) = directory {
        let _guard = storage::guard(dir)?;
        if storage::exists(dir)? {
            storage::assert_private_directory(dir)?;
            let key = fingerprint_profile(info, profile, strategy, encoded_suffix)?;
            let path = dir.join(format!("tuning-{key}.json"));
            if let Ok(saved) = storage::read_private_json::<Saved>(&path)
                && saved.schema == 2
                && saved.key == key
                && saved.median_per_second.is_finite()
                && saved.median_per_second > 0.
                && eligible_tuning(info, profile, &saved.tuning)
            {
                return Ok((saved.tuning, "validated profile cache"));
            }
        }
    }
    if let Some(tuning) = super::qualification::gpu(info, profile, strategy, encoded_suffix) {
        return Ok((tuning, "measured profile incumbent"));
    }
    let mut tuning = preset(info);
    profile_bounds(info, profile, &mut tuning);
    ensure!(
        eligible_tuning(info, profile, &tuning),
        "no legal GPU preset for profile/device"
    );
    Ok((tuning, "portable profile preset"))
}
pub fn open_automatic(index: usize, directory: Option<&Path>) -> Result<Opencl> {
    let info = opencl::discover()?
        .into_iter()
        .find(|d| d.index == index)
        .context("unknown GPU")?;
    let (tuning, origin) = resolve_profile(
        &info,
        directory,
        Default::default(),
        crate::model::SearchStrategy::EndomorphismV1,
        false,
    )?;
    let mut worker = Opencl::with_tuning(index, true, None, tuning)?;
    worker.tuning_origin = origin.into();
    Ok(worker)
}
pub fn preset(info: &DeviceInfo) -> Tuning {
    // Capability-compatible NVIDIA devices start from the accepted 4060 bundle.
    // This is an incumbent, not a claim that other hardware has been benchmarked.
    let mut tuning = if info.nvidia_eligible() {
        Tuning {
            curve: Curve::Recurrence,
            fast_field: true,
            inversion_width: 255,
            work_group_size: if info.max_work_group >= 64 { 64 } else { 32 },
            poll_microseconds: 0,
            max_lanes: 4_194_304,
            interleaved_inverse: true,
            tuned_keccak: true,
            ..Tuning::default()
        }
    } else {
        Tuning {
            curve: Curve::Recurrence,
            fast_field: true,
            inversion_width: 128,
            work_group_size: if info.vendor_id == 0x10de && info.max_work_group >= 32 {
                32
            } else {
                0
            },
            poll_microseconds: 50,
            max_lanes: 1_048_576,
            ..Tuning::default()
        }
    };
    bound_lanes(info, &mut tuning);
    tuning
}
fn lane_limit(info: &DeviceInfo) -> usize {
    // Conservative bound for the largest shipped per-lane buffer and aggregate
    // live state. Runtime allocation/kernel checks remain authoritative.
    let allocation = info.max_allocation_bytes / 96;
    let total = (info.memory_bytes / 2).saturating_sub(400_000) / 256;
    allocation.min(total).min(4_194_304) as usize
}
fn bound_lanes(info: &DeviceInfo, tuning: &mut Tuning) {
    tuning.max_lanes = tuning.max_lanes.min(lane_limit(info).max(1));
}
/// Reject impossible configurations before invoking the driver. Compiled-kernel
/// resource checks and cryptographic startup tests are still required.
pub fn eligible_tuning(
    info: &DeviceInfo,
    profile: crate::chains::Profile,
    tuning: &Tuning,
) -> bool {
    use crate::chains::{AddressType, Chain, KeyFamily};
    info.suitable
        && info.max_work_group > 0
        && profile.validate().is_ok()
        && profile.key_family() == KeyFamily::Secp256k1
        && tuning.validate().is_ok()
        && tuning.work_group_size <= info.max_work_group
        && tuning.max_lanes <= lane_limit(info)
        && (profile.address_type != AddressType::P2tr || tuning.max_lanes <= 4096)
        && (!tuning.word_match || profile.is_evm())
        && (!tuning.address_keccak || profile.is_evm() || profile.chain == Chain::Tron)
        && (!tuning.ternary_keccak
            || (info.vendor_id == 0x10de
                && info.has_extension("cl_nv_compiler_options")
                && (profile.is_evm() || profile.chain == Chain::Tron)))
}
fn profile_bounds(info: &DeviceInfo, profile: crate::chains::Profile, tuning: &mut Tuning) {
    bound_lanes(info, tuning);
    if profile.address_type == crate::chains::AddressType::P2tr {
        tuning.max_lanes = tuning.max_lanes.min(4096);
    }
}
/// Bounded fast screening set. Architecture attributes may order trials, but
/// missing optional NVIDIA queries never exclude otherwise suitable hardware.
pub fn quick_candidates(
    info: &DeviceInfo,
    profile: crate::chains::Profile,
    strategy: crate::model::SearchStrategy,
    suffix: bool,
) -> Vec<Tuning> {
    let mut incumbent =
        super::qualification::gpu(info, profile, strategy, suffix).unwrap_or_else(|| preset(info));
    profile_bounds(info, profile, &mut incumbent);
    let mut fast = incumbent.clone();
    fast.curve = Curve::Recurrence;
    fast.fast_field = true;
    fast.fixed_hash = true;
    fast.bounded_multiply = true;
    fast.canonical_field = true;
    fast.wide_multiply = false;
    fast.interleaved_inverse = true;
    fast.tuned_keccak = true;
    fast.address_keccak = profile.is_evm() || profile.chain == crate::chains::Chain::Tron;
    fast.word_match = profile.is_evm();
    fast.ternary_keccak = fast.address_keccak
        && info.vendor_id == 0x10de
        && info.has_extension("cl_nv_compiler_options");
    let mut candidates = vec![incumbent];
    let groups = if info.compute_capability.is_some_and(|(major, _)| major >= 8) {
        [64, 128, 32]
    } else {
        [32, 64, 128]
    };
    for group in groups {
        let mut candidate = fast.clone();
        candidate.inversion_width = 64;
        candidate.work_group_size = group;
        candidates.push(candidate);
    }
    fast.work_group_size = 64;
    fast.inversion_width = 128;
    candidates.push(fast.clone());
    fast.inversion_width = 64;
    fast.interleaved_inverse = false;
    candidates.push(fast.clone());
    fast.interleaved_inverse = true;
    fast.tuned_keccak = false;
    fast.address_keccak = false;
    fast.word_match = false;
    fast.ternary_keccak = false;
    candidates.push(fast.clone());
    // Keep an independently compiled portable field/hash alternative.
    fast.bounded_multiply = false;
    fast.canonical_field = false;
    fast.fixed_hash = false;
    candidates.push(fast);
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|t| {
        eligible_tuning(info, profile, t)
            && seen.insert(serde_json::to_string(t).expect("Tuning serialization cannot fail"))
    });
    candidates
}
#[cfg(any(test, feature = "developer-tools"))]
pub fn load(info: &DeviceInfo, directory: Option<&Path>) -> Result<Option<Tuning>> {
    let Some(dir) = directory else {
        return Ok(None);
    };
    let _guard = storage::guard(dir)?;
    if !storage::exists(dir)? {
        return Ok(None);
    }
    storage::assert_private_directory(dir)?;
    let key = fingerprint(info)?;
    let path = dir.join(format!("tuning-{key}.json"));
    let Ok(saved) = storage::read_private_json::<Saved>(&path) else {
        return Ok(None);
    };
    if saved.schema != 2
        || saved.key != key
        || !saved.median_per_second.is_finite()
        || saved.median_per_second <= 0.0
        || !eligible_tuning(info, Default::default(), &saved.tuning)
    {
        return Ok(None);
    }
    Ok(Some(saved.tuning))
}
#[cfg(any(test, feature = "developer-tools"))]
pub fn resolve(info: &DeviceInfo, directory: Option<&Path>) -> Result<(Tuning, &'static str)> {
    match load(info, directory)? {
        Some(t) => Ok((t, "validated cache")),
        None => Ok((preset(info), "portable preset")),
    }
}
#[cfg(test)]
fn save(info: &DeviceInfo, dir: &Path, tuning: Tuning, rate: f64) -> Result<()> {
    let _guard = storage::guard(dir)?;
    if !storage::exists(dir)? {
        storage::create_directory(dir, true)?;
        storage::private(dir)?;
    }
    storage::assert_private_directory(dir)?;
    let key = fingerprint(info)?;
    storage::write_json(
        &dir.join(format!("tuning-{key}.json")),
        &Saved {
            schema: 2,
            key,
            tuning,
            median_per_second: rate,
        },
        true,
    )
}
#[derive(Clone, Copy)]
pub struct TuningWorkload {
    pub profile: crate::chains::Profile,
    pub strategy: crate::model::SearchStrategy,
    pub encoded_suffix: bool,
}
#[cfg(any(test, feature = "developer-tools"))]
fn save_profile(
    info: &DeviceInfo,
    dir: &Path,
    tuning: Tuning,
    rate: f64,
    work: TuningWorkload,
) -> Result<()> {
    let _guard = storage::guard(dir)?;
    if !storage::exists(dir)? {
        storage::create_directory(dir, true)?;
        storage::private(dir)?;
    }
    storage::assert_private_directory(dir)?;
    let key = fingerprint_profile(info, work.profile, work.strategy, work.encoded_suffix)?;
    storage::write_json(
        &dir.join(format!("tuning-{key}.json")),
        &Saved {
            schema: 2,
            key,
            tuning,
            median_per_second: rate,
        },
        true,
    )
}
/// Persist an invalid marker rather than deleting an existing cache record.
/// No secrets are involved; the marker cannot deserialize as trusted settings.
pub fn invalidate_profile(info: &DeviceInfo, dir: &Path, work: TuningWorkload) -> Result<()> {
    let _guard = storage::guard(dir)?;
    if !storage::exists(dir)? {
        return Ok(());
    }
    storage::assert_private_directory(dir)?;
    let key = fingerprint_profile(info, work.profile, work.strategy, work.encoded_suffix)?;
    storage::write_json(
        &dir.join(format!("tuning-{key}.json")),
        &serde_json::json!({"schema":2,"key":key,"invalidated":true,
            "fault":"cryptographic correctness failure"}),
        true,
    )
}
#[cfg(feature = "developer-tools")]
fn timed(
    index: usize,
    tuning: &Tuning,
    batch: u32,
    seconds: f64,
    cancel: &AtomicBool,
    job: &Job,
) -> Result<serde_json::Value> {
    let init = Instant::now();
    let mut worker = Opencl::with_profile_strategy(
        index,
        true,
        None,
        tuning.clone(),
        job.profile(),
        Some(job.strategy),
    )?;
    worker.self_test()?;
    let startup = init.elapsed().as_secs_f64();
    let batch = super::aligned_batch(job, batch, true);
    // Avoid the known generator hit at offset zero. Calibration evaluates the
    // same complete path as production without intentionally finding a wallet.
    let mut offset = crate::work::WorkIndex::from_u64(1_000_000_000_000);
    let mut rates = vec![];
    let mut samples = vec![];
    for run in 0..4 {
        let started = Instant::now();
        let mut completed = 0u64;
        while started.elapsed().as_secs_f64() < if run == 0 { 0.2 } else { seconds }
            && !cancel.load(Ordering::Relaxed)
        {
            let range = Interval::new(offset, batch)?;
            let result = worker.run(job, &range, cancel)?;
            ensure!(
                result.completed == batch,
                "tuning configuration did not complete its assigned range"
            );
            offset = range.end;
            completed += result.evaluated as u64;
        }
        ensure!(!cancel.load(Ordering::Relaxed), "GPU tuning cancelled");
        let elapsed = started.elapsed().as_secs_f64();
        let rate = completed as f64 / elapsed;
        if run > 0 {
            rates.push(rate);
            samples.push(
                serde_json::json!({"candidates":completed,"seconds":elapsed,"per_second":rate}),
            );
        }
    }
    rates.sort_by(f64::total_cmp);
    Ok(
        serde_json::json!({"tuning":tuning,"startup_seconds":startup,"runs":samples,
        "median":rates[1],"min":rates[0],"max":rates[2],"diagnostics":worker.diagnostics()}),
    )
}
#[cfg(any(test, feature = "developer-tools"))]
fn rejected_trial(phase: u32, tuning: &Tuning, error: anyhow::Error) -> Result<serde_json::Value> {
    if error.downcast_ref::<CorrectnessError>().is_some() {
        // A wrong result is a fault in a cryptographic implementation/driver,
        // never a slow or unsupported tuning candidate that may be skipped.
        return Err(error);
    }
    Ok(serde_json::json!({"phase":phase,"tuning":tuning,"rejected":format!("{error:#}")}))
}
#[cfg(feature = "developer-tools")]
pub fn tune(
    index: usize,
    directory: &Path,
    seconds: f64,
    cancel: Arc<AtomicBool>,
) -> Result<serde_json::Value> {
    tune_profile(
        index,
        directory,
        seconds,
        cancel,
        TuningWorkload {
            profile: Default::default(),
            strategy: crate::model::SearchStrategy::EndomorphismV1,
            encoded_suffix: false,
        },
    )
}
#[cfg(feature = "developer-tools")]
pub fn tune_profile(
    index: usize,
    directory: &Path,
    seconds: f64,
    cancel: Arc<AtomicBool>,
    work: TuningWorkload,
) -> Result<serde_json::Value> {
    work.profile.validate()?;
    ensure!(
        work.profile.key_family() == crate::chains::KeyFamily::Secp256k1,
        "GPU tuning requires secp256k1"
    );
    let address = work.profile.address(&generator())?;
    let pattern = if work.encoded_suffix {
        Pattern::for_profile(work.profile, "", &address[address.len() - 8..])?
    } else {
        Pattern::for_profile(work.profile, &address, "")?
    };
    let job = Job {
        schema: 3,
        session_id: uuid::Uuid::nil(),
        public_key: hex::encode(generator().serialize()),
        pattern,
        strategy: work.strategy,
    };
    job.validate()?;
    ensure!(
        seconds.is_finite() && (0.1..=20.0).contains(&seconds),
        "tuning seconds must be 0.1..20"
    );
    let info = opencl::discover()?
        .into_iter()
        .find(|d| d.index == index)
        .context("unknown GPU")?;
    ensure!(info.suitable, "GPU is not suitable for OpenCL tuning");
    let mut best = resolve_profile(
        &info,
        Some(directory),
        work.profile,
        work.strategy,
        work.encoded_suffix,
    )?
    .0;
    let mut best_rate = 0.0;
    let mut records = vec![];
    let mut tested = std::collections::HashSet::new();
    let mut final_pass = false;
    // Coordinate search bounds the explicit retune instead of a huge Cartesian
    // sweep. Every trial rebuilds/validates the actual variant before timing.
    for phase in 0..16 {
        let mut candidates = vec![best.clone()];
        match phase {
            0 => {
                candidates.extend(quick_candidates(
                    &info,
                    work.profile,
                    work.strategy,
                    work.encoded_suffix,
                ));
                for curve in [Curve::Affine, Curve::Recurrence] {
                    for tuned_keccak in [false, true] {
                        let mut t = best.clone();
                        t.curve = curve;
                        t.tuned_keccak = tuned_keccak;
                        candidates.push(t);
                    }
                }
            }
            1 => {
                for width in [16, 32, 64, 128, 255, 256, 512, 1024] {
                    let mut t = best.clone();
                    t.inversion_width = width;
                    candidates.push(t);
                }
            }
            2 => {
                for group in [0, 32, 64, 128, 256] {
                    let mut t = best.clone();
                    t.work_group_size = group;
                    candidates.push(t);
                }
            }
            3 => {
                for global in [false, true] {
                    for interleaved in [false, true] {
                        let mut t = best.clone();
                        t.global_prefix = global;
                        t.interleaved_inverse = interleaved;
                        candidates.push(t);
                    }
                }
            }
            4 => {
                for lanes in [262144, 1048576, 4194304] {
                    let mut t = best.clone();
                    t.max_lanes = lanes;
                    candidates.push(t);
                }
            }
            5 => {
                for poll in [0, 50, 250, 1000] {
                    let mut t = best.clone();
                    t.poll_microseconds = poll;
                    candidates.push(t);
                }
            }
            6 => {
                for width in [32, 64, 128, 255, 256, 512] {
                    let mut t = best.clone();
                    t.inversion_width = width;
                    candidates.push(t);
                }
            }
            7 => {
                for group in [32, 64, 128] {
                    let mut t = best.clone();
                    t.work_group_size = group;
                    candidates.push(t);
                }
            }
            8 => {
                for wide in [false, true] {
                    let mut t = best.clone();
                    t.wide_multiply = wide;
                    candidates.push(t);
                }
            }
            9 => {
                for synchronous in [false, true] {
                    let mut t = best.clone();
                    t.synchronous_dispatch = synchronous;
                    candidates.push(t);
                }
            }
            10 => {
                for fixed in [false, true] {
                    let mut t = best.clone();
                    t.fixed_hash = fixed;
                    candidates.push(t);
                }
            }
            11 => {
                for enabled in [false, true] {
                    let mut t = best.clone();
                    t.fast_field = enabled;
                    candidates.push(t);
                }
            }
            12 => {
                for enabled in [false, true] {
                    let mut t = best.clone();
                    t.bounded_multiply = enabled;
                    t.canonical_field = enabled;
                    if enabled {
                        t.wide_multiply = false;
                    }
                    candidates.push(t);
                }
            }
            13 => {
                if work.profile.is_evm() || work.profile.chain == crate::chains::Chain::Tron {
                    for address in [false, true] {
                        for ternary in [false, true] {
                            let mut t = best.clone();
                            t.tuned_keccak = true;
                            t.address_keccak = address;
                            t.word_match = address && work.profile.is_evm();
                            t.ternary_keccak = address && ternary;
                            candidates.push(t);
                        }
                    }
                }
            }
            14 => {
                for enabled in [false, true] {
                    let mut t = best.clone();
                    t.word_match = enabled;
                    candidates.push(t);
                }
            }
            _ => {}
        }
        for candidate in candidates {
            ensure!(!cancel.load(Ordering::Relaxed), "GPU tuning cancelled");
            if !tested.insert(serde_json::to_string(&candidate)?) && phase != 15 {
                continue;
            }
            if !eligible_tuning(&info, work.profile, &candidate) {
                records.push(serde_json::json!({"phase":phase,"tuning":candidate,
                    "rejected":"unsupported profile or device resources"}));
                continue;
            }
            std::thread::sleep(Duration::from_millis(250));
            // Keep the durable workload constant while geometry changes, as in
            // the normal application's default four-million-candidate interval.
            let batch = 4_194_304;
            match timed(
                index,
                &candidate,
                batch,
                if phase == 15 {
                    seconds.max(2.0)
                } else {
                    seconds
                },
                &cancel,
                &job,
            ) {
                Ok(mut record) => {
                    let rate = record["median"].as_f64().context("missing tuning rate")?;
                    record["phase"] = phase.into();
                    records.push(record);
                    if phase == 15 {
                        final_pass = true;
                    }
                    if rate > best_rate || phase == 15 {
                        best_rate = rate;
                        best = candidate;
                    }
                }
                Err(e) => {
                    if e.downcast_ref::<CorrectnessError>().is_some()
                        && let Err(invalidation) = invalidate_profile(&info, directory, work)
                    {
                        return Err(
                            e.context(format!("cache invalidation failed: {invalidation:#}"))
                        );
                    }
                    records.push(rejected_trial(phase, &candidate, e)?);
                    if cancel.load(Ordering::Relaxed) {
                        anyhow::bail!("GPU tuning cancelled");
                    }
                }
            }
        }
    }
    ensure!(
        best_rate > 0.0 && final_pass,
        "no correct GPU tuning configuration completed final validation"
    );
    save_profile(&info, directory, best.clone(), best_rate, work)?;
    Ok(
        serde_json::json!({"schema":2,"device":info,"profile":work.profile,"strategy":work.strategy,"encoded_suffix":work.encoded_suffix,"fingerprint":fingerprint_profile(&info,work.profile,work.strategy,work.encoded_suffix)?,
        "selected":best,"median_per_second":best_rate,"trials":records,
        "method":"correctness first; 0.2s warmup; three windows; bounded coordinate search; final >=2s windows"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device() -> DeviceInfo {
        serde_json::from_value(serde_json::json!({
            "index":0,"name":"unrecognized NVIDIA device","vendor":"NVIDIA Corporation",
            "vendor_id":0x10de,"compute_capability":[12,0],"warp_size":32,
            "platform":"generic ICD","driver":"new driver","api":"OpenCL 3.0",
            "language":"OpenCL C 1.2","memory_bytes":8_589_934_592u64,
            "max_allocation_bytes":2_147_483_648u64,"compute_units":36,
            "max_work_group":1024,"integer_width":1,
            "extensions":"cl_nv_compiler_options cl_nv_device_attribute_query",
            "physical_id":"uuid:synthetic-device","suitable":true,"self_test":"not run"
        }))
        .unwrap()
    }
    #[test]
    fn stable_fingerprints_ignore_index_and_status_but_bind_hardware_and_compiler() {
        let info = device();
        let expected = fingerprint(&info).unwrap();
        let mut changed = info.clone();
        changed.index = 8;
        changed.self_test = "passed".into();
        changed.name = "new diagnostic name".into();
        changed.extensions =
            "cl_nv_device_attribute_query cl_nv_compiler_options cl_nv_compiler_options".into();
        assert_eq!(fingerprint(&changed).unwrap(), expected);
        for kind in 0..4 {
            let mut changed = info.clone();
            match kind {
                0 => changed.driver = "different".into(),
                1 => changed.physical_id = Some("uuid:other-identical-adapter".into()),
                2 => changed.language = "different compiler language".into(),
                _ => changed.compute_capability = Some((8, 6)),
            }
            assert_ne!(fingerprint(&changed).unwrap(), expected);
        }
    }
    #[test]
    fn quick_screening_candidates_obey_all_profiles_and_resource_limits() {
        let mut info = device();
        for capability in [Some((8, 6)), Some((8, 9)), Some((12, 0)), None] {
            info.compute_capability = capability;
            for row in crate::chains::registry() {
                for strategy in [
                    crate::model::SearchStrategy::Linear,
                    crate::model::SearchStrategy::EndomorphismV1,
                ] {
                    for suffix in [false, true] {
                        let choices = quick_candidates(&info, row.profile, strategy, suffix);
                        assert!(choices.len() <= 8);
                        if row.key_family == crate::chains::KeyFamily::Secp256k1 {
                            assert!(!choices.is_empty());
                        } else {
                            assert!(choices.is_empty());
                        }
                        assert!(
                            choices
                                .iter()
                                .all(|t| eligible_tuning(&info, row.profile, t))
                        );
                    }
                }
            }
        }
        info.extensions.clear();
        assert!(
            quick_candidates(
                &info,
                Default::default(),
                crate::model::SearchStrategy::Linear,
                false
            )
            .iter()
            .all(|t| !t.ternary_keccak)
        );
        info.max_work_group = 32;
        info.memory_bytes = 64 * 1024 * 1024;
        info.max_allocation_bytes = 1024 * 1024;
        let small = quick_candidates(
            &info,
            Default::default(),
            crate::model::SearchStrategy::Linear,
            false,
        );
        assert!(!small.is_empty());
        assert!(
            small
                .iter()
                .all(|t| t.work_group_size <= 32 && t.max_lanes <= lane_limit(&info))
        );
        info.max_allocation_bytes = 0;
        assert!(
            quick_candidates(
                &info,
                Default::default(),
                crate::model::SearchStrategy::Linear,
                false
            )
            .is_empty()
        );
    }
    #[test]
    fn correctness_faults_abort_instead_of_becoming_tuning_rejections() {
        let ordinary = rejected_trial(
            0,
            &Tuning::default(),
            anyhow::anyhow!("unsupported compiler option"),
        );
        assert!(ordinary.unwrap()["rejected"].is_string());
        let failure = anyhow::Error::new(CorrectnessError("injected wrong digest".into()))
            .context("trial startup self-test");
        let failure = rejected_trial(0, &Tuning::default(), failure).unwrap_err();
        assert!(failure.downcast_ref::<CorrectnessError>().is_some());
    }
    #[test]
    fn a_correctness_fault_marker_invalidates_profile_settings() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        let info = device();
        let work = TuningWorkload {
            profile: Default::default(),
            strategy: crate::model::SearchStrategy::Linear,
            encoded_suffix: false,
        };
        let chosen = quick_candidates(&info, work.profile, work.strategy, false).remove(0);
        save_profile(&info, root.path(), chosen, 1.0, work).unwrap();
        assert_eq!(
            resolve_profile(&info, Some(root.path()), work.profile, work.strategy, false)
                .unwrap()
                .1,
            "validated profile cache"
        );
        invalidate_profile(&info, root.path(), work).unwrap();
        assert_ne!(
            resolve_profile(&info, Some(root.path()), work.profile, work.strategy, false)
                .unwrap()
                .1,
            "validated profile cache"
        );
        let key = fingerprint_profile(&info, work.profile, work.strategy, false).unwrap();
        let invalid: serde_json::Value =
            storage::read_private_json(&root.path().join(format!("tuning-{key}.json"))).unwrap();
        assert_eq!(invalid["invalidated"], true);
    }
    #[test]
    fn cache_never_accepts_shared_or_invalid_settings() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        // GPU-free coverage uses a real serialized fake device from selection tests.
        let info:DeviceInfo=serde_json::from_value(serde_json::json!({"index":0,"name":"test","vendor":"test",
            "platform":"test","driver":"1","api":"OpenCL 1.2","language":"OpenCL C 1.2","memory_bytes":1073741824u64,
            "max_allocation_bytes":268435456u64,"compute_units":1,"max_work_group":256,"integer_width":1,
            "extensions":"","physical_id":null,"suitable":true,"self_test":"not run"})).unwrap();
        let chosen = preset(&info);
        save(&info, root.path(), chosen.clone(), 1.0).unwrap();
        assert_eq!(
            load(&info, Some(root.path())).unwrap(),
            Some(chosen.clone())
        );
        let mut changed = info.clone();
        changed.driver = "2".into();
        assert!(load(&changed, Some(root.path())).unwrap().is_none());
        let key = fingerprint(&info).unwrap();
        let path = root.path().join(format!("tuning-{key}.json"));
        storage::write_json(
            &path,
            &serde_json::json!({"schema":1,"key":key,"tuning":chosen,"median_per_second":1.0}),
            true,
        )
        .unwrap();
        let old = storage::read_bytes(&path).unwrap();
        assert!(load(&info, Some(root.path())).unwrap().is_none());
        assert_eq!(storage::read_bytes(&path).unwrap(), old);
        storage::write_json(&path,&serde_json::json!({"schema":2,"key":key,"tuning":{"inversion_width":0},"median_per_second":1.0}),true).unwrap();
        assert!(load(&info, Some(root.path())).unwrap().is_none());
    }
}
