use super::{BatchResult, Compute, CorrectnessError, correct};
use crate::{
    crypto::{Offset, Pattern, address, generator, public_at},
    model::{Candidate, Interval, Job, SCHEMA},
    storage,
};
use anyhow::{Context as _, Result, ensure};
use opencl3::{
    command_queue::{CL_QUEUE_PROFILING_ENABLE, CommandQueue},
    context::Context,
    device::{CL_DEVICE_TYPE_GPU, Device},
    kernel::{ExecuteKernel, Kernel},
    memory::{Buffer, CL_MEM_READ_ONLY, CL_MEM_READ_WRITE, CL_MEM_WRITE_ONLY},
    platform::get_platforms,
    program::Program,
    types::CL_BLOCKING,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "chain_gpu.rs"]
pub mod chain_gpu;

pub const SOURCE: &str = include_str!("../../kernels/search.cl");
pub const FAST_FIELD_SOURCE: &str = include_str!("../../kernels/fast_field.cl");
pub const FIELD_PROBE: &str = include_str!("../../kernels/field_probe.cl");
#[cfg(feature = "developer-tools")]
const LAB_PROBES: &str = include_str!("../../kernels/lab_probes.cl");
pub const RECURRENCE_SOURCE: &str = include_str!("../../kernels/recurrence.cl");
pub const TUNED_KECCAK_SOURCE: &str = include_str!("../../kernels/keccak_tuned.cl");
pub const BOUNDED_FIELD_SOURCE: &str = include_str!("../../kernels/field_bounded.cl");
pub const TERNARY_KECCAK_SOURCE: &str = include_str!("../../kernels/keccak_ternary.cl");
pub fn source_for(tuning: &Tuning) -> String {
    let mut source = String::new();
    for (enabled, name) in [
        (tuning.bounded_multiply, "BOUNDED_MULTIPLY"),
        (tuning.canonical_field, "CANONICAL_FIELD"),
        (tuning.word_match, "WORD_MATCH"),
        (tuning.ternary_keccak, "TERNARY_KECCAK"),
    ] {
        if enabled {
            source.push_str(&format!("#define {name} 1\n"));
        }
    }
    if tuning.interleaved_inverse {
        source.push_str("#define REC_INTERLEAVED_INVERSE 1\n");
    }
    if tuning.wide_multiply {
        source.push_str("#define WIDE_MULTIPLY 1\n");
    }
    if tuning.fast_field {
        source.push_str(&format!("#define FAST_FIELD 1\n{FAST_FIELD_SOURCE}\n"));
    }
    if tuning.address_keccak {
        source.push_str("#define ADDRESS_KECCAK 1\n");
    }
    if tuning.tuned_keccak {
        source.push_str(&format!("#define TUNED_KECCAK 1\n{TUNED_KECCAK_SOURCE}\n"));
    }
    if tuning.ternary_keccak {
        source.push_str(TERNARY_KECCAK_SOURCE);
    }
    source.push_str(&SOURCE.replace(
        "/* BOUNDED_FIELD_SOURCE */",
        if tuning.bounded_multiply {
            BOUNDED_FIELD_SOURCE
        } else {
            ""
        },
    ));
    source.push_str(FIELD_PROBE);
    #[cfg(feature = "developer-tools")]
    source.push_str(LAB_PROBES);
    if tuning.curve != Curve::Jacobian {
        if tuning.global_prefix {
            source.push_str("\n#define REC_GLOBAL_PREFIX 1\n");
        }
        source.push_str(RECURRENCE_SOURCE);
    }
    source
}
pub const OPTIONS: &str = "-cl-std=CL1.2";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Curve {
    #[default]
    Jacobian,
    Affine,
    Recurrence,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tuning {
    pub inversion_width: usize,
    pub work_group_size: usize,
    pub poll_microseconds: u64,
    pub fast_field: bool,
    pub fixed_hash: bool,
    pub curve: Curve,
    pub max_lanes: usize,
    pub global_prefix: bool,
    pub tuned_keccak: bool,
    pub address_keccak: bool,
    pub bounded_multiply: bool,
    pub canonical_field: bool,
    pub word_match: bool,
    pub ternary_keccak: bool,
    pub wide_multiply: bool,
    pub interleaved_inverse: bool,
    pub synchronous_dispatch: bool,
}
impl Default for Tuning {
    fn default() -> Self {
        Self {
            inversion_width: 16,
            work_group_size: 0,
            poll_microseconds: 1000,
            fast_field: false,
            fixed_hash: false,
            curve: Curve::Jacobian,
            max_lanes: 1_048_576,
            global_prefix: false,
            tuned_keccak: false,
            address_keccak: false,
            bounded_multiply: false,
            canonical_field: false,
            word_match: false,
            ternary_keccak: false,
            wide_multiply: false,
            interleaved_inverse: false,
            synchronous_dispatch: false,
        }
    }
}
impl Tuning {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.bounded_multiply || !self.wide_multiply,
            "bounded and wide multiplication are separate implementations"
        );
        ensure!(
            !self.word_match || self.address_keccak,
            "word matching requires address Keccak"
        );
        ensure!(
            !self.ternary_keccak || self.address_keccak,
            "ternary Keccak requires address Keccak"
        );
        ensure!(
            !self.address_keccak || self.tuned_keccak,
            "address Keccak requires tuned Keccak"
        );
        ensure!(
            [16, 32, 64, 128, 255, 256, 512, 1024].contains(&self.inversion_width),
            "unsupported inversion width"
        );
        ensure!(
            self.work_group_size <= 1024,
            "work-group size exceeds limit"
        );
        ensure!(
            self.poll_microseconds <= 10000,
            "GPU polling interval exceeds limit"
        );
        ensure!(
            (1..=4_194_304).contains(&self.max_lanes),
            "GPU lane limit must be 1..4194304"
        );
        Ok(())
    }
}
#[path = "profiling.rs"]
pub mod profiling;
#[path = "recurrence.rs"]
mod recurrence;

/// Apply user exclusions before deduplicating automatic adapter identities.
/// A disabled ambiguous adapter must not suppress the explicitly remaining GPU.
pub fn automatic_enabled(infos: &[DeviceInfo], excluded: &[usize]) -> Result<Vec<usize>> {
    let enabled: Vec<_> = infos
        .iter()
        .filter(|d| !excluded.contains(&d.index))
        .cloned()
        .collect();
    automatic(&enabled)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    pub index: usize,
    pub name: String,
    pub vendor: String,
    #[serde(default)]
    pub vendor_id: u32,
    #[serde(default)]
    pub compute_capability: Option<(u32, u32)>,
    #[serde(default)]
    pub warp_size: Option<u32>,
    pub platform: String,
    pub driver: String,
    pub api: String,
    pub language: String,
    pub memory_bytes: u64,
    pub max_allocation_bytes: u64,
    pub compute_units: u32,
    pub max_work_group: usize,
    pub integer_width: u32,
    pub extensions: String,
    pub physical_id: Option<String>,
    pub suitable: bool,
    pub self_test: String,
}
impl DeviceInfo {
    pub fn has_extension(&self, extension: &str) -> bool {
        self.extensions.split_whitespace().any(|v| v == extension)
    }
    /// Capability eligibility is independent of product names and driver versions.
    /// The optional NVIDIA attributes only order trials; startup tests remain mandatory.
    pub fn nvidia_eligible(&self) -> bool {
        self.vendor_id == 0x10de
            && self.suitable
            && self.max_work_group >= 32
            && self.max_allocation_bytes >= 1024 * 1024
            && self.memory_bytes >= 64 * 1024 * 1024
    }
    /// Stable compiler/device identity. Discovery order and diagnostic self-test
    /// text must never invalidate a measured configuration or a compiled kernel.
    pub fn cache_identity(&self) -> serde_json::Value {
        let mut extensions: Vec<_> = self.extensions.split_whitespace().collect();
        extensions.sort_unstable();
        extensions.dedup();
        serde_json::json!({
            "vendor_id": self.vendor_id, "vendor": self.vendor,
            "physical_id": self.physical_id,
            "model_without_uuid": self.physical_id.is_none().then_some(&self.name),
            "platform": self.platform, "driver": self.driver, "api": self.api,
            "language": self.language, "extensions": extensions,
            "memory_bytes": self.memory_bytes,
            "max_allocation_bytes": self.max_allocation_bytes,
            "compute_units": self.compute_units, "max_work_group": self.max_work_group,
            "integer_width": self.integer_width,
            "compute_capability": self.compute_capability, "warp_size": self.warp_size,
        })
    }
}
fn devices() -> Result<Vec<Device>> {
    let mut out = vec![];
    for platform in get_platforms().context("OpenCL loader or vendor ICD unavailable")? {
        match platform.get_devices(CL_DEVICE_TYPE_GPU) {
            Ok(ids) => out.extend(ids.into_iter().map(Device::new)),
            Err(e) if e.0 == -1 => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}
pub fn discover() -> Result<Vec<DeviceInfo>> {
    devices()?
        .iter()
        .enumerate()
        .map(|(index, d)| {
            let extensions = d.extensions()?;
            let physical_id = if extensions.contains("cl_khr_device_uuid") {
                d.uuid_khr()
                    .ok()
                    .map(|id| format!("uuid:{}", hex::encode(id)))
            } else {
                None
            };
            let language = d.opencl_c_version()?;
            let vendor_id = d.vendor_id()?;
            let nvidia_attributes = vendor_id == 0x10de
                && extensions
                    .split_whitespace()
                    .any(|v| v == "cl_nv_device_attribute_query");
            let compute_capability = nvidia_attributes
                .then(|| {
                    d.compute_capability_major_nv()
                        .ok()
                        .zip(d.compute_capability_minor_nv().ok())
                })
                .flatten();
            let warp_size = nvidia_attributes.then(|| d.wrap_size_nv().ok()).flatten();
            let suitable = d.available()?
                && d.compiler_available()?
                && d.profile()? == "FULL_PROFILE"
                && !language.starts_with("OpenCL C 1.0")
                && !language.starts_with("OpenCL C 1.1");
            Ok(DeviceInfo {
                index,
                name: d.name()?,
                vendor: d.vendor()?,
                vendor_id,
                compute_capability,
                warp_size,
                platform: opencl3::platform::Platform::new(d.platform()?).name()?,
                driver: d.driver_version()?,
                api: d.version()?,
                language,
                memory_bytes: d.global_mem_size()?,
                max_allocation_bytes: d.max_mem_alloc_size()?,
                compute_units: d.max_compute_units()?,
                max_work_group: d.max_work_group_size()?,
                integer_width: d.native_vector_width_long()?,
                extensions,
                physical_id,
                suitable,
                self_test: "not run".into(),
            })
        })
        .collect()
}
/// UUIDs deduplicate physical devices. Ambiguous identities with the same model
/// across different platforms require explicit selection, even for identical GPUs.
pub fn automatic(infos: &[DeviceInfo]) -> Result<Vec<usize>> {
    let mut ids = HashSet::new();
    let mut models = HashMap::new();
    let mut result = vec![];
    for d in infos.iter().filter(|d| d.suitable) {
        let model = (d.vendor.clone(), d.name.clone());
        if let Some(id) = &d.physical_id {
            if !ids.insert(id.clone()) {
                continue;
            }
            ensure!(
                !models.get(&model).copied().unwrap_or(false),
                "ambiguous physical GPU identities; select --devices explicitly"
            );
            models.entry(model).or_insert(false);
        } else {
            ensure!(
                !models.contains_key(&model),
                "ambiguous physical GPU identities; select --devices explicitly"
            );
            models.insert(model, true);
        }
        result.push(d.index);
    }
    Ok(result)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    schema: u32,
    key: String,
    sha256: String,
    binary: Vec<u8>,
}
/// Public-only wall-clock and OpenCL event measurements. Device event intervals
/// can overlap host intervals; they must not be added to the host wall totals.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PipelineProfile {
    pub batches: u64,
    pub host_preparation_seconds: f64,
    pub allocation_seconds: f64,
    pub upload_wall_seconds: f64,
    pub upload_device_seconds: f64,
    pub kernel_seconds: f64,
    pub dispatch_wait_seconds: f64,
    pub download_wall_seconds: f64,
    pub download_device_seconds: f64,
    pub result_verification_seconds: f64,
    pub endpoint_verification_seconds: f64,
    pub endpoint_kernel_seconds: f64,
    pub device_idle_between_evaluations_seconds: f64,
    pub total_worker_seconds: f64,
}
#[derive(Clone, Copy)]
struct OrbitWindow {
    width: u8,
    skip: u8,
    count: u32,
}
pub struct Opencl {
    linear_only: bool,
    orbit: Option<OrbitWindow>,
    last_family_width: u8,
    chain_profile: crate::chains::Profile,
    matching_cache: std::cell::RefCell<Option<(Pattern, Vec<u8>)>>,
    info: DeviceInfo,
    context: Context,
    queue: CommandQueue,
    kernel: Kernel,
    _program: Program,
    batched: bool,
    kernel_seconds: f64,
    memory_bytes: usize,
    validated: bool,
    last_profile: PipelineProfile,
    profile: PipelineProfile,
    last_device_end: u64,
    initialization_seconds: f64,
    self_test_seconds: f64,
    resources: serde_json::Value,
    buffers: Option<Reusable>,
    public_state: Option<(String, crate::work::WorkIndex, u32)>,
    last_pattern: Vec<u8>,
    buffer_allocations: u64,
    state_reuses: u64,
    tuning: Tuning,
    compiler_options: String,
    source_hash: String,
    pub(crate) tuning_origin: String,
    recurrence_state: Option<recurrence::State>,
}
struct Reusable {
    invalid: Buffer<u32>,
    starts: Buffer<u8>,
    valid: Buffer<u8>,
    pattern: Buffer<u8>,
    hits: Buffer<u32>,
    addresses: Buffer<u8>,
    points: Buffer<u8>,
    states: Buffer<u8>,
    jump: Buffer<u8>,
    lanes: usize,
    address_capacity: usize,
    point_capacity: usize,
    bytes: usize,
}
impl Reusable {
    fn new(
        context: &Context,
        info: &DeviceInfo,
        lanes: usize,
        addresses: usize,
        points: usize,
    ) -> Result<Self> {
        let sizes = [
            lanes * 64,
            lanes,
            chain_gpu::WIRE_SIZE,
            lanes * 4,
            addresses,
            points,
            lanes * 96,
            64,
        ];
        ensure!(
            sizes
                .iter()
                .all(|n| *n > 0 && *n as u64 <= info.max_allocation_bytes),
            "GPU buffer exceeds allocation limit"
        );
        let bytes: usize = sizes.iter().sum::<usize>() + 4;
        ensure!(
            bytes as u64 <= info.memory_bytes / 2,
            "GPU memory budget exceeded"
        );
        // SAFETY: every bounded buffer belongs to context, uses positive sizes,
        // and is accessed with the matching byte/uint kernel layout. Allocation
        // replacement happens only after prior blocking result reads completed.
        unsafe {
            Ok(Self {
                invalid: Buffer::create(context, CL_MEM_READ_WRITE, 1, ptr::null_mut())?,
                starts: Buffer::create(context, CL_MEM_READ_ONLY, sizes[0], ptr::null_mut())?,
                valid: Buffer::create(context, CL_MEM_READ_ONLY, sizes[1], ptr::null_mut())?,
                pattern: Buffer::create(context, CL_MEM_READ_ONLY, sizes[2], ptr::null_mut())?,
                hits: Buffer::create(context, CL_MEM_READ_WRITE, lanes, ptr::null_mut())?,
                addresses: Buffer::create(context, CL_MEM_WRITE_ONLY, addresses, ptr::null_mut())?,
                points: Buffer::create(context, CL_MEM_WRITE_ONLY, points, ptr::null_mut())?,
                states: Buffer::create(context, CL_MEM_READ_WRITE, sizes[6], ptr::null_mut())?,
                jump: Buffer::create(context, CL_MEM_READ_ONLY, 64, ptr::null_mut())?,
                lanes,
                address_capacity: addresses,
                point_capacity: points,
                bytes,
            })
        }
    }
    fn fits(&self, lanes: usize, addresses: usize, points: usize) -> bool {
        self.lanes >= lanes && self.address_capacity >= addresses && self.point_capacity >= points
    }
}
struct Evaluation {
    invalid: u32,
    hits: Vec<u32>,
    addresses: Vec<u8>,
    points: Vec<u8>,
}
impl Opencl {
    pub fn new(index: usize, batched: bool, cache: Option<&Path>) -> Result<Self> {
        Self::with_tuning(index, batched, cache, Tuning::default())
    }
    pub fn with_tuning(
        index: usize,
        batched: bool,
        cache: Option<&Path>,
        tuning: Tuning,
    ) -> Result<Self> {
        Self::with_profile(
            index,
            batched,
            cache,
            tuning,
            crate::chains::Profile::default(),
        )
    }
    pub fn with_profile(
        index: usize,
        batched: bool,
        cache: Option<&Path>,
        tuning: Tuning,
        profile: crate::chains::Profile,
    ) -> Result<Self> {
        Self::with_profile_strategy(index, batched, cache, tuning, profile, None)
    }
    pub(crate) fn with_profile_strategy(
        index: usize,
        batched: bool,
        cache: Option<&Path>,
        mut tuning: Tuning,
        profile: crate::chains::Profile,
        strategy: Option<crate::model::SearchStrategy>,
    ) -> Result<Self> {
        let linear_only = strategy == Some(crate::model::SearchStrategy::Linear);
        profile.validate()?;
        if profile.address_type == crate::chains::AddressType::P2tr {
            tuning.max_lanes = tuning.max_lanes.min(4096);
        }
        tuning.validate()?;
        ensure!(
            batched || tuning.curve == Curve::Jacobian,
            "per-point baseline inversion requires the Jacobian variant"
        );
        let mut options = format!("{OPTIONS} -D BLOCK={}", tuning.inversion_width);
        if linear_only {
            options.push_str(" -D LINEAR_SEARCH=1");
        }
        let source = chain_gpu::source(&tuning, profile)?;
        let initialized = Instant::now();
        let info = discover()?
            .into_iter()
            .find(|d| d.index == index)
            .context("unknown OpenCL device index")?;
        ensure!(info.suitable, "OpenCL device is unsuitable");
        ensure!(
            !tuning.ternary_keccak
                || (info.vendor_id == 0x10de && info.has_extension("cl_nv_compiler_options")),
            "ternary Keccak requires the NVIDIA OpenCL compiler"
        );
        let device = devices()?
            .into_iter()
            .nth(index)
            .context("device disappeared")?;
        let context = Context::from_device(&device)?;
        let queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)?;
        let key = hex::encode(Sha256::digest(format!(
            "cache3:{}:{}:{}:{source}:{options}:{}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
            serde_json::to_string(&info.cache_identity())?
        )));
        let cache_path = cache.map(|p| p.join(format!("{key}.json")));
        if let Some(dir) = cache {
            let _guard = storage::guard(dir)?;
            if !storage::exists(dir)? {
                storage::create_directory(dir, false)?;
                storage::private(dir)?;
            }
            // Never convert a shared existing directory into a trusted cache.
            // Validate ownership/protection before reading any executable bytes.
            storage::assert_private_directory(dir)?;
        }
        let _cache_guard = cache.map(storage::guard).transpose()?;
        let cached = cache_path
            .as_ref()
            .and_then(|p| storage::read_private_json::<Cache>(p).ok())
            .filter(|c| {
                c.schema == 2 && c.key == key && c.sha256 == hex::encode(Sha256::digest(&c.binary))
            });
        let program = match cached.and_then(|c| {
            Program::create_and_build_from_binary(&context, &[&c.binary], &options).ok()
        }) {
            Some(program) => program,
            None => {
                let program = Program::create_and_build_from_source(&context, &source, &options)
                    .map_err(|e| anyhow::anyhow!("OpenCL compilation failed: {e}"))?;
                if let Some(path) = &cache_path {
                    let binary = program
                        .get_binaries()?
                        .into_iter()
                        .next()
                        .context("compiler returned no binary")?;
                    storage::write_json(
                        path,
                        &Cache {
                            schema: 2,
                            key,
                            sha256: hex::encode(Sha256::digest(&binary)),
                            binary,
                        },
                        true,
                    )?;
                }
                program
            }
        };
        let kernel = Kernel::create(&program, "search")?;
        if tuning.curve == Curve::Jacobian {
            ensure!(
                tuning.work_group_size <= kernel.get_work_group_size(device.id())?,
                "work group exceeds compiled kernel/device limit"
            );
        }
        let resources = serde_json::json!({
            "max_work_group_size": kernel.get_work_group_size(device.id()).ok(),
            "preferred_work_group_multiple": kernel.get_work_group_size_multiple(device.id()).ok(),
            "private_memory_bytes_reported": kernel.get_private_mem_size(device.id()).ok(),
            "local_memory_bytes_reported": kernel.get_local_mem_size(device.id()).ok(),
            "register_count_and_occupancy": "not exposed by portable OpenCL 1.2",
        });
        Ok(Self {
            linear_only,
            orbit: None,
            last_family_width: 1,
            chain_profile: profile,
            matching_cache: std::cell::RefCell::new(None),
            info,
            context,
            queue,
            kernel,
            _program: program,
            batched,
            kernel_seconds: 0.0,
            memory_bytes: 0,
            validated: false,
            last_profile: PipelineProfile::default(),
            profile: PipelineProfile::default(),
            last_device_end: 0,
            initialization_seconds: initialized.elapsed().as_secs_f64(),
            self_test_seconds: 0.0,
            resources,
            buffers: None,
            public_state: None,
            last_pattern: vec![],
            buffer_allocations: 0,
            state_reuses: 0,
            tuning,
            compiler_options: options,
            source_hash: hex::encode(Sha256::digest(source.as_bytes())),
            tuning_origin: "manual".into(),
            recurrence_state: None,
        })
    }
    fn matching_wire(&self, pattern: &Pattern) -> Result<Vec<u8>> {
        let mut cache = self.matching_cache.borrow_mut();
        let mut wire = if let Some((p, v)) = cache.as_ref()
            && p == pattern
        {
            v.clone()
        } else {
            let v = chain_gpu::wire(pattern)?;
            *cache = Some((pattern.clone(), v.clone()));
            v
        };
        if let Some(window) = self.orbit {
            wire[484] = window.width;
            wire[485] = window.skip;
            wire[488..492].copy_from_slice(&window.count.to_le_bytes());
        }
        Ok(wire)
    }
    fn selected_candidate(
        &self,
        job: &Job,
        range: &Interval,
        index: u32,
        actual: &[u8],
    ) -> Result<Candidate> {
        let width = self.orbit.map_or(1, |w| w.width);
        let offset =
            Offset::try_from(range.start)?.checked_add(u64::from(index / u32::from(width)))?;
        let transform =
            crate::transforms::Transform::from_branch((index % u32::from(width)) as u8)?;
        let mut found = Candidate {
            offset,
            transform,
            address: String::new(),
        };
        let point = found
            .point(job)
            .map_err(|error| CorrectnessError(error.to_string()))?;
        let payload = job
            .profile()
            .payload(&point)
            .map_err(|error| CorrectnessError(error.to_string()))?;
        correct(
            actual == &payload[..20],
            "GPU payload disagrees with independently reconstructed transformed key",
        )?;
        found.address = job
            .profile()
            .candidate(&point)
            .map_err(|error| CorrectnessError(error.to_string()))?;
        found
            .verify(job)
            .map_err(|e| CorrectnessError(e.to_string()))?;
        Ok(found)
    }
    fn evaluate(&mut self, job: &Job, range: &Interval, diagnostics: bool) -> Result<Evaluation> {
        let evaluation_started = Instant::now();
        let mut profile = PipelineProfile::default();
        let count = range.count()?;
        ensure!((1..=1_048_576).contains(&count), "invalid GPU batch size");
        let width = self.tuning.inversion_width;
        let lanes = count.div_ceil(width as u32) as usize;
        let addresses_size = if diagnostics {
            count as usize * 20
        } else {
            lanes * 20
        };
        let points_size = if diagnostics {
            count as usize * 65
        } else {
            130
        };
        let allocation_started = Instant::now();
        if self
            .buffers
            .as_ref()
            .is_none_or(|b| !b.fits(lanes, addresses_size, points_size))
        {
            self.buffers = Some(Reusable::new(
                &self.context,
                &self.info,
                lanes,
                addresses_size,
                points_size,
            )?);
            self.public_state = None;
            self.last_pattern.clear();
            self.buffer_allocations += 1;
        }
        profile.allocation_seconds = allocation_started.elapsed().as_secs_f64();
        let reuse = !diagnostics
            && self.public_state.as_ref().is_some_and(|(key, next, size)| {
                key == &job.public_key && *next == range.start && *size == count
            });
        let persist = !diagnostics && count.is_multiple_of(width as u32);
        let point = job.point()?;
        let mut starts = if reuse { vec![] } else { vec![0u8; lanes * 64] };
        let mut valid = if reuse { vec![] } else { vec![0u8; lanes] };
        // One reference multiplication per initialization, then public strides.
        // This avoids making host scalar multiplication the GPU bottleneck.
        if !reuse {
            let stride = public_at(&generator(), Offset::from_u64(width as u64 - 1))?
                .context("invalid public stride")?;
            let mut starting = public_at(&point, range.start)?;
            for lane in 0..lanes {
                if let Some(p) = starting {
                    starts[lane * 64..(lane + 1) * 64]
                        .copy_from_slice(&p.serialize_uncompressed()[1..]);
                    valid[lane] = 1;
                }
                starting = starting.and_then(|p| p.combine(&stride).ok()).or_else(|| {
                    if starting.is_none() {
                        Some(stride)
                    } else {
                        None
                    }
                });
            }
        }
        let pattern = self.matching_wire(&job.pattern)?;
        let prefix = job.pattern.prefix.len() as u32;
        let suffix = job.pattern.suffix.len() as u32;
        let batched = u32::from(self.batched);
        let diagnostic = u32::from(diagnostics);
        let mut jump = [0u8; 64];
        let jump_valid = u32::from(count > width as u32);
        if !reuse && persist && count > width as u32 {
            jump.copy_from_slice(
                &public_at(
                    &generator(),
                    Offset::from_u64(count as u64 - width as u64 - 1),
                )?
                .context("invalid public batch jump")?
                .serialize_uncompressed()[1..],
            );
        }
        profile.host_preparation_seconds =
            (evaluation_started.elapsed().as_secs_f64() - profile.allocation_seconds).max(0.0);
        // SAFETY: all buffers belong to this context, sizes are positive and bounded;
        // null host pointers request device allocation. Blocking transfers keep
        // host slices alive. Kernel bounds use count and lane count; output slots
        // have exactly the required capacity, including diagnostic coordinates.
        unsafe {
            let buffers = self.buffers.as_mut().expect("allocated reusable buffers");
            self.memory_bytes = buffers.bytes;
            let upload_started = Instant::now();
            self.queue
                .enqueue_write_buffer(&mut buffers.invalid, CL_BLOCKING, 0, &[0u32], &[])?;
            if !reuse {
                for event in [
                    self.queue.enqueue_write_buffer(
                        &mut buffers.starts,
                        CL_BLOCKING,
                        0,
                        &starts,
                        &[],
                    )?,
                    self.queue.enqueue_write_buffer(
                        &mut buffers.valid,
                        CL_BLOCKING,
                        0,
                        &valid,
                        &[],
                    )?,
                ] {
                    profile.upload_device_seconds += event_seconds(&event)?;
                }
                if persist {
                    profile.upload_device_seconds +=
                        event_seconds(&self.queue.enqueue_write_buffer(
                            &mut buffers.jump,
                            CL_BLOCKING,
                            0,
                            &jump,
                            &[],
                        )?)?;
                }
            }
            if pattern != self.last_pattern {
                profile.upload_device_seconds += event_seconds(&self.queue.enqueue_write_buffer(
                    &mut buffers.pattern,
                    CL_BLOCKING,
                    0,
                    &pattern,
                    &[],
                )?)?;
                self.last_pattern = pattern;
            }
            profile.upload_wall_seconds = upload_started.elapsed().as_secs_f64();
            let dispatch_started = Instant::now();
            let mut execution = ExecuteKernel::new(&self.kernel);
            execution
                .set_arg(&buffers.starts)
                .set_arg(&buffers.valid)
                .set_arg(&buffers.pattern)
                .set_arg(&prefix)
                .set_arg(&suffix)
                .set_arg(&count)
                .set_arg(&batched)
                .set_arg(&diagnostic)
                .set_arg(&buffers.hits)
                .set_arg(&buffers.addresses)
                .set_arg(&buffers.points)
                .set_arg(&buffers.states)
                .set_arg(&u32::from(reuse))
                .set_arg(&u32::from(persist))
                .set_arg(&buffers.jump)
                .set_arg(&jump_valid)
                .set_arg(&buffers.invalid);
            let local = self.tuning.work_group_size;
            execution.set_global_work_size(if local == 0 {
                lanes
            } else {
                lanes.div_ceil(local) * local
            });
            if local != 0 {
                execution.set_local_work_size(local);
            }
            let event = execution.enqueue_nd_range(&self.queue)?;
            self.queue.flush()?;
            let started = Instant::now();
            loop {
                let status = event.command_execution_status()?.0;
                ensure!(status >= 0, "OpenCL execution failed with status {status}");
                if status == 0 {
                    break;
                }
                ensure!(
                    started.elapsed() < Duration::from_secs(60),
                    "OpenCL kernel timeout; batch remains pending"
                );
                if self.tuning.poll_microseconds == 0 {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(Duration::from_micros(self.tuning.poll_microseconds));
                }
            }
            self.kernel_seconds =
                (event.profiling_command_end()? - event.profiling_command_start()?) as f64 / 1e9;
            profile.kernel_seconds = self.kernel_seconds;
            profile.dispatch_wait_seconds = dispatch_started.elapsed().as_secs_f64();
            if self.last_device_end != 0 {
                profile.device_idle_between_evaluations_seconds = event
                    .profiling_command_start()?
                    .saturating_sub(self.last_device_end)
                    as f64
                    / 1e9;
            }
            self.last_device_end = event.profiling_command_end()?;
            let download_started = Instant::now();
            let mut invalid = [0u32];
            self.queue
                .enqueue_read_buffer(&buffers.invalid, CL_BLOCKING, 0, &mut invalid, &[])?;
            let logical_count = self.orbit.map_or(count, |w| w.count);
            correct(
                invalid[0] <= logical_count,
                "GPU invalid counter exceeds assigned work",
            )?;
            let mut hits = vec![u32::MAX; lanes];
            let mut addresses = vec![0; addresses_size];
            let mut points = vec![0; points_size];
            for event in [
                self.queue
                    .enqueue_read_buffer(&buffers.hits, CL_BLOCKING, 0, &mut hits, &[])?,
                self.queue.enqueue_read_buffer(
                    &buffers.addresses,
                    CL_BLOCKING,
                    0,
                    &mut addresses,
                    &[],
                )?,
            ] {
                profile.download_device_seconds += event_seconds(&event)?;
            }
            {
                profile.download_device_seconds +=
                    event_seconds(&self.queue.enqueue_read_buffer(
                        &buffers.points,
                        CL_BLOCKING,
                        0,
                        &mut points,
                        &[],
                    )?)?;
            }
            profile.download_wall_seconds = download_started.elapsed().as_secs_f64();
            for (lane, hit) in hits.iter().enumerate() {
                correct(
                    *hit == u32::MAX
                        || (*hit < count * u32::from(self.orbit.map_or(1, |w| w.width))
                            && (*hit / u32::from(self.orbit.map_or(1, |w| w.width))) as usize
                                / width
                                == lane
                            && self.orbit.is_none_or(|w| {
                                *hit >= u32::from(w.skip) && *hit - u32::from(w.skip) < w.count
                            })),
                    "OpenCL returned invalid match index",
                )?;
            }
            self.last_profile = profile;
            if !diagnostics {
                self.public_state = persist.then(|| (job.public_key.clone(), range.end, count));
                self.state_reuses += u64::from(reuse);
            }
            Ok(Evaluation {
                invalid: invalid[0],
                hits,
                addresses,
                points,
            })
        }
    }
    fn compare(&mut self, initial: secp256k1::PublicKey, start: Offset, count: u32) -> Result<()> {
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: Uuid::nil(),
            public_key: hex::encode(initial.serialize()),
            pattern: Pattern::new("7", "f")?,
        };
        let range = Interval::new(start, count)?;
        let actual = self.evaluate(&job, &range, true)?;
        let mut expected_hits = vec![u32::MAX; actual.hits.len()];
        for i in 0..count {
            let expected = public_at(&initial, start.checked_add(i as u64)?)?;
            if let Some(p) = expected {
                correct(
                    actual.points[i as usize * 65..(i as usize + 1) * 65]
                        == p.serialize_uncompressed(),
                    format!("OpenCL public point mismatch at {i}"),
                )?;
                let addr = address(&p);
                correct(
                    actual.addresses[i as usize * 20..(i as usize + 1) * 20] == addr,
                    format!("OpenCL address mismatch at {i}"),
                )?;
                if job.pattern.matches(&addr)
                    && expected_hits[i as usize / self.tuning.inversion_width] == u32::MAX
                {
                    expected_hits[i as usize / self.tuning.inversion_width] = i;
                }
            } else {
                correct(
                    actual.points[i as usize * 65..(i as usize + 1) * 65]
                        .iter()
                        .all(|b| *b == 0),
                    "OpenCL infinity mismatch",
                )?;
            }
        }
        correct(
            actual.hits == expected_hits,
            "OpenCL matching decision mismatch",
        )?;
        Ok(())
    }
    fn compare_production(
        &mut self,
        initial: secp256k1::PublicKey,
        start: Offset,
        count: u32,
    ) -> Result<()> {
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: Uuid::nil(),
            public_key: hex::encode(initial.serialize()),
            pattern: Pattern::new("7", "f")?,
        };
        let range = Interval::new(start, count)?;
        let actual = self.evaluate(&job, &range, false)?;
        verify_endpoints(&job, &range, &actual.points)?;
        let mut expected_hits = vec![u32::MAX; actual.hits.len()];
        for i in 0..count {
            if let Some(point) = public_at(&initial, start.checked_add(i as u64)?)? {
                let addr = address(&point);
                if job.pattern.matches(&addr)
                    && expected_hits[i as usize / self.tuning.inversion_width] == u32::MAX
                {
                    expected_hits[i as usize / self.tuning.inversion_width] = i;
                    correct(
                        actual.addresses[i as usize / self.tuning.inversion_width * 20
                            ..(i as usize / self.tuning.inversion_width + 1) * 20]
                            == addr,
                        "persistent GPU match address mismatch",
                    )?;
                }
            }
        }
        correct(
            actual.hits == expected_hits,
            "persistent GPU candidate enumeration mismatch",
        )?;
        Ok(())
    }
}
impl Compute for Opencl {
    fn name(&self) -> String {
        format!("opencl:{}:{}", self.info.index, self.info.name)
    }
    fn diagnostics(&self) -> serde_json::Value {
        if self.tuning.curve != Curve::Jacobian {
            let parallel = recurrence::diagnostics(self);
            return serde_json::json!({"linear_specialization":self.linear_only,"candidate_family_width":self.last_family_width,"validated":self.validated,"tuning":self.tuning,"tuning_origin":self.tuning_origin,
                "compiler_options":self.compiler_options,"kernel_sha256":self.source_hash,
                "initialization_seconds":self.initialization_seconds,"self_test_seconds":self.self_test_seconds,
                "device_buffer_bytes":parallel.get("device_buffer_bytes"),"kernel_resources":parallel.get("kernel_resources"),
                "parallel":parallel});
        }
        serde_json::json!({"linear_specialization":self.linear_only,"candidate_family_width":self.last_family_width,"validated":self.validated,"last_kernel_seconds":self.kernel_seconds,"device_buffer_bytes":self.memory_bytes,"field_limbs":"8x32","points_per_lane":self.tuning.inversion_width,"batched_inversion":self.batched,"tuning":self.tuning,"compiler_options":self.compiler_options,"kernel_sha256":self.source_hash,"host_start_points":"public stride additions; contiguous batches retain GPU state", "pipeline_profile":self.profile,"initialization_seconds":self.initialization_seconds,"self_test_seconds":self.self_test_seconds,"kernel_resources":self.resources,"buffer_allocations":self.buffer_allocations,"persistent_state_reuses":self.state_reuses})
    }
    fn self_test(&mut self) -> Result<()> {
        if !self.chain_profile.is_evm() {
            return self.chain_self_test();
        }
        let started = Instant::now();
        self.validated = false;
        self.public_state = None;
        profiling::known_field_checks(self)?;
        if self.tuning.curve != Curve::Jacobian {
            recurrence::self_test(self)?;
            self.validated = true;
            self.orbit_self_test()?;
            self.self_test_seconds = started.elapsed().as_secs_f64();
            return Ok(());
        }
        self.compare(generator(), Offset::ZERO, 65)?;
        let negative = generator().negate(&secp256k1::Secp256k1::verification_only());
        self.compare(negative, Offset::ZERO, 33)?;
        let boundary =
            Offset::parse("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364120")?;
        self.compare(generator(), boundary, 33)?;
        for _ in 0..4 {
            let mut bytes = [0; 32];
            getrandom::fill(&mut bytes)
                .map_err(|e| anyhow::anyhow!("self-test entropy unavailable: {e}"))?;
            bytes[0] &= 0x7f;
            let offset = Offset(bytes);
            let initial =
                public_at(&generator(), offset)?.context("invalid randomized test point")?;
            self.compare(initial, offset, 64)?;
        }
        // Exercise production buffers/matching, including a full-length prefix.
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: Pattern::new(&hex::encode(address(&generator())), "")?,
        };
        let result = self.evaluate(&job, &Interval::new(Offset::ZERO, 33)?, false)?;
        correct(
            result.hits[0] == 0 && result.hits[1..].iter().all(|i| *i == u32::MAX),
            "production matching self-test failed",
        )?;
        correct(
            result.addresses[..20] == address(&generator()),
            "production address self-test failed",
        )?;
        verify_endpoints(&job, &Interval::new(Offset::ZERO, 33)?, &result.points)?;
        // Validate persistent transitions, gaps, tails, changes of public key,
        // infinity and doubling through the actual production buffers.
        let block = self.tuning.inversion_width as u64 * 2;
        for initial in [generator(), negative] {
            for start in [0, block, block * 2, block * 16, block * 17] {
                self.compare_production(initial, Offset::from_u64(start), block as u32)?;
            }
            self.compare_production(initial, Offset::from_u64(block * 18), 17)?;
            self.compare_production(initial, Offset::from_u64(block * 18 + 17), block as u32)?;
        }
        self.validated = true;
        self.orbit_self_test()?;
        self.self_test_seconds = started.elapsed().as_secs_f64();
        self.last_device_end = 0;
        self.profile = PipelineProfile::default();
        self.public_state = None;
        self.state_reuses = 0;
        Ok(())
    }
    fn run(&mut self, job: &Job, range: &Interval, cancel: &AtomicBool) -> Result<BatchResult> {
        correct(
            !self.linear_only || job.strategy == crate::model::SearchStrategy::Linear,
            "transformed job cannot use a linear-only OpenCL program",
        )?;
        ensure!(
            range.end <= job.work_limit(),
            "GPU work exceeds job enumeration"
        );
        if job.width() == 1 {
            self.last_family_width = 1;
            self.orbit = None;
            return self.run_base(job, range, cancel);
        }
        job.validate()?;
        let started = Instant::now();
        let count = range.count()?;
        let family = job.width();
        let mut completed = 0u32;
        let mut evaluated = 0u32;
        let mut candidate = None;
        while completed < count && !cancel.load(Ordering::Relaxed) {
            let cursor = range.start.checked_add(completed.into())?;
            let (base, skip) = cursor.div_rem(family)?;
            let cap = if self.chain_profile.address_type == crate::chains::AddressType::P2tr {
                4096
            } else if self.tuning.curve == Curve::Jacobian {
                if self.batched { 1_048_576 } else { 32768 }
            } else {
                crate::backend::MAX_BATCH
            };
            let n = (count - completed).min(cap * u32::from(family) - u32::from(skip));
            let base_count = (n + u32::from(skip)).div_ceil(u32::from(family));
            let base_range = Interval::new(base, base_count)?;
            self.orbit = Some(OrbitWindow {
                width: family,
                skip,
                count: n,
            });
            self.last_family_width = family;
            let result = self.run_base(job, &base_range, cancel);
            self.orbit = None;
            let result = result?;
            if result.completed == 0 {
                break;
            }
            correct(
                result.completed == base_count,
                "partial transformed dispatch without cursor",
            )?;
            completed += n;
            evaluated += result.evaluated;
            candidate = result.candidate;
            if candidate.is_some() {
                break;
            }
        }
        Ok(BatchResult {
            completed,
            evaluated,
            candidate,
            seconds: started.elapsed().as_secs_f64(),
        })
    }
}

fn event_seconds(event: &opencl3::event::Event) -> Result<f64> {
    Ok((event.profiling_command_end()? - event.profiling_command_start()?) as f64 / 1e9)
}

fn verify_endpoints(job: &Job, range: &Interval, actual: &[u8]) -> Result<()> {
    correct(actual.len() == 130, "invalid GPU endpoint buffer length")?;
    for (slot, offset) in [
        (0, range.start),
        (
            usize::from(range.count()? != 1),
            range.start.checked_add(range.count()? as u64 - 1)?,
        ),
    ] {
        let expected = public_at(&job.point()?, offset)?
            .map(|p| p.serialize_uncompressed())
            .unwrap_or([0u8; 65]);
        correct(
            actual[slot * 65..(slot + 1) * 65] == expected,
            "GPU production endpoint disagrees with CPU",
        )?;
    }
    Ok(())
}

impl Opencl {
    fn run_base(
        &mut self,
        job: &Job,
        range: &Interval,
        cancel: &AtomicBool,
    ) -> Result<BatchResult> {
        ensure!(
            self.validated,
            "OpenCL backend must pass self-test before production work"
        );
        if cancel.load(Ordering::Relaxed) {
            return Ok(BatchResult {
                evaluated: 0,
                completed: 0,
                candidate: None,
                seconds: 0.0,
            });
        }
        ensure!(
            job.profile() == self.chain_profile,
            "GPU profile differs from job"
        );
        let cap = if self.chain_profile.address_type == crate::chains::AddressType::P2tr {
            4096
        } else {
            crate::backend::MAX_BATCH
        };
        if range.count()? > cap {
            let started = Instant::now();
            let mut completed = 0;
            let mut evaluated = 0;
            let mut candidate = None;
            while completed < range.count()? && !cancel.load(Ordering::Relaxed) {
                let piece = Interval::new(
                    range.start.checked_add(completed as u64)?,
                    (range.count()? - completed).min(cap),
                )?;
                let r = self.run_base(job, &piece, cancel)?;
                completed += r.completed;
                evaluated += r.evaluated;
                candidate = r.candidate;
                if candidate.is_some() || r.completed < piece.count()? {
                    break;
                }
            }
            return Ok(BatchResult {
                evaluated,
                completed,
                candidate,
                seconds: started.elapsed().as_secs_f64(),
            });
        }
        if self.tuning.curve != Curve::Jacobian {
            let result = recurrence::run(self, job, range);
            if result.is_err() {
                self.validated = false;
            }
            return result;
        }
        // Preserve bounded dispatches even when the durable interval is larger.
        let quantum = if self.batched { 1_048_576 } else { 32768 };
        if range.count()? > quantum {
            let started = Instant::now();
            let mut completed = 0;
            let mut evaluated = 0;
            let mut candidate = None;
            while completed < range.count()? && !cancel.load(Ordering::Relaxed) {
                let piece = Interval::new(
                    range.start.checked_add(completed as u64)?,
                    (range.count()? - completed).min(quantum),
                )?;
                let result = self.run_base(job, &piece, cancel)?;
                completed += result.completed;
                evaluated += result.evaluated;
                candidate = result.candidate;
                if candidate.is_some() || result.completed < piece.count()? {
                    break;
                }
            }
            return Ok(BatchResult {
                evaluated,
                completed,
                candidate,
                seconds: started.elapsed().as_secs_f64(),
            });
        }
        let started = Instant::now();
        let actual = match self.evaluate(job, range, false) {
            Ok(actual) => actual,
            Err(e) => {
                self.validated = false;
                return Err(e);
            }
        };
        let mut profile = self.last_profile.clone();
        let verification_started = Instant::now();
        let mut candidate = None;
        for (lane, index) in actual
            .hits
            .iter()
            .enumerate()
            .filter(|(_, i)| **i != u32::MAX)
        {
            let found = self.selected_candidate(
                job,
                range,
                *index,
                &actual.addresses[lane * 20..(lane + 1) * 20],
            )?;
            if let Err(e) = found.verify(job) {
                self.validated = false;
                return Err(CorrectnessError(e.to_string()).into());
            }
            if candidate
                .as_ref()
                .is_none_or(|c: &Candidate| found.offset < c.offset)
            {
                candidate = Some(found);
            }
        }
        profile.result_verification_seconds = verification_started.elapsed().as_secs_f64();
        // Verify actual boundary points returned by the main dispatch. No extra
        // GPU evaluation is needed; failures still leave the whole range pending.
        let checked = (|| -> Result<()> {
            let endpoints_started = Instant::now();
            verify_endpoints(job, range, &actual.points)?;
            profile.endpoint_verification_seconds = endpoints_started.elapsed().as_secs_f64();
            Ok(())
        })();
        if let Err(e) = checked {
            self.validated = false;
            return Err(e);
        }
        profile.batches = 1;
        profile.total_worker_seconds = started.elapsed().as_secs_f64();
        self.profile.batches += profile.batches;
        self.profile.host_preparation_seconds += profile.host_preparation_seconds;
        self.profile.allocation_seconds += profile.allocation_seconds;
        self.profile.upload_wall_seconds += profile.upload_wall_seconds;
        self.profile.upload_device_seconds += profile.upload_device_seconds;
        self.profile.kernel_seconds += profile.kernel_seconds;
        self.profile.dispatch_wait_seconds += profile.dispatch_wait_seconds;
        self.profile.download_wall_seconds += profile.download_wall_seconds;
        self.profile.download_device_seconds += profile.download_device_seconds;
        self.profile.result_verification_seconds += profile.result_verification_seconds;
        self.profile.endpoint_verification_seconds += profile.endpoint_verification_seconds;
        self.profile.endpoint_kernel_seconds += profile.endpoint_kernel_seconds;
        self.profile.device_idle_between_evaluations_seconds +=
            profile.device_idle_between_evaluations_seconds;
        self.profile.total_worker_seconds += profile.total_worker_seconds;
        Ok(BatchResult {
            evaluated: self.orbit.map_or(range.count()?, |w| w.count) - actual.invalid,
            completed: range.count()?,
            candidate,
            seconds: started.elapsed().as_secs_f64(),
        })
    }
}

impl Opencl {
    fn orbit_self_test(&mut self) -> Result<()> {
        if self.linear_only {
            return Ok(());
        }
        let profile = self.chain_profile;
        let width = if profile.address_type == crate::chains::AddressType::P2tr {
            3
        } else {
            6
        };
        let target = public_at(&generator(), Offset::from_u64(2))?.expect("small public multiple");
        let result = (|| -> Result<()> {
            for initial in [
                generator(),
                generator().negate(&secp256k1::Secp256k1::verification_only()),
            ] {
                for branch in 0..width {
                    let transformed =
                        crate::transforms::Transform::from_branch(branch)?.public(&target)?;
                    let job = Job {
                        schema: 3,
                        strategy: crate::model::SearchStrategy::EndomorphismV1,
                        session_id: Uuid::nil(),
                        public_key: hex::encode(initial.serialize()),
                        pattern: Pattern::for_profile(
                            profile,
                            &profile.address(&transformed)?,
                            "",
                        )?,
                    };
                    let range = Interval::new(Offset::from_u64(1), u32::from(width) * 5 - 2)?;
                    let cancel = AtomicBool::new(false);
                    let expected =
                        crate::backend::cpu::Cpu { index: 0 }.run(&job, &range, &cancel)?;
                    let actual = self.run(&job, &range, &cancel)?;
                    correct(
                        actual.completed == expected.completed
                            && actual.evaluated == expected.evaluated
                            && actual.candidate == expected.candidate,
                        "GPU transformed family self-test mismatch",
                    )?;
                }
            }
            Ok(())
        })();
        self.orbit = None;
        self.public_state = None;
        self.recurrence_state = None;
        if result.is_err() {
            self.validated = false;
        }
        result
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    #[test]
    fn production_source_keeps_known_answer_checks_and_gates_lab_kernels() {
        for fast_field in [false, true] {
            let source = source_for(&Tuning {
                fast_field,
                ..Tuning::default()
            });
            assert!(source.contains("kernel void field_probe("));
            for probe in [
                "kernel void ethereum_hash_probe(",
                "kernel void ethereum_word_match_probe(",
                "kernel void field_reduce512_probe(",
            ] {
                assert_eq!(source.contains(probe), cfg!(feature = "developer-tools"));
            }
        }
    }
    #[test]
    fn actual_production_boundaries_reject_corruption() {
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: Pattern::new("0", "").unwrap(),
        };
        for count in [1, 33] {
            let range = Interval::new(Offset::ZERO, count).unwrap();
            let mut bytes = vec![0u8; 130];
            bytes[..65].copy_from_slice(&generator().serialize_uncompressed());
            if count != 1 {
                bytes[65..].copy_from_slice(
                    &public_at(&generator(), Offset::from_u64(count as u64 - 1))
                        .unwrap()
                        .unwrap()
                        .serialize_uncompressed(),
                );
            }
            verify_endpoints(&job, &range, &bytes).unwrap();
            bytes[17] ^= 1;
            assert!(verify_endpoints(&job, &range, &bytes).is_err());
            assert!(verify_endpoints(&job, &range, &bytes[..64]).is_err());
        }
    }
}
