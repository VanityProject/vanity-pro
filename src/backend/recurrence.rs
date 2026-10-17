//! Contiguous parallel affine/slope walks over public points and offsets only.
//! Volatile state is a cache: a gap or restart always reconstructs a known offset.
use super::*;
use opencl3::event::Event;

const NAMES: [&str; 11] = [
    "r_prepare_step",
    "r_initialize",
    "r_jump",
    "r_inverse",
    "r_affine",
    "r_seed_slope",
    "r_denominators",
    "r_reset",
    "r_iterate",
    "a_iterate",
    "r_gather",
];
#[derive(Clone, Default, Serialize)]
struct Profile {
    batches: u64,
    initializations: u64,
    state_reuses: u64,
    state_jumps: u64,
    derived_addresses: u64,
    peak_buffer_bytes: usize,
    queue_gap_seconds: f64,
    allocation_seconds: f64,
    host_preparation_seconds: f64,
    upload_wall_seconds: f64,
    gpu_initialization_seconds: f64,
    gpu_state_jump_seconds: f64,
    gpu_inversion_seconds: f64,
    gpu_curve_hash_match_seconds: f64,
    gpu_reset_gather_seconds: f64,
    gpu_total_seconds: f64,
    max_dispatch_seconds: f64,
    wait_wall_seconds: f64,
    download_wall_seconds: f64,
    verification_seconds: f64,
    worker_seconds: f64,
}
pub(super) struct State {
    kernels: HashMap<&'static str, Kernel>,
    x: Buffer<u32>,
    y: Buffer<u32>,
    z: Buffer<u32>,
    inverse: Buffer<u32>,
    scratch: Buffer<u32>,
    flags: Buffer<u32>,
    hits: Buffer<u32>,
    addresses: Buffer<u8>,
    minimum: Buffer<u32>,
    invalid: Buffer<u32>,
    fault: Buffer<u32>,
    endpoints: Buffer<u8>,
    summary: Buffer<u8>,
    powers: Buffer<u8>,
    base: Buffer<u8>,
    step_input: Buffer<u8>,
    step: Buffer<u8>,
    pattern: Buffer<u8>,
    diagnostic_addresses: Buffer<u8>,
    diagnostic_points: Buffer<u8>,
    capacity: usize,
    diagnostic_capacity: usize,
    memory_bytes: usize,
    key: Option<(String, crate::work::WorkIndex, usize)>,
    step_lanes: Option<usize>,
    stride: Option<secp256k1::PublicKey>,
    last_device_end: u64,
    last_pattern: Vec<u8>,
    resources: serde_json::Value,
    profile: Profile,
}
fn buffer<T>(context: &Context, flags: u64, count: usize, info: &DeviceInfo) -> Result<Buffer<T>> {
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .context("GPU size overflow")?;
    ensure!(
        count > 0 && bytes as u64 <= info.max_allocation_bytes,
        "GPU buffer exceeds device allocation limit"
    );
    // SAFETY: positive checked element sizes, null host pointer and the caller's
    // context. Kernel/transfer layouts are checked at their bounded call sites.
    Ok(unsafe { Buffer::create(context, flags, count, ptr::null_mut())? })
}
fn wait_for_event(event: &Event, poll_microseconds: u64) -> Result<()> {
    let started = Instant::now();
    loop {
        let status = event.command_execution_status()?.0;
        ensure!(status >= 0, "OpenCL graph failed with status {status}");
        if status == 0 {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(60),
            "GPU graph timeout; assigned interval remains pending"
        );
        if poll_microseconds == 0 {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(poll_microseconds));
        }
    }
}
impl State {
    fn new(worker: &Opencl, lanes: usize, diagnostic_count: usize) -> Result<Self> {
        let allocated = Instant::now();
        let scratch_words = if worker.tuning.global_prefix {
            lanes * 8
        } else {
            8
        };
        let diagnostic_capacity = diagnostic_count.max(1);
        let memory_bytes =
            lanes * (32 * 4 + 4 * 2 + 20) + scratch_words * 4 + diagnostic_capacity * 85 + 2245;
        ensure!(
            memory_bytes as u64 <= worker.info.memory_bytes / 2,
            "GPU public-state memory budget exceeded"
        );
        let device = devices()?
            .into_iter()
            .nth(worker.info.index)
            .context("GPU disappeared")?;
        let mut kernels = HashMap::new();
        let mut resources = serde_json::Map::new();
        for name in NAMES {
            let kernel = Kernel::create(&worker._program, name)?;
            let max = kernel.get_work_group_size(device.id())?;
            if !matches!(name, "r_prepare_step" | "r_gather") {
                ensure!(
                    worker.tuning.work_group_size <= max,
                    "work group exceeds {name} kernel limit"
                );
            }
            resources.insert(
                name.into(),
                serde_json::json!({"max_work_group":max,
                "private_memory_bytes_reported":kernel.get_private_mem_size(device.id()).ok(),
                "local_memory_bytes_reported":kernel.get_local_mem_size(device.id()).ok()}),
            );
            kernels.insert(name, kernel);
        }
        let context = &worker.context;
        let info = &worker.info;
        let mut state = Self {
            kernels,
            x: buffer(context, CL_MEM_READ_WRITE, lanes * 8, info)?,
            y: buffer(context, CL_MEM_READ_WRITE, lanes * 8, info)?,
            z: buffer(context, CL_MEM_READ_WRITE, lanes * 8, info)?,
            inverse: buffer(context, CL_MEM_READ_WRITE, lanes * 8, info)?,
            scratch: buffer(context, CL_MEM_READ_WRITE, scratch_words, info)?,
            flags: buffer(context, CL_MEM_READ_WRITE, lanes, info)?,
            hits: buffer(context, CL_MEM_READ_WRITE, lanes, info)?,
            addresses: buffer(context, CL_MEM_READ_WRITE, lanes * 20, info)?,
            minimum: buffer(context, CL_MEM_READ_WRITE, 1, info)?,
            invalid: buffer(context, CL_MEM_READ_WRITE, 1, info)?,
            fault: buffer(context, CL_MEM_READ_WRITE, 1, info)?,
            endpoints: buffer(context, CL_MEM_READ_WRITE, 130, info)?,
            summary: buffer(context, CL_MEM_WRITE_ONLY, 166, info)?,
            powers: buffer(context, CL_MEM_READ_ONLY, 22 * 64, info)?,
            base: buffer(context, CL_MEM_READ_ONLY, 65, info)?,
            step_input: buffer(context, CL_MEM_READ_ONLY, 128, info)?,
            step: buffer(context, CL_MEM_READ_WRITE, 256, info)?,
            pattern: buffer(context, CL_MEM_READ_ONLY, chain_gpu::WIRE_SIZE, info)?,
            diagnostic_addresses: buffer(
                context,
                CL_MEM_WRITE_ONLY,
                diagnostic_capacity * 20,
                info,
            )?,
            diagnostic_points: buffer(context, CL_MEM_WRITE_ONLY, diagnostic_capacity * 65, info)?,
            capacity: lanes,
            diagnostic_capacity,
            memory_bytes,
            key: None,
            step_lanes: None,
            stride: None,
            last_device_end: 0,
            last_pattern: vec![],
            resources: serde_json::Value::Object(resources),
            profile: Profile::default(),
        };
        let mut powers = Vec::with_capacity(22 * 64);
        for bit in 0..22 {
            let p = public_at(&generator(), Offset::from_u64((1u64 << bit) - 1))?
                .context("invalid public power")?;
            powers.extend_from_slice(&p.serialize_uncompressed()[1..]);
        }
        // SAFETY: the blocking write copies exactly the public precomputation
        // allocation; the owned source remains live until the transfer completes.
        unsafe {
            worker
                .queue
                .enqueue_write_buffer(&mut state.powers, CL_BLOCKING, 0, &powers, &[])?;
        }
        state.profile.allocation_seconds = allocated.elapsed().as_secs_f64();
        state.profile.peak_buffer_bytes = memory_bytes;
        Ok(state)
    }
    fn fits(&self, lanes: usize, diagnostic_count: usize) -> bool {
        self.capacity >= lanes && self.diagnostic_capacity >= diagnostic_count
    }
    fn evaluate(
        &mut self,
        worker: &Opencl,
        job: &Job,
        range: &Interval,
        lanes: usize,
        diagnostic: bool,
    ) -> Result<Raw> {
        let started = Instant::now();
        let prepare = Instant::now();
        let count = range.count()?;
        let rows = (count as usize).div_ceil(lanes);
        ensure!(
            rows <= 256,
            "GPU dispatch graph exceeds 256 rows; increase --gpu-lanes or reduce batch size"
        );
        let previous_next = self
            .key
            .as_ref()
            .and_then(|(key, next, n)| (key == &job.public_key && *n == lanes).then_some(*next));
        let reuse = previous_next.is_some();
        let shifted = previous_next.is_some_and(|next| next != range.start);
        let recurrent = worker.tuning.curve == Curve::Recurrence;
        let point = job.point()?;
        let need_step = self.step_lanes != Some(lanes);
        let h = if need_step {
            public_at(&generator(), Offset::from_u64(lanes as u64 - 1))?
                .context("invalid public lane stride")?
        } else {
            self.stride.context("missing public stride")?
        };
        let mut step_input = vec![];
        if need_step {
            step_input.extend_from_slice(&h.serialize_uncompressed()[1..]);
            step_input.extend_from_slice(&h.combine(&h)?.serialize_uncompressed()[1..]);
        }
        let mut base = [0u8; 65];
        if let Some(next) = previous_next.filter(|next| *next != range.start) {
            let (difference, negative) = if range.start >= next {
                (next.difference(range.start)?, false)
            } else {
                (range.start.difference(next)?, true)
            };
            // public_at(G,k-1) gives kG. A difference equal to the curve
            // order is the identity; no private scalar is involved.
            let point = public_at(
                &generator(),
                Offset::from_u64(1).difference(difference.try_into()?)?,
            )?;
            if let Some(point) = point {
                base = if negative {
                    point.negate(&secp256k1::Secp256k1::verification_only())
                } else {
                    point
                }
                .serialize_uncompressed();
            }
        } else if !reuse {
            let mut p = public_at(&point, range.start)?;
            if recurrent {
                let negative = h.negate(&secp256k1::Secp256k1::verification_only());
                p = match p {
                    Some(p) => p.combine(&negative).ok(),
                    None => Some(negative),
                };
            }
            if let Some(p) = p {
                base = p.serialize_uncompressed();
            }
        }
        let pattern = worker.matching_wire(&job.pattern)?;
        let prefix = job.pattern.prefix.len() as u32;
        let suffix = job.pattern.suffix.len() as u32;
        let n = lanes as u32;
        let local = worker.tuning.work_group_size;
        let mode = u32::from(recurrent);
        let diagnostic_flag = u32::from(diagnostic);
        let family = u32::from(worker.orbit.map_or(1, |w| w.width));
        let mut events: Vec<(&str, Event)> = Vec::with_capacity(rows * 3 + 32);
        self.profile.host_preparation_seconds += prepare.elapsed().as_secs_f64();
        // SAFETY: every named kernel has the fixed signature in recurrence.cl.
        // Buffers belong to this context, sizes cover all guarded indices, scalar
        // layouts match uint, and the final in-order gather/read completes every
        // enqueue before any buffer, slice or state transition can be released.
        unsafe {
            macro_rules! enqueue {
                ($name:expr,$total:expr,$group:expr,$offset:expr; $($arg:expr),+ $(,)?) => {{
                    let mut execution=ExecuteKernel::new(self.kernels.get($name).expect("known kernel"));
                    $(execution.set_arg($arg);)+
                    let group:usize=$group;let total:usize=$total;
                    execution.set_global_work_offset($offset).set_global_work_size(if group==0{total}else{total.div_ceil(group)*group});
                    if group!=0 {execution.set_local_work_size(group);}
                    let event=execution.enqueue_nd_range(&worker.queue)?;
                    if worker.tuning.synchronous_dispatch {
                        worker.queue.flush()?;
                        let wait=Instant::now();
                        wait_for_event(&event,worker.tuning.poll_microseconds)?;
                        self.profile.wait_wall_seconds+=wait.elapsed().as_secs_f64();
                    }
                    events.push(($name,event));
                }};
            }
            let upload = Instant::now();
            if need_step {
                worker.queue.enqueue_write_buffer(
                    &mut self.step_input,
                    CL_BLOCKING,
                    0,
                    &step_input,
                    &[],
                )?;
            }
            if !reuse || shifted {
                worker
                    .queue
                    .enqueue_write_buffer(&mut self.base, CL_BLOCKING, 0, &base, &[])?;
            }
            if pattern != self.last_pattern {
                worker.queue.enqueue_write_buffer(
                    &mut self.pattern,
                    CL_BLOCKING,
                    0,
                    &pattern,
                    &[],
                )?;
                self.last_pattern = pattern;
            }
            self.profile.upload_wall_seconds += upload.elapsed().as_secs_f64();
            if need_step {
                enqueue!("r_prepare_step",1,0,0;&self.step_input,&self.step);
                self.step_lanes = Some(lanes);
                self.stride = Some(h);
            }
            if !reuse {
                let chunk = 131072usize
                    .checked_div(local)
                    .map_or(131072, |groups| groups.max(1) * local);
                for offset in (0..lanes).step_by(chunk) {
                    enqueue!("r_initialize",(lanes-offset).min(chunk),local,offset;
                        &self.base,&self.powers,&n,&self.x,&self.y,&self.z,&self.flags);
                }
            } else if shifted {
                enqueue!("r_jump",lanes,local,0;&self.base,&n,&self.x,&self.y,&self.z,&self.flags,&self.step,&mode);
            }
            if !reuse || shifted {
                enqueue!("r_inverse",lanes.div_ceil(worker.tuning.inversion_width),local,0;
                    &self.z,&n,&self.inverse,&self.scratch,&self.step,&0u32);
                enqueue!("r_affine",lanes,local,0;&self.x,&self.y,&self.z,&self.inverse,&self.flags,&self.step,&n,&mode);
                if recurrent {
                    enqueue!("r_inverse",lanes.div_ceil(worker.tuning.inversion_width),local,0;
                        &self.x,&n,&self.inverse,&self.scratch,&self.step,&0u32);
                    enqueue!("r_seed_slope",lanes,local,0;&self.x,&self.y,&self.inverse,&self.flags,&self.step,&n);
                }
            }
            enqueue!("r_reset",lanes,local,0;&self.hits,&n,&self.minimum,&self.invalid,&self.fault,&self.endpoints);
            for row in 0..rows as u32 {
                if !recurrent {
                    enqueue!("r_denominators",lanes,local,0;&self.x,&self.flags,&self.step,&n,&self.z);
                }
                let source = if recurrent { &self.x } else { &self.z };
                enqueue!("r_inverse",lanes.div_ceil(worker.tuning.inversion_width),local,0;
                    source,&n,&self.inverse,&self.scratch,&self.step,&mode);
                let name = if recurrent { "r_iterate" } else { "a_iterate" };
                enqueue!(name,lanes,local,0;&self.x,&self.y,&self.flags,&self.inverse,&self.step,
                    &n,&row,&count,&self.pattern,&prefix,&suffix,&self.hits,&self.addresses,&self.minimum,
                    &self.invalid,&self.fault,&self.endpoints,&diagnostic_flag,&self.diagnostic_addresses,&self.diagnostic_points);
            }
            enqueue!("r_gather",1,0,0;&self.minimum,&self.invalid,&self.fault,&self.hits,&self.addresses,&self.endpoints,&n,&count,&family,&self.summary);
            worker.queue.flush()?;
            let wait = Instant::now();
            let last = &events.last().expect("gather event").1;
            wait_for_event(last, worker.tuning.poll_microseconds)?;
            self.profile.wait_wall_seconds += wait.elapsed().as_secs_f64();
            let download = Instant::now();
            let mut summary = vec![0u8; 166];
            worker
                .queue
                .enqueue_read_buffer(&self.summary, CL_BLOCKING, 0, &mut summary, &[])?;
            let mut points = vec![];
            let mut addresses = vec![];
            if diagnostic {
                points.resize(count as usize * 65, 0);
                addresses.resize(count as usize * 20, 0);
                worker.queue.enqueue_read_buffer(
                    &self.diagnostic_points,
                    CL_BLOCKING,
                    0,
                    &mut points,
                    &[],
                )?;
                worker.queue.enqueue_read_buffer(
                    &self.diagnostic_addresses,
                    CL_BLOCKING,
                    0,
                    &mut addresses,
                    &[],
                )?;
            }
            self.profile.download_wall_seconds += download.elapsed().as_secs_f64();
            let mut initialization = !reuse || shifted;
            for (name, event) in events {
                let seconds = event_seconds(&event)?;
                if self.last_device_end != 0 {
                    self.profile.queue_gap_seconds += event
                        .profiling_command_start()?
                        .saturating_sub(self.last_device_end)
                        as f64
                        / 1e9;
                }
                self.last_device_end = event.profiling_command_end()?;
                self.profile.gpu_total_seconds += seconds;
                self.profile.max_dispatch_seconds = self.profile.max_dispatch_seconds.max(seconds);
                if name == "r_reset" {
                    initialization = false;
                }
                if initialization {
                    if shifted {
                        self.profile.gpu_state_jump_seconds += seconds;
                    } else {
                        self.profile.gpu_initialization_seconds += seconds;
                    }
                } else if name == "r_inverse" {
                    self.profile.gpu_inversion_seconds += seconds;
                } else if matches!(name, "r_iterate" | "a_iterate" | "r_denominators") {
                    self.profile.gpu_curve_hash_match_seconds += seconds;
                } else {
                    self.profile.gpu_reset_gather_seconds += seconds;
                }
            }
            let (index, invalid) = validate_summary_width(&summary, count, worker.orbit)?;
            let cached_next = range.start.checked_add((rows * lanes) as u64)?;
            self.key = (cached_next <= crate::crypto::ORDER)
                .then(|| (job.public_key.clone(), cached_next, lanes));
            self.profile.batches += 1;
            self.profile.initializations += u64::from(!reuse);
            self.profile.state_reuses += u64::from(reuse);
            self.profile.state_jumps += u64::from(shifted);
            self.profile.derived_addresses +=
                (worker.orbit.map_or(count, |w| w.count) - invalid) as u64;
            self.profile.worker_seconds += started.elapsed().as_secs_f64();
            Ok(Raw {
                index,
                address: summary[16..36].to_vec(),
                endpoints: summary[36..166].to_vec(),
                points,
                addresses,
                invalid,
            })
        }
    }
}
struct Raw {
    index: u32,
    address: Vec<u8>,
    endpoints: Vec<u8>,
    points: Vec<u8>,
    addresses: Vec<u8>,
    invalid: u32,
}
fn raw(
    worker: &mut Opencl,
    job: &Job,
    range: &Interval,
    diagnostic: bool,
    limit: usize,
) -> Result<Raw> {
    let count = range.count()?;
    ensure!(
        count > 0 && count <= crate::backend::MAX_BATCH,
        "invalid GPU batch size"
    );
    ensure!(
        !diagnostic || count <= 4096,
        "diagnostic range exceeds 4096 points"
    );
    let per_lane = 156 + if worker.tuning.global_prefix { 32 } else { 0 };
    let memory_cap = (worker.info.memory_bytes / 2).saturating_sub(400_000) / per_lane;
    let cap = limit
        .min(memory_cap as usize)
        .min(worker.info.max_allocation_bytes as usize / 32)
        .max(1);
    // Stable geometry permits reuse across partial-family boundaries.
    let maximum = (count as usize).min(cap);
    let lanes = 1usize << (usize::BITS - 1 - maximum.leading_zeros());
    let diagnostic_count = if diagnostic { count as usize } else { 0 };
    let mut state = match worker.recurrence_state.take() {
        Some(state) if state.fits(lanes, diagnostic_count) => state,
        previous => {
            let mut next = State::new(worker, lanes, diagnostic_count)?;
            let allocation = next.profile.allocation_seconds;
            if let Some(previous) = previous {
                next.profile = previous.profile;
                next.profile.allocation_seconds += allocation;
                next.last_device_end = previous.last_device_end;
                next.profile.peak_buffer_bytes =
                    next.profile.peak_buffer_bytes.max(next.memory_bytes);
            }
            next.profile.worker_seconds += allocation;
            next
        }
    };
    let result = state.evaluate(worker, job, range, lanes, diagnostic);
    if result.is_err() {
        state.key = None;
        state.step_lanes = None;
        state.stride = None;
    }
    worker.recurrence_state = Some(state);
    result
}
#[cfg(test)]
fn validate_summary(summary: &[u8], count: u32) -> Result<(u32, u32)> {
    validate_summary_width(summary, count, None)
}
fn validate_summary_width(
    summary: &[u8],
    count: u32,
    window: Option<OrbitWindow>,
) -> Result<(u32, u32)> {
    correct(summary.len() == 166, "invalid compact GPU result length")?;
    let word = |i: usize| u32::from_le_bytes(summary[i..i + 4].try_into().expect("four bytes"));
    let index = word(0);
    let invalid = word(4);
    correct(word(8) == 0, "GPU public-state flag corruption")?;
    correct(
        invalid <= window.map_or(count, |w| w.count),
        "GPU derived-address counter exceeds assigned range",
    )?;
    correct(
        index == u32::MAX
            || (index < count * u32::from(window.map_or(1, |w| w.width))
                && window.is_none_or(|w| {
                    index >= u32::from(w.skip) && index - u32::from(w.skip) < w.count
                })),
        "GPU match outside assigned range",
    )?;
    correct(
        word(12) == index,
        "GPU compact result disagrees with its bounded lane slot",
    )?;
    Ok((index, invalid))
}
pub(super) fn run(worker: &mut Opencl, job: &Job, range: &Interval) -> Result<BatchResult> {
    let started = Instant::now();
    let actual = raw(worker, job, range, false, worker.tuning.max_lanes)?;
    let verify = Instant::now();
    verify_endpoints(job, range, &actual.endpoints)?;
    let candidate = if actual.index == u32::MAX {
        None
    } else {
        let candidate = worker.selected_candidate(job, range, actual.index, &actual.address)?;
        candidate
            .verify(job)
            .map_err(|e| CorrectnessError(e.to_string()))?;
        Some(candidate)
    };
    if let Some(state) = &mut worker.recurrence_state {
        let seconds = verify.elapsed().as_secs_f64();
        state.profile.verification_seconds += seconds;
        state.profile.worker_seconds += seconds;
    }
    Ok(BatchResult {
        evaluated: worker.orbit.map_or(range.count()?, |w| w.count) - actual.invalid,
        completed: range.count()?,
        candidate,
        seconds: started.elapsed().as_secs_f64(),
    })
}
pub(super) fn diagnostics(worker: &Opencl) -> serde_json::Value {
    worker.recurrence_state.as_ref().map_or_else(||serde_json::json!({}),|state|
        serde_json::json!({"profile":state.profile,"device_buffer_bytes":state.memory_bytes,
            "kernel_resources":state.resources,"curve":worker.tuning.curve,"inversion_width":worker.tuning.inversion_width,
            "normal_result_transfer_bytes":166,"offset_mapping":"start + row * lanes + lane"}))
}
pub(super) fn compare(
    worker: &mut Opencl,
    initial: secp256k1::PublicKey,
    start: Offset,
    count: u32,
    limit: usize,
    pattern: Pattern,
) -> Result<()> {
    let job = Job {
        strategy: crate::model::SearchStrategy::Linear,
        schema: crate::model::JOB_SCHEMA,
        session_id: Uuid::nil(),
        public_key: hex::encode(initial.serialize()),
        pattern,
    };
    let range = Interval::new(start, count)?;
    let actual = raw(worker, &job, &range, true, limit)?;
    verify_endpoints(&job, &range, &actual.endpoints)?;
    let mut expected = u32::MAX;
    let mut invalid = 0;
    for i in 0..count {
        if let Some(p) = public_at(&initial, start.checked_add(i as u64)?)? {
            correct(
                actual.points[i as usize * 65..(i as usize + 1) * 65] == p.serialize_uncompressed(),
                format!("parallel GPU point mismatch at {i}"),
            )?;
            let addr = worker.chain_profile.payload(&p)?;
            correct(
                actual.addresses[i as usize * 20..(i as usize + 1) * 20] == addr[..20],
                format!("parallel GPU address mismatch at {i}"),
            )?;
            if expected == u32::MAX && job.pattern.compiled()?.accepts_payload(&addr) {
                expected = i;
            }
        } else {
            invalid += 1;
            correct(
                actual.points[i as usize * 65..(i as usize + 1) * 65]
                    .iter()
                    .all(|b| *b == 0),
                "parallel infinity mismatch",
            )?;
        }
    }
    correct(
        actual.index == expected,
        "parallel GPU matching decision mismatch",
    )?;
    correct(
        actual.invalid == invalid,
        "parallel GPU valid-address count mismatch",
    )?;
    if expected != u32::MAX {
        chain_gpu::candidate(&job, start.checked_add(expected as u64)?, &actual.address)?;
    }
    Ok(())
}
pub(super) fn self_test(worker: &mut Opencl) -> Result<()> {
    let limit = worker.tuning.max_lanes.min(64);
    let negative = generator().negate(&secp256k1::Secp256k1::verification_only());
    for initial in [generator(), negative] {
        for start in [0, 64, 128, 4096, 4160, 64] {
            compare(
                worker,
                initial,
                Offset::from_u64(start),
                64,
                limit,
                Pattern::new("7", "f")?,
            )?;
        }
        compare(
            worker,
            initial,
            Offset::from_u64(4224),
            17,
            limit,
            Pattern::new("a", "")?,
        )?;
    }
    let count = (limit * 4).min(257) as u32;
    let boundary = Offset::from_u64(count as u64).difference(crate::crypto::ORDER)?;
    compare(
        worker,
        generator(),
        boundary,
        count,
        limit,
        Pattern::new("0", "")?,
    )?;
    // Rewind from the exclusive curve-order cursor: a shift of nG is identity.
    compare(
        worker,
        generator(),
        Offset::ZERO,
        limit as u32,
        limit,
        Pattern::new("0", "")?,
    )?;
    compare(
        worker,
        generator(),
        Offset::ZERO,
        130,
        limit,
        Pattern::new(&hex::encode(address(&generator())), "")?,
    )?;
    // Exercise full prefix arrays as well as partial groups. Interleaving a
    // width*2+3 range creates three shorter groups rather than two full ones.
    let full_width_count = (worker.tuning.inversion_width * 2).min(worker.tuning.max_lanes) as u32;
    compare(
        worker,
        generator(),
        Offset::ZERO,
        full_width_count,
        full_width_count as usize,
        Pattern::new("0", "")?,
    )?;
    let width_count = (worker.tuning.inversion_width * 2 + 3).min(worker.tuning.max_lanes) as u32;
    for i in 0..3 {
        compare(
            worker,
            generator(),
            Offset::from_u64(i * width_count as u64),
            width_count,
            width_count as usize,
            Pattern::new("7", "f")?,
        )?;
    }
    for _ in 0..3 {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| anyhow::anyhow!("GPU test entropy unavailable: {e}"))?;
        bytes[0] &= 0x7f;
        let offset = Offset(bytes);
        let initial =
            public_at(&generator(), offset)?.context("invalid random public test point")?;
        compare(worker, initial, offset, 97, limit, Pattern::new("7", "f")?)?;
    }
    if let Some(state) = &mut worker.recurrence_state {
        state.key = None;
        state.profile = Profile::default();
        state.last_device_end = 0;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_single_wallet_slots_reject_corruption_and_overflow() {
        let mut data = vec![0u8; 166];
        data[..4].copy_from_slice(&3u32.to_le_bytes());
        data[12..16].copy_from_slice(&3u32.to_le_bytes());
        validate_summary(&data, 8).unwrap();
        for (offset, value) in [(0usize, 8u32), (4, 9), (8, 1), (12, 4)] {
            let mut bad = data.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(validate_summary(&bad, 8).is_err());
        }
        assert!(validate_summary(&data[..165], 8).is_err());
        data[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        data[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        validate_summary(&data, 8).unwrap();
    }

    #[test]
    #[ignore = "requires real OpenCL hardware; corrupts only a throwaway public GPU state flag"]
    fn shifted_public_state_does_not_hide_a_corrupt_flag() {
        let info = discover().unwrap().remove(0);
        let mut worker =
            Opencl::with_tuning(0, true, None, crate::backend::autotune::preset(&info)).unwrap();
        worker.self_test().unwrap();
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: Pattern::new(&"0".repeat(40), "").unwrap(),
        };
        // A device claiming a hit at infinity is a cryptographic fault, never
        // an availability error that could silently fall back to another worker.
        let mut infinity_job = job.clone();
        infinity_job.schema = 3;
        infinity_job.strategy = crate::model::SearchStrategy::EndomorphismV1;
        infinity_job.public_key = hex::encode(
            generator()
                .negate(&secp256k1::Secp256k1::verification_only())
                .serialize(),
        );
        worker.orbit = Some(OrbitWindow {
            width: 6,
            skip: 0,
            count: 6,
        });
        let error = worker
            .selected_candidate(
                &infinity_job,
                &Interval::new(Offset::from_u64(1), 1).unwrap(),
                0,
                &[0; 20],
            )
            .unwrap_err();
        assert!(error.downcast_ref::<CorrectnessError>().is_some());
        worker.orbit = None;
        let cancel = std::sync::atomic::AtomicBool::new(false);
        worker
            .run(&job, &Interval::new(Offset::ZERO, 4096).unwrap(), &cancel)
            .unwrap();
        let state = worker.recurrence_state.as_mut().unwrap();
        // SAFETY: fault injection writes one public uint within this context's
        // flags allocation; the blocking copy retains the one-word source.
        unsafe {
            worker
                .queue
                .enqueue_write_buffer(&mut state.flags, CL_BLOCKING, 0, &[4u32], &[])
                .unwrap();
        }
        assert!(
            worker
                .run(
                    &job,
                    &Interval::new(Offset::from_u64(8192), 4096).unwrap(),
                    &cancel
                )
                .is_err()
        );
        assert!(!worker.validated);
    }
}
