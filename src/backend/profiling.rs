//! Explicit stage probes of the original portable kernel. Global intermediate
//! buffers preserve the work but add traffic absent from its fused production
//! kernel, so these timings describe isolated stages, not an additive breakdown.
use super::*;
#[cfg(feature = "developer-tools")]
use opencl3::memory::CL_MEM_READ_WRITE;

#[cfg(feature = "developer-tools")]
const PROBES: &str = include_str!("../../kernels/profile.cl");

/// Check every public point, address and matching decision in a bounded interval
/// against the independent CPU library; this does not create or finalize a key.
#[cfg(feature = "developer-tools")]
pub fn verify_interval(worker: &mut Opencl, job: &Job, range: &Interval) -> Result<()> {
    ensure!(worker.validated, "interval probing requires validated GPU");
    ensure!(
        worker.tuning.curve != Curve::Jacobian,
        "full interval probing requires affine or recurrence kernel"
    );
    let limit = worker.tuning.max_lanes;
    recurrence::compare(
        worker,
        job.point()?,
        range.start.try_into()?,
        range.count()?,
        limit,
        job.pattern.clone(),
    )
}

/// Public diagnostic arithmetic on canonical inputs below the field prime.
/// This is independent of candidate-throughput counting; zero inverse is zero.
#[cfg(feature = "developer-tools")]
pub fn field_vectors(worker: &Opencl, inputs: &[[u32; 16]]) -> Result<Vec<[u32; 32]>> {
    ensure!(worker.validated, "field probing requires validated GPU");
    field_vectors_unchecked(worker, inputs)
}
const FIELD_PRIME: [u32; 8] = [
    0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
];
fn validate_field_inputs(inputs: &[[u32; 16]]) -> Result<()> {
    ensure!(
        !inputs.is_empty() && inputs.len() <= 4096,
        "field vectors must be 1..4096"
    );
    for pair in inputs {
        for value in pair.as_chunks::<8>().0 {
            ensure!(
                value.iter().rev().cmp(FIELD_PRIME.iter().rev()).is_lt(),
                "field arithmetic inputs must be canonical integers below p"
            );
        }
    }
    Ok(())
}
fn field_vectors_unchecked(worker: &Opencl, inputs: &[[u32; 16]]) -> Result<Vec<[u32; 32]>> {
    validate_field_inputs(inputs)?;
    let kernel = Kernel::create(&worker._program, "field_probe")?;
    let count = inputs.len() as u32;
    let flat: Vec<u32> = inputs
        .iter()
        .flat_map(|pair| pair.iter().copied())
        .collect();
    let mut results = vec![0u32; inputs.len() * 32];
    // SAFETY: bounded public uint layouts match field_probe, all buffers share
    // context, and blocking transfers and the completed event retain lifetimes.
    unsafe {
        let mut input = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            flat.len(),
            ptr::null_mut(),
        )?;
        let output = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            results.len(),
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut input, CL_BLOCKING, 0, &flat, &[])?;
        let event = ExecuteKernel::new(&kernel)
            .set_arg(&input)
            .set_arg(&count)
            .set_arg(&output)
            .set_global_work_size(inputs.len())
            .enqueue_nd_range(&worker.queue)?;
        event.wait()?;
        worker
            .queue
            .enqueue_read_buffer(&output, CL_BLOCKING, 0, &mut results, &[])?;
    }
    Ok(results.as_chunks::<32>().0.to_vec())
}

pub(super) fn known_field_checks(worker: &Opencl) -> Result<()> {
    #[derive(Deserialize)]
    struct Cases {
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        a: String,
        b: String,
        expected: [String; 4],
    }
    fn words(value: &str) -> Result<Vec<u32>> {
        let bytes = hex::decode(value)?;
        ensure!(bytes.len() == 32, "invalid embedded field vector");
        Ok(bytes
            .rchunks_exact(4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")))
            .collect())
    }
    let cases: Cases = serde_json::from_str(include_str!("../../assets/field-known.json"))?;
    let mut inputs = vec![];
    for c in &cases.cases {
        let mut input = words(&c.a)?;
        input.extend(words(&c.b)?);
        inputs.push(input.try_into().expect("two field elements"));
    }
    let actual = field_vectors_unchecked(worker, &inputs)?;
    for (case, result) in cases.cases.iter().zip(actual) {
        for op in 0..4 {
            correct(
                result[op * 8..(op + 1) * 8] == words(&case.expected[op])?,
                format!("GPU field known-answer failure, operation {op}"),
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "developer-tools")]
pub fn components(worker: &mut Opencl, count: u32, repeats: u32) -> Result<serde_json::Value> {
    ensure!(
        (16..=65536).contains(&count),
        "profile count must be 16..65536"
    );
    ensure!(
        (1..=1000).contains(&repeats),
        "profile repeats must be 1..1000"
    );
    ensure!(
        worker.validated,
        "profiling requires validated OpenCL worker"
    );
    let lanes = count.div_ceil(16) as usize;
    let count_usize = count as usize;
    let program = Program::create_and_build_from_source(
        &worker.context,
        &format!("{}\n{PROBES}", source_for(&worker.tuning)),
        OPTIONS,
    )
    .map_err(|e| anyhow::anyhow!("profiling probe compilation: {e}"))?;
    let names = [
        "profile_seed",
        "profile_curve",
        "profile_inverse",
        "profile_affine",
        "profile_keccak",
        "profile_match",
    ];
    let kernels: Vec<_> = names
        .iter()
        .map(|name| Kernel::create(&program, name))
        .collect::<std::result::Result<_, _>>()?;
    let mut starts = Vec::with_capacity(lanes * 64);
    for i in 0..lanes {
        let p = public_at(&generator(), Offset::from_u64((i * 16) as u64))?
            .context("profile infinity")?;
        starts.extend_from_slice(&p.serialize_uncompressed()[1..]);
    }
    let valid = vec![1u8; lanes];
    let pattern = vec![0u8; 40];
    // SAFETY: sizes exactly match the kernel's uint/fe/point wire layouts. All
    // buffers share worker.context and live until every event completes. The
    // bounded count prevents index/size overflow; blocking uploads retain slices.
    unsafe {
        let mut s = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            starts.len(),
            ptr::null_mut(),
        )?;
        let mut v = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            valid.len(),
            ptr::null_mut(),
        )?;
        let mut p = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            pattern.len(),
            ptr::null_mut(),
        )?;
        let projected = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_WRITE,
            count_usize * 96,
            ptr::null_mut(),
        )?;
        let inverses = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_WRITE,
            count_usize * 32,
            ptr::null_mut(),
        )?;
        let affine = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_WRITE,
            count_usize * 65,
            ptr::null_mut(),
        )?;
        let hashes = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_WRITE,
            count_usize * 20,
            ptr::null_mut(),
        )?;
        let matches = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            count_usize,
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut s, CL_BLOCKING, 0, &starts, &[])?;
        worker
            .queue
            .enqueue_write_buffer(&mut v, CL_BLOCKING, 0, &valid, &[])?;
        worker
            .queue
            .enqueue_write_buffer(&mut p, CL_BLOCKING, 0, &pattern, &[])?;
        let prefix = 40u32;
        let suffix = 0u32;
        let mut samples = vec![Vec::<f64>::new(); names.len()];
        for repeat in 0..=repeats {
            for (index, kernel) in kernels.iter().enumerate() {
                let event = match index {
                    0 | 1 => ExecuteKernel::new(kernel)
                        .set_arg(&s)
                        .set_arg(&v)
                        .set_arg(&count)
                        .set_arg(&projected)
                        .set_global_work_size(lanes)
                        .enqueue_nd_range(&worker.queue)?,
                    2 => ExecuteKernel::new(kernel)
                        .set_arg(&projected)
                        .set_arg(&count)
                        .set_arg(&inverses)
                        .set_global_work_size(lanes)
                        .enqueue_nd_range(&worker.queue)?,
                    3 => ExecuteKernel::new(kernel)
                        .set_arg(&projected)
                        .set_arg(&inverses)
                        .set_arg(&count)
                        .set_arg(&affine)
                        .set_global_work_size(count_usize)
                        .enqueue_nd_range(&worker.queue)?,
                    4 => ExecuteKernel::new(kernel)
                        .set_arg(&affine)
                        .set_arg(&count)
                        .set_arg(&hashes)
                        .set_global_work_size(count_usize)
                        .enqueue_nd_range(&worker.queue)?,
                    5 => ExecuteKernel::new(kernel)
                        .set_arg(&hashes)
                        .set_arg(&p)
                        .set_arg(&prefix)
                        .set_arg(&suffix)
                        .set_arg(&count)
                        .set_arg(&matches)
                        .set_global_work_size(count_usize)
                        .enqueue_nd_range(&worker.queue)?,
                    _ => unreachable!(),
                };
                event.wait()?;
                if repeat != 0 {
                    samples[index].push(event_seconds(&event)?);
                }
            }
        }
        let mut actual_points = vec![0u8; count_usize * 65];
        let mut actual_hashes = vec![0u8; count_usize * 20];
        let mut actual_matches = vec![0u32; count_usize];
        worker
            .queue
            .enqueue_read_buffer(&affine, CL_BLOCKING, 0, &mut actual_points, &[])?;
        worker
            .queue
            .enqueue_read_buffer(&hashes, CL_BLOCKING, 0, &mut actual_hashes, &[])?;
        worker
            .queue
            .enqueue_read_buffer(&matches, CL_BLOCKING, 0, &mut actual_matches, &[])?;
        for i in 0..count_usize {
            let expected = public_at(&generator(), Offset::from_u64(i as u64))?
                .context("invalid profile reference")?;
            correct(
                actual_points[i * 65..(i + 1) * 65] == expected.serialize_uncompressed(),
                "staged profiling point disagrees with CPU",
            )?;
            let addr = address(&expected);
            correct(
                actual_hashes[i * 20..(i + 1) * 20] == addr,
                "staged profiling Keccak disagrees with CPU",
            )?;
            correct(
                actual_matches[i] == u32::from(addr == [0u8; 20]),
                "staged profiling matching disagrees with CPU",
            )?;
        }
        let device = devices()?
            .into_iter()
            .nth(worker.info.index)
            .context("profile device disappeared")?;
        let stages: Vec<_> = names.iter().enumerate().map(|(index, name)| {
            let mut sorted = samples[index].clone();
            sorted.sort_by(f64::total_cmp);
            serde_json::json!({"stage":name,"event_seconds":samples[index],"median_seconds":sorted[sorted.len()/2],
                "private_memory_bytes_reported":kernels[index].get_private_mem_size(device.id()).ok(),
                "local_memory_bytes_reported":kernels[index].get_local_mem_size(device.id()).ok(),
                "max_work_group":kernels[index].get_work_group_size(device.id()).ok()})
        }).collect();
        Ok(
            serde_json::json!({"scope":"isolated staged probes; extra intermediate VRAM traffic; do not add as fused-kernel costs",
            "count":count,"repeats":repeats,"correctness":"every staged public point, hash and matching decision checked against CPU",
            "scratch_buffer_bytes":count_usize*(96+32+65+20+4),"stages":stages}),
        )
    }
}

#[cfg(feature = "developer-tools")]
pub fn report(index: usize, count: u32, repeats: u32) -> Result<serde_json::Value> {
    let info = discover()?
        .into_iter()
        .find(|d| d.index == index)
        .context("unknown GPU")?;
    let (tuning, origin) = crate::backend::autotune::resolve(
        &info,
        crate::backend::autotune::default_directory().as_deref(),
    )?;
    let mut worker = Opencl::with_tuning(index, true, None, tuning)?;
    worker.tuning_origin = origin.into();
    worker.self_test()?;
    let job = Job {
        strategy: crate::model::SearchStrategy::Linear,
        schema: SCHEMA,
        session_id: Uuid::nil(),
        public_key: hex::encode(generator().serialize()),
        pattern: Pattern::new(&"0".repeat(40), "")?,
    };
    let warmup = Instant::now();
    let mut offset = crate::work::WorkIndex::ZERO;
    while warmup.elapsed().as_secs_f64() < 2.0 {
        let range = Interval::new(offset, count)?;
        worker.run(&job, &range, &AtomicBool::new(false))?;
        offset = range.end;
    }
    worker.profile = PipelineProfile::default();
    worker.last_device_end = 0;
    for i in 0..repeats {
        let range = Interval::new(offset.checked_add(i as u64 * count as u64)?, count)?;
        worker.run(&job, &range, &AtomicBool::new(false))?;
    }
    let production = worker.diagnostics();
    let probes = components(&mut worker, count, repeats)?;
    Ok(
        serde_json::json!({"schema":1,"application":env!("CARGO_PKG_VERSION"),"public_only":true,
        "device":worker.info,"warmup_seconds":2,"original_kernel_sha256":hex::encode(Sha256::digest(SOURCE)),
        "probe_source_sha256":hex::encode(Sha256::digest(PROBES)),"production":production,"probes":probes}),
    )
}

/// Compare public, fixed-width coordinate hashing without requiring curve points.
#[cfg(feature = "developer-tools")]
pub fn ethereum_hash_vectors(worker: &Opencl, inputs: &[[u8; 64]]) -> Result<Vec<[u8; 20]>> {
    ensure!(
        worker.validated && worker.chain_profile.is_evm(),
        "Ethereum hash probing requires a validated EVM worker"
    );
    ensure!(
        !inputs.is_empty() && inputs.len() <= 4096,
        "Ethereum vectors must be 1..4096"
    );
    let kernel = Kernel::create(&worker._program, "ethereum_hash_probe")?;
    let count = inputs.len() as u32;
    let flat: Vec<u8> = inputs.iter().flatten().copied().collect();
    let mut result = vec![0u8; inputs.len() * 20];
    // SAFETY: bounded public byte layouts match the probe. All buffers share
    // the worker context and remain live through blocking copies/event completion.
    unsafe {
        let mut input = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            flat.len(),
            ptr::null_mut(),
        )?;
        let output = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            result.len(),
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut input, CL_BLOCKING, 0, &flat, &[])?;
        ExecuteKernel::new(&kernel)
            .set_arg(&input)
            .set_arg(&output)
            .set_arg(&count)
            .set_global_work_size(inputs.len())
            .enqueue_nd_range(&worker.queue)?
            .wait()?;
        worker
            .queue
            .enqueue_read_buffer(&output, CL_BLOCKING, 0, &mut result, &[])?;
    }
    Ok(result.as_chunks::<20>().0.to_vec())
}

/// Public diagnostic record: payload20, raw pattern wire492, prefix/suffix LE32.
/// Raw masks allow explicit mutation tests; never creates search candidates.
#[cfg(feature = "developer-tools")]
pub fn ethereum_word_match_vectors(worker: &Opencl, inputs: &[[u8; 520]]) -> Result<Vec<[u32; 3]>> {
    ensure!(
        worker.validated
            && worker.chain_profile.is_evm()
            && worker.tuning.address_keccak
            && worker.tuning.word_match,
        "word matching probe requires a validated address-Keccak EVM worker"
    );
    ensure!(
        !inputs.is_empty() && inputs.len() <= 4096,
        "matcher vectors must be 1..4096"
    );
    for record in inputs {
        let prefix = u32::from_le_bytes(record[512..516].try_into().expect("four bytes"));
        let suffix = u32::from_le_bytes(record[516..520].try_into().expect("four bytes"));
        ensure!(
            prefix <= 40 && suffix <= 40 && (1..=40).contains(&(prefix + suffix)),
            "invalid matcher vector lengths"
        );
    }
    let kernel = Kernel::create(&worker._program, "ethereum_word_match_probe")?;
    let count = inputs.len() as u32;
    let flat: Vec<u8> = inputs.iter().flatten().copied().collect();
    let mut result = vec![0u32; inputs.len() * 3];
    // SAFETY: checked bounded 520-byte public records match the kernel ABI;
    // exact uint outputs, common context, blocking transfers and event completion.
    unsafe {
        let mut input = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            flat.len(),
            ptr::null_mut(),
        )?;
        let output = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            result.len(),
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut input, CL_BLOCKING, 0, &flat, &[])?;
        ExecuteKernel::new(&kernel)
            .set_arg(&input)
            .set_arg(&output)
            .set_arg(&count)
            .set_global_work_size(inputs.len())
            .enqueue_nd_range(&worker.queue)?
            .wait()?;
        worker
            .queue
            .enqueue_read_buffer(&output, CL_BLOCKING, 0, &mut result, &[])?;
    }
    Ok(result.as_chunks::<3>().0.to_vec())
}

/// Public fixed-64-byte coordinate hashing through the new word-output helper.
#[cfg(feature = "developer-tools")]
pub fn ethereum_word_hash_vectors(worker: &Opencl, inputs: &[[u8; 64]]) -> Result<Vec<[u8; 20]>> {
    ensure!(
        worker.validated
            && worker.chain_profile.is_evm()
            && worker.tuning.address_keccak
            && worker.tuning.word_match,
        "word hashing requires a validated address-Keccak EVM worker"
    );
    ensure!(
        !inputs.is_empty() && inputs.len() <= 4096,
        "Ethereum vectors must be 1..4096"
    );
    let kernel = Kernel::create(&worker._program, "ethereum_word_hash_probe")?;
    let count = inputs.len() as u32;
    let flat: Vec<u8> = inputs.iter().flatten().copied().collect();
    let mut result = vec![0u8; inputs.len() * 20];
    // SAFETY: bounded public coordinate inputs and exact20-byte outputs match
    // the probe, with common context and blocking/event-completed transfers.
    unsafe {
        let mut input = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            flat.len(),
            ptr::null_mut(),
        )?;
        let output = Buffer::<u8>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            result.len(),
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut input, CL_BLOCKING, 0, &flat, &[])?;
        ExecuteKernel::new(&kernel)
            .set_arg(&input)
            .set_arg(&output)
            .set_arg(&count)
            .set_global_work_size(inputs.len())
            .enqueue_nd_range(&worker.queue)?
            .wait()?;
        worker
            .queue
            .enqueue_read_buffer(&output, CL_BLOCKING, 0, &mut result, &[])?;
    }
    Ok(result.as_chunks::<20>().0.to_vec())
}

/// Reduce bounded public 512-bit integers without requiring canonical inputs.
/// Records contain sixteen least-significant-first numeric uint32 limbs.
#[cfg(feature = "developer-tools")]
pub fn bounded_reduction_vectors(worker: &Opencl, inputs: &[[u32; 16]]) -> Result<Vec<[u32; 8]>> {
    ensure!(
        worker.validated && worker.tuning.bounded_multiply,
        "512-bit reduction probing requires a validated bounded-multiply worker"
    );
    ensure!(
        !inputs.is_empty() && inputs.len() <= 4096,
        "reduction vectors must be 1..4096"
    );
    let kernel = Kernel::create(&worker._program, "field_reduce512_probe")?;
    let count = inputs.len() as u32;
    let flat: Vec<u32> = inputs.iter().flatten().copied().collect();
    let mut result = vec![0u32; inputs.len() * 8];
    // SAFETY: checked 16-word public inputs and exact eight-word outputs match
    // the bounded kernel ABI. Context and completed transfers retain all buffers.
    unsafe {
        let mut input = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_READ_ONLY,
            flat.len(),
            ptr::null_mut(),
        )?;
        let output = Buffer::<u32>::create(
            &worker.context,
            CL_MEM_WRITE_ONLY,
            result.len(),
            ptr::null_mut(),
        )?;
        worker
            .queue
            .enqueue_write_buffer(&mut input, CL_BLOCKING, 0, &flat, &[])?;
        ExecuteKernel::new(&kernel)
            .set_arg(&input)
            .set_arg(&count)
            .set_arg(&output)
            .set_global_work_size(inputs.len())
            .enqueue_nd_range(&worker.queue)?
            .wait()?;
        worker
            .queue
            .enqueue_read_buffer(&output, CL_BLOCKING, 0, &mut result, &[])?;
    }
    Ok(result.as_chunks::<8>().0.to_vec())
}

#[cfg(test)]
mod field_input_tests {
    use super::*;
    #[test]
    fn field_diagnostics_require_canonical_add_sub_operands() {
        let mut pair = [0; 16];
        assert!(validate_field_inputs(&[pair]).is_ok());
        pair[..8].copy_from_slice(&FIELD_PRIME);
        assert!(validate_field_inputs(&[pair]).is_err());
        pair[0] -= 1;
        assert!(validate_field_inputs(&[pair]).is_ok());
        pair[8..].copy_from_slice(&FIELD_PRIME);
        assert!(validate_field_inputs(&[pair]).is_err());
        assert!(validate_field_inputs(&[[u32::MAX; 16]]).is_err());
        assert!(validate_field_inputs(&[]).is_err());
        assert!(validate_field_inputs(&vec![[0; 16]; 4097]).is_err());
    }
}
