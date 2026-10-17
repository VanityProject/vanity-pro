use crate::{
    backend::{
        Compute, CorrectnessError, correct,
        cpu::Cpu,
        cpu_info,
        opencl::{self, Opencl},
    },
    model::{Checkpoint, Interval, Job, Results, SCHEMA},
    storage,
};
use anyhow::{Context as _, Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    // Read legacy preferences/session metadata without exposing Hybrid in CLI.
    #[serde(alias = "hybrid")]
    Auto,
    Cpu,
    Opencl,
}
#[derive(Clone, Debug)]
pub struct Config {
    pub mode: Mode,
    pub profile: Option<crate::chains::Profile>,
    pub threads: usize,
    pub devices: Vec<usize>,
    pub exclude_devices: Vec<usize>,
    pub batch_size: u32,
    pub max_candidates: Option<u64>,
    pub max_seconds: Option<f64>,
    pub cache: Option<PathBuf>,
    pub quiet: bool,
    pub json_lines: bool,
    pub batched: bool,
    pub cpu_engine: crate::backend::CpuEngine,
    pub hash_mode: crate::backend::HashMode,
    pub ed_table: crate::backend::EdTable,
    pub benchmark_strategy: Option<crate::model::SearchStrategy>,
    pub benchmark_pattern: Option<crate::crypto::Pattern>,
    pub encoded_suffix: bool,
    pub gpu_tuning: opencl::Tuning,
    pub automatic_gpu: bool,
    pub tuning_cache: Option<PathBuf>,
    /// Public local-selection evidence, separate from persisted job/wallet formats.
    pub calibration: Option<serde_json::Value>,
    pub calibration_record: Option<PathBuf>,
    pub calibration_cancel: Option<Arc<AtomicBool>>,
    pub tuning_mode: crate::backend::calibration::TuningMode,
    pub calibration_hardware: Vec<(usize, String)>,
    pub calibration_skip: Option<Arc<AtomicBool>>,
    pub calibration_active: Option<Arc<AtomicBool>>,
    pub calibration_status: Option<mpsc::SyncSender<String>>,
    pub calibration_overrides: Option<(
        crate::backend::CpuEngine,
        crate::backend::HashMode,
        crate::backend::EdTable,
    )>,
    /// Bounded public statistics stream; a slow UI never blocks computation.
    pub progress: Option<mpsc::SyncSender<Progress>>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Auto,
            profile: None,
            threads: cpu_info().logical_processors.saturating_sub(1).max(1),
            devices: vec![],
            exclude_devices: vec![],
            batch_size: 4_194_304,
            max_candidates: None,
            max_seconds: None,
            cache: None,
            quiet: false,
            json_lines: false,
            batched: true,
            cpu_engine: Default::default(),
            hash_mode: Default::default(),
            ed_table: Default::default(),
            benchmark_strategy: None,
            benchmark_pattern: None,
            encoded_suffix: false,
            gpu_tuning: opencl::Tuning::default(),
            automatic_gpu: true,
            tuning_cache: crate::backend::autotune::default_directory(),
            calibration: None,
            calibration_record: None,
            calibration_cancel: None,
            tuning_mode: Default::default(),
            calibration_hardware: vec![],
            calibration_skip: None,
            calibration_active: None,
            calibration_status: None,
            calibration_overrides: None,
            progress: None,
        }
    }
}
fn can_skip_device(config: &Config, error: &anyhow::Error) -> bool {
    config.devices.is_empty() && error.downcast_ref::<CorrectnessError>().is_none()
}
fn checked_selection(
    selected: Result<Vec<Box<dyn Compute>>>,
    checkpoint: &mut Checkpoint,
    path: &Path,
) -> Result<Vec<Box<dyn Compute>>> {
    match selected {
        Err(error) if error.downcast_ref::<CorrectnessError>().is_some() => {
            checkpoint.fault = Some(format!("compute startup: {error:#}"));
            if let Err(storage_error) = storage::save_checkpoint(path, checkpoint) {
                return Err(error.context(format!(
                    "record cryptographic startup failure: {storage_error:#}"
                )));
            }
            Err(error)
        }
        other => other,
    }
}
struct CalibratedWorker {
    inner: Box<dyn Compute>,
    diagnostics: serde_json::Value,
    record: Option<PathBuf>,
}
impl Compute for CalibratedWorker {
    fn name(&self) -> String {
        self.inner.name()
    }
    fn diagnostics(&self) -> serde_json::Value {
        let mut value = self.inner.diagnostics();
        value["calibration"] = self.diagnostics.clone();
        value
    }
    fn self_test(&mut self) -> Result<()> {
        let result = self.inner.self_test();
        crate::backend::calibration::with_fault_record(self.record.as_deref(), result)
    }
    fn run(
        &mut self,
        job: &Job,
        range: &Interval,
        cancel: &AtomicBool,
    ) -> Result<crate::backend::BatchResult> {
        let result = self.inner.run(job, range, cancel);
        crate::backend::calibration::with_fault_record(self.record.as_deref(), result)
    }
}
fn decorate(worker: Box<dyn Compute>, config: &Config) -> Box<dyn Compute> {
    if let Some(diagnostics) = &config.calibration {
        Box::new(CalibratedWorker {
            inner: worker,
            diagnostics: diagnostics.clone(),
            record: config.calibration_record.clone(),
        })
    } else {
        worker
    }
}
pub fn select(config: &Config) -> Result<Vec<Box<dyn Compute>>> {
    config.gpu_tuning.validate()?;
    ensure!(
        (1..=256).contains(&config.threads),
        "thread count must be 1..256"
    );
    ensure!(
        (1..=crate::backend::MAX_BATCH).contains(&config.batch_size),
        "batch size must be 1..16777216"
    );
    ensure!(
        config.max_seconds.is_none_or(|s| s.is_finite() && s > 0.0),
        "duration must be positive and finite"
    );
    ensure!(
        config.max_candidates != Some(0),
        "candidate budget must be positive"
    );
    let mut workers: Vec<Box<dyn Compute>> = vec![];
    if !matches!(config.mode, Mode::Cpu) {
        let result = (|| -> Result<Vec<Box<dyn Compute>>> {
            let infos = opencl::discover()?;
            let selected = if config.devices.is_empty() {
                opencl::automatic_enabled(&infos, &config.exclude_devices)?
            } else {
                config.devices.clone()
            };
            let mut seen = HashSet::new();
            let mut physical = HashSet::new();
            let mut gpus: Vec<Box<dyn Compute>> = vec![];
            for index in selected {
                ensure!(seen.insert(index), "duplicate device index");
                if config.exclude_devices.contains(&index) {
                    continue;
                }
                if let Some(id) = infos
                    .iter()
                    .find(|d| d.index == index)
                    .and_then(|d| d.physical_id.as_ref())
                {
                    ensure!(
                        physical.insert(id.clone()),
                        "same physical GPU selected twice"
                    );
                }
                let device = (|| -> Result<Opencl> {
                    let info = infos
                        .iter()
                        .find(|d| d.index == index)
                        .context("unknown GPU index")?;
                    if !config.calibration_hardware.is_empty() {
                        let expected = config
                            .calibration_hardware
                            .iter()
                            .find(|(device, _)| *device == index)
                            .context("GPU selection changed since calibration")?;
                        ensure!(
                            crate::backend::autotune::fingerprint(info)? == expected.1,
                            "GPU identity changed since calibration"
                        );
                    }
                    let (tuning, origin) = if config.automatic_gpu && config.batched {
                        crate::backend::autotune::resolve_profile(
                            info,
                            config.tuning_cache.as_deref(),
                            config.profile.unwrap_or_default(),
                            config.benchmark_strategy.unwrap_or_default(),
                            config.encoded_suffix,
                        )?
                    } else {
                        (config.gpu_tuning.clone(), "manual")
                    };
                    let mut device = Opencl::with_profile_strategy(
                        index,
                        config.batched,
                        config.cache.as_deref(),
                        tuning,
                        config.profile.unwrap_or_default(),
                        config.benchmark_strategy,
                    )
                    .with_context(|| format!("initialize OpenCL device {index}"))?;
                    device.tuning_origin = config
                        .calibration
                        .as_ref()
                        .and_then(|c| c["origin"].as_str())
                        .unwrap_or(origin)
                        .into();
                    device
                        .self_test()
                        .with_context(|| format!("self-test OpenCL device {index}"))?;
                    Ok(device)
                })();
                match device {
                    Ok(device) => gpus.push(decorate(Box::new(device), config)),
                    Err(e) => {
                        if let Err(fault) = crate::backend::calibration::invalidate(config, &e) {
                            return Err(e.context(format!("record calibration fault: {fault:#}")));
                        }
                        if !can_skip_device(config, &e) {
                            return Err(e);
                        }
                        if !config.quiet {
                            eprintln!("Device {index} disabled: {e:#}");
                        }
                    }
                }
            }
            if matches!(config.mode, Mode::Opencl) {
                ensure!(!gpus.is_empty(), "no validated OpenCL GPU available");
            }
            Ok(gpus)
        })();
        match result {
            Ok(gpus) => workers.extend(gpus),
            Err(e) if matches!(config.mode, Mode::Auto) && can_skip_device(config, &e) => {
                if !config.quiet {
                    eprintln!("OpenCL unavailable; using CPU: {e:#}");
                }
            }
            Err(e) => return Err(e),
        }
    }
    // Keep GPU and CPU searches separate: CPU additions can reduce GPU throughput
    // through scheduler gaps and host contention. Auto uses CPU only as fallback.
    if config.mode == Mode::Cpu || (config.mode == Mode::Auto && workers.is_empty()) {
        let fallback;
        let cpu_config = if config.mode == Mode::Auto
            && config
                .calibration
                .as_ref()
                .is_some_and(|d| !d["choice"]["gpu_tuning"].is_null())
        {
            fallback = crate::backend::calibration::cpu_fallback(config)?;
            &fallback
        } else {
            config
        };
        let (engine, hash) = crate::backend::qualification::cpu(cpu_config);
        for index in 0..config.threads {
            let mut worker: Box<dyn Compute> = if engine == crate::backend::CpuEngine::Batched {
                Box::new(crate::backend::cpu::BatchedCpu::new(index, hash.simd()))
            } else {
                Box::new(Cpu { index })
            };
            if let Err(error) = worker.self_test() {
                return crate::backend::calibration::with_fault_record(
                    cpu_config.calibration_record.as_deref(),
                    Err(error),
                );
            }
            workers.push(decorate(worker, cpu_config));
        }
    }
    ensure!(!workers.is_empty(), "no selected compute workers");
    Ok(workers)
}
#[derive(Clone, Debug, Serialize)]
pub struct WorkerStats {
    pub name: String,
    pub candidates: u64,
    pub base_point_slots: u64,
    pub batches: u64,
    pub seconds: f64,
    pub peak_per_second: f64,
    pub status: String,
    pub diagnostics: serde_json::Value,
}
#[derive(Clone, Debug, Serialize)]
pub struct Progress {
    pub session_id: String,
    pub prefix: String,
    pub suffix: String,
    pub candidates: f64,
    pub candidates_exact: String,
    pub elapsed_seconds: f64,
    pub candidates_per_second: f64,
    pub expected_trials: f64,
    pub expected_remaining_seconds: Option<f64>,
    pub success_probability: f64,
    pub checkpoint: String,
    pub workers: Vec<WorkerStats>,
    pub errors: Vec<String>,
    pub candidate: Option<crate::model::Candidate>,
    pub orchestration: Option<SchedulingProfile>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct SchedulingProfile {
    pub checkpoint_writes: u64,
    pub checkpoint_wall_seconds: f64,
    pub worker_event_wait_seconds: f64,
    /// Includes checkpoint I/O, validation, scheduling and public UI reporting.
    pub coordinator_active_seconds: f64,
    pub search_wall_seconds: f64,
}
impl Progress {
    fn new(job: &Job, cp: &Checkpoint, workers: &[WorkerStats], errors: &[String]) -> Self {
        let trials = cp.trials();
        Self {
            session_id: job.session_id.to_string(),
            prefix: job.pattern.prefix.clone(),
            suffix: job.pattern.suffix.clone(),
            candidates: trials,
            candidates_exact: cp.evaluated_count().expect("validated intervals").decimal(),
            elapsed_seconds: cp.elapsed_seconds,
            candidates_per_second: trials / cp.elapsed_seconds.max(1e-9),
            expected_trials: 1.0 / job.pattern.probability(),
            expected_remaining_seconds: if trials > 0.0 {
                Some((1.0 / job.pattern.probability()) / (trials / cp.elapsed_seconds.max(1e-9)))
            } else {
                None
            },
            success_probability: job.pattern.success_probability(trials),
            checkpoint: "saved".into(),
            workers: workers.to_vec(),
            errors: errors.to_vec(),
            candidate: cp.candidate.clone(),
            orchestration: None,
        }
    }
}
fn display(progress: &Progress, config: &Config) {
    if let Some(sender) = &config.progress {
        let _ = sender.try_send(progress.clone());
    }
    if config.json_lines {
        println!(
            "{}",
            serde_json::to_string(progress).expect("public statistics")
        );
    } else if !config.quiet {
        eprintln!(
            "{} candidates | {:.0}/s | {:.1}s | P(match) {:.3}% | progress {}",
            progress.candidates_exact,
            progress.candidates_per_second,
            progress.elapsed_seconds,
            progress.success_probability * 100.0,
            progress.checkpoint
        );
    }
}
pub fn search(job_path: &Path, config: &Config, cancel: Arc<AtomicBool>) -> Result<Progress> {
    let _path_guard = storage::guard(job_path)?;
    let session = job_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let _lock = storage::lock_session(session)?;
    let job: Job = storage::read_json(job_path)?;
    job.validate()?;
    ensure!(
        crate::split::session_kind(session)? != crate::split::SessionKind::Owner,
        "Import the request on a helper computer to start the search."
    );
    let checkpoint_path = session.join("checkpoint.json");
    let mut cp = storage::load_checkpoint(&checkpoint_path, &job)?;
    ensure!(
        cp.fault.is_none(),
        "session blocked by cryptographic failure; repair the backend and explicitly recover the session"
    );
    if cp.candidate.is_some() {
        storage::write_json(
            &session.join("results.json"),
            &Results::from_checkpoint(&job, &cp)?,
            true,
        )?;
        return Ok(Progress::new(&job, &cp, &[], &[]));
    }
    ensure!(
        config.profile.is_none_or(|p| p == job.profile()),
        "requested chain/type differs from the saved job"
    );
    let mut selected = config.clone();
    selected.profile = Some(job.profile());
    selected.benchmark_strategy = Some(job.strategy);
    selected.encoded_suffix = !job.pattern.suffix.is_empty();
    let workers = checked_selection(select(&selected), &mut cp, &checkpoint_path)?;
    search_workers(job, cp, session, &checkpoint_path, config, cancel, workers)
}
fn search_workers(
    job: Job,
    mut cp: Checkpoint,
    session: &Path,
    checkpoint_path: &Path,
    config: &Config,
    cancel: Arc<AtomicBool>,
    workers: Vec<Box<dyn Compute>>,
) -> Result<Progress> {
    let mut scheduling = SchedulingProfile::default();
    let mut stats: Vec<_> = workers
        .iter()
        .map(|w| WorkerStats {
            name: w.name(),
            candidates: 0,
            base_point_slots: 0,
            batches: 0,
            seconds: 0.0,
            peak_per_second: 0.0,
            status: "ready".into(),
            diagnostics: w.diagnostics(),
        })
        .collect();
    if !config.quiet {
        eprintln!(
            "Session {}: {} workers; expected {:.0} trials",
            job.session_id,
            workers.len(),
            1.0 / job.pattern.probability()
        );
    }
    display(&Progress::new(&job, &cp, &stats, &[]), config);
    let started = Instant::now();
    let elapsed_before = cp.elapsed_seconds;
    let mut reported = Instant::now();
    let mut submitted = 0u64;
    let mut errors = vec![];
    let job = Arc::new(job);
    let (event_tx, event_rx) = mpsc::channel();
    let mut senders = vec![];
    let mut handles = vec![];
    for (index, mut worker) in workers.into_iter().enumerate() {
        let (tx, rx) = mpsc::channel::<Interval>();
        senders.push(tx);
        let event_tx = event_tx.clone();
        let job = job.clone();
        let cancel = cancel.clone();
        handles.push(std::thread::spawn(move || {
            while let Ok(range) = rx.recv() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.run(&job, &range, &cancel)
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("compute worker panicked")));
                let failed = result.is_err();
                if event_tx
                    .send((index, range, result, worker.diagnostics()))
                    .is_err()
                {
                    break;
                }
                if failed {
                    break;
                }
            }
        }));
    }
    drop(event_tx);
    let mut inflight: Vec<Option<Interval>> = vec![None; senders.len()];
    let mut alive = vec![true; senders.len()];
    let execution = (|| -> Result<()> {
        loop {
            if config
                .max_seconds
                .is_some_and(|s| started.elapsed().as_secs_f64() >= s)
            {
                cancel.store(true, Ordering::Relaxed);
            }
            let stopping =
                cancel.load(Ordering::Relaxed) || cp.candidate.is_some() || cp.fault.is_some();
            if !stopping {
                for index in 0..senders.len() {
                    if !alive[index] || inflight[index].is_some() {
                        continue;
                    }
                    let budget = config
                        .max_candidates
                        .map_or(u64::MAX, |limit| limit.saturating_sub(submitted));
                    if budget == 0 {
                        break;
                    }
                    let range = if let Some(range) = cp
                        .pending
                        .iter()
                        .find(|r| !inflight.iter().flatten().any(|a| a == *r))
                        .cloned()
                    {
                        if range.count()? as u64 > budget {
                            let position = cp
                                .pending
                                .iter()
                                .position(|r| r == &range)
                                .expect("pending");
                            let end = range.start.checked_add(budget)?;
                            cp.pending[position] = Interval {
                                start: range.start,
                                end,
                            };
                            cp.pending.push(Interval {
                                start: end,
                                end: range.end,
                            });
                            cp.pending[position].clone()
                        } else {
                            range
                        }
                    } else {
                        if cp.next == job.work_limit() {
                            continue;
                        }
                        // Target approximately 200ms per batch after measurements,
                        // subject to the user's explicit maximum batch size.
                        let measured = if stats[index].seconds > 0.0 {
                            stats[index].candidates as f64 / stats[index].seconds
                        } else if stats[index].name.starts_with("cpu:") {
                            250_000.0
                        } else {
                            config.batch_size as f64 * 5.0
                        };
                        let size = (measured * 0.2).clamp(1.0, config.batch_size as f64) as u32;
                        let size = crate::backend::aligned_batch(
                            &job,
                            size,
                            !stats[index].name.starts_with("cpu:"),
                        );
                        cp.allocate((size as u64).min(budget) as u32)?
                    };
                    cp.validate(&job)?;
                    submitted = submitted
                        .checked_add(range.count()? as u64)
                        .ok_or_else(|| anyhow::anyhow!("run counter overflow"))?;
                    inflight[index] = Some(range.clone());
                    stats[index].status = "running".into();
                    senders[index].send(range)?;
                }
            }
            // Assigned ranges and verified completions remain authoritative in
            // memory. Save on pause/stop or a match/fault, never per dispatch.
            // A process crash can repeat work since the last explicit save.
            if inflight.iter().all(Option::is_none) {
                break;
            }
            let wait_started = Instant::now();
            let event = event_rx.recv_timeout(Duration::from_millis(200));
            scheduling.worker_event_wait_seconds += wait_started.elapsed().as_secs_f64();
            match event {
                Ok((index, range, result, diagnostics)) => {
                    ensure!(
                        inflight[index].as_ref() == Some(&range),
                        "worker returned unexpected interval"
                    );
                    inflight[index] = None;
                    stats[index].diagnostics = diagnostics;
                    stats[index].diagnostics["search_strategy"] =
                        serde_json::to_value(job.strategy)?;
                    stats[index].diagnostics["candidate_family_width"] = job.width().into();
                    let result = result.and_then(|batch| {
                        correct(
                            batch.completed <= range.count()?
                                && batch.evaluated <= batch.completed
                                && batch.seconds.is_finite()
                                && batch.seconds >= 0.0,
                            "invalid worker progress",
                        )?;
                        if let Some(candidate) = &batch.candidate {
                            candidate
                                .verify(&job)
                                .map_err(|e| CorrectnessError(e.to_string()))?;
                            correct(
                                candidate.work_index(&job)? >= range.start
                                    && candidate.work_index(&job)?
                                        < range.start.checked_add(batch.completed as u64)?,
                                "worker match outside completed work",
                            )?;
                        }
                        Ok(batch)
                    });
                    match result {
                        Ok(batch) => {
                            submitted = submitted
                                .saturating_sub(u64::from(range.count()? - batch.evaluated));
                            cp.complete_evaluated(&range, batch.completed, batch.evaluated)?;
                            stats[index].candidates += batch.evaluated as u64;
                            stats[index].base_point_slots +=
                                u64::from(job.base_slots(range.start, batch.completed)?);
                            stats[index].batches += 1;
                            stats[index].seconds += batch.seconds;
                            stats[index].peak_per_second = stats[index]
                                .peak_per_second
                                .max(batch.evaluated as f64 / batch.seconds.max(1e-9));
                            stats[index].status = "ready".into();
                            if cp.fault.is_none()
                                && cp.candidate.is_none()
                                && batch.candidate.is_some()
                            {
                                cp.candidate = batch.candidate;
                                cancel.store(true, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            submitted = submitted.saturating_sub(u64::from(range.count()?));
                            let message = format!("{}: {e:#}", stats[index].name);
                            stats[index].status = "disabled".into();
                            alive[index] = false;
                            if e.downcast_ref::<CorrectnessError>().is_some() {
                                cp.fault = Some(message.clone());
                                cp.candidate = None;
                                cancel.store(true, Ordering::Relaxed);
                            }
                            if !config.quiet {
                                eprintln!("{message}; unfinished work retained");
                            }
                            errors.push(message);
                        }
                    }
                    cp.elapsed_seconds = elapsed_before + started.elapsed().as_secs_f64();
                    cp.validate(&job)?;
                    if cp.candidate.is_some() || cp.fault.is_some() {
                        profiled_checkpoint(checkpoint_path, &cp, &mut scheduling)?;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(e) => return Err(e.into()),
            }
            if reported.elapsed() >= Duration::from_millis(500) {
                cp.elapsed_seconds = elapsed_before + started.elapsed().as_secs_f64();
                let mut progress = Progress::new(&job, &cp, &stats, &errors);
                progress.checkpoint = "saved on pause".into();
                display(&progress, config);
                reported = Instant::now();
            }
        }
        Ok(())
    })();
    cancel.store(true, Ordering::Relaxed);
    drop(senders);
    // Joining avoids releasing a session lock with work still live. If saving
    // fails, a restart repeats work from the preceding saved frontier.
    for handle in handles {
        let _ = handle.join();
    }
    execution?;
    cp.elapsed_seconds = elapsed_before + started.elapsed().as_secs_f64();
    cp.validate(&job)?;
    profiled_checkpoint(checkpoint_path, &cp, &mut scheduling)?;
    ensure!(
        cp.fault.is_none(),
        "cryptographic backend failure: {}",
        cp.fault.as_deref().unwrap_or("")
    );
    ensure!(
        alive.iter().any(|a| *a),
        "all compute workers failed; resume with a working backend"
    );
    if cp.candidate.is_some() {
        storage::write_json(
            &session.join("results.json"),
            &Results::from_checkpoint(&job, &cp)?,
            true,
        )?;
    }
    scheduling.search_wall_seconds = started.elapsed().as_secs_f64();
    scheduling.coordinator_active_seconds =
        (scheduling.search_wall_seconds - scheduling.worker_event_wait_seconds).max(0.0);
    let mut progress = Progress::new(&job, &cp, &stats, &errors);
    progress.orchestration = Some(scheduling);
    display(&progress, config);
    Ok(progress)
}
fn profiled_checkpoint(
    path: &Path,
    cp: &Checkpoint,
    profile: &mut SchedulingProfile,
) -> Result<()> {
    let started = Instant::now();
    storage::save_checkpoint(path, cp)?;
    profile.checkpoint_writes += 1;
    profile.checkpoint_wall_seconds += started.elapsed().as_secs_f64();
    Ok(())
}
pub fn recover(session: &Path) -> Result<()> {
    let _path_guard = storage::guard(session)?;
    let _lock = storage::lock_session(session)?;
    let job: Job = storage::read_json(&session.join("job.json"))?;
    job.validate()?;
    let kind = crate::split::session_kind(session)?;
    ensure!(
        kind != crate::split::SessionKind::Owner,
        "Owner requests cannot restart a search."
    );
    ensure!(
        kind == crate::split::SessionKind::Worker || session.join("seed.keystore.json").is_file(),
        "encrypted seed is missing"
    );
    ensure!(
        !storage::exists(&session.join("finalization.json"))?,
        "finalized session cannot restart; create an independent session"
    );
    let checkpoint = session.join("checkpoint.json");
    if storage::exists(&checkpoint)? {
        storage::write_bytes(
            &session.join(format!("checkpoint.backup.{}.json", uuid::Uuid::new_v4())),
            &storage::read_bytes(&checkpoint)?,
            false,
        )?;
    }
    storage::save_checkpoint(&checkpoint, &Checkpoint::new(&job)?)?;
    Ok(())
}

/// Shared public-only benchmark for both CLI and desktop frontends.
pub fn benchmark(
    config: &Config,
    seconds: f64,
    warmup: f64,
    runs: u32,
    cancel: Arc<AtomicBool>,
) -> Result<serde_json::Value> {
    use crate::crypto::{Pattern, generator};
    ensure!(
        seconds.is_finite()
            && (0.01..=3600.0).contains(&seconds)
            && warmup.is_finite()
            && (0.0..=60.0).contains(&warmup)
            && (1..=100).contains(&runs),
        "invalid benchmark intervals"
    );
    ensure!(
        config.max_candidates.is_none() && config.max_seconds.is_none(),
        "benchmark limits use seconds, warmup and runs"
    );
    let profile = config.profile.unwrap_or_default();
    profile.validate()?;
    if profile.key_family() == crate::chains::KeyFamily::Ed25519 {
        return crate::key_manager::benchmark_ed25519(config, seconds, warmup, runs, cancel);
    }
    let pattern = if let Some(pattern) = &config.benchmark_pattern {
        ensure!(
            pattern.profile == profile,
            "benchmark pattern/profile mismatch"
        );
        pattern.validate()?;
        pattern.clone()
    } else if profile.is_evm() {
        Pattern::for_profile(profile, &"0".repeat(40), "")?
    } else {
        Pattern::for_profile(profile, &profile.address(&generator())?, "")?
    };
    let mut selected = config.clone();
    selected.encoded_suffix = !pattern.suffix.is_empty();
    let strategy = config
        .benchmark_strategy
        .unwrap_or_else(|| crate::backend::qualification::new_strategy(profile));
    selected.benchmark_strategy = Some(strategy);
    let workers = select(&selected)?;
    let job = Arc::new(Job {
        strategy,
        schema: crate::model::JOB_SCHEMA,
        session_id: uuid::Uuid::nil(),
        public_key: hex::encode(generator().serialize()),
        pattern,
    });
    let barrier = Arc::new(std::sync::Barrier::new(workers.len()));
    let mut handles = vec![];
    for (index, mut worker) in workers.into_iter().enumerate() {
        let job = job.clone();
        let cancel = cancel.clone();
        let barrier = barrier.clone();
        let batch = crate::backend::aligned_batch(
            &job,
            config.batch_size,
            !worker.name().starts_with("cpu:"),
        );
        handles.push(std::thread::spawn(move||->Result<serde_json::Value> {
            let mut offset=crate::work::WorkIndex::from_u64(index as u64*1_000_000_000_000); let started=Instant::now();
            let warmup_result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<()> {
                while started.elapsed().as_secs_f64()<warmup && !cancel.load(Ordering::Relaxed) {
                    let range=Interval::new(offset,batch)?; let result=worker.run(&job,&range,&cancel)?;
                    correct(result.completed<=range.count()?,"invalid benchmark completion count")?;
                    offset=range.start.checked_add(result.completed as u64)?;
                } Ok(())
            })).unwrap_or_else(|_|Err(anyhow::anyhow!("benchmark warmup worker panicked")));
            if warmup_result.is_err(){cancel.store(true,Ordering::Relaxed);}
            barrier.wait(); warmup_result?; let mut measurements=vec![];
            for _ in 0..runs {
                let started=Instant::now(); let mut count=0u64;let mut base_slots=0u64; let mut peak=0.0f64; let mut batches=0u64;
                while started.elapsed().as_secs_f64()<seconds && !cancel.load(Ordering::Relaxed) {
                    let range=Interval::new(offset,batch)?; let result=worker.run(&job,&range,&cancel)?;
                    correct(result.completed<=range.count()?,"invalid benchmark completion count")?;
                    offset=range.start.checked_add(result.completed as u64)?;
                    count+=result.evaluated as u64;base_slots+=u64::from(job.base_slots(range.start,result.completed)?); batches+=1; peak=peak.max(result.evaluated as f64/result.seconds.max(1e-9));
                }
                let duration=started.elapsed().as_secs_f64(); measurements.push(serde_json::json!({"candidates":count,"base_point_slots":base_slots,"seconds":duration,"per_second":count as f64/duration.max(1e-9),"peak_per_second":peak,"batches":batches}));
            }
            let mut diagnostics=worker.diagnostics();diagnostics["search_strategy"]=serde_json::to_value(job.strategy)?;diagnostics["candidate_family_width"]=job.width().into();Ok(serde_json::json!({"device":worker.name(),"runs":measurements,"diagnostics":diagnostics}))
        }));
    }
    let mut measurements = vec![];
    let mut failure = None;
    for handle in handles {
        match handle
            .join()
            .map_err(|_| anyhow::anyhow!("benchmark worker panicked"))
            .and_then(|r| r)
        {
            Ok(m) => measurements.push(m),
            Err(e) => crate::backend::retain_failure(&mut failure, e),
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    use sha2::{Digest, Sha256};
    Ok(
        serde_json::json!({"schema":SCHEMA,"application":env!("CARGO_PKG_VERSION"),"profile":profile,"workload":format!("{} public-point search, address derivation and prefix matching",profile.info().name),"backend":config.mode,"cpu":cpu_info(),"opencl":opencl::discover().unwrap_or_default(),"requested_kernel_sha256":if config.automatic_gpu {None}else{Some(hex::encode(Sha256::digest(opencl::chain_gpu::source(&config.gpu_tuning,profile)?.as_bytes())))},"gpu_selection":if config.automatic_gpu {"automatic"}else{"manual"},"requested_gpu_tuning":config.gpu_tuning,"batched_inversion":config.batched,"batch_size":config.batch_size,"pattern":job.pattern,"warmup_seconds":warmup,"measurement_seconds":seconds,"runs":runs,"measurements":measurements}),
    )
}

pub fn clear_cache(directory: &Path) -> Result<()> {
    let _path_guard = storage::read_guard(directory)?;
    if !storage::exists(directory)? {
        return Ok(());
    }
    storage::assert_private_directory(directory)?;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.len() == 69
            && name.ends_with(".json")
            && name[..64].bytes().all(|b| b.is_ascii_hexdigit())
        {
            storage::regular(&path)?;
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backend::BatchResult,
        crypto::{Offset, Pattern, generator},
        model::Candidate,
    };
    #[test]
    fn crypto_startup_failure_is_never_device_fallback_and_is_durable() {
        let config = Config::default();
        let crypto = anyhow::Error::new(CorrectnessError("injected startup mismatch".into()))
            .context("device self-test");
        assert!(!can_skip_device(&config, &crypto));
        assert!(can_skip_device(
            &config,
            &anyhow::anyhow!("device unavailable")
        ));
        assert!(!can_skip_device(
            &Config {
                devices: vec![0],
                ..config
            },
            &anyhow::anyhow!("device unavailable")
        ));
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let mut checkpoint = Checkpoint::new(&job).unwrap();
        let path = root.path().join("checkpoint.json");
        storage::save_checkpoint(&path, &checkpoint).unwrap();
        assert!(checked_selection(Err(crypto), &mut checkpoint, &path).is_err());
        let saved = storage::load_checkpoint(&path, &job).unwrap();
        assert!(
            saved
                .fault
                .as_deref()
                .unwrap()
                .contains("injected startup mismatch")
        );
        assert!(saved.candidate.is_none());
        let mut fresh = Checkpoint::new(&job).unwrap();
        storage::save_checkpoint(&path, &fresh).unwrap();
        assert!(
            checked_selection(
                Err(anyhow::anyhow!("device unavailable")),
                &mut fresh,
                &path
            )
            .is_err()
        );
        assert!(
            storage::load_checkpoint(&path, &job)
                .unwrap()
                .fault
                .is_none()
        );
    }
    #[test]
    fn cache_clear_preserves_unrecognized_files_under_read_pin() {
        let temp = tempfile::tempdir().unwrap();
        storage::private(temp.path()).unwrap();
        let cache = temp.path().join(format!("{}.json", "a".repeat(64)));
        let other = temp.path().join("other.json");
        storage::write_bytes(&cache, b"{}", false).unwrap();
        storage::write_bytes(&other, b"{}", false).unwrap();
        clear_cache(temp.path()).unwrap();
        assert!(!cache.exists());
        assert!(other.exists());
    }
    enum Fault {
        Device,
        Correctness,
        InvalidMatch,
    }
    struct Bad(Fault);
    impl Compute for Bad {
        fn name(&self) -> String {
            "injected-test-worker".into()
        }
        fn self_test(&mut self) -> Result<()> {
            Ok(())
        }
        fn run(
            &mut self,
            _job: &Job,
            range: &Interval,
            _cancel: &AtomicBool,
        ) -> Result<BatchResult> {
            match self.0 {
                Fault::Device => anyhow::bail!("simulated device loss"),
                Fault::Correctness => Err(CorrectnessError("injected hash failure".into()).into()),
                Fault::InvalidMatch => Ok(BatchResult {
                    evaluated: range.count()?,
                    completed: range.count()?,
                    candidate: Some(Candidate {
                        transform: crate::transforms::Transform::Identity,
                        offset: range.start.try_into()?,
                        address: "00".repeat(20),
                    }),
                    seconds: 0.01,
                }),
            }
        }
    }
    fn job() -> Job {
        Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: SCHEMA,
            session_id: uuid::Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: Pattern::new(&"0".repeat(40), "").unwrap(),
        }
    }
    #[test]
    fn fallback_worker_fault_invalidates_its_cpu_record_and_preserves_gpu_record() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        let cpu = root.path().join("cpu-calibration.json");
        let gpu = root.path().join("gpu-calibration.json");
        storage::write_json(&cpu, &serde_json::json!({"synthetic":true}), false).unwrap();
        storage::write_json(&gpu, &serde_json::json!({"synthetic":true}), false).unwrap();
        let mut worker = CalibratedWorker {
            inner: Box::new(Bad(Fault::Correctness)),
            diagnostics: serde_json::json!({"origin":"CPU fallback"}),
            record: Some(cpu.clone()),
        };
        let error = worker
            .run(
                &job(),
                &Interval::new(crate::work::WorkIndex::ZERO, 8).unwrap(),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(error.downcast_ref::<CorrectnessError>().is_some());
        assert_eq!(
            storage::read_json::<serde_json::Value>(&cpu).unwrap()["invalid"],
            true
        );
        assert_eq!(
            storage::read_json::<serde_json::Value>(&gpu).unwrap()["synthetic"],
            true
        );
        assert_eq!(
            worker.diagnostics()["calibration"]["origin"],
            "CPU fallback"
        );
    }
    fn config() -> Config {
        Config {
            mode: Mode::Cpu,
            threads: 1,
            batch_size: 256,
            max_candidates: Some(2048),
            quiet: true,
            ..Config::default()
        }
    }
    #[test]
    fn search_keeps_progress_in_memory_until_stop() {
        struct AuditWorker(PathBuf);
        impl Compute for AuditWorker {
            fn name(&self) -> String {
                "durability-audit".into()
            }
            fn self_test(&mut self) -> Result<()> {
                Ok(())
            }
            fn run(
                &mut self,
                job: &Job,
                range: &Interval,
                _cancel: &AtomicBool,
            ) -> Result<BatchResult> {
                let saved = storage::load_checkpoint(&self.0, job)?;
                ensure!(
                    saved.next == Offset::ZERO
                        && saved.pending.is_empty()
                        && saved.completed.is_empty(),
                    "ordinary dispatch unexpectedly wrote search progress"
                );
                Ok(BatchResult {
                    evaluated: range.count()?,
                    completed: range.count()?,
                    candidate: None,
                    seconds: 0.1,
                })
            }
        }
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let checkpoint = Checkpoint::new(&job).unwrap();
        let path = root.path().join("checkpoint.json");
        storage::save_checkpoint(&path, &checkpoint).unwrap();
        let config = Config {
            batch_size: crate::backend::MAX_BATCH,
            max_candidates: Some(crate::backend::MAX_BATCH as u64 * 3),
            ..config()
        };
        let progress = search_workers(
            job.clone(),
            checkpoint,
            root.path(),
            &path,
            &config,
            Arc::new(AtomicBool::new(false)),
            vec![Box::new(AuditWorker(path.clone()))],
        )
        .unwrap();
        assert_eq!(progress.orchestration.unwrap().checkpoint_writes, 1);
        let saved = storage::load_checkpoint(&path, &job).unwrap();
        assert!(saved.pending.is_empty());
        assert_eq!(
            saved.completed_count().unwrap(),
            Offset::from_u64(crate::backend::MAX_BATCH as u64 * 3)
        );
    }
    #[test]
    fn device_loss_reassigns_pending_work_without_gaps() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let cp = Checkpoint::new(&job).unwrap();
        let path = root.path().join("checkpoint.json");
        storage::save_checkpoint(&path, &cp).unwrap();
        let result = search_workers(
            job.clone(),
            cp,
            root.path(),
            &path,
            &config(),
            Arc::new(AtomicBool::new(false)),
            vec![Box::new(Bad(Fault::Device)), Box::new(Cpu { index: 0 })],
        )
        .unwrap();
        assert_eq!(result.errors.len(), 1);
        let cp = storage::load_checkpoint(&path, &job).unwrap();
        assert!(cp.pending.is_empty());
        assert_eq!(cp.completed.len(), 1);
        assert_eq!(cp.completed[0].start, Offset::ZERO);
        assert_eq!(cp.completed[0].end, cp.next);
    }
    #[test]
    fn correctness_failure_and_forged_matches_block_session() {
        for fault in [Fault::Correctness, Fault::InvalidMatch] {
            let root = tempfile::tempdir().unwrap();
            let job = job();
            let cp = Checkpoint::new(&job).unwrap();
            let path = root.path().join("checkpoint.json");
            storage::save_checkpoint(&path, &cp).unwrap();
            assert!(
                search_workers(
                    job.clone(),
                    cp,
                    root.path(),
                    &path,
                    &config(),
                    Arc::new(AtomicBool::new(false)),
                    vec![Box::new(Bad(fault))]
                )
                .is_err()
            );
            let saved = storage::load_checkpoint(&path, &job).unwrap();
            assert!(saved.fault.is_some());
            assert!(saved.completed.is_empty());
            assert!(!saved.pending.is_empty());
            assert!(!root.path().join("results.json").exists());
        }
    }
    #[test]
    fn cancel_and_resume_replays_durable_pending_interval() {
        let root = tempfile::tempdir().unwrap();
        let job = job();
        let mut cp = Checkpoint::new(&job).unwrap();
        cp.allocate(256).unwrap();
        let path = root.path().join("checkpoint.json");
        storage::save_checkpoint(&path, &cp).unwrap();
        search_workers(
            job.clone(),
            cp.clone(),
            root.path(),
            &path,
            &config(),
            Arc::new(AtomicBool::new(true)),
            vec![Box::new(Cpu { index: 0 })],
        )
        .unwrap();
        let pending = storage::load_checkpoint(&path, &job).unwrap();
        assert_eq!(pending.pending, cp.pending);
        search_workers(
            job.clone(),
            pending,
            root.path(),
            &path,
            &config(),
            Arc::new(AtomicBool::new(false)),
            vec![Box::new(Cpu { index: 0 })],
        )
        .unwrap();
        let complete = storage::load_checkpoint(&path, &job).unwrap();
        assert!(complete.pending.is_empty());
        assert_eq!(complete.trials(), 2048.0);
    }
}
