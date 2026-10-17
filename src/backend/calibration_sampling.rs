//! Bounded calibration windows over the real public search workers.
//!
//! No wallet, session, private scalar, or winning address leaves this module.
//! Workers and their nonzero public cursors survive successive timing windows,
//! so warmup is not repeated inside a measured window.
use super::{Compute, correct};
use crate::{
    chains::KeyFamily,
    coordinator::Config,
    crypto::{Pattern, generator},
    model::{Interval, Job, SearchStrategy},
    work::WorkIndex,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub evaluated: u64,
    pub seconds: f64,
    pub per_second: f64,
    pub workers: Value,
}

struct Worker {
    compute: Box<dyn Compute>,
    cursor: WorkIndex,
    batch: u32,
}

enum Engine {
    Secp { job: Job, workers: Vec<Worker> },
    Ed(Box<Config>),
}

pub struct Sampler {
    engine: Engine,
}

impl Sampler {
    /// Normalize the public workload and pin its strategy before selecting and
    /// self-testing workers. The caller supplies explicit execution settings;
    /// automatic GPU tuning is disabled to prevent recursive calibration.
    pub fn new(config: &Config, pattern: &Pattern, strategy: SearchStrategy) -> Result<Self> {
        pattern.validate()?;
        let profile = config.profile.unwrap_or(pattern.profile);
        profile.validate()?;
        ensure!(
            profile == pattern.profile,
            "calibration pattern/profile mismatch"
        );
        let mut selected = config.clone();
        selected.profile = Some(profile);
        selected.benchmark_strategy = Some(strategy);
        selected.benchmark_pattern = Some(pattern.clone());
        selected.encoded_suffix = !pattern.suffix.is_empty();
        selected.automatic_gpu = false;
        selected.max_candidates = None;
        selected.max_seconds = None;
        selected.progress = None;
        selected.quiet = true;
        selected.json_lines = false;
        let engine = if profile.key_family() == KeyFamily::Ed25519 {
            ensure!(
                strategy == SearchStrategy::Linear,
                "Ed25519 calibration requires standard seeds"
            );
            ensure!(
                selected.mode != crate::coordinator::Mode::Opencl,
                "Ed25519 calibration requires CPU execution"
            );
            Engine::Ed(Box::new(selected))
        } else {
            let job = Job {
                schema: crate::model::JOB_SCHEMA,
                session_id: uuid::Uuid::nil(),
                public_key: hex::encode(generator().serialize()),
                pattern: pattern.clone(),
                strategy,
            };
            job.validate()?;
            let workers = crate::coordinator::select(&selected)?
                .into_iter()
                .enumerate()
                .map(|(index, compute)| -> Result<Worker> {
                    let cpu = compute.name().starts_with("cpu:");
                    // Reference CPU cancellation is per point, and optimized
                    // cancellation per group; avoid an oversized timing tail.
                    let requested = if cpu {
                        selected.batch_size.min(32_768)
                    } else {
                        selected.batch_size
                    };
                    let batch = super::aligned_batch(&job, requested, !cpu);
                    Ok(Worker {
                        compute,
                        cursor: initial_cursor(index, job.width())?,
                        batch,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Engine::Secp { job, workers }
        };
        Ok(Self { engine })
    }

    /// Measure total complete evaluations divided by the global wall time until
    /// every worker joins. A deadline only cancels this window; it never changes
    /// the caller's cancellation flag. External cancellation returns an error.
    pub fn sample(&mut self, seconds: f64, cancel: Arc<AtomicBool>) -> Result<Sample> {
        ensure!(
            seconds.is_finite() && (0.001..=60.0).contains(&seconds),
            "invalid calibration sample duration"
        );
        ensure!(!cancel.load(Ordering::Relaxed), "calibration cancelled");
        match &mut self.engine {
            Engine::Secp { job, workers } => sample_secp(job, workers, seconds, cancel),
            Engine::Ed(config) => {
                let started = Instant::now();
                // KeyManager owns and zeroizes all freshly generated seed
                // microbatches and independently self-tests every selected path.
                let benchmark =
                    crate::key_manager::benchmark_ed25519(config, seconds, 0.0, 1, cancel.clone())?;
                let elapsed = started.elapsed().as_secs_f64();
                ensure!(!cancel.load(Ordering::Relaxed), "calibration cancelled");
                let workers = benchmark["measurements"]
                    .as_array()
                    .context("missing Ed25519 calibration measurements")?;
                ensure!(
                    workers.len() == config.threads,
                    "incomplete Ed25519 calibration workers"
                );
                let evaluated = workers
                    .iter()
                    .try_fold(0u64, |total, worker| -> Result<u64> {
                        let runs = worker["runs"]
                            .as_array()
                            .context("missing Ed25519 calibration window")?;
                        ensure!(runs.len() == 1, "invalid Ed25519 calibration windows");
                        let n = runs[0]["candidates"]
                            .as_u64()
                            .context("invalid Ed25519 evaluation count")?;
                        ensure!(
                            n > 0 && n.is_multiple_of(32),
                            "incomplete Ed25519 seed microbatch"
                        );
                        total
                            .checked_add(n)
                            .context("calibration evaluation count overflow")
                    })?;
                sample_result(evaluated, elapsed, Value::Array(workers.clone()))
            }
        }
    }
}

/// Space workers by public base offsets, then map to the first transformation.
/// An unaligned logical cursor adds a base point to a full power-of-two family
/// dispatch and can double the recurrence kernel's padded lane allocation.
fn initial_cursor(index: usize, width: u8) -> Result<WorkIndex> {
    ensure!(index < 256, "too many calibration workers");
    ensure!(
        matches!(width, 1 | 3 | 6),
        "invalid calibration family width"
    );
    WorkIndex::from_u64((index as u64 + 1) * 1_000_000_000_000).times(width)
}

fn sample_result(evaluated: u64, seconds: f64, workers: Value) -> Result<Sample> {
    let per_second = evaluated as f64 / seconds;
    ensure!(
        evaluated > 0
            && seconds.is_finite()
            && seconds > 0.0
            && per_second.is_finite()
            && per_second > 0.0,
        "calibration window made no finite positive progress"
    );
    Ok(Sample {
        evaluated,
        seconds,
        per_second,
        workers,
    })
}

fn sample_secp(
    job: &Job,
    workers: &mut [Worker],
    seconds: f64,
    cancel: Arc<AtomicBool>,
) -> Result<Sample> {
    ensure!(!workers.is_empty(), "no calibration workers");
    let stop = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let barrier = Barrier::new(workers.len() + 1);
    let started = Instant::now();
    let output = std::thread::scope(|scope| -> Result<Vec<Value>> {
        let monitor = scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if cancel.load(Ordering::Relaxed) || started.elapsed().as_secs_f64() >= seconds {
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let handles: Vec<_> = workers
            .iter_mut()
            .map(|worker| {
                let (stop, barrier) = (&stop, &barrier);
                scope.spawn(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || -> Result<Value> {
                            barrier.wait();
                            run_worker(job, worker, started, seconds, stop)
                        },
                    ))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("calibration worker panicked")));
                    if result.is_err() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    result
                })
            })
            .collect();
        barrier.wait();
        let mut output = Vec::with_capacity(handles.len());
        let mut failure = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(value)) => output.push(value),
                Ok(Err(error)) => super::retain_failure(&mut failure, error),
                Err(_) => {
                    stop.store(true, Ordering::Relaxed);
                    super::retain_failure(
                        &mut failure,
                        anyhow::anyhow!("calibration worker panicked"),
                    );
                }
            }
        }
        done.store(true, Ordering::Relaxed);
        if monitor.join().is_err() {
            super::retain_failure(&mut failure, anyhow::anyhow!("calibration timer panicked"));
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(output)
    })?;
    let elapsed = started.elapsed().as_secs_f64();
    ensure!(!cancel.load(Ordering::Relaxed), "calibration cancelled");
    let evaluated = output
        .iter()
        .try_fold(0u64, |total, worker| -> Result<u64> {
            total
                .checked_add(
                    worker["evaluated"]
                        .as_u64()
                        .context("invalid calibration evaluation count")?,
                )
                .context("calibration evaluation count overflow")
        })?;
    sample_result(evaluated, elapsed, Value::Array(output))
}

fn run_worker(
    job: &Job,
    worker: &mut Worker,
    started: Instant,
    seconds: f64,
    stop: &AtomicBool,
) -> Result<Value> {
    let start = worker.cursor;
    let mut evaluated = 0u64;
    let mut completed = 0u64;
    let mut batches = 0u64;
    while started.elapsed().as_secs_f64() < seconds && !stop.load(Ordering::Relaxed) {
        let range = Interval::new(worker.cursor, worker.batch)?;
        let result = worker.compute.run(job, &range, stop)?;
        correct(
            result.completed <= range.count()? && result.evaluated <= result.completed,
            "invalid calibration worker counters",
        )?;
        correct(
            result.seconds.is_finite() && result.seconds >= 0.0,
            "invalid calibration worker timing",
        )?;
        if let Some(candidate) = result.candidate {
            let index = candidate
                .work_index(job)
                .map_err(|e| super::CorrectnessError(e.to_string()))?;
            correct(
                range.contains(index)
                    && index < range.start.checked_add(result.completed.into())?,
                "calibration hit outside completed interval",
            )?;
            candidate
                .verify(job)
                .map_err(|e| super::CorrectnessError(e.to_string()))?;
        }
        correct(
            result.completed > 0 || stop.load(Ordering::Relaxed),
            "calibration worker made no progress",
        )?;
        worker.cursor = range.start.checked_add(result.completed.into())?;
        evaluated = evaluated
            .checked_add(result.evaluated.into())
            .context("calibration evaluation count overflow")?;
        completed = completed
            .checked_add(result.completed.into())
            .context("calibration completion count overflow")?;
        batches += 1;
    }
    Ok(json!({
        "device":worker.compute.name(), "evaluated":evaluated, "completed":completed,
        "batches":batches, "start":start, "end":worker.cursor,
        "effective_dispatch":worker.batch, "diagnostics":worker.compute.diagnostics()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BatchResult;

    #[test]
    fn nonzero_worker_cursors_preserve_exact_family_dispatch_geometry() {
        for width in [1, 3, 6] {
            for index in 0..256 {
                let cursor = initial_cursor(index, width).unwrap();
                let expected =
                    crate::crypto::Offset::from_u64((index as u64 + 1) * 1_000_000_000_000);
                let (base, branch) = cursor.div_rem(width).unwrap();
                assert_eq!(base, expected);
                assert_eq!(branch, 0);
                for bases in [1u32, 1024, 524_288] {
                    let logical = bases * u32::from(width);
                    let base_count = (logical + u32::from(branch)).div_ceil(u32::from(width));
                    assert_eq!(base_count, bases);
                    assert_eq!(base_count.next_power_of_two(), bases);
                    let (end_base, end_branch) = cursor
                        .checked_add(u64::from(logical))
                        .unwrap()
                        .div_rem(width)
                        .unwrap();
                    assert_eq!(end_base, expected.checked_add(u64::from(bases)).unwrap());
                    assert_eq!(end_branch, 0);
                }
            }
        }
        assert!(initial_cursor(256, 6).is_err());
        assert!(initial_cursor(0, 0).is_err());
        assert!(initial_cursor(0, 2).is_err());
    }

    struct Fake {
        invalid: bool,
        zero: bool,
        stop_after_batch: bool,
    }
    impl Compute for Fake {
        fn name(&self) -> String {
            "cpu:fake".into()
        }
        fn self_test(&mut self) -> Result<()> {
            Ok(())
        }
        fn run(&mut self, _: &Job, range: &Interval, cancel: &AtomicBool) -> Result<BatchResult> {
            if !self.stop_after_batch {
                std::thread::sleep(Duration::from_millis(1));
            }
            let n = if self.zero || cancel.load(Ordering::Relaxed) {
                0
            } else {
                range.count()?
            };
            if self.stop_after_batch {
                cancel.store(true, Ordering::Relaxed);
            }
            Ok(BatchResult {
                completed: n,
                evaluated: n + u32::from(self.invalid),
                candidate: None,
                seconds: 0.001,
            })
        }
    }
    fn fake_sampler(invalid: bool, zero: bool) -> Sampler {
        Sampler {
            engine: Engine::Secp {
                job: Job {
                    schema: 3,
                    session_id: uuid::Uuid::nil(),
                    public_key: hex::encode(generator().serialize()),
                    pattern: Pattern::new(&"0".repeat(40), "").unwrap(),
                    strategy: SearchStrategy::EndomorphismV1,
                },
                workers: vec![Worker {
                    compute: Box::new(Fake {
                        invalid,
                        zero,
                        stop_after_batch: false,
                    }),
                    cursor: WorkIndex::from_u64(1_000_000_000_000),
                    batch: 32,
                }],
            },
        }
    }

    #[test]
    fn windows_retain_nonzero_cursors_and_keep_cancellation_private() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut sampler = fake_sampler(false, false);
        let Engine::Secp { workers, .. } = &mut sampler.engine else {
            unreachable!()
        };
        workers[0].compute = Box::new(Fake {
            invalid: false,
            zero: false,
            stop_after_batch: true,
        });
        // End each window after one complete batch, without depending on a
        // sleeping worker waking before a short wall-clock deadline.
        let first = sampler.sample(60.0, cancel.clone()).unwrap();
        let second = sampler.sample(60.0, cancel.clone()).unwrap();
        assert!(!cancel.load(Ordering::Relaxed));
        assert_eq!(first.workers[0]["end"], second.workers[0]["start"]);
        assert_eq!(first.evaluated, 32);
        assert_eq!(second.evaluated, 32);
        assert_eq!(first.per_second, first.evaluated as f64 / first.seconds);
        assert_eq!(
            serde_json::from_value::<Sample>(serde_json::to_value(first).unwrap())
                .unwrap()
                .evaluated
                % 32,
            0
        );
    }

    #[test]
    fn rejects_invalid_counters_and_zero_progress() {
        for (invalid, zero) in [(true, false), (false, true)] {
            let error = fake_sampler(invalid, zero)
                .sample(60.0, Arc::new(AtomicBool::new(false)))
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<super::super::CorrectnessError>()
                    .is_some()
            );
        }
    }

    struct SynchronizedFailure {
        entered: Arc<Barrier>,
        cryptographic: bool,
        panic_ordinary: bool,
    }
    impl Compute for SynchronizedFailure {
        fn name(&self) -> String {
            "cpu:synthetic-failure".into()
        }
        fn self_test(&mut self) -> Result<()> {
            Ok(())
        }
        fn run(&mut self, _: &Job, _: &Interval, _: &AtomicBool) -> Result<BatchResult> {
            // Both workers must be inside their dispatch before either failure
            // sets the shared stop flag, making join order the sole variable.
            self.entered.wait();
            if self.cryptographic {
                return Err(anyhow::Error::new(super::super::CorrectnessError(
                    "synthetic cryptographic mismatch".into(),
                ))
                .context("synthetic worker dispatch"));
            }
            assert!(!self.panic_ordinary, "synthetic ordinary worker panic");
            anyhow::bail!("synthetic ordinary worker error")
        }
    }

    fn assert_failure_priority(cryptographic_first: bool, panic_ordinary: bool) {
        let mut sampler = fake_sampler(false, false);
        let Engine::Secp { workers, .. } = &mut sampler.engine else {
            unreachable!()
        };
        let entered = Arc::new(Barrier::new(2));
        *workers = [cryptographic_first, !cryptographic_first]
            .into_iter()
            .enumerate()
            .map(|(index, cryptographic)| Worker {
                compute: Box::new(SynchronizedFailure {
                    entered: entered.clone(),
                    cryptographic,
                    panic_ordinary,
                }),
                cursor: WorkIndex::from_u64((index as u64 + 1) * 1_000_000_000_000),
                batch: 32,
            })
            .collect();
        let error = sampler
            .sample(1.0, Arc::new(AtomicBool::new(false)))
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::CorrectnessError>()
                .is_some()
        );
        assert!(format!("{error:#}").contains("synthetic cryptographic mismatch"));
    }

    #[test]
    fn cryptographic_fault_survives_ordinary_error_in_both_worker_orders() {
        for cryptographic_first in [false, true] {
            assert_failure_priority(cryptographic_first, false);
        }
    }

    #[test]
    fn cryptographic_fault_survives_worker_panic_in_both_worker_orders() {
        for cryptographic_first in [false, true] {
            assert_failure_priority(cryptographic_first, true);
        }
    }

    #[test]
    fn cancellation_and_invalid_windows_are_bounded() {
        let mut sampler = fake_sampler(false, false);
        assert!(
            sampler
                .sample(0.1, Arc::new(AtomicBool::new(true)))
                .is_err()
        );
        for seconds in [f64::NAN, f64::INFINITY, 0.0, -1.0, 61.0] {
            assert!(
                sampler
                    .sample(seconds, Arc::new(AtomicBool::new(false)))
                    .is_err()
            );
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let trigger = cancel.clone();
        let started = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(5));
                trigger.store(true, Ordering::Relaxed);
            });
            assert!(sampler.sample(1.0, cancel).is_err());
        });
        assert!(started.elapsed().as_secs_f64() < 0.5);
    }

    #[test]
    fn real_cpu_selection_and_independent_windows_use_the_pinned_strategy() {
        let config = Config {
            mode: crate::coordinator::Mode::Cpu,
            threads: 1,
            batch_size: 128,
            cpu_engine: super::super::CpuEngine::Batched,
            hash_mode: super::super::HashMode::Scalar,
            ..Config::default()
        };
        let pattern = Pattern::new(&"0".repeat(40), "").unwrap();
        let mut sampler = Sampler::new(&config, &pattern, SearchStrategy::EndomorphismV1).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let first = sampler.sample(1.0, cancel.clone()).unwrap();
        let second = sampler.sample(1.0, cancel).unwrap();
        assert!(first.evaluated > 0 && second.evaluated > 0);
        assert_eq!(first.workers[0]["end"], second.workers[0]["start"]);
        assert_eq!(first.workers[0]["effective_dispatch"], 128);
        assert_eq!(
            first.workers[0]["diagnostics"]["engine"],
            "public-affine-montgomery"
        );
    }
}
