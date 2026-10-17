//! Local, data-only performance selection. Workers receive synthetic inputs only.
use super::{CorrectnessError, CpuEngine, EdTable, HashMode, autotune, cpu_info, opencl};
use crate::{
    chains::{AddressType, KeyFamily, Profile},
    coordinator::{Config, Mode},
    crypto::Pattern,
    model::SearchStrategy,
    storage,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const SCHEMA: u32 = 2;
const WORKER_ARGUMENT: &str = "--internal-calibration-worker";
const MAX_OUTPUT: u64 = 2 * 1024 * 1024;
const CORRECTNESS_EXIT: i32 = 70;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TuningMode {
    #[default]
    Auto,
    Off,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Choice {
    strategy: SearchStrategy,
    cpu_engine: CpuEngine,
    hash_mode: HashMode,
    ed_table: EdTable,
    gpu_tuning: Option<opencl::Tuning>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    nonce: String,
    profile: Profile,
    suffix: bool,
    fixed_strategy: Option<SearchStrategy>,
    backend: Mode,
    devices: Vec<usize>,
    hardware: Vec<String>,
    threads: usize,
    batch_size: u32,
    batched: bool,
    cpu_engine: CpuEngine,
    hash_mode: HashMode,
    ed_table: EdTable,
    implementation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema: u32,
    key: String,
    choice: Choice,
    confirmed: bool,
    promoted: bool,
    pairs: Vec<[f64; 2]>,
    records: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub strategy: SearchStrategy,
    pub origin: String,
    pub diagnostics: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    schema: u32,
    nonce: String,
    kind: String,
    message: String,
    correctness: bool,
    report: Option<Report>,
}

fn canonical(profile: Profile) -> Profile {
    if profile.is_evm() {
        Profile::default()
    } else {
        profile
    }
}
fn implementation() -> String {
    env!("VANITY_CALIBRATION_IMPLEMENTATION").to_owned()
}
fn cpu_identity() -> String {
    // Branding is diagnostic only. Capabilities and process-visible concurrency bind selection.
    let c = cpu_info();
    let identity = serde_json::json!({"os":std::env::consts::OS,"arch":c.architecture,
        "vendor":c.vendor,"family":c.family,"model":c.model_id,"stepping":c.stepping,
        "features":c.instruction_sets,"available_processors":c.logical_processors});
    hex::encode(Sha256::digest(identity.to_string()))
}
fn key(request: &Request) -> Result<String> {
    let mut stable = request.clone();
    stable.nonce.clear();
    stable.devices.clear();
    stable.hardware.sort();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&stable)?)))
}
fn valid_request(r: &Request) -> Result<()> {
    ensure!(
        r.schema == SCHEMA && r.implementation == implementation(),
        "incompatible calibration request"
    );
    r.profile.validate()?;
    ensure!(
        (1..=256).contains(&r.threads) && (1..=super::MAX_BATCH).contains(&r.batch_size),
        "invalid calibration bounds"
    );
    ensure!(
        matches!(r.backend, Mode::Cpu | Mode::Opencl),
        "unresolved calibration backend"
    );
    ensure!(
        !r.hardware.is_empty()
            && r.hardware
                .iter()
                .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid hardware identity"
    );
    ensure!(
        r.profile.key_family() != KeyFamily::Ed25519
            || (r.backend == Mode::Cpu
                && r.fixed_strategy.is_none_or(|s| s == SearchStrategy::Linear)),
        "invalid Ed25519 calibration"
    );
    if r.backend == Mode::Cpu {
        ensure!(r.hardware == [cpu_identity()], "CPU capabilities changed");
    } else {
        let infos = opencl::discover()?;
        let identities = r
            .devices
            .iter()
            .map(|index| {
                let info = infos
                    .iter()
                    .find(|d| d.index == *index)
                    .context("calibration GPU disappeared")?;
                autotune::fingerprint(info)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !identities.is_empty() && identities == r.hardware,
            "calibration GPU identity changed"
        );
    }
    Ok(())
}
fn validate_choice(r: &Request, c: &Choice) -> Result<()> {
    ensure!(
        r.fixed_strategy.is_none_or(|s| s == c.strategy),
        "calibration changed persisted strategy"
    );
    ensure!(
        r.profile.key_family() != KeyFamily::Ed25519 || c.strategy == SearchStrategy::Linear,
        "invalid seed strategy"
    );
    ensure!(
        r.fixed_strategy.is_some()
            || r.profile.address_type != AddressType::P2tr
            || c.strategy == SearchStrategy::Linear,
        "invalid new Taproot strategy"
    );
    ensure!(
        c.cpu_engine != CpuEngine::Auto
            && c.hash_mode != HashMode::Auto
            && c.ed_table != EdTable::Auto,
        "unresolved calibration choice"
    );
    ensure!(
        r.cpu_engine == CpuEngine::Auto || c.cpu_engine == r.cpu_engine,
        "CPU override changed"
    );
    ensure!(
        r.hash_mode == HashMode::Auto
            || c.hash_mode == r.hash_mode
            || (r.profile.key_family() == KeyFamily::Secp256k1
                && c.cpu_engine == CpuEngine::Reference)
            || (r.profile.key_family() == KeyFamily::Ed25519 && c.ed_table == EdTable::Reference),
        "hash override changed"
    );
    ensure!(
        r.ed_table == EdTable::Auto || c.ed_table == r.ed_table,
        "table override changed"
    );
    if r.backend == Mode::Opencl {
        let t = c.gpu_tuning.as_ref().context("missing GPU configuration")?;
        t.validate()?;
        for info in opencl::discover()?
            .iter()
            .filter(|d| r.devices.contains(&d.index))
        {
            ensure!(
                autotune::eligible_tuning(info, r.profile, t),
                "ineligible GPU configuration"
            );
        }
    } else {
        ensure!(
            c.gpu_tuning.is_none(),
            "CPU choice contains GPU configuration"
        );
    }
    Ok(())
}
fn validate_report(r: &Request, report: &Report) -> Result<()> {
    ensure!(
        report.schema == SCHEMA && report.key == key(r)?,
        "foreign calibration result"
    );
    validate_choice(r, &report.choice)?;
    ensure!(
        report.promoted || report.choice == incumbent(r)?,
        "unpromoted calibration changed incumbent"
    );
    ensure!(
        !report.promoted
            || (report.confirmed
                && report.pairs.len() == 5
                && report.pairs.iter().all(|p| p[0].is_finite()
                    && p[1].is_finite()
                    && p[0] > 0.0
                    && p[1] / p[0] >= 1.05)),
        "unconfirmed calibration promotion"
    );
    ensure!(
        !report.confirmed
            || (report.pairs.len() == 5
                && report
                    .pairs
                    .iter()
                    .all(|p| p.iter().all(|v| v.is_finite() && *v > 0.0))),
        "invalid calibration confirmation"
    );
    Ok(())
}
fn incumbent(r: &Request) -> Result<Choice> {
    let mut c = Choice {
        strategy: r.fixed_strategy.unwrap_or(SearchStrategy::Linear),
        cpu_engine: if r.cpu_engine == CpuEngine::Auto {
            CpuEngine::Reference
        } else {
            r.cpu_engine
        },
        hash_mode: if r.hash_mode == HashMode::Auto {
            HashMode::Scalar
        } else {
            r.hash_mode
        },
        ed_table: if r.ed_table == EdTable::Auto {
            EdTable::Reference
        } else {
            r.ed_table
        },
        gpu_tuning: None,
    };
    if (r.profile.key_family() == KeyFamily::Secp256k1 && c.cpu_engine == CpuEngine::Reference)
        || (r.profile.key_family() == KeyFamily::Ed25519 && c.ed_table == EdTable::Reference)
    {
        c.hash_mode = HashMode::Scalar;
    }
    if r.backend == Mode::Opencl {
        let infos = opencl::discover()?;
        let info = infos
            .iter()
            .find(|d| r.devices.contains(&d.index))
            .context("missing calibration GPU")?;
        if r.fixed_strategy.is_none() {
            // Retain a previously measured profile's accepted stream when
            // calibration is skipped or inconclusive. Both streams still compete.
            let selected: Vec<_> = infos
                .iter()
                .filter(|d| r.devices.contains(&d.index))
                .collect();
            c.strategy = super::qualification::gpu_incumbent_strategy(
                &selected,
                r.profile,
                r.suffix,
                r.fixed_strategy,
            );
        }
        let candidates = autotune::quick_candidates(info, r.profile, c.strategy, r.suffix);
        c.gpu_tuning = Some(
            candidates
                .into_iter()
                .find(|t| {
                    infos
                        .iter()
                        .filter(|d| r.devices.contains(&d.index))
                        .all(|d| autotune::eligible_tuning(d, r.profile, t))
                })
                .context("no common eligible GPU incumbent")?,
        );
    }
    Ok(c)
}
fn synthetic(r: &Request) -> Result<Pattern> {
    let payload = r.profile.diagnostic_address()?;
    if r.suffix {
        Pattern::for_profile(r.profile, "", &payload[payload.len().saturating_sub(8)..])
    } else {
        Pattern::for_profile(r.profile, &payload, "")
    }
}
fn candidate_config(r: &Request, c: &Choice) -> Config {
    Config {
        mode: r.backend,
        profile: Some(r.profile),
        threads: r.threads,
        devices: r.devices.clone(),
        batch_size: r.batch_size,
        batched: r.batched,
        cpu_engine: c.cpu_engine,
        hash_mode: c.hash_mode,
        ed_table: c.ed_table,
        benchmark_strategy: Some(c.strategy),
        encoded_suffix: r.suffix,
        gpu_tuning: c.gpu_tuning.clone().unwrap_or_default(),
        automatic_gpu: false,
        tuning_cache: None,
        quiet: true,
        ..Config::default()
    }
}
fn candidates(r: &Request, initial: &Choice) -> Result<Vec<Choice>> {
    let strategies = if let Some(s) = r.fixed_strategy {
        vec![s]
    } else if r.profile.key_family() == KeyFamily::Ed25519
        || r.profile.address_type == AddressType::P2tr
    {
        vec![SearchStrategy::Linear]
    } else {
        vec![SearchStrategy::Linear, SearchStrategy::EndomorphismV1]
    };
    let mut choices = vec![initial.clone()];
    if r.backend == Mode::Cpu {
        if r.profile.key_family() == KeyFamily::Ed25519 {
            for &table in EdTable::calibration_candidates() {
                for hash in [HashMode::Scalar, HashMode::Simd] {
                    let dispatch = super::hash_dispatch(r.profile, true);
                    if hash == HashMode::Simd
                        && r.hash_mode != HashMode::Simd
                        && !dispatch.starts_with("avx2-")
                        && !dispatch.starts_with("sse2-")
                    {
                        continue;
                    }
                    if r.profile.address_type == AddressType::P2tr && hash == HashMode::Simd {
                        continue;
                    }
                    if table == EdTable::Reference && hash == HashMode::Simd {
                        continue;
                    }
                    choices.push(Choice {
                        ed_table: table,
                        hash_mode: hash,
                        ..initial.clone()
                    });
                }
            }
        } else {
            for strategy in strategies {
                if r.fixed_strategy.is_some() || strategy == SearchStrategy::Linear {
                    choices.push(Choice {
                        strategy,
                        cpu_engine: CpuEngine::Reference,
                        hash_mode: HashMode::Scalar,
                        ..initial.clone()
                    });
                }
                for hash in [HashMode::Scalar, HashMode::Simd] {
                    let dispatch = super::hash_dispatch(r.profile, true);
                    if hash == HashMode::Simd
                        && r.hash_mode != HashMode::Simd
                        && !dispatch.starts_with("avx2-")
                        && !dispatch.starts_with("sse2-")
                    {
                        continue;
                    }
                    choices.push(Choice {
                        strategy,
                        cpu_engine: CpuEngine::Batched,
                        hash_mode: hash,
                        ..initial.clone()
                    });
                }
            }
        }
    } else {
        let infos = opencl::discover()?;
        let info = infos
            .iter()
            .find(|d| r.devices.contains(&d.index))
            .context("missing calibration GPU")?;
        // Compare both streams before refining geometry. Eight total trials, never a Cartesian search.
        let mut portfolios = vec![];
        for strategy in strategies {
            portfolios.push((
                strategy,
                autotune::quick_candidates(info, r.profile, strategy, r.suffix),
            ));
        }
        for (strategy, ts) in &portfolios {
            if let Some(t) = ts.iter().find(|t| t.bounded_multiply) {
                choices.push(Choice {
                    strategy: *strategy,
                    gpu_tuning: Some(t.clone()),
                    ..initial.clone()
                });
            }
        }
        for index in 0..8 {
            for (strategy, ts) in &portfolios {
                if let Some(t) = ts.get(index) {
                    choices.push(Choice {
                        strategy: *strategy,
                        gpu_tuning: Some(t.clone()),
                        ..initial.clone()
                    });
                }
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    choices.retain(|c| {
        validate_choice(r, c).is_ok() && seen.insert(serde_json::to_string(c).unwrap_or_default())
    });
    if r.backend == Mode::Opencl {
        choices.truncate(8);
    }
    ensure!(!choices.is_empty(), "no valid calibration candidates");
    Ok(choices)
}
fn emit(
    nonce: &str,
    kind: &str,
    message: String,
    correctness: bool,
    report: Option<Report>,
) -> Result<()> {
    let event = Event {
        schema: SCHEMA,
        nonce: nonce.into(),
        kind: kind.into(),
        message,
        correctness,
        report,
    };
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &event)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn worker(r: &Request) -> Result<Report> {
    valid_request(r)?;
    let started = Instant::now();
    let initial = incumbent(r)?;
    let mut report = Report {
        schema: SCHEMA,
        key: key(r)?,
        choice: initial.clone(),
        confirmed: false,
        promoted: false,
        pairs: vec![],
        records: vec![],
    };
    let pattern = synthetic(r)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let mut best_rate = 0.0;
    let mut best = initial.clone();
    for (i, c) in candidates(r, &initial)?.into_iter().enumerate() {
        if started.elapsed() >= Duration::from_secs(38) {
            break;
        }
        emit(
            &r.nonce,
            "progress",
            format!(
                "Screening {} candidate {}",
                if r.backend == Mode::Cpu {
                    "CPU"
                } else {
                    "OpenCL"
                },
                i + 1
            ),
            false,
            None,
        )?;
        let trial = (|| -> Result<f64> {
            let mut sampler = super::calibration_sampling::Sampler::new(
                &candidate_config(r, &c),
                &pattern,
                c.strategy,
            )?;
            sampler.sample(0.2, cancel.clone())?;
            let mut rates = vec![];
            for _ in 0..3 {
                let sample = sampler.sample(0.4, cancel.clone())?;
                rates.push(sample.per_second);
                report
                    .records
                    .push(serde_json::json!({"phase":"screen","choice":c,"sample":sample}));
            }
            rates.sort_by(f64::total_cmp);
            Ok(rates[1])
        })();
        match trial {
            Ok(rate) if rate > best_rate => {
                best_rate = rate;
                best = c;
            }
            Ok(_) => {}
            Err(e) if e.downcast_ref::<CorrectnessError>().is_some() => return Err(e),
            Err(e) => report
                .records
                .push(serde_json::json!({"phase":"rejected","choice":c,"reason":format!("{e:#}")})),
        }
    }
    if started.elapsed() >= Duration::from_secs(40) {
        return Ok(report);
    }
    emit(
        &r.nonce,
        "progress",
        "Confirming incumbent and challenger in five alternating pairs".into(),
        false,
        None,
    )?;
    let mut a = super::calibration_sampling::Sampler::new(
        &candidate_config(r, &initial),
        &pattern,
        initial.strategy,
    )?;
    let mut b = super::calibration_sampling::Sampler::new(
        &candidate_config(r, &best),
        &pattern,
        best.strategy,
    )?;
    a.sample(1.0, cancel.clone())?;
    b.sample(1.0, cancel.clone())?;
    for i in 0..5 {
        if started.elapsed() >= Duration::from_secs(60) {
            return Ok(report);
        }
        let (aa, bb) = if i % 2 == 0 {
            (
                a.sample(1.5, cancel.clone())?,
                b.sample(1.5, cancel.clone())?,
            )
        } else {
            let bb = b.sample(1.5, cancel.clone())?;
            (a.sample(1.5, cancel.clone())?, bb)
        };
        report.pairs.push([aa.per_second, bb.per_second]);
        report.records.push(
            serde_json::json!({"phase":"confirmation","pair":i,"incumbent":aa,"challenger":bb}),
        );
    }
    report.confirmed = true;
    report.promoted = report.pairs.iter().all(|p| p[1] / p[0] >= 1.05);
    if report.promoted {
        report.choice = best;
    }
    validate_report(r, &report)?;
    Ok(report)
}

/// Both shipped executables handle this private mode before starting their normal UI.
/// Input and output are bounded public calibration data; no passwords, keys or sessions.
pub fn worker_entry() -> Option<i32> {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new(WORKER_ARGUMENT)) {
        return None;
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = linux_worker_group() {
        eprintln!("Cannot own calibration process group: {e}");
        return Some(1);
    }
    let mut text = String::new();
    let parsed = (|| -> Result<Request> {
        std::io::stdin().take(65_537).read_to_string(&mut text)?;
        ensure!(
            text.len() <= 65_536 && std::env::args_os().count() == 2,
            "invalid calibration worker input"
        );
        Ok(serde_json::from_str(&text)?)
    })();
    Some(match parsed {
        Ok(r) => match worker(&r) {
            Ok(report) => {
                if emit(
                    &r.nonce,
                    "result",
                    "Calibration finished".into(),
                    false,
                    Some(report),
                )
                .is_ok()
                {
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                let correctness = e.downcast_ref::<CorrectnessError>().is_some();
                let _ = emit(&r.nonce, "fatal", format!("{e:#}"), correctness, None);
                // The process status preserves fault classification even if the
                // public event cannot be written (for example, a full disk).
                if correctness { CORRECTNESS_EXIT } else { 1 }
            }
        },
        Err(e) => {
            eprintln!("Invalid calibration request: {e:#}");
            1
        }
    })
}
fn private_directory(path: &Path) -> Result<()> {
    let _guard = storage::guard(path)?;
    if !storage::exists(path)? {
        storage::create_directory(path, true)?;
        storage::private(path)?;
    }
    storage::assert_private_directory(path)
}
// The worker waits for its request, so Windows ownership is established before
// any calibration or driver compilation can start. Closing the parent process's
// non-inherited job handle also terminates descendants after abrupt parent exit.
#[cfg(windows)]
struct WorkerTree(std::os::windows::io::OwnedHandle);
#[cfg(windows)]
impl WorkerTree {
    fn bind(child: &std::process::Child) -> Result<Self> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::JobObjects::*;
        // SAFETY: null attributes/name create a private, non-inherited job.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        ensure!(
            !raw.is_null(),
            "create calibration job: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: a successful CreateJobObjectW returns an owned kernel handle.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job and process handles remain live; limits has the exact API layout.
        let configured = unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        ensure!(
            configured != 0,
            "configure calibration job: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the child is owned and still blocked awaiting its request.
        let assigned = unsafe { AssignProcessToJobObject(raw, child.as_raw_handle()) };
        ensure!(
            assigned != 0,
            "own calibration process tree: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self(job))
    }
}
#[cfg(windows)]
impl Drop for WorkerTree {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        // SAFETY: the handle is owned and valid until the field is dropped. Explicit
        // termination also covers a worker that already exited leaving a compiler.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0.as_raw_handle(), 1);
        }
    }
}
#[cfg(target_os = "linux")]
extern "C" fn stop_linux_worker(_: libc::c_int) {
    // SAFETY: kill/getpid are async-signal-safe. worker_entry first made this
    // process the group leader; the negative ID addresses only its owned group.
    unsafe {
        libc::kill(-libc::getpid(), libc::SIGKILL);
    }
}
#[cfg(target_os = "linux")]
fn linux_worker_group() -> std::io::Result<()> {
    // SAFETY: these calls touch only the calling process. No workload starts until
    // its process group and parent-death handler are established.
    unsafe {
        if libc::getpgrp() != libc::getpid() && libc::setpgid(0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::signal(
            libc::SIGTERM,
            stop_linux_worker as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
fn supervise(
    r: &Request,
    cancel: &AtomicBool,
    skip: &AtomicBool,
    notify: &mut impl FnMut(String),
) -> Result<Report> {
    let mut command = Command::new(std::env::current_exe()?);
    command.arg(WORKER_ARGUMENT);
    supervise_command(r, cancel, skip, notify, command, Duration::from_secs(120))
}

/// Internal injection boundary for exercising the actual bounded supervisor.
/// Production always uses the current executable's private worker and 120s.
fn supervise_command(
    r: &Request,
    cancel: &AtomicBool,
    skip: &AtomicBool,
    notify: &mut impl FnMut(String),
    mut command: Command,
    deadline: Duration,
) -> Result<Report> {
    let folder = tempfile::tempdir()?;
    storage::private(folder.path())?;
    let output = folder.path().join("public-calibration.jsonl");
    storage::write_bytes(&output, b"", false)?;
    let _guard = storage::guard(&output)?;
    let file = std::fs::OpenOptions::new().write(true).open(&output)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file))
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::process::id() as libc::pid_t;
        command.process_group(0);
        // SAFETY: pre_exec invokes only async-signal-safe Linux syscalls. The
        // parent-ID check closes the race between fork and PR_SET_PDEATHSIG.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
    }
    let input = serde_json::to_vec(r)?;
    let mut child = command.spawn().context("start owned calibration worker")?;
    #[cfg(windows)]
    let tree = match WorkerTree::bind(&child) {
        Ok(tree) => tree,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let write = child
        .stdin
        .take()
        .context("missing worker input")?
        .write_all(&input);
    if let Err(e) = write {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.into());
    }
    let start = Instant::now();
    let mut seen = 0;
    let mut exited = false;
    let result = (|| -> Result<Report> {
        loop {
            ensure!(!cancel.load(Ordering::Relaxed), "calibration stopped");
            if skip.load(Ordering::Relaxed) || start.elapsed() > deadline {
                return Ok(Report {
                    schema: SCHEMA,
                    key: key(r)?,
                    choice: incumbent(r)?,
                    confirmed: false,
                    promoted: false,
                    pairs: vec![],
                    records: vec![],
                });
            }
            ensure!(
                storage::metadata(&output)?.len() <= MAX_OUTPUT,
                "calibration output exceeded bound"
            );
            let raw = storage::read_bytes(&output)?;
            let complete = raw.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            for line in raw[seen..complete]
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
            {
                let event: Event = serde_json::from_slice(line)?;
                ensure!(
                    event.schema == SCHEMA && event.nonce == r.nonce,
                    "foreign calibration worker output"
                );
                match event.kind.as_str() {
                    "progress" => notify(event.message),
                    "result" => {
                        let report = event.report.context("missing calibration result")?;
                        validate_report(r, &report)?;
                        return Ok(report);
                    }
                    "fatal" if event.correctness => {
                        return Err(CorrectnessError(event.message).into());
                    }
                    "fatal" => anyhow::bail!("calibration worker: {}", event.message),
                    _ => anyhow::bail!("invalid calibration event"),
                }
            }
            seen = complete;
            if let Some(status) = worker_status(&mut child)? {
                if exited {
                    return Err(worker_exit_error(status));
                }
                exited = true;
                continue;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    #[cfg(windows)]
    drop(tree);
    #[cfg(target_os = "linux")]
    // SAFETY: worker_status never reaps the owned group leader, so its ID stays
    // reserved until this group termination and the following child.wait().
    // Also stop compiler descendants on cancellation or the outer deadline.
    unsafe {
        libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
    }
    // Cleanup failure cannot replace an already reported cryptographic fault.
    if !matches!(worker_status(&mut child), Ok(Some(_))) {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}
fn worker_status(
    child: &mut std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;
        // Observe without reaping: the group leader's reserved PID prevents its
        // process-group ID being reused until owned descendants are terminated.
        // SAFETY: info has the required layout; waitid addresses our owned child.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the pointer is valid and these flags never reap the child.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: waitid initialized the child-status union selected by si_code.
        let pid = unsafe { info.si_pid() };
        if pid == 0 {
            return Ok(None);
        }
        // SAFETY: a nonzero si_pid identifies the initialized child-status union.
        let code = unsafe { info.si_status() };
        let raw = if info.si_code == libc::CLD_EXITED {
            code << 8
        } else if info.si_code == libc::CLD_DUMPED {
            code | 0x80
        } else {
            code
        };
        Ok(Some(std::process::ExitStatus::from_raw(raw)))
    }
    #[cfg(not(target_os = "linux"))]
    child.try_wait()
}
fn worker_exit_error(status: std::process::ExitStatus) -> anyhow::Error {
    if status.code() == Some(CORRECTNESS_EXIT) {
        CorrectnessError(
            "calibration worker reported a cryptographic mismatch; public event unavailable".into(),
        )
        .into()
    } else {
        anyhow::anyhow!("calibration worker exited without a result: {status}")
    }
}
fn apply(config: &mut Config, choice: &Choice, origin: &str, report: Option<&Report>) -> Summary {
    config.benchmark_strategy = Some(choice.strategy);
    config.cpu_engine = choice.cpu_engine;
    config.hash_mode = choice.hash_mode;
    config.ed_table = choice.ed_table;
    if let Some(t) = &choice.gpu_tuning {
        config.gpu_tuning = t.clone();
        config.automatic_gpu = false;
    }
    let summary = Summary {
        strategy: choice.strategy,
        origin: origin.into(),
        diagnostics: serde_json::json!({
        "origin":origin,"choice":choice,"locally_calibrated":report.is_some_and(|r|r.confirmed),
        "promoted":report.is_some_and(|r|r.promoted),"pairs":report.map(|r|&r.pairs),
        "qualification":"local selection, not generation-wide benchmark qualification"}),
    };
    config.calibration = Some(summary.diagnostics.clone());
    summary
}
/// Startup/dispatch correctness failures invalidate performance data, never enable fallback.
pub fn invalidate(config: &Config, error: &anyhow::Error) -> Result<()> {
    invalidate_record(config.calibration_record.as_deref(), error)
}
pub(crate) fn with_fault_record<T>(record: Option<&Path>, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            if let Err(fault) = invalidate_record(record, &error) {
                return Err(error.context(format!("record calibration fault failed: {fault:#}")));
            }
            Err(error)
        }
    }
}
pub(crate) fn invalidate_record(record: Option<&Path>, error: &anyhow::Error) -> Result<()> {
    if error.downcast_ref::<CorrectnessError>().is_none() {
        return Ok(());
    }
    if let Some(path) = record {
        let parent = path.parent().context("invalid calibration cache path")?;
        storage::write_json(
            path,
            &serde_json::json!({"schema":SCHEMA,"invalid":true}),
            true,
        )?;
        storage::write_json(
            &parent.join(format!("calibration-fault-{}.json", uuid::Uuid::new_v4())),
            &serde_json::json!({"schema":SCHEMA,"error":format!("{error:#}"),"private_material":false}),
            false,
        )?;
    }
    Ok(())
}
/// Auto's ordinary GPU-startup fallback gets independent CPU selection for the saved stream.
pub(crate) fn cpu_fallback(config: &Config) -> Result<Config> {
    let mut cpu = config.clone();
    cpu.mode = Mode::Cpu;
    cpu.devices.clear();
    cpu.automatic_gpu = true;
    let (engine, hash, table) =
        config
            .calibration_overrides
            .unwrap_or((CpuEngine::Auto, HashMode::Auto, EdTable::Auto));
    cpu.cpu_engine = engine;
    cpu.hash_mode = hash;
    cpu.ed_table = table;
    let profile = config.profile.unwrap_or_default();
    let address = profile.address(&crate::crypto::generator())?;
    let public_pattern = if config.encoded_suffix {
        Pattern::for_profile(profile, "", &address[address.len().saturating_sub(8)..])?
    } else {
        Pattern::for_profile(profile, &address, "")?
    };
    let r = request(&cpu, &public_pattern, config.benchmark_strategy)?;
    let pattern = synthetic(&r)?;
    let quiet = config.quiet;
    struct Active(Option<Arc<AtomicBool>>);
    impl Drop for Active {
        fn drop(&mut self) {
            if let Some(a) = &self.0 {
                a.store(false, Ordering::Relaxed);
            }
        }
    }
    let active = Active(config.calibration_active.clone());
    if let Some(a) = &active.0 {
        a.store(true, Ordering::Relaxed);
    }
    let status = config.calibration_status.clone();
    resolve(
        &mut cpu,
        &pattern,
        config.benchmark_strategy,
        config.tuning_mode,
        config
            .calibration_cancel
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false))),
        config
            .calibration_skip
            .clone()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false))),
        |s| {
            if let Some(tx) = &status {
                let _ = tx.try_send(s.clone());
            }
            if !quiet {
                eprintln!("{s}");
            }
        },
    )?;
    Ok(cpu)
}
fn request(config: &Config, pattern: &Pattern, fixed: Option<SearchStrategy>) -> Result<Request> {
    pattern.validate()?;
    let mut mode = config.mode;
    let mut devices = vec![];
    let mut hardware = vec![];
    if mode != Mode::Cpu && pattern.profile.key_family() != KeyFamily::Ed25519 {
        let discovery = (|| -> Result<()> {
            let infos = opencl::discover()?;
            devices = if config.devices.is_empty() {
                opencl::automatic_enabled(&infos, &config.exclude_devices)?
            } else {
                config.devices.clone()
            };
            devices.retain(|d| !config.exclude_devices.contains(d));
            ensure!(
                devices
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == devices.len(),
                "duplicate GPU selection"
            );
            for index in &devices {
                let info = infos
                    .iter()
                    .find(|d| d.index == *index && d.suitable)
                    .context("requested GPU unavailable")?;
                hardware.push(autotune::fingerprint(info)?);
            }
            ensure!(!devices.is_empty(), "no suitable OpenCL GPU");
            Ok(())
        })();
        match discovery {
            Ok(()) => mode = Mode::Opencl,
            Err(e) if config.mode == Mode::Opencl || !config.devices.is_empty() => return Err(e),
            Err(_) => {
                devices.clear();
                hardware.clear();
                mode = Mode::Cpu;
            }
        }
    } else {
        ensure!(mode != Mode::Opencl, "Ed25519 requires CPU execution");
        mode = Mode::Cpu;
    }
    if mode == Mode::Cpu {
        hardware = vec![cpu_identity()];
    }
    let (engine, hash, table) = config.calibration_overrides.unwrap_or((
        config.cpu_engine,
        config.hash_mode,
        config.ed_table,
    ));
    Ok(Request {
        schema: SCHEMA,
        nonce: uuid::Uuid::new_v4().to_string(),
        profile: canonical(pattern.profile),
        suffix: !pattern.suffix.is_empty(),
        fixed_strategy: fixed,
        backend: mode,
        devices,
        hardware,
        threads: config.threads,
        batch_size: config.batch_size,
        batched: config.batched,
        cpu_engine: engine,
        hash_mode: hash,
        ed_table: table,
        implementation: implementation(),
    })
}
/// Resolve before new-job persistence, or with the immutable saved strategy on resume.
pub fn resolve(
    config: &mut Config,
    pattern: &Pattern,
    fixed: Option<SearchStrategy>,
    mode: TuningMode,
    cancel: Arc<AtomicBool>,
    skip: Arc<AtomicBool>,
    notify: impl FnMut(String),
) -> Result<Summary> {
    resolve_inner(config, pattern, fixed, mode, cancel, skip, notify, false)
}
pub fn retune(
    config: &mut Config,
    pattern: &Pattern,
    fixed: Option<SearchStrategy>,
    mode: TuningMode,
    cancel: Arc<AtomicBool>,
    skip: Arc<AtomicBool>,
    notify: impl FnMut(String),
) -> Result<Summary> {
    resolve_inner(config, pattern, fixed, mode, cancel, skip, notify, true)
}
#[allow(clippy::too_many_arguments)]
fn resolve_inner(
    config: &mut Config,
    pattern: &Pattern,
    fixed: Option<SearchStrategy>,
    mode: TuningMode,
    cancel: Arc<AtomicBool>,
    skip: Arc<AtomicBool>,
    mut notify: impl FnMut(String),
    force: bool,
) -> Result<Summary> {
    ensure!(!cancel.load(Ordering::Relaxed), "calibration stopped");
    config.profile = Some(pattern.profile);
    config.encoded_suffix = !pattern.suffix.is_empty();
    config.tuning_mode = mode;
    config.calibration_cancel = Some(cancel.clone());
    config.calibration_skip = Some(skip.clone());
    config.calibration_record = None;
    if config.calibration_overrides.is_none() {
        config.calibration_overrides = Some((config.cpu_engine, config.hash_mode, config.ed_table));
    }
    if !config.batched || (!config.automatic_gpu && config.mode != Mode::Cpu) {
        let choice = Choice {
            strategy: fixed.unwrap_or(SearchStrategy::Linear),
            cpu_engine: CpuEngine::Reference,
            hash_mode: HashMode::Scalar,
            ed_table: EdTable::Reference,
            gpu_tuning: if config.mode == Mode::Cpu {
                None
            } else {
                Some(config.gpu_tuning.clone())
            },
        };
        return Ok(apply(
            config,
            &choice,
            "explicit configuration / baseline",
            None,
        ));
    }
    let r = request(config, pattern, fixed)?;
    valid_request(&r)?;
    config.calibration_hardware = if r.backend == Mode::Opencl {
        r.devices
            .iter()
            .copied()
            .zip(r.hardware.iter().cloned())
            .collect()
    } else {
        vec![]
    };
    let fallback = incumbent(&r)?;
    #[cfg(not(feature = "developer-tools"))]
    if r.profile.key_family() == KeyFamily::Ed25519 {
        // Standard builds have one native seed derivation implementation. Timing
        // it against itself cannot select another path or qualify an improvement.
        return Ok(apply(
            config,
            &fallback,
            "standard Ed25519 implementation",
            None,
        ));
    }
    let cache = config.tuning_cache.clone();
    let mut cache_path = None;
    let mut locks = vec![];
    if let Some(dir) = &cache {
        private_directory(dir)?;
        let mut hardware_keys = r.hardware.clone();
        hardware_keys.sort();
        hardware_keys.dedup();
        for hardware_key in hardware_keys {
            let lock_dir = dir.join(format!("calibration-lock-{hardware_key}"));
            private_directory(&lock_dir)?;
            let started = Instant::now();
            loop {
                match storage::lock_session(&lock_dir) {
                    Ok(file) => {
                        locks.push(file);
                        break;
                    }
                    Err(_) if started.elapsed() < Duration::from_secs(120) => {
                        ensure!(
                            !cancel.load(Ordering::Relaxed),
                            "calibration stopped while waiting"
                        );
                        if skip.load(Ordering::Relaxed) {
                            return Ok(apply(config, &fallback, "calibration skipped", None));
                        }
                        if started.elapsed() < Duration::from_millis(100) {
                            notify("Waiting for this device's calibration lock".into());
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => return Err(e.context("acquire calibration lock")),
                }
            }
        }
        let path = dir.join(format!("calibration-v2-{}.json", key(&r)?));
        if !force
            && let Ok(saved) = storage::read_private_json::<Report>(&path)
            && saved.confirmed
            && validate_report(&r, &saved).is_ok()
        {
            config.calibration_record = Some(path);
            return Ok(apply(
                config,
                &saved.choice,
                "validated local calibration cache",
                Some(&saved),
            ));
        }
        cache_path = Some(path);
    }
    if mode == TuningMode::Off || skip.load(Ordering::Relaxed) {
        return Ok(apply(
            config,
            &fallback,
            "portable incumbent; calibration disabled",
            None,
        ));
    }
    notify(format!(
        "Calibrating {:?}; synthetic inputs only",
        r.backend
    ));
    let report = match supervise(&r, &cancel, &skip, &mut notify) {
        Ok(report) => report,
        Err(e) if e.downcast_ref::<CorrectnessError>().is_some() => {
            // Invalidation IO must never demote a cryptographic mismatch into an
            // ordinary tuning failure, which could otherwise permit fallback.
            if let Err(fault) = invalidate_record(cache_path.as_deref(), &e) {
                return Err(e.context(format!("record calibration fault failed: {fault:#}")));
            }
            return Err(e);
        }
        Err(e) if cancel.load(Ordering::Relaxed) => return Err(e),
        Err(e) => {
            notify(format!(
                "Calibration unavailable; retaining checked incumbent: {e:#}"
            ));
            if r.backend == Mode::Opencl && config.mode == Mode::Auto && config.devices.is_empty() {
                config.mode = Mode::Cpu;
                return resolve_inner(config, pattern, fixed, mode, cancel, skip, notify, force);
            }
            return Ok(apply(
                config,
                &fallback,
                "portable incumbent; calibration unavailable",
                None,
            ));
        }
    };
    validate_report(&r, &report)?;
    if report.confirmed
        && let Some(path) = cache_path
    {
        storage::write_json(&path, &report, true)?;
        config.calibration_record = Some(path);
    }
    drop(locks);
    Ok(apply(
        config,
        &report.choice,
        if report.confirmed {
            "local calibration"
        } else {
            "portable incumbent; calibration incomplete"
        },
        Some(&report),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::Chain;
    #[cfg(all(windows, feature = "gui"))]
    use std::path::PathBuf;

    #[cfg(any(windows, unix))]
    enum SyntheticWorker {
        Exit(i32),
        Block,
        ForeignNonce,
    }

    #[cfg(any(windows, unix))]
    fn synthetic_worker(behavior: SyntheticWorker) -> Command {
        let event = serde_json::to_string(&Event {
            schema: SCHEMA,
            nonce: "synthetic-foreign-nonce".into(),
            kind: "progress".into(),
            message: "must not reach observer".into(),
            correctness: false,
            report: None,
        })
        .unwrap();
        #[cfg(windows)]
        {
            let system = std::env::var_os("SystemRoot")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("C:\\Windows"));
            let mut command =
                Command::new(system.join("System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
            // Only fixed synthetic test data is interpolated; production has
            // no shell command or configurable executable/deadline interface.
            let ending = match behavior {
                SyntheticWorker::Exit(code) => format!("exit {code}"),
                SyntheticWorker::Block => "Start-Sleep -Seconds 30".into(),
                SyntheticWorker::ForeignNonce => {
                    format!("[Console]::Out.WriteLine('{}')", event.replace('\'', "''"))
                }
            };
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("$null = [Console]::In.ReadToEnd(); {ending}"),
            ]);
            command
        }
        #[cfg(unix)]
        {
            let mut command = Command::new("/bin/sh");
            match behavior {
                SyntheticWorker::Exit(code) => {
                    command
                        .args(["-c", "cat >/dev/null; exit \"$1\"", "calibration-test"])
                        .arg(code.to_string());
                }
                SyntheticWorker::Block => {
                    command.args(["-c", "cat >/dev/null; sleep 30", "calibration-test"]);
                }
                SyntheticWorker::ForeignNonce => {
                    command
                        .args([
                            "-c",
                            "cat >/dev/null; printf '%s\\n' \"$1\"",
                            "calibration-test",
                        ])
                        .arg(event);
                }
            }
            command
        }
    }

    fn cpu_request() -> Request {
        request(
            &Config {
                mode: Mode::Cpu,
                threads: 1,
                tuning_cache: None,
                ..Config::default()
            },
            &Pattern::new("0000000000000000", "").unwrap(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn synthetic_ed25519_patterns_use_valid_public_keys_for_prefix_and_suffix() {
        for chain in [Chain::Solana, Chain::Stellar, Chain::Algorand] {
            let profile = Profile::new(chain, None).unwrap();
            let address = profile.diagnostic_address().unwrap();
            let public = crate::chains::ed_public(profile, &address).unwrap();
            for suffix in [false, true] {
                let mut request = cpu_request();
                request.profile = profile;
                request.fixed_strategy = Some(SearchStrategy::Linear);
                request.suffix = suffix;
                valid_request(&request).unwrap();
                let pattern = synthetic(&request).unwrap();
                pattern.validate().unwrap();
                let expected = if suffix {
                    Pattern::for_profile(profile, "", &address[address.len() - 8..]).unwrap()
                } else {
                    Pattern::for_profile(profile, &address, "").unwrap()
                };
                assert_eq!(pattern, expected);
                assert!(pattern.compiled().unwrap().accepts_payload(&public));
            }
        }
    }

    #[cfg(all(windows, feature = "gui"))]
    #[test]
    #[ignore = "requires VANITY_GUI_CALIBRATION_BINARY pointing to a staged standalone GUI; runs real bounded CPU calibration"]
    fn standalone_gui_calibration_worker_needs_no_cli() {
        let binary = PathBuf::from(
            std::env::var_os("VANITY_GUI_CALIBRATION_BINARY")
                .expect("set VANITY_GUI_CALIBRATION_BINARY to the standalone GUI executable"),
        );
        assert!(binary.is_absolute(), "the staged GUI path must be absolute");
        storage::regular(&binary).unwrap();
        let folder = binary.parent().unwrap();
        assert!(
            !folder.join("vanity.exe").exists(),
            "stage the GUI without its CLI sibling"
        );
        assert!(
            !folder.join("vanity").exists(),
            "stage the GUI without a CLI executable"
        );

        let mut request = cpu_request();
        request.fixed_strategy = Some(SearchStrategy::Linear);
        valid_request(&request).unwrap();
        let mut command = Command::new(&binary);
        command.arg(WORKER_ARGUMENT).current_dir(folder);
        let mut notifications = vec![];
        let report = supervise_command(
            &request,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &mut |message| notifications.push(message),
            command,
            Duration::from_secs(120),
        )
        .unwrap();
        validate_report(&request, &report).unwrap();
        assert_eq!(report.key, key(&request).unwrap());
        assert_eq!(report.choice.strategy, SearchStrategy::Linear);
        assert!(report.choice.gpu_tuning.is_none());
        assert!(
            report.confirmed,
            "the actual GUI worker must complete its paired samples"
        );
        assert_eq!(report.pairs.len(), 5);
        assert!(!notifications.is_empty());

        let mut samples = 0;
        for record in &report.records {
            for name in ["sample", "incumbent", "challenger"] {
                let Some(value) = record.get(name) else {
                    continue;
                };
                let sample: super::super::calibration_sampling::Sample =
                    serde_json::from_value(value.clone()).unwrap();
                assert!(sample.evaluated > 0);
                assert!(sample.seconds.is_finite() && sample.seconds > 0.0);
                assert!(sample.per_second.is_finite() && sample.per_second > 0.0);
                assert_eq!(sample.per_second, sample.evaluated as f64 / sample.seconds);
                let workers = sample.workers.as_array().unwrap();
                assert_eq!(workers.len(), request.threads);
                assert!(
                    workers
                        .iter()
                        .all(|worker| worker["device"].as_str().unwrap().starts_with("cpu:"))
                );
                let evaluated: u64 = workers
                    .iter()
                    .map(|worker| worker["evaluated"].as_u64().unwrap())
                    .sum();
                assert_eq!(evaluated, sample.evaluated);
                samples += 1;
            }
        }
        assert!(
            samples >= 10,
            "retain both sides of all five confirmation pairs"
        );
        println!(
            "Standalone GUI CPU calibration passed: {} measured samples, promoted={}",
            samples, report.promoted
        );
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn supervisor_classifies_actual_worker_crash_and_reserved_crypto_exit() {
        let request = cpu_request();
        for (code, cryptographic) in [(7, false), (CORRECTNESS_EXIT, true)] {
            let error = supervise_command(
                &request,
                &AtomicBool::new(false),
                &AtomicBool::new(false),
                &mut |_| {},
                synthetic_worker(SyntheticWorker::Exit(code)),
                Duration::from_secs(10),
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<CorrectnessError>().is_some(),
                cryptographic
            );
            assert!(format!("{error:#}").contains(if cryptographic {
                "cryptographic mismatch"
            } else {
                "exited without a result"
            }));
        }
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn supervisor_rejects_foreign_nonce_before_observer_notification() {
        let mut notifications = vec![];
        let error = supervise_command(
            &cpu_request(),
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &mut |message| notifications.push(message),
            synthetic_worker(SyntheticWorker::ForeignNonce),
            Duration::from_secs(10),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("foreign calibration worker output")
        );
        assert!(notifications.is_empty());
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn supervisor_deadline_returns_only_an_unconfirmed_incumbent() {
        let request = cpu_request();
        let started = Instant::now();
        let report = supervise_command(
            &request,
            &AtomicBool::new(false),
            &AtomicBool::new(false),
            &mut |_| {},
            synthetic_worker(SyntheticWorker::Block),
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(report.choice, incumbent(&request).unwrap());
        assert!(!report.confirmed && !report.promoted);
        assert!(report.pairs.is_empty() && report.records.is_empty());
        validate_report(&request, &report).unwrap();
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn supervisor_skip_retains_incumbent_while_stop_cancels_without_a_result() {
        let request = cpu_request();
        for stop in [false, true] {
            let cancel = AtomicBool::new(false);
            let skip = AtomicBool::new(false);
            let signal = if stop { &cancel } else { &skip };
            let started = Instant::now();
            let result = std::thread::scope(|scope| {
                scope.spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    signal.store(true, Ordering::Relaxed);
                });
                supervise_command(
                    &request,
                    &cancel,
                    &skip,
                    &mut |_| {},
                    synthetic_worker(SyntheticWorker::Block),
                    Duration::from_secs(10),
                )
            });
            assert!(started.elapsed() < Duration::from_secs(5));
            if stop {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("calibration stopped")
                );
                assert!(!skip.load(Ordering::Relaxed));
            } else {
                let report = result.unwrap();
                assert_eq!(report.choice, incumbent(&request).unwrap());
                assert!(!report.confirmed && !report.promoted);
                assert!(report.pairs.is_empty() && report.records.is_empty());
                validate_report(&request, &report).unwrap();
                assert!(!cancel.load(Ordering::Relaxed));
            }
        }
    }

    #[test]
    fn v2_corrupt_stale_and_incomplete_cache_records_remain_untouched() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        let cache = root.path().join("private-cache");
        private_directory(&cache).unwrap();
        let legacy = cache.join("tuning-legacy.json");
        let legacy_bytes = b"synthetic opaque legacy cache; never migrated";
        storage::write_bytes(&legacy, legacy_bytes, false).unwrap();
        let pattern = Pattern::new("0000000000000000", "").unwrap();
        let config = Config {
            mode: Mode::Cpu,
            threads: 1,
            tuning_cache: Some(cache),
            ..Config::default()
        };
        let request = request(&config, &pattern, None).unwrap();
        let path = config
            .tuning_cache
            .as_ref()
            .unwrap()
            .join(format!("calibration-v2-{}.json", key(&request).unwrap()));
        let valid = Report {
            schema: SCHEMA,
            key: key(&request).unwrap(),
            choice: incumbent(&request).unwrap(),
            confirmed: true,
            promoted: false,
            pairs: vec![[100.0, 101.0]; 5],
            records: vec![],
        };
        let mut stale = valid.clone();
        stale.schema = SCHEMA - 1;
        let mut foreign = valid.clone();
        foreign.key = "f".repeat(64);
        let mut incomplete = valid.clone();
        incomplete.confirmed = false;
        incomplete.pairs.truncate(2);
        let mut invalid_rates = valid.clone();
        invalid_rates.pairs[0] = [0.0, 0.0];
        let cases = [
            b"{not a JSON cache".to_vec(),
            serde_json::to_vec(&stale).unwrap(),
            serde_json::to_vec(&foreign).unwrap(),
            serde_json::to_vec(&incomplete).unwrap(),
            serde_json::to_vec(&invalid_rates).unwrap(),
        ];
        for bytes in cases {
            storage::write_bytes(&path, &bytes, true).unwrap();
            let mut current = config.clone();
            let summary = resolve(
                &mut current,
                &pattern,
                None,
                TuningMode::Off,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                |_| {},
            )
            .unwrap();
            assert_eq!(summary.origin, "portable incumbent; calibration disabled");
            assert!(current.calibration_record.is_none());
            assert_eq!(storage::read_bytes(&path).unwrap(), bytes);
            assert_eq!(storage::read_bytes(&legacy).unwrap(), legacy_bytes);
        }
        storage::write_json(&path, &valid, true).unwrap();
        let mut current = config;
        let summary = resolve(
            &mut current,
            &pattern,
            None,
            TuningMode::Off,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .unwrap();
        assert_eq!(summary.origin, "validated local calibration cache");
        assert_eq!(current.calibration_record, Some(path));
        assert_eq!(storage::read_bytes(&legacy).unwrap(), legacy_bytes);
    }

    #[test]
    fn identity_ignores_nonce_and_gpu_ordinal_but_binds_stream_and_workers() {
        let r = cpu_request();
        let mut other = r.clone();
        other.nonce = "another process".into();
        other.devices = vec![42];
        assert_eq!(key(&r).unwrap(), key(&other).unwrap());
        other.fixed_strategy = Some(SearchStrategy::Linear);
        assert_ne!(key(&r).unwrap(), key(&other).unwrap());
        other = r.clone();
        other.threads += 1;
        assert_ne!(key(&r).unwrap(), key(&other).unwrap());
        other = r.clone();
        other.implementation.push('0');
        assert_ne!(key(&r).unwrap(), key(&other).unwrap());
    }
    #[test]
    fn promotion_requires_every_finite_pair_and_saved_strategy() {
        let mut r = cpu_request();
        r.fixed_strategy = Some(SearchStrategy::Linear);
        let mut report = Report {
            schema: SCHEMA,
            key: key(&r).unwrap(),
            choice: incumbent(&r).unwrap(),
            confirmed: true,
            promoted: true,
            pairs: vec![[100.0, 106.0]; 5],
            records: vec![],
        };
        validate_report(&r, &report).unwrap();
        report.pairs[2][1] = 104.9;
        assert!(validate_report(&r, &report).is_err());
        report.pairs[2][1] = f64::NAN;
        assert!(validate_report(&r, &report).is_err());
        report.pairs[2][1] = 106.0;
        report.choice.strategy = SearchStrategy::EndomorphismV1;
        assert!(validate_report(&r, &report).is_err());
    }
    #[test]
    fn unpromoted_or_nonfinite_records_never_authorize_a_different_stream() {
        let r = cpu_request();
        let mut report = Report {
            schema: SCHEMA,
            key: key(&r).unwrap(),
            choice: incumbent(&r).unwrap(),
            confirmed: true,
            promoted: false,
            pairs: vec![[100.0, 101.0]; 5],
            records: vec![],
        };
        validate_report(&r, &report).unwrap();
        report.pairs[0] = [0.0, 0.0];
        assert!(validate_report(&r, &report).is_err());
        report.pairs[0] = [100.0, 101.0];
        report.choice.strategy = SearchStrategy::EndomorphismV1;
        assert!(validate_report(&r, &report).is_err());
    }
    #[test]
    fn cache_fault_io_cannot_hide_a_cryptographic_failure() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing").join("cache.json");
        let error = with_fault_record::<()>(
            Some(&missing),
            Err(CorrectnessError("injected derivation mismatch".into()).into()),
        )
        .unwrap_err();
        assert!(error.downcast_ref::<CorrectnessError>().is_some());
    }
    #[cfg(windows)]
    #[test]
    fn closing_owned_job_terminates_a_worker_blocked_before_its_request() {
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/Q", "/c", "set /p calibration_test_input="])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let tree = WorkerTree::bind(&child).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        drop(tree);
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let exited = child.try_wait().unwrap().is_some();
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            exited,
            "closing calibration job left the blocked worker running"
        );
    }
    #[test]
    fn correctness_exit_remains_fatal_without_a_public_event() {
        #[cfg(windows)]
        let status = {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(CORRECTNESS_EXIT as u32)
        };
        #[cfg(unix)]
        let status = {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(CORRECTNESS_EXIT << 8)
        };
        assert!(
            worker_exit_error(status)
                .downcast_ref::<CorrectnessError>()
                .is_some()
        );
    }
    #[test]
    fn cpu_fallback_keeps_suffix_class_saved_strategy_and_explicit_overrides() {
        let c = Config {
            mode: Mode::Auto,
            threads: 1,
            profile: Some(Profile::default()),
            encoded_suffix: true,
            benchmark_strategy: Some(SearchStrategy::EndomorphismV1),
            tuning_mode: TuningMode::Off,
            tuning_cache: None,
            calibration_overrides: Some((CpuEngine::Reference, HashMode::Scalar, EdTable::Auto)),
            ..Config::default()
        };
        let fallback = cpu_fallback(&c).unwrap();
        assert!(fallback.encoded_suffix);
        assert_eq!(fallback.benchmark_strategy, c.benchmark_strategy);
        assert_eq!(fallback.cpu_engine, CpuEngine::Reference);
        assert_eq!(fallback.hash_mode, HashMode::Scalar);
    }
    #[test]
    fn baseline_and_off_never_dispatch_a_worker() {
        let mut config = Config {
            mode: Mode::Cpu,
            threads: 1,
            tuning_cache: None,
            ..Config::default()
        };
        let p = Pattern::new("0000000000000000", "").unwrap();
        let s = resolve(
            &mut config,
            &p,
            Some(SearchStrategy::EndomorphismV1),
            TuningMode::Off,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .unwrap();
        assert_eq!(s.strategy, SearchStrategy::EndomorphismV1);
        assert_eq!(config.cpu_engine, CpuEngine::Reference);
        config.batched = false;
        assert_eq!(
            resolve(
                &mut config,
                &p,
                None,
                TuningMode::Auto,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                |_| {}
            )
            .unwrap()
            .strategy,
            SearchStrategy::Linear
        );
    }
    #[cfg(not(feature = "developer-tools"))]
    #[test]
    fn standard_ed25519_has_no_redundant_calibration_worker_or_cache() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("unused-calibration");
        let config = Config {
            mode: Mode::Cpu,
            threads: 1,
            tuning_cache: Some(cache.clone()),
            ..Config::default()
        };
        for chain in [Chain::Solana, Chain::Stellar, Chain::Algorand] {
            let pattern = Pattern::for_profile(
                Profile::new(chain, None).unwrap(),
                if chain == Chain::Stellar { "GA" } else { "A" },
                "",
            )
            .unwrap();
            for mode in [TuningMode::Auto, TuningMode::Off] {
                for skip in [false, true] {
                    let mut selected = config.clone();
                    let summary = resolve(
                        &mut selected,
                        &pattern,
                        Some(SearchStrategy::Linear),
                        mode,
                        Arc::new(AtomicBool::new(false)),
                        Arc::new(AtomicBool::new(skip)),
                        |_| panic!("the fixed implementation must not start a tuning worker"),
                    )
                    .unwrap();
                    assert_eq!(summary.origin, "standard Ed25519 implementation");
                    assert_eq!(summary.strategy, SearchStrategy::Linear);
                    assert_eq!(selected.ed_table, EdTable::Reference);
                    assert_eq!(selected.hash_mode, HashMode::Scalar);
                    assert!(selected.calibration_record.is_none());
                    assert_eq!(summary.diagnostics["locally_calibrated"], false);
                    assert_eq!(summary.diagnostics["promoted"], false);
                    assert!(summary.diagnostics["pairs"].is_null());
                }
            }
            for (stopped, backend, threads, strategy) in [
                (true, Mode::Cpu, 1, SearchStrategy::Linear),
                (false, Mode::Opencl, 1, SearchStrategy::Linear),
                (false, Mode::Cpu, 0, SearchStrategy::Linear),
                (false, Mode::Cpu, 1, SearchStrategy::EndomorphismV1),
            ] {
                let mut invalid = Config {
                    mode: backend,
                    threads,
                    ..config.clone()
                };
                assert!(
                    resolve(
                        &mut invalid,
                        &pattern,
                        Some(strategy),
                        TuningMode::Auto,
                        Arc::new(AtomicBool::new(stopped)),
                        Arc::new(AtomicBool::new(false)),
                        |_| panic!("an invalid request must not start a tuning worker"),
                    )
                    .is_err()
                );
            }
        }
        assert!(!cache.exists());
    }

    #[test]
    fn cancellation_while_waiting_for_device_lock_does_not_start_a_worker() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        let dir = root.path().join("cache");
        private_directory(&dir).unwrap();
        let lock_dir = dir.join(format!("calibration-lock-{}", cpu_identity()));
        private_directory(&lock_dir).unwrap();
        let lock = storage::lock_session(&lock_dir).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = cancel.clone();
        let started = Instant::now();
        let thread = std::thread::spawn(move || {
            let mut c = Config {
                mode: Mode::Cpu,
                threads: 1,
                tuning_cache: Some(dir),
                ..Config::default()
            };
            resolve(
                &mut c,
                &Pattern::new("0000000000000000", "").unwrap(),
                None,
                TuningMode::Auto,
                cancel,
                Arc::new(AtomicBool::new(false)),
                |_| {},
            )
        });
        std::thread::sleep(Duration::from_millis(150));
        signal.store(true, Ordering::Relaxed);
        assert!(thread.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(lock);
    }
}
