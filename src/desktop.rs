//! Nonvisual desktop workflow. No private keys or cryptographic arithmetic here.
//! Both frontends call the same KeyManager, coordinator and persistence APIs.
use crate::{
    backend::{
        calibration::{self, TuningMode},
        cpu_info, opencl,
    },
    coordinator::{self, Config, Mode, Progress},
    crypto::Pattern,
    model::{Job, SearchStrategy},
    split::{self, SessionKind, SplitRequest},
    storage,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    CreatingSession,
    Searching,
    Pausing,
    Paused,
    MatchFound,
    Finalizing,
    Completed,
    Error,
}
impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Ready",
            Self::CreatingSession => "Session creation",
            Self::Searching => "Search active",
            Self::Pausing => "Pause in progress",
            Self::Paused => "Paused",
            Self::MatchFound => "Match found",
            Self::Finalizing => "Wallet operation",
            Self::Completed => "Completed",
            Self::Error => "Error",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Dark,
    Light,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub schema: u32,
    #[serde(default)]
    pub profile: crate::chains::Profile,
    pub sessions_root: PathBuf,
    pub wallets_root: PathBuf,
    pub theme: Theme,
    pub detect_hardware: bool,
    pub mode: Mode,
    pub threads: usize,
    pub excluded_devices: Vec<usize>,
    pub batch_size: u32,
    pub max_seconds: Option<f64>,
    #[serde(default)]
    pub tuning: TuningMode,
    pub benchmark_per_second: Option<f64>,
}
impl Settings {
    pub fn defaults(data: &Path) -> Self {
        let c = Config::default();
        Self {
            schema: 3,
            profile: Default::default(),
            sessions_root: data.join("Sessions"),
            wallets_root: data.join("Wallets"),
            theme: Theme::System,
            detect_hardware: true,
            mode: Mode::Auto,
            threads: c.threads,
            excluded_devices: vec![],
            batch_size: 4_194_304,
            max_seconds: None,
            tuning: TuningMode::Auto,
            benchmark_per_second: None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=3).contains(&self.schema),
            "unsupported settings version"
        );
        ensure!(
            self.sessions_root.is_absolute() && self.wallets_root.is_absolute(),
            "storage folders must be absolute paths"
        );
        let _sessions = storage::guard(&self.sessions_root)?;
        let _wallets = storage::guard(&self.wallets_root)?;
        ensure!(
            (1..=256).contains(&self.threads)
                && (1..=crate::backend::MAX_BATCH).contains(&self.batch_size),
            "invalid performance settings"
        );
        ensure!(
            self.excluded_devices.len() <= 256,
            "too many device preferences"
        );
        ensure!(
            self.max_seconds
                .is_none_or(|s| s.is_finite() && (0.1..=86400.0).contains(&s)),
            "invalid time limit"
        );
        ensure!(
            self.benchmark_per_second
                .is_none_or(|r| r.is_finite() && r > 0.0),
            "invalid benchmark rate"
        );
        self.profile.validate()?;
        Ok(())
    }
    pub fn config(&self) -> Config {
        Config {
            mode: self.mode,
            profile: Some(self.profile),
            threads: self.threads,
            exclude_devices: self.excluded_devices.clone(),
            batch_size: self.batch_size,
            max_seconds: self.max_seconds,
            batched: true,
            quiet: true,
            ..Config::default()
        }
    }
}
pub fn validate_prefix(input: &str) -> Result<Pattern> {
    let pattern = Pattern::new(input.trim(), "")?;
    ensure!(
        !pattern.prefix.is_empty(),
        "enter at least one hexadecimal digit"
    );
    Ok(pattern)
}
pub fn validate_password(password: &str, confirmation: &str) -> Result<()> {
    ensure!(password == confirmation, "Passwords do not agree.");
    ensure!(
        password.len() >= 12,
        "Use at least 12 characters. Do not use this password for another application."
    );
    Ok(())
}
pub fn difficulty(pattern: &Pattern, rate: Option<f64>) -> (f64, Option<f64>) {
    let attempts = 1.0 / pattern.probability();
    (
        attempts,
        rate.filter(|r| attempts.is_finite() && r.is_finite() && *r > 0.0)
            .map(|r| attempts / r),
    )
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Windows Known Folder API, including redirected profiles. No hardcoded user path.
#[cfg(windows)]
pub fn default_data_directory() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };
    let mut raw = std::ptr::null_mut();
    // SAFETY: valid known-folder GUID/output pointer; returned allocation is freed below.
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut raw) };
    ensure!(
        status >= 0 && !raw.is_null(),
        "Windows could not locate Local AppData ({status})"
    );
    // SAFETY: successful API result is a NUL-terminated UTF-16 buffer owned by COM.
    let path = unsafe {
        let mut len = 0;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let value = std::ffi::OsString::from_wide(std::slice::from_raw_parts(raw, len));
        CoTaskMemFree(raw.cast());
        PathBuf::from(value)
    };
    Ok(path.join("VanityPro"))
}
#[cfg(not(windows))]
pub fn default_data_directory() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .context("cannot locate application data folder")?;
    Ok(base.join("VanityPro"))
}
fn real_directory(path: &Path) -> Result<()> {
    let guard = storage::guard(path)?;
    let m = storage::metadata(guard.path())?;
    ensure!(
        m.is_dir() && !m.file_type().is_symlink(),
        "storage folder must be a real directory"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            m.file_attributes() & 0x400 == 0,
            "storage folder cannot be a junction/reparse point"
        );
    }
    Ok(())
}
pub fn create_root(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "storage folder must be absolute");
    storage::create_directory(path, true)
        .with_context(|| format!("create storage folder {}", path.display()))?;
    real_directory(path)?;
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub address: String,
    pub wallet: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMeta {
    pub schema: u32,
    pub session_id: uuid::Uuid,
    pub created: u64,
    pub last_backend: Mode,
    pub receipt: Option<Receipt>,
}
#[derive(Clone, Debug)]
pub struct Session {
    pub directory: PathBuf,
    pub job: Job,
    pub kind: SessionKind,
    pub created: u64,
    pub state: State,
    pub candidates: String,
    pub elapsed: f64,
    pub address: Option<String>,
    pub last_backend: Option<Mode>,
    pub receipt: Option<Receipt>,
}
pub fn load_session(directory: &Path) -> Result<Session> {
    let directory_guard = storage::read_guard(directory)?;
    let directory = directory_guard.path();
    real_directory(directory)?;
    let job: Job = storage::read_json(&directory.join("job.json"))?;
    job.validate()?;
    let kind = split::session_kind(directory)?;
    if kind != SessionKind::Worker {
        storage::regular(&directory.join("seed.keystore.json"))?;
    }
    let cp = if kind == SessionKind::Owner {
        None
    } else {
        Some(storage::load_checkpoint(
            &directory.join("checkpoint.json"),
            &job,
        )?)
    };
    let address = if kind == SessionKind::Owner {
        split::imported_result(directory)?
            .map(|result| job.profile().display_candidate(&result.candidate.address))
            .transpose()?
    } else if let Some(c) = cp
        .as_ref()
        .and_then(|checkpoint| checkpoint.candidate.as_ref())
    {
        c.verify(&job)?;
        Some(job.profile().display_candidate(&c.address)?)
    } else {
        None
    };
    let meta = if storage::exists(&directory.join("gui-session.json"))? {
        let m: SessionMeta = storage::read_json(&directory.join("gui-session.json"))?;
        ensure!(
            m.schema == 1 && m.session_id == job.session_id,
            "invalid GUI session metadata"
        );
        Some(m)
    } else {
        None
    };
    let created = meta.as_ref().map(|m| m.created).unwrap_or_else(|| {
        storage::metadata(&directory.join("job.json"))
            .ok()
            .and_then(|m| m.created().ok().or_else(|| m.modified().ok()))
            .and_then(|s| s.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    });
    let receipt = meta
        .as_ref()
        .and_then(|m| m.receipt.clone())
        // A receipt is public history, never proof of ownership or file availability.
        // Do not touch its target until an explicit wallet action.
        .filter(|r| {
            kind != SessionKind::Worker
                && address.as_ref() == Some(&r.address)
                && storage::receipt_path(&r.wallet)
        });
    let state = if cp
        .as_ref()
        .is_some_and(|checkpoint| checkpoint.fault.is_some())
    {
        State::Error
    } else if receipt.is_some() {
        State::Completed
    } else if address.is_some() {
        State::MatchFound
    } else {
        State::Paused
    };
    Ok(Session {
        directory: directory.to_owned(),
        job,
        kind,
        created,
        state,
        candidates: cp
            .as_ref()
            .map(|checkpoint| checkpoint.completed_count().map(|count| count.decimal()))
            .transpose()?
            .unwrap_or_else(|| "0".into()),
        elapsed: cp
            .as_ref()
            .map_or(0.0, |checkpoint| checkpoint.elapsed_seconds),
        address,
        last_backend: meta.map(|m| m.last_backend),
        receipt,
    })
}
pub fn discover_sessions(root: &Path) -> Result<(Vec<Session>, usize)> {
    let root_guard = storage::read_guard(root)?;
    let root = root_guard.path();
    if !storage::exists(root)? {
        return Ok((vec![], 0));
    }
    real_directory(root)?;
    let mut sessions = vec![];
    let mut rejected = 0;
    for entry in fs::read_dir(root)?.take(1001) {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if sessions.len() + rejected >= 1000 {
            rejected += 1;
            break;
        }
        match load_session(&entry.path()) {
            Ok(s) => sessions.push(s),
            Err(_) => rejected += 1,
        }
    }
    sessions.sort_by_key(|s| std::cmp::Reverse(s.created));
    Ok((sessions, rejected))
}
fn metadata_for(session: &Session, mode: Mode) -> SessionMeta {
    SessionMeta {
        schema: 1,
        session_id: session.job.session_id,
        created: session.created,
        last_backend: mode,
        receipt: session.receipt.clone(),
    }
}
pub fn create_session(
    root: &Path,
    pattern: Pattern,
    password: &str,
    mode: Mode,
) -> Result<Session> {
    create_session_with_strategy(root, pattern, password, mode, SearchStrategy::Linear)
}
fn create_session_with_strategy(
    root: &Path,
    pattern: Pattern,
    password: &str,
    mode: Mode,
    strategy: SearchStrategy,
) -> Result<Session> {
    ensure!(!pattern.prefix.is_empty(), "prefix cannot be empty");
    pattern.validate()?;
    create_root(root)?;
    // Native prefixes may contain Windows-reserved punctuation (CashAddr colon).
    let name = format!(
        "{:?}-{}-{}",
        pattern.profile.chain,
        now(),
        uuid::Uuid::new_v4()
    );
    let directory = root.join(name);
    crate::initialize_with_strategy(&directory, pattern, password, strategy)?;
    let mut session = load_session(&directory)?;
    session.created = now();
    storage::write_json(
        &directory.join("gui-session.json"),
        &metadata_for(&session, mode),
        false,
    )?;
    storage::create_directory(&directory.join("logs"), false)?;
    storage::private(&directory.join("logs"))?;
    session.last_backend = Some(mode);
    log_event(&directory, "Encrypted session created")?;
    Ok(session)
}
fn split_session_directory(root: &Path, pattern: &Pattern) -> Result<PathBuf> {
    pattern.validate()?;
    create_root(root)?;
    Ok(root.join(format!(
        "{:?}-{}-{}",
        pattern.profile.chain,
        now(),
        uuid::Uuid::new_v4()
    )))
}
fn finish_split_session(directory: &Path, mode: Mode, event: &'static str) -> Result<Session> {
    let mut session = load_session(directory)?;
    session.created = now();
    storage::write_json(
        &directory.join("gui-session.json"),
        &metadata_for(&session, mode),
        false,
    )?;
    log_event(directory, event)?;
    session.last_backend = Some(mode);
    Ok(session)
}
/// Logging accepts only static allowlisted event descriptions, never password/error payloads.
fn log_event(session: &Path, message: &'static str) -> Result<()> {
    let session_guard = storage::guard(session)?;
    let session = session_guard.path();
    let logs = session.join("logs");
    if !storage::exists(&logs)? {
        storage::create_directory(&logs, false)?;
        storage::private(&logs)?;
    }
    real_directory(&logs)?;
    let path = logs.join("events.log");
    let mut text = if storage::exists(&path)? {
        String::from_utf8(storage::read_bytes(&path)?)?
    } else {
        String::new()
    };
    if text.len() > 256 * 1024 {
        text.clear();
    }
    text.push_str(&format!("{} {message}\n", now()));
    storage::write_bytes(&path, text.as_bytes(), true)
}
pub fn save_settings(data: &Path, settings: &Settings) -> Result<()> {
    settings.validate()?;
    create_root(data)?;
    storage::write_json(&data.join("settings.json"), settings, true)
}
pub fn read_settings(data: &Path) -> Result<Settings> {
    let data_guard = storage::guard(data)?;
    let data = data_guard.path();
    let mut settings: Settings = if storage::exists(&data.join("settings.json"))? {
        let mut value: serde_json::Value = storage::read_json(&data.join("settings.json"))?;
        if let Some(fields) = value.as_object_mut()
            && let Some(retired) = fields.remove("batched")
        {
            ensure!(retired.is_boolean(), "invalid retired batching preference");
        }
        serde_json::from_value(value)?
    } else {
        Settings::defaults(data)
    };
    settings.validate()?;
    // Upgrade the prior stock preset once; retain every custom batch choice.
    if settings.schema == 1 && settings.batch_size == 32768 {
        settings.batch_size = 4_194_304;
    }
    settings.schema = 3;
    Ok(settings)
}
/// Only a direct child of the configured root can be removed, after typed confirmation.
/// Reject every symlink/junction, including descendants, before recursive removal.
pub fn remove_session(root: &Path, directory: &Path, confirmation: &str) -> Result<()> {
    let root_guard = storage::read_guard(root)?;
    let root = root_guard.path();
    let target_guard = storage::read_guard(directory)?;
    let target = target_guard.path().to_owned();
    let directory = target.as_path();
    ensure!(
        confirmation == "DELETE",
        "type DELETE to confirm permanent session removal"
    );
    real_directory(root)?;
    real_directory(directory)?;
    let canonical = root.canonicalize()?;
    let canonical_target = directory.canonicalize()?;
    ensure!(
        canonical_target.parent() == Some(canonical.as_path()),
        "session must be a direct child of the configured session folder"
    );
    let _session = load_session(&target)?;
    let _lock = storage::lock_session(&target)?;
    let mut queue = vec![target.clone()];
    let mut count = 0;
    while let Some(path) = queue.pop() {
        let read_guard = storage::read_guard(&path)?;
        for item in fs::read_dir(read_guard.path())? {
            let item = item?;
            let m = fs::symlink_metadata(item.path())?;
            count += 1;
            ensure!(
                count <= 4096 && !m.file_type().is_symlink(),
                "session has unsafe or excessive contents"
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                ensure!(
                    m.file_attributes() & 0x400 == 0,
                    "session contains a reparse point"
                );
            }
            if m.is_dir() {
                queue.push(item.path());
            } else {
                ensure!(m.is_file(), "unsupported session file");
            }
        }
    }
    // Keep the parent pinned. std's recursive remover does not follow reparse
    // points, and must be allowed to remove the target directory itself.
    drop(target_guard);
    fs::remove_dir_all(target)?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Hardware {
    pub cpu: String,
    pub devices: Vec<opencl::DeviceInfo>,
    pub warning: Option<String>,
}
pub fn hardware() -> Hardware {
    let cpu = cpu_info();
    let (devices, warning) = match opencl::discover() {
        Ok(d) => (d, None),
        Err(e) => (vec![], Some(format!("{e:#}"))),
    };
    Hardware {
        cpu: format!(
            "{} · {} logical processors · {}",
            cpu.model,
            cpu.logical_processors,
            cpu.instruction_sets.join(", ")
        ),
        devices,
        warning,
    }
}
enum Outcome {
    Created(Session, Option<Zeroizing<String>>, Box<Config>),
    OwnerCreated(Session),
    SplitImported(Session),
    PublicFileSaved(PathBuf),
    Searched(Progress),
    Unlocked(Zeroizing<String>),
    Exported(Receipt),
    ExistingVerified,
    NativeExported(PathBuf),
    History(Vec<Session>, usize),
    Hardware(Hardware),
    Settings,
    Diagnostic(String, Option<f64>),
    Deleted(uuid::Uuid),
}
type TaskResult = std::result::Result<Outcome, String>;
struct CalibrationActivity(Arc<AtomicBool>);
impl Drop for CalibrationActivity {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}
struct CalibrationObserver {
    active: Arc<AtomicBool>,
    status: mpsc::SyncSender<String>,
    result: mpsc::SyncSender<(String, serde_json::Value)>,
    cancel: Arc<AtomicBool>,
    skip: Arc<AtomicBool>,
    mode: TuningMode,
    force: bool,
}
impl CalibrationObserver {
    fn attach(&self, config: &mut Config) {
        config.calibration_cancel = Some(self.cancel.clone());
        config.calibration_skip = Some(self.skip.clone());
        config.calibration_active = Some(self.active.clone());
        config.calibration_status = Some(self.status.clone());
    }
    fn resolve(
        &self,
        config: &mut Config,
        pattern: &Pattern,
        fixed_strategy: Option<SearchStrategy>,
    ) -> Result<calibration::Summary> {
        self.attach(config);
        let _activity = CalibrationActivity(self.active.clone());
        let notify = |status| {
            let _ = self.status.try_send(status);
        };
        let summary = if self.force {
            calibration::retune(
                config,
                pattern,
                fixed_strategy,
                self.mode,
                self.cancel.clone(),
                self.skip.clone(),
                notify,
            )?
        } else {
            calibration::resolve(
                config,
                pattern,
                fixed_strategy,
                self.mode,
                self.cancel.clone(),
                self.skip.clone(),
                notify,
            )?
        };
        let _ = self
            .result
            .try_send((summary.origin.clone(), summary.diagnostics.clone()));
        Ok(summary)
    }
}
pub struct Controller {
    pub state: State,
    pub settings: Settings,
    pub data: PathBuf,
    pub session: Option<Session>,
    pub progress: Option<Progress>,
    pub history: Vec<Session>,
    pub hardware: Option<Hardware>,
    pub error: Option<String>,
    pub notice: String,
    pub diagnostic: String,
    pub execution_origin: String,
    pub execution_diagnostics: String,
    pub unlocked_password: Option<Zeroizing<String>>,
    search_password: Option<Zeroizing<String>>,
    pub verified_this_run: bool,
    task: Option<mpsc::Receiver<TaskResult>>,
    stats: Option<mpsc::Receiver<Progress>>,
    calibration_status: Option<mpsc::Receiver<String>>,
    calibration_result: Option<mpsc::Receiver<(String, serde_json::Value)>>,
    calibration_active: Arc<AtomicBool>,
    skip_tuning: Arc<AtomicBool>,
    prepared_config: Option<Config>,
    cancel: Arc<AtomicBool>,
    auto_start: bool,
    stopped: bool,
}
impl Controller {
    pub fn new(data: PathBuf) -> Self {
        let (settings, error) = match read_settings(&data) {
            Ok(s) => (s, None),
            Err(e) => (
                Settings::defaults(&data),
                Some(format!("Preferences could not be loaded: {e:#}")),
            ),
        };
        Self {
            state: State::Idle,
            settings,
            data,
            session: None,
            progress: None,
            history: vec![],
            hardware: None,
            error,
            notice: String::new(),
            diagnostic: String::new(),
            execution_origin: String::new(),
            execution_diagnostics: String::new(),
            unlocked_password: None,
            search_password: None,
            verified_this_run: false,
            task: None,
            stats: None,
            calibration_status: None,
            calibration_result: None,
            calibration_active: Arc::new(AtomicBool::new(false)),
            skip_tuning: Arc::new(AtomicBool::new(false)),
            prepared_config: None,
            cancel: Arc::new(AtomicBool::new(false)),
            auto_start: false,
            stopped: false,
        }
    }
    pub fn busy(&self) -> bool {
        self.task.is_some()
    }
    pub fn calibrating(&self) -> bool {
        self.calibration_active.load(Ordering::Relaxed)
    }
    pub fn skip_calibration(&self) {
        self.skip_tuning.store(true, Ordering::Relaxed);
    }
    pub fn stop_calibration(&mut self) {
        self.auto_start = false;
        self.stopped = true;
        self.cancel.store(true, Ordering::Relaxed);
        self.notice = "Stopping calibration. Waiting for the owned worker to exit.".into();
    }
    fn calibration_observer(&mut self, mode: TuningMode, force: bool) -> CalibrationObserver {
        let (status, status_rx) = mpsc::sync_channel(4);
        let (result, result_rx) = mpsc::sync_channel(1);
        self.calibration_status = Some(status_rx);
        self.calibration_result = Some(result_rx);
        self.calibration_active = Arc::new(AtomicBool::new(true));
        self.skip_tuning = Arc::new(AtomicBool::new(false));
        self.execution_origin.clear();
        self.execution_diagnostics.clear();
        self.notice = "Checking this hardware and its validated calibration cache.".into();
        CalibrationObserver {
            active: self.calibration_active.clone(),
            status,
            result,
            cancel: self.cancel.clone(),
            skip: self.skip_tuning.clone(),
            mode,
            force,
        }
    }
    fn launch(&mut self, action: impl FnOnce() -> Result<Outcome> + Send + 'static) -> Result<()> {
        ensure!(!self.busy(), "another operation is still running");
        let (tx, rx) = mpsc::channel();
        self.task = Some(rx);
        self.error = None;
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
                .map_err(|_| "Operation failed unexpectedly; session data is retained".to_owned())
                .and_then(|r| r.map_err(|e| format!("{e:#}")));
            let _ = tx.send(result);
        });
        Ok(())
    }
    pub fn create(
        &mut self,
        input: &str,
        password: Zeroizing<String>,
        confirmation: &str,
    ) -> Result<()> {
        ensure!(
            !self.busy()
                && matches!(
                    self.state,
                    State::Idle
                        | State::Paused
                        | State::MatchFound
                        | State::Completed
                        | State::Error
                ),
            "cannot create a session now"
        );
        validate_password(&password, confirmation)?;
        let pattern = Pattern::for_profile(self.settings.profile, input.trim(), "")?;
        self.settings.validate()?;
        self.prepared_config = None;
        let root = self.settings.sessions_root.clone();
        let mode = self.settings.mode;
        let mut config = self.settings.config();
        config.tuning_cache = Some(self.data.join("Calibration"));
        self.cancel = Arc::new(AtomicBool::new(false));
        let calibration = self.calibration_observer(self.settings.tuning, false);
        let cancel = self.cancel.clone();
        self.launch(move || {
            let ed = pattern.profile.key_family() == crate::chains::KeyFamily::Ed25519;
            let selected = calibration.resolve(&mut config, &pattern, None)?;
            ensure!(
                !cancel.load(Ordering::Relaxed),
                "Session creation cancelled"
            );
            let session =
                create_session_with_strategy(&root, pattern, &password, mode, selected.strategy)?;
            Ok(Outcome::Created(
                session,
                if ed { Some(password) } else { None },
                Box::new(config),
            ))
        })?;
        self.state = State::CreatingSession;
        self.auto_start = true;
        self.progress = None;
        self.unlocked_password = None;
        self.search_password = None;
        self.verified_this_run = false;
        Ok(())
    }
    pub fn search_with_password(&mut self, password: Zeroizing<String>) -> Result<()> {
        self.search_password = Some(password);
        let result = self.search();
        if result.is_err() {
            self.search_password = None;
        }
        result
    }
    pub fn create_split_request(
        &mut self,
        input: &str,
        password: Zeroizing<String>,
        confirmation: &str,
    ) -> Result<()> {
        ensure!(
            !self.busy() && self.state != State::Finalizing,
            "Complete the current operation first."
        );
        validate_password(&password, confirmation)?;
        self.settings.validate()?;
        let pattern = Pattern::for_profile(self.settings.profile, input.trim(), "")?;
        ensure!(!pattern.prefix.is_empty(), "Enter an address prefix.");
        ensure!(
            pattern.profile.key_family() == crate::chains::KeyFamily::Secp256k1,
            "Split-key search is unavailable for this address type."
        );
        let root = self.settings.sessions_root.clone();
        let mode = self.settings.mode;
        self.launch(move || {
            let directory = split_session_directory(&root, &pattern)?;
            split::create_request(&directory, pattern, &password)?;
            Ok(Outcome::OwnerCreated(finish_split_session(
                &directory,
                mode,
                "Encrypted private share created",
            )?))
        })?;
        self.auto_start = false;
        self.prepared_config = None;
        self.progress = None;
        self.unlocked_password = None;
        self.search_password = None;
        self.verified_this_run = false;
        self.state = State::CreatingSession;
        self.notice =
            "The application saves the encrypted private share. No search starts on this computer."
                .into();
        Ok(())
    }
    pub fn start_split_worker(&mut self, request: SplitRequest) -> Result<()> {
        ensure!(
            !self.busy() && self.state != State::Finalizing,
            "Complete the current operation first."
        );
        request.validate()?;
        self.settings.validate()?;
        self.settings.profile = request.job.profile();
        let mut config = self.settings.config();
        config.tuning_cache = Some(self.data.join("Calibration"));
        let root = self.settings.sessions_root.clone();
        let mode = self.settings.mode;
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let calibration = self.calibration_observer(self.settings.tuning, false);
        self.launch(move || {
            let selected = calibration.resolve(&mut config, &request.job.pattern, None)?;
            ensure!(!cancel.load(Ordering::Relaxed), "Search cancelled.");
            let directory = split_session_directory(&root, &request.job.pattern)?;
            split::create_worker(&directory, &request, selected.strategy)?;
            let session =
                finish_split_session(&directory, mode, "Public split-key worker session created")?;
            Ok(Outcome::Created(session, None, Box::new(config)))
        })?;
        self.auto_start = true;
        self.prepared_config = None;
        self.progress = None;
        self.unlocked_password = None;
        self.search_password = None;
        self.verified_this_run = false;
        self.state = State::CreatingSession;
        Ok(())
    }
    pub fn save_split_request(&mut self, output: PathBuf) -> Result<()> {
        let session = self.session.as_ref().context("Select an owner session.")?;
        ensure!(
            session.kind == SessionKind::Owner,
            "Select an owner session."
        );
        let directory = session.directory.clone();
        self.launch(move || {
            split::export_request(&directory, &output)?;
            Ok(Outcome::PublicFileSaved(output))
        })
    }
    pub fn save_split_result(&mut self, output: PathBuf) -> Result<()> {
        let session = self.session.as_ref().context("Select a helper session.")?;
        ensure!(
            session.kind == SessionKind::Worker,
            "Select a helper session."
        );
        let directory = session.directory.clone();
        self.launch(move || {
            split::export_result(&directory, &output)?;
            Ok(Outcome::PublicFileSaved(output))
        })
    }
    pub fn import_split_result(&mut self, path: PathBuf) -> Result<()> {
        ensure!(
            self.state != State::Finalizing,
            "Complete the wallet operation first."
        );
        let session = self.session.as_ref().context("Select an owner session.")?;
        ensure!(
            session.kind == SessionKind::Owner,
            "Select an owner session."
        );
        let directory = session.directory.clone();
        self.launch(move || {
            let result = split::read_result(&path)?;
            split::import_result(&directory, &result)?;
            let _ = log_event(&directory, "Public split-key result imported");
            Ok(Outcome::SplitImported(load_session(&directory)?))
        })?;
        self.unlocked_password = None;
        self.verified_this_run = false;
        Ok(())
    }
    pub fn search(&mut self) -> Result<()> {
        ensure!(
            !self.busy() && matches!(self.state, State::Paused | State::Error),
            "session cannot be searched in this state"
        );
        let session = self
            .session
            .as_ref()
            .context("no selected session")?
            .clone();
        ensure!(
            session.kind != SessionKind::Owner,
            "Import the request on a helper computer to start the search."
        );
        self.settings.validate()?;
        let prepared_config = self.prepared_config.take();
        let requires_calibration = prepared_config.is_none();
        let mut config = prepared_config.unwrap_or_else(|| self.settings.config());
        config.profile = Some(session.job.profile());
        let ed = session.job.profile().key_family() == crate::chains::KeyFamily::Ed25519;
        ensure!(
            !ed || self.search_password.is_some(),
            "enter the session password to resume Ed25519 CPU generation"
        );
        let search_password = self.search_password.take();
        config.tuning_cache = Some(self.data.join("Calibration"));
        let (tx, rx) = mpsc::sync_channel(4);
        config.progress = Some(tx);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        // Rebind a prepared plan to this search's UI controls, including any later CPU fallback.
        let already_skipped = !requires_calibration
            && config
                .calibration_skip
                .as_ref()
                .is_some_and(|skip| skip.load(Ordering::Relaxed));
        let calibration = self.calibration_observer(self.settings.tuning, false);
        calibration.attach(&mut config);
        if !requires_calibration {
            self.calibration_active.store(false, Ordering::Relaxed);
            self.skip_tuning.store(already_skipped, Ordering::Relaxed);
            if let Some(diagnostics) = &config.calibration {
                self.execution_origin = diagnostics["origin"]
                    .as_str()
                    .unwrap_or("selected configuration")
                    .into();
                self.execution_diagnostics = serde_json::to_string_pretty(diagnostics)
                    .unwrap_or_else(|_| diagnostics.to_string());
            }
        }
        let mode = config.mode;
        self.launch(move || {
            let current = load_session(&session.directory)?;
            ensure!(
                current.address.is_none(),
                "session already has a verified match"
            );
            if requires_calibration {
                let summary = calibration.resolve(
                    &mut config,
                    &current.job.pattern,
                    Some(current.job.strategy),
                )?;
                ensure!(
                    summary.strategy == current.job.strategy,
                    "Calibration changed the saved enumeration strategy"
                );
            }
            ensure!(!cancel.load(Ordering::Relaxed), "Search cancelled");
            let _lock = storage::lock_session(&session.directory)?;
            storage::write_json(
                &session.directory.join("gui-session.json"),
                &metadata_for(&current, mode),
                true,
            )?;
            drop(_lock);
            let _ = log_event(&session.directory, "Search started");
            let result = if ed {
                crate::search_ed25519(
                    &session.directory.join("job.json"),
                    &config,
                    cancel,
                    search_password
                        .as_deref()
                        .map(|s| s.as_str())
                        .context("missing session password")?,
                )
            } else {
                coordinator::search(&session.directory.join("job.json"), &config, cancel)
            };
            let _ = log_event(
                &session.directory,
                if result.is_ok() {
                    "Search stopped with recoverable progress"
                } else {
                    "Search error; durable session retained"
                },
            );
            Ok(Outcome::Searched(result?))
        })?;
        self.stats = Some(rx);
        // A resumed search must not display a prior run as already active while calibrating.
        self.progress = None;
        self.state = State::Searching;
        self.notice = "Device check in progress.".into();
        self.stopped = false;
        Ok(())
    }
    pub fn pause(&mut self, stop: bool) -> Result<()> {
        ensure!(self.state == State::Searching, "search is not running");
        self.stopped = stop;
        self.cancel.store(true, Ordering::Relaxed);
        self.state = State::Pausing;
        self.notice =
            "Wait for the application to complete the batch and save the checkpoint.".into();
        Ok(())
    }
    pub fn select_session(&mut self, session: Session) -> Result<()> {
        ensure!(!self.busy(), "wait for the active operation to finish");
        self.state = session.state;
        self.session = Some(session);
        self.progress = None;
        self.error = None;
        self.unlocked_password = None;
        self.search_password = None;
        self.verified_this_run = false;
        self.prepared_config = None;
        Ok(())
    }
    pub fn refresh_history(&mut self) -> Result<()> {
        let root = self.settings.sessions_root.clone();
        self.launch(move || {
            let (s, n) = discover_sessions(&root)?;
            Ok(Outcome::History(s, n))
        })
    }
    pub fn detect_hardware(&mut self) -> Result<()> {
        self.launch(|| Ok(Outcome::Hardware(hardware())))
    }
    pub fn unlock(&mut self, password: Zeroizing<String>) -> Result<()> {
        ensure!(
            matches!(self.state, State::MatchFound | State::Completed),
            "no public candidate to finalize"
        );
        ensure!(
            self.session
                .as_ref()
                .is_some_and(|session| session.kind != SessionKind::Worker),
            "A helper cannot save the owner's wallet."
        );
        let directory = self
            .session
            .as_ref()
            .context("no session")?
            .directory
            .clone();
        self.launch(move || {
            crate::validate_finalization_password(&directory, &password)?;
            Ok(Outcome::Unlocked(password))
        })?;
        self.state = State::Finalizing;
        Ok(())
    }
    pub fn export(
        &mut self,
        output: PathBuf,
        password: Zeroizing<String>,
        confirmation: &str,
    ) -> Result<()> {
        ensure!(
            !self.busy() && self.state == State::Finalizing,
            "unlock the seed before exporting"
        );
        validate_password(&password, confirmation)?;
        let _output_guard = storage::guard(&output)?;
        ensure!(
            output.is_absolute() && !storage::exists(&output)?,
            "choose a new wallet filename with an absolute path"
        );
        let directory = self
            .session
            .as_ref()
            .context("no session")?
            .directory
            .clone();
        let seed = self
            .unlocked_password
            .take()
            .context("unlock the session first")?;
        self.launch(move || {
            let address = crate::finalize(&directory, &output, &seed, &password)?;
            let verified = crate::verify_wallet(&output, &password, None)?;
            ensure!(
                address == verified,
                "exported wallet independent verification failed"
            );
            let receipt = Receipt {
                address,
                wallet: output,
            };
            let _lock = storage::lock_session(&directory)?;
            let current = load_session(&directory)?;
            let mut meta = metadata_for(&current, current.last_backend.unwrap_or(Mode::Auto));
            meta.receipt = Some(receipt.clone());
            // An encrypted, verified wallet stays successful even if a public receipt/log cannot be saved.
            let _ = storage::write_json(&directory.join("gui-session.json"), &meta, true);
            let _ = log_event(
                &directory,
                "Encrypted wallet exported and independently verified",
            );
            Ok(Outcome::Exported(receipt))
        })?;
        Ok(())
    }
    pub fn export_native_wallet(
        &mut self,
        output: PathBuf,
        password: Zeroizing<String>,
    ) -> Result<()> {
        ensure!(
            !self.busy() && self.state == State::Completed,
            "select a finalized wallet first"
        );
        let session = self.session.as_ref().context("no selected session")?;
        let receipt = session
            .receipt
            .as_ref()
            .context("no finalized wallet")?
            .clone();
        self.launch(move || {
            let address = crate::export_native(&receipt.wallet, &password, &output)?;
            ensure!(address == receipt.address, "native export address mismatch");
            Ok(Outcome::NativeExported(output))
        })
    }
    pub fn cancel_finalization(&mut self) {
        if !self.busy() {
            self.unlocked_password = None;
            self.search_password = None;
            self.state = self.session.as_ref().map_or(State::Idle, |s| {
                if s.receipt.is_some() {
                    State::Completed
                } else if s.address.is_some() {
                    State::MatchFound
                } else {
                    State::Paused
                }
            });
        }
    }
    pub fn verify_saved_wallet(&mut self, password: Zeroizing<String>) -> Result<()> {
        ensure!(
            !self.busy() && self.state == State::Completed,
            "select a previously exported wallet first"
        );
        let session = self
            .session
            .as_ref()
            .context("no selected session")?
            .clone();
        let receipt = session
            .receipt
            .as_ref()
            .context("no saved wallet record")?
            .clone();
        self.verified_this_run = false;
        self.launch(move || {
            let actual =
                crate::verify_wallet(&receipt.wallet, &password, Some(&session.job.pattern))?;
            ensure!(
                Some(&actual) == session.address.as_ref(),
                "saved wallet does not correspond to the verified session match"
            );
            let _ = log_event(
                &session.directory,
                "Saved encrypted wallet independently verified",
            );
            Ok(Outcome::ExistingVerified)
        })?;
        self.state = State::Finalizing;
        Ok(())
    }
    pub fn save_preferences(&mut self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let data = self.data.clone();
        let copy = settings.clone();
        self.launch(move || {
            save_settings(&data, &copy)?;
            Ok(Outcome::Settings)
        })?;
        self.settings = settings;
        Ok(())
    }
    pub fn benchmark(&mut self, config: Config) -> Result<()> {
        self.benchmark_with_intervals(config, 3.0, 1.0)
    }
    fn benchmark_with_intervals(
        &mut self,
        mut config: Config,
        seconds: f64,
        warmup: f64,
    ) -> Result<()> {
        config.profile = Some(self.settings.profile);
        if let Some(session) = self
            .session
            .as_ref()
            .filter(|session| session.job.profile() == self.settings.profile)
        {
            config.benchmark_strategy = Some(session.job.strategy);
            config.benchmark_pattern = Some(session.job.pattern.clone());
        }
        ensure!(!self.busy(), "another operation is still running");
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        config.max_seconds = None;
        config.tuning_cache = Some(self.data.join("Calibration"));
        let pattern = self.diagnostic_pattern(self.settings.profile)?;
        let fixed_strategy = config.benchmark_strategy;
        let calibration = self.calibration_observer(self.settings.tuning, false);
        self.launch(move || {
            calibration.resolve(&mut config, &pattern, fixed_strategy)?;
            ensure!(!cancel.load(Ordering::Relaxed), "Benchmark cancelled");
            let report = coordinator::benchmark(&config, seconds, warmup, 1, cancel)?;
            let runs = report["measurements"]
                .as_array()
                .context("invalid benchmark result")?;
            let count: f64 = runs
                .iter()
                .filter_map(|r| r["runs"][0]["candidates"].as_f64())
                .sum();
            let duration = runs
                .iter()
                .filter_map(|r| r["runs"][0]["seconds"].as_f64())
                .fold(0.0, f64::max);
            Ok(Outcome::Diagnostic(
                serde_json::to_string_pretty(&report)?,
                Some(count / duration.max(1e-9)),
            ))
        })
    }
    pub fn recalibrate(&mut self, settings: &Settings) -> Result<()> {
        ensure!(
            self.state != State::Finalizing,
            "Complete the wallet operation first."
        );
        settings.validate()?;
        self.retune(settings.config())
    }
    fn diagnostic_pattern(&self, profile: crate::chains::Profile) -> Result<Pattern> {
        self.session
            .as_ref()
            .filter(|session| session.job.profile() == profile)
            .map(|session| Ok(session.job.pattern.clone()))
            .unwrap_or_else(|| {
                // Use a valid public fixture, including native-key address formats.
                let address = profile.diagnostic_address()?;
                Pattern::for_profile(profile, &address, "")
            })
    }
    fn retune(&mut self, mut config: Config) -> Result<()> {
        ensure!(!self.busy(), "another operation is still running");
        let pattern = self.diagnostic_pattern(config.profile.unwrap_or(self.settings.profile))?;
        let fixed_strategy = self
            .session
            .as_ref()
            .filter(|session| session.job.profile() == pattern.profile)
            .map(|session| session.job.strategy);
        config.max_seconds = None;
        config.tuning_cache = Some(self.data.join("Calibration"));
        self.cancel = Arc::new(AtomicBool::new(false));
        let calibration = self.calibration_observer(TuningMode::Auto, true);
        self.diagnostic = "Calibrating the selected hardware. Skip tuning keeps the self-tested incumbent; Stop cancels the operation.".into();
        self.launch(move || {
            let report = calibration.resolve(&mut config, &pattern, fixed_strategy)?;
            Ok(Outcome::Diagnostic(
                if report.origin == "standard Ed25519 implementation" {
                    "The standard Ed25519 implementation is selected. Calibration is not necessary."
                        .into()
                } else {
                    serde_json::to_string_pretty(&report.diagnostics)?
                },
                None,
            ))
        })
    }
    pub fn cancel_diagnostic(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
    pub fn logs(&mut self) -> Result<()> {
        let path = self
            .session
            .as_ref()
            .context("no selected session")?
            .directory
            .join("logs/events.log");
        self.launch(move || {
            Ok(Outcome::Diagnostic(
                if storage::exists(&path)? {
                    String::from_utf8(storage::read_bytes(&path)?)?
                } else {
                    "No GUI events recorded for this session.".into()
                },
                None,
            ))
        })
    }
    pub fn delete(&mut self, directory: PathBuf, confirmation: &str) -> Result<()> {
        ensure!(confirmation == "DELETE", "type DELETE to confirm");
        ensure!(
            self.state != State::Finalizing,
            "complete the wallet operation before deleting a session"
        );
        let root = self.settings.sessions_root.clone();
        self.launch(move || {
            let session_id = load_session(&directory)?.job.session_id;
            remove_session(&root, &directory, "DELETE")?;
            Ok(Outcome::Deleted(session_id))
        })
    }
    pub fn poll(&mut self) {
        if let Some(rx) = &self.calibration_status {
            while let Ok(status) = rx.try_recv() {
                if self.calibrating() {
                    self.notice = status.clone();
                    self.diagnostic = status;
                    self.execution_origin.clear();
                    self.execution_diagnostics.clear();
                }
            }
        }
        if let Some(rx) = &self.calibration_result {
            while let Ok((origin, diagnostics)) = rx.try_recv() {
                self.execution_origin = origin;
                self.execution_diagnostics = serde_json::to_string_pretty(&diagnostics)
                    .unwrap_or_else(|_| diagnostics.to_string());
            }
        }
        if let Some(rx) = &self.stats {
            while let Ok(p) = rx.try_recv() {
                if let Some(diagnostics) = p
                    .workers
                    .iter()
                    .map(|worker| &worker.diagnostics["calibration"])
                    .find(|diagnostics| diagnostics.is_object())
                {
                    self.execution_origin = diagnostics["origin"]
                        .as_str()
                        .unwrap_or("selected configuration")
                        .into();
                    self.execution_diagnostics = serde_json::to_string_pretty(diagnostics)
                        .unwrap_or_else(|_| diagnostics.to_string());
                }
                self.progress = Some(p);
                self.notice = "Search active.".into();
            }
        }
        let result = self.task.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(r) => Some(r),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                "Background worker disconnected; session data is retained".into(),
            )),
            Err(mpsc::TryRecvError::Empty) => None,
        });
        let Some(result) = result else { return };
        self.task = None;
        self.calibration_status = None;
        self.calibration_result = None;
        self.calibration_active.store(false, Ordering::Relaxed);
        match result {
            Err(error) => {
                self.error = Some(error);
                self.auto_start = false;
                self.unlocked_password = None;
                self.search_password = None;
                self.prepared_config = None;
                if matches!(
                    self.state,
                    State::Searching | State::Pausing | State::CreatingSession
                ) {
                    self.state = State::Error;
                } else if let Some(s) = &self.session {
                    self.state = load_session(&s.directory).map_or(State::Error, |s| s.state);
                } else {
                    self.state = State::Error;
                }
            }
            Ok(Outcome::Created(s, password, config)) => {
                self.search_password = password;
                self.prepared_config = Some(*config);
                self.state = State::Paused;
                self.session = Some(s);
                if self.auto_start {
                    self.auto_start = false;
                    if let Err(e) = self.search() {
                        self.error = Some(format!("{e:#}"));
                    }
                }
            }
            Ok(Outcome::OwnerCreated(session)) => {
                self.state = session.state;
                self.session = Some(session);
                self.prepared_config = None;
                self.notice = "Private share saved. Select Save public request to make the file for the helper.".into();
            }
            Ok(Outcome::SplitImported(session)) => {
                self.state = session.state;
                self.session = Some(session);
                self.progress = None;
                self.prepared_config = None;
                self.verified_this_run = false;
                self.notice = "Public result imported. Select Combine and save wallet to do the key ownership check.".into();
            }
            Ok(Outcome::PublicFileSaved(path)) => {
                self.notice = format!("Public file saved to {}.", path.display());
            }
            Ok(Outcome::Searched(p)) => {
                self.state = if p.candidate.is_some() {
                    State::MatchFound
                } else {
                    State::Paused
                };
                self.progress = Some(p);
                self.stats = None;
                if let Some(s) = &self.session
                    && let Ok(s) = load_session(&s.directory)
                {
                    self.session = Some(s);
                }
                let worker = self
                    .session
                    .as_ref()
                    .is_some_and(|s| s.kind == SessionKind::Worker);
                self.notice = if self.state == State::MatchFound && worker {
                    "Public match found. Select Save search result to make the file for the owner."
                } else if self.state == State::MatchFound {
                    "Match found. Select Save wallet to do the key ownership check."
                } else if self.stopped {
                    "Stopped. The session is available. Select Resume to continue."
                } else if worker {
                    "Search paused. The application keeps the public request and progress."
                } else {
                    "Search paused. The application keeps the encrypted seed and progress."
                }
                .into();
            }
            Ok(Outcome::Unlocked(p)) => {
                self.unlocked_password = Some(p);
                self.state = State::Finalizing;
                self.notice = if self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.kind == SessionKind::Owner)
                {
                    "The application unlocked the private share and calculated the wallet address."
                } else {
                    "The application unlocked the seed and calculated the wallet address."
                }
                .into();
            }
            Ok(Outcome::Exported(r)) => {
                self.state = State::Completed;
                self.verified_this_run = true;
                if let Some(s) = &mut self.session {
                    s.receipt = Some(r);
                    s.state = State::Completed;
                }
                self.notice = "Wallet saved. Wallet check: correct.".into();
            }
            Ok(Outcome::NativeExported(path)) => {
                let encrypted = path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| {
                        ["db", "db3", "sqlite"]
                            .iter()
                            .any(|name| extension.eq_ignore_ascii_case(name))
                    });
                self.notice = if encrypted {
                    format!("Encrypted Wart Dapp database saved to {}.", path.display())
                } else {
                    format!(
                        "Native import file saved to {}. This file contains the unencrypted private key.",
                        path.display()
                    )
                };
            }
            Ok(Outcome::ExistingVerified) => {
                self.verified_this_run = true;
                self.state = State::Completed;
                self.notice = "Saved wallet check: correct.".into();
            }
            Ok(Outcome::History(s, n)) => {
                self.history = s;
                if n > 0 {
                    self.notice = format!("The application cannot read {n} session folders.");
                }
            }
            Ok(Outcome::Hardware(h)) => self.hardware = Some(h),
            Ok(Outcome::Settings) => {
                self.notice = "Preferences saved. The preferences do not contain passwords.".into()
            }
            Ok(Outcome::Diagnostic(t, rate)) => {
                self.diagnostic = t;
                if let Some(r) = rate {
                    self.settings.benchmark_per_second = Some(r);
                    let _ = save_settings(&self.data, &self.settings);
                }
            }
            Ok(Outcome::Deleted(session_id)) => {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.job.session_id == session_id)
                {
                    self.session = None;
                    self.progress = None;
                    self.state = State::Idle;
                    self.unlocked_password = None;
                    self.search_password = None;
                    self.verified_this_run = false;
                }
                self.history
                    .retain(|session| session.job.session_id != session_id);
                self.notice = "Session deleted.".into();
                let _ = self.refresh_history();
            }
        }
        if let Some(s) = self.session.clone() {
            self.history
                .retain(|old| old.job.session_id != s.job.session_id);
            self.history.insert(0, s);
        }
    }
    pub fn shutdown(&mut self) {
        self.auto_start = false;
        self.cancel.store(true, Ordering::Relaxed);
        self.unlocked_password = None;
        self.search_password = None;
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod calibration_ui_tests {
    use super::*;

    #[test]
    fn diagnostic_benchmarks_without_a_session_use_valid_native_public_addresses() {
        use crate::chains::{AddressType, Chain, Profile};
        for profile in [
            Profile::new(Chain::Solana, None).unwrap(),
            Profile::new(Chain::Stellar, None).unwrap(),
            Profile::new(Chain::Algorand, None).unwrap(),
            Profile::new(Chain::Bitcoin, Some(AddressType::P2tr)).unwrap(),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut controller = Controller::new(temp.path().to_owned());
            controller.settings.profile = profile;
            controller.settings.mode = Mode::Cpu;
            controller.settings.threads = 1;
            controller.settings.batch_size = 64;
            controller.settings.tuning = TuningMode::Off;
            assert!(controller.session.is_none());
            controller
                .benchmark_with_intervals(controller.settings.config(), 0.01, 0.0)
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while controller.busy() {
                controller.poll();
                assert!(
                    std::time::Instant::now() < deadline,
                    "{} benchmark timed out",
                    profile.chain.label()
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            assert!(
                controller.error.is_none(),
                "{}: {:?}",
                profile.chain.label(),
                controller.error
            );
            let report: serde_json::Value = serde_json::from_str(&controller.diagnostic).unwrap();
            assert_eq!(report["profile"], serde_json::to_value(profile).unwrap());
            assert!(
                report["measurements"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|measurement| measurement["runs"][0]["candidates"]
                        .as_f64()
                        .is_some_and(|count| count > 0.0))
            );
            assert!(
                controller
                    .settings
                    .benchmark_per_second
                    .is_some_and(|rate| rate.is_finite() && rate > 0.0)
            );
            assert!(controller.session.is_none());
        }
    }

    #[test]
    fn retired_batching_preference_keeps_optimized_operation_and_other_preferences() {
        let temp = tempfile::tempdir().unwrap();
        let mut settings = Settings::defaults(temp.path());
        settings.threads = 16;
        settings.excluded_devices = vec![1];
        settings.batch_size = 32_768;
        settings.max_seconds = Some(60.0);
        let mut value = serde_json::to_value(&settings).unwrap();
        assert!(value.get("batched").is_none());
        value["batched"] = serde_json::json!(false);
        storage::write_json(&temp.path().join("settings.json"), &value, false).unwrap();
        let migrated = read_settings(temp.path()).unwrap();
        assert!(migrated.config().batched);
        assert_eq!(migrated.threads, 16);
        assert_eq!(migrated.excluded_devices, vec![1]);
        assert_eq!(migrated.batch_size, 32_768);
        assert_eq!(migrated.max_seconds, Some(60.0));
        save_settings(temp.path(), &migrated).unwrap();
        let saved: serde_json::Value =
            storage::read_json(&temp.path().join("settings.json")).unwrap();
        assert!(saved.get("batched").is_none());
        value["password"] = serde_json::json!("unexpected preference");
        storage::write_json(&temp.path().join("settings.json"), &value, true).unwrap();
        assert!(read_settings(temp.path()).is_err());
    }

    #[test]
    fn skip_and_stop_are_separate_and_ui_updates_do_not_block_workers() {
        let temp = tempfile::tempdir().unwrap();
        let mut controller = Controller::new(temp.path().to_owned());
        let observer = controller.calibration_observer(TuningMode::Auto, false);
        assert!(controller.calibrating());
        controller.skip_calibration();
        assert!(observer.skip.load(Ordering::Relaxed));
        assert!(!observer.cancel.load(Ordering::Relaxed));
        for index in 0..4 {
            observer
                .status
                .try_send(format!("Screening configuration {index}"))
                .unwrap();
        }
        assert!(matches!(
            observer.status.try_send("Extra progress".into()),
            Err(mpsc::TrySendError::Full(_))
        ));
        observer
            .result
            .try_send((
                "validated local calibration cache".into(),
                serde_json::json!({"choice":{"strategy":"linear"}}),
            ))
            .unwrap();
        controller.poll();
        assert_eq!(controller.notice, "Screening configuration 3");
        assert_eq!(
            controller.execution_origin,
            "validated local calibration cache"
        );
        assert!(controller.execution_diagnostics.contains("linear"));
        controller.stop_calibration();
        assert!(observer.cancel.load(Ordering::Relaxed));
        assert!(!controller.auto_start);
        assert!(controller.session.is_none());
        // The activity guard closes the UI even when resolution returns early.
        drop(CalibrationActivity(observer.active.clone()));
        assert!(!controller.calibrating());
    }
}
