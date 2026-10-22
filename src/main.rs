#[cfg(feature = "developer-tools")]
use anyhow::Context as _;
use anyhow::{Result, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use vanity_pro::{
    backend::{
        Compute,
        cpu::Cpu,
        cpu_info,
        opencl::{self, Opencl},
    },
    chains::{AddressType, Chain, KeyFamily, Profile},
    coordinator::{self, Config, Mode},
    crypto::Pattern,
    split, storage,
};
use zeroize::Zeroizing;

fn finalize_command(
    session: &Path,
    out: &Path,
    mut prompt: impl FnMut(&str, bool) -> Result<Zeroizing<String>>,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let _session_guard = storage::guard(session)?;
    let _output_guard = storage::guard(out)?;
    ensure!(
        !storage::exists(out)?,
        "wallet output already exists; verify it instead of overwriting"
    );
    // Public consistency is useful preflight, but cannot prove private ownership.
    vanity_pro::check_finalization(session)?;
    let seed = prompt("Seed password: ", false)?;
    vanity_pro::validate_finalization_password(session, &seed)?;
    let wallet = prompt("New wallet encryption password: ", true)?;
    let addr = vanity_pro::finalize(session, out, &seed, &wallet)?;
    writeln!(
        output,
        "Verified wallet {addr} written to {}. Retain the encrypted seed backup.",
        out.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod finalization_tests {
    use super::*;
    fn completed_session(root: &Path, name: &str) -> PathBuf {
        let session = root.join(name);
        vanity_pro::initialize(
            &session,
            Pattern::new("a", "").unwrap(),
            "synthetic seed password",
        )
        .unwrap();
        coordinator::search(
            &session.join("job.json"),
            &coordinator::Config {
                mode: coordinator::Mode::Cpu,
                batch_size: 1,
                threads: 1,
                ..Default::default()
            },
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        session
    }
    #[test]
    fn no_verified_output_before_private_proof() {
        let temp = tempfile::tempdir().unwrap();
        let session = completed_session(temp.path(), "session");
        let out = temp.path().join("wallet.json");
        let mut output = vec![];
        let mut prompts = 0;
        assert!(
            finalize_command(
                &session,
                &out,
                |_, _| {
                    prompts += 1;
                    Ok(Zeroizing::new("wrong seed password".to_owned()))
                },
                &mut output
            )
            .is_err()
        );
        assert_eq!(prompts, 1);
        assert!(output.is_empty());
        assert!(!out.exists());
        let other = completed_session(temp.path(), "other");
        let substituted = storage::read_bytes(&other.join("seed.keystore.json")).unwrap();
        storage::write_bytes(&session.join("seed.keystore.json"), &substituted, true).unwrap();
        assert!(
            finalize_command(
                &session,
                &out,
                |_, _| Ok(Zeroizing::new("synthetic seed password".into())),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
        assert!(!out.exists());
        let mut count = 0;
        finalize_command(
            &other,
            &out,
            |_, _| {
                count += 1;
                Ok(Zeroizing::new(
                    if count == 1 {
                        "synthetic seed password"
                    } else {
                        "synthetic wallet password"
                    }
                    .into(),
                ))
            },
            &mut output,
        )
        .unwrap();
        let address = vanity_pro::verify_wallet(&out, "synthetic wallet password", None).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with(&format!("Verified wallet {address}")));
        assert!(!text.contains("Verified candidate"));
    }
}

#[derive(Parser)]
#[command(
    name = "vanity",
    version,
    about = "Offline multi-chain vanity wallets; compute workers receive public data only"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// List typed mainnet chain profiles and available key formats.
    Chains,
    /// List address types supported by a chain.
    AddressTypes {
        #[arg(long, value_enum)]
        chain: Chain,
    },
    /// Create a secure session and search. Finalize exports the encrypted wallet.
    Generate {
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        suffix: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        compute: ComputeArgs,
    },
    /// Create public requests, search requests, and combine split-key results.
    Split {
        #[command(subcommand)]
        action: SplitCommand,
    },
    /// Export a finalized wallet in its native format; Warthog .db is encrypted for Wart Dapp.
    ExportNative {
        #[arg(long, alias = "keystore")]
        wallet: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a fresh seed encrypted with an interactive password.
    Init {
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        suffix: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Enumerate CPU capabilities and OpenCL GPUs.
    Devices {
        #[arg(long)]
        self_test: bool,
        #[arg(long)]
        json: bool,
    },
    /// Run a public job until a match, cancellation, or a resource limit.
    Search {
        #[arg(long)]
        job: PathBuf,
        #[command(flatten)]
        compute: ComputeArgs,
    },
    /// Replay unfinished ranges and continue a session.
    Resume {
        #[arg(long)]
        session: PathBuf,
        #[command(flatten)]
        compute: ComputeArgs,
    },
    /// Independently verify a match and export one encrypted wallet.
    Finalize {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decrypt and verify a Web3 V3 wallet without displaying its key.
    Verify {
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, alias = "wallet")]
        keystore: PathBuf,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        suffix: String,
    },
    /// Discard corrupted public progress, retain seed, and start coverage at zero.
    Recover {
        #[arg(long)]
        session: PathBuf,
        #[arg(long, required = true)]
        restart: bool,
    },
    /// Repeat public-only benchmark workloads after warmup.
    Benchmark {
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        suffix: Option<String>,
        #[arg(long, value_enum)]
        search_strategy: Option<vanity_pro::model::SearchStrategy>,
        #[cfg(feature = "developer-tools")]
        #[arg(long, value_enum, default_value = "auto")]
        cpu_engine: vanity_pro::backend::CpuEngine,
        #[cfg(feature = "developer-tools")]
        #[arg(long, value_enum, default_value = "auto")]
        hash_mode: vanity_pro::backend::HashMode,
        #[cfg(feature = "developer-tools")]
        #[arg(long, value_enum, default_value = "auto")]
        ed_table: vanity_pro::backend::EdTable,
        #[command(flatten)]
        compute: ComputeArgs,
        #[arg(long, default_value_t = 3.0)]
        seconds: f64,
        #[arg(long, default_value_t = 1.0)]
        warmup: f64,
        #[arg(long, default_value_t = 3)]
        runs: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Calibrate the selected CPU or GPU with bounded public test inputs.
    Tune {
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, value_enum, default_value_t = Mode::Auto)]
        backend: Mode,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<usize>,
        #[arg(long, value_delimiter = ',')]
        exclude_devices: Vec<usize>,
        #[arg(long, default_value_t = 4_194_304)]
        batch_size: u32,
        #[arg(long = "tuning-cache")]
        directory: Option<PathBuf>,
        #[arg(long, value_enum)]
        search_strategy: Option<vanity_pro::model::SearchStrategy>,
        #[arg(long)]
        checksum_suffix: bool,
        #[arg(long)]
        quiet: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Diagnose GPU and host stages using public test inputs only.
    #[cfg(feature = "developer-tools")]
    ProfileGpu {
        #[arg(long, default_value_t = 0)]
        device: usize,
        #[arg(long, default_value_t = 32768)]
        batch_size: u32,
        #[arg(long, default_value_t = 20)]
        repeats: u32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Explicitly retune a GPU and save validated nonsecret settings.
    #[cfg(feature = "developer-tools")]
    GpuTune {
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, value_enum)]
        search_strategy: Option<vanity_pro::model::SearchStrategy>,
        #[arg(long)]
        checksum_suffix: bool,
        #[arg(long, default_value_t = 0)]
        device: usize,
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long, default_value_t = 0.3)]
        seconds: f64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Calibrate CPU implementations and save validated nonsecret settings.
    #[cfg(feature = "developer-tools")]
    CpuTune {
        #[command(flatten)]
        compute: ComputeArgs,
        #[arg(long, value_enum)]
        search_strategy: Option<vanity_pro::model::SearchStrategy>,
        #[arg(long)]
        checksum_suffix: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Run known-answer CPU tests and per-device cryptographic equivalence checks.
    SelfTest {
        #[arg(long,value_enum,default_value_t=TestTarget::All)]
        backend: TestTarget,
        #[arg(long, value_delimiter = ',')]
        devices: Vec<usize>,
        #[arg(long)]
        baseline: bool,
    },
    /// Manage opt-in compiled kernel caches.
    Cache {
        #[command(subcommand)]
        action: CacheCommand,
    },
}
#[derive(Subcommand)]
enum SplitCommand {
    /// Make an encrypted private share and save its public search request.
    CreateRequest {
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        suffix: String,
        /// Folder for the owner's private share and original request.
        #[arg(long)]
        session: PathBuf,
        /// Public request file to send to the helper.
        #[arg(long)]
        out: PathBuf,
    },
    /// Import a public request, prepare the compute device, and start a worker session.
    Search {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        compute: Box<ComputeArgs>,
    },
    /// Save another public request file from an existing owner session.
    ExportRequest {
        #[arg(long)]
        session: PathBuf,
        #[arg(long, alias = "output")]
        out: PathBuf,
    },
    /// Save a public result from a worker session with a completed match.
    ExportResult {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Validate and retain a helper's result in its original owner session.
    ImportResult {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        result: PathBuf,
    },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum TestTarget {
    All,
    Cpu,
    Opencl,
}
#[derive(Subcommand)]
enum CacheCommand {
    Clear {
        #[arg(long, default_value = ".vanity-cache")]
        directory: PathBuf,
    },
}
#[derive(Args)]
struct ComputeArgs {
    #[command(flatten)]
    profile: ProfileArgs,
    #[arg(long,value_enum,default_value_t=Mode::Auto)]
    backend: Mode,
    #[arg(long)]
    threads: Option<usize>,
    #[arg(long, value_delimiter = ',')]
    devices: Vec<usize>,
    #[arg(long, value_delimiter = ',')]
    exclude_devices: Vec<usize>,
    #[arg(long, default_value_t = 4_194_304)]
    batch_size: u32,
    #[arg(long)]
    max_candidates: Option<u64>,
    #[arg(long)]
    max_seconds: Option<f64>,
    /// Opt in to a private compiled-binary cache; default compiles from source.
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    #[arg(long)]
    quiet: bool,
    #[arg(long, conflicts_with = "json_lines")]
    json: bool,
    #[arg(long)]
    json_lines: bool,
    /// Use reference CPU/scalar hashing and disable GPU batched inversion.
    #[arg(long)]
    baseline: bool,
    #[cfg(feature = "developer-tools")]
    #[command(flatten)]
    research: ResearchArgs,
    #[arg(long = "tuning-cache", alias = "gpu-tuning-cache")]
    gpu_tuning_cache: Option<PathBuf>,
    /// Automatically calibrate a new device/workload; off uses cache or checked defaults.
    #[arg(long, value_enum, default_value = "auto")]
    tuning: vanity_pro::backend::calibration::TuningMode,
}
#[cfg(feature = "developer-tools")]
#[derive(Args, Default)]
struct ResearchArgs {
    /// Public GPU inversion batch width (16,32,64,128,255,256,512,1024).
    #[arg(long)]
    inversion_width: Option<usize>,
    /// Local work-group size; zero lets the driver choose.
    #[arg(long)]
    work_group_size: Option<usize>,
    /// Host status polling sleep; zero yields while retaining timeout checks.
    #[arg(long)]
    gpu_poll_microseconds: Option<u64>,
    /// Experimental correctness-gated sparse-reduction/binary-inverse arithmetic.
    #[arg(long)]
    fast_field: bool,
    /// Curve kernel; affine/recurrence use contiguous parallel public offset walks.
    #[arg(long, value_enum)]
    gpu_curve: Option<opencl::Curve>,
    #[arg(long)]
    gpu_lanes: Option<usize>,
    /// Store inversion prefix products in global scratch rather than private arrays.
    #[arg(long)]
    gpu_global_prefix: bool,
    #[arg(long)]
    gpu_tuned_keccak: bool,
    /// Fixed coordinate packing and Ethereum-address-only final Keccak round.
    #[arg(long)]
    gpu_address_keccak: bool,
    /// Original fixed-reduction 8x32 public field multiplication.
    #[arg(long)]
    gpu_bounded_multiply: bool,
    /// Bounded canonical public-field addition and subtraction.
    #[arg(long)]
    gpu_canonical_field: bool,
    /// Compare Ethereum output words against compiled nibble masks.
    #[arg(long)]
    gpu_word_match: bool,
    /// NVIDIA OpenCL ternary-logic Keccak specialization.
    #[arg(long)]
    gpu_ternary_keccak: bool,
    /// Fixed-message SHA-256/RIPEMD-160 kernels for Hash160 profiles.
    #[arg(long)]
    gpu_fixed_hash: bool,
    /// Compare 4x64 multiplication with canonical 8x32 field storage/reduction.
    #[arg(long)]
    gpu_wide_multiply: bool,
    /// Interleave inversion groups to compare device memory-access layouts.
    #[arg(long)]
    gpu_interleaved_inverse: bool,
    /// Diagnostic comparison: wait after every kernel instead of submitting a graph.
    #[arg(long)]
    gpu_synchronous_dispatch: bool,
    /// Select manual portable defaults even without another GPU override.
    #[arg(long)]
    gpu_manual: bool,
}
#[derive(Args, Clone, Default)]
struct ProfileArgs {
    #[arg(long, value_enum)]
    chain: Option<Chain>,
    #[arg(long = "type", value_enum)]
    address_type: Option<AddressType>,
}
impl ProfileArgs {
    fn resolve(&self) -> Result<Profile> {
        Profile::new(self.chain.unwrap_or_default(), self.address_type)
    }
    fn explicit(&self) -> Option<Profile> {
        if self.chain.is_some() || self.address_type.is_some() {
            self.resolve().ok()
        } else {
            None
        }
    }
}
impl ComputeArgs {
    fn config(&self) -> Config {
        let automatic = !self.baseline;
        #[cfg(feature = "developer-tools")]
        let automatic = automatic
            && !(self.research.gpu_manual
                || self.research.inversion_width.is_some()
                || self.research.work_group_size.is_some()
                || self.research.gpu_poll_microseconds.is_some()
                || self.research.gpu_curve.is_some()
                || self.research.gpu_lanes.is_some()
                || self.research.fast_field
                || self.research.gpu_global_prefix
                || self.research.gpu_fixed_hash
                || self.research.gpu_tuned_keccak
                || self.research.gpu_address_keccak
                || self.research.gpu_bounded_multiply
                || self.research.gpu_canonical_field
                || self.research.gpu_word_match
                || self.research.gpu_ternary_keccak
                || self.research.gpu_wide_multiply
                || self.research.gpu_interleaved_inverse
                || self.research.gpu_synchronous_dispatch);
        Config {
            mode: self.backend,
            profile: self.profile.explicit(),
            threads: self.threads.unwrap_or_else(|| Config::default().threads),
            devices: self.devices.clone(),
            exclude_devices: self.exclude_devices.clone(),
            batch_size: self.batch_size,
            max_candidates: self.max_candidates,
            max_seconds: self.max_seconds,
            cache: self.cache_dir.clone(),
            quiet: self.quiet || self.json,
            json_lines: self.json_lines,
            batched: !self.baseline,
            cpu_engine: Default::default(),
            hash_mode: Default::default(),
            ed_table: Default::default(),
            benchmark_strategy: None,
            benchmark_pattern: None,
            encoded_suffix: false,
            gpu_tuning: {
                #[cfg(feature = "developer-tools")]
                {
                    opencl::Tuning {
                        inversion_width: self.research.inversion_width.unwrap_or(16),
                        work_group_size: self.research.work_group_size.unwrap_or(0),
                        poll_microseconds: self.research.gpu_poll_microseconds.unwrap_or(1000),
                        fast_field: self.research.fast_field,
                        fixed_hash: self.research.gpu_fixed_hash,
                        curve: self.research.gpu_curve.unwrap_or(opencl::Curve::Jacobian),
                        max_lanes: self.research.gpu_lanes.unwrap_or(1_048_576),
                        global_prefix: self.research.gpu_global_prefix,
                        tuned_keccak: self.research.gpu_tuned_keccak,
                        address_keccak: self.research.gpu_address_keccak,
                        bounded_multiply: self.research.gpu_bounded_multiply,
                        canonical_field: self.research.gpu_canonical_field,
                        word_match: self.research.gpu_word_match,
                        ternary_keccak: self.research.gpu_ternary_keccak,
                        wide_multiply: self.research.gpu_wide_multiply,
                        interleaved_inverse: self.research.gpu_interleaved_inverse,
                        synchronous_dispatch: self.research.gpu_synchronous_dispatch,
                    }
                }
                #[cfg(not(feature = "developer-tools"))]
                {
                    opencl::Tuning::default()
                }
            },
            automatic_gpu: automatic,
            tuning_cache: self
                .gpu_tuning_cache
                .clone()
                .or_else(vanity_pro::backend::autotune::default_directory),
            progress: None,
            calibration: None,
            calibration_record: None,
            calibration_cancel: None,
            tuning_mode: self.tuning,
            calibration_hardware: vec![],
            calibration_skip: None,
            calibration_active: None,
            calibration_status: None,
            calibration_overrides: None,
        }
    }
}
fn password(label: &str, confirm: bool) -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(rpassword::prompt_password(label)?);
    if confirm {
        let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
        ensure!(*password == *again, "passwords do not match");
        ensure!(
            password.len() >= 12,
            "use at least 12 bytes for the password"
        );
    }
    Ok(password)
}
fn cancellation() -> Result<Arc<AtomicBool>> {
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    Ok(cancel)
}
fn do_search(job: &Path, args: ComputeArgs) -> Result<()> {
    let session = job
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let kind = split::session_kind(session)?;
    ensure!(
        kind != split::SessionKind::Owner,
        "owner sessions cannot search; send the public request to a helper"
    );
    let saved: vanity_pro::model::Job = storage::read_json(job)?;
    let requested = args.profile.resolve()?;
    ensure!(
        args.profile.explicit().is_none() || requested == saved.profile(),
        "requested chain/type differs from the saved job"
    );
    saved.validate()?;
    let mut config = args.config();
    let cancel = cancellation()?;
    vanity_pro::backend::calibration::resolve(
        &mut config,
        &saved.pattern,
        Some(saved.strategy),
        args.tuning,
        cancel.clone(),
        Arc::new(AtomicBool::new(false)),
        |s| {
            if !args.quiet {
                eprintln!("{s}");
            }
        },
    )?;
    let result = if saved.profile().key_family() == KeyFamily::Ed25519 {
        vanity_pro::search_ed25519(
            job,
            &config,
            cancel,
            &password("Session password: ", false)?,
        )?
    } else {
        coordinator::search(job, &config, cancel)?
    };
    if args.json {
        println!("{}", serde_json::to_string(&result)?);
    } else if let Some(candidate) = result.candidate {
        if kind == split::SessionKind::Worker {
            println!(
                "Public candidate: {}. Use split export-result to save the result for the owner.",
                saved.profile().display_candidate(&candidate.address)?
            );
        } else {
            println!(
                "Public candidate: {} (finalize and verify ownership before use)",
                saved.profile().display_candidate(&candidate.address)?
            );
        }
    } else if !args.quiet {
        println!("Paused. Resume the same session to continue coverage.");
    }
    Ok(())
}
fn split_create_request_command(
    session: &Path,
    out: &Path,
    pattern: Pattern,
    mut prompt: impl FnMut(&str, bool) -> Result<Zeroizing<String>>,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let _output_guard = storage::guard(out)?;
    ensure!(!storage::exists(out)?, "request output already exists");
    ensure!(
        pattern.profile.key_family() == KeyFamily::Secp256k1,
        "split-key search requires a secp256k1 address type"
    );
    let secret = prompt("Private-share encryption password: ", true)?;
    split::create_request(session, pattern, &secret)?;
    split::export_request(session, out)?;
    writeln!(output, "Public search request saved to {}.", out.display())?;
    writeln!(
        output,
        "Retain the owner session at {} and its password. Both are necessary to save the wallet.",
        session.display()
    )?;
    Ok(())
}
fn split_search_command(
    request_path: &Path,
    session: &Path,
    args: ComputeArgs,
    cancel: Arc<AtomicBool>,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let request = split::read_request(request_path)?;
    let requested = args.profile.resolve()?;
    ensure!(
        args.profile.explicit().is_none() || requested == request.job.profile(),
        "requested chain/type differs from the public request"
    );
    let _session_guard = storage::guard(session)?;
    ensure!(
        !storage::exists(session)?,
        "worker session output already exists"
    );
    let mut config = args.config();
    let selected = vanity_pro::backend::calibration::resolve(
        &mut config,
        &request.job.pattern,
        None,
        args.tuning,
        cancel.clone(),
        Arc::new(AtomicBool::new(false)),
        |status| {
            if !args.quiet {
                eprintln!("{status}");
            }
        },
    )?;
    ensure!(
        !cancel.load(Ordering::Relaxed),
        "search stopped before session creation"
    );
    split::create_worker(session, &request, selected.strategy)?;
    let result = coordinator::search(&session.join("job.json"), &config, cancel)?;
    if args.json {
        writeln!(output, "{}", serde_json::to_string(&result)?)?;
    } else if args.json_lines {
        // The coordinator already writes each progress record as JSON.
    } else if let Some(candidate) = result.candidate {
        writeln!(
            output,
            "Public candidate: {}. Save the search result and send it to the owner.",
            request
                .job
                .profile()
                .display_candidate(&candidate.address)?
        )?;
    } else if !args.quiet {
        writeln!(
            output,
            "Paused. Use resume --session {} to continue.",
            session.display()
        )?;
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    if let Some(code) = vanity_pro::backend::calibration::worker_entry() {
        return std::process::ExitCode::from(if code == 0 { 0 } else { 1 });
    }
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Chains => println!(
            "{}",
            serde_json::to_string_pretty(&vanity_pro::chains::registry())?
        ),
        Command::AddressTypes { chain } => {
            for t in chain.types() {
                println!(
                    "{}",
                    serde_json::to_string(&Profile::new(chain, Some(*t))?.info())?
                );
            }
        }
        Command::Split { action } => match action {
            SplitCommand::CreateRequest {
                profile,
                prefix,
                suffix,
                session,
                out,
            } => {
                split_create_request_command(
                    &session,
                    &out,
                    Pattern::for_profile(profile.resolve()?, &prefix, &suffix)?,
                    password,
                    &mut std::io::stdout().lock(),
                )?;
            }
            SplitCommand::Search {
                request,
                output,
                compute,
            } => {
                split_search_command(
                    &request,
                    &output,
                    *compute,
                    cancellation()?,
                    &mut std::io::stdout().lock(),
                )?;
            }
            SplitCommand::ExportRequest { session, out } => {
                split::export_request(&session, &out)?;
                println!("Public search request saved to {}.", out.display());
            }
            SplitCommand::ExportResult { session, out } => {
                split::export_result(&session, &out)?;
                println!("Public search result saved to {}.", out.display());
            }
            SplitCommand::ImportResult { session, result } => {
                split::import_result(&session, &split::read_result(&result)?)?;
                println!(
                    "Search result imported. Use finalize with the owner session to save and verify the wallet."
                );
            }
        },
        Command::ExportNative { wallet, out } => {
            let address = vanity_pro::export_native(
                &wallet,
                &password("Wallet password (native export): ", false)?,
                &out,
            )?;
            println!("Native wallet {address} written to {}.", out.display());
        }
        Command::Generate {
            prefix,
            suffix,
            output,
            compute,
        } => {
            let profile = compute.profile.resolve()?;
            let pattern = Pattern::for_profile(profile, &prefix, &suffix)?;
            ensure!(
                profile.key_family() != KeyFamily::Ed25519 || compute.backend != Mode::Opencl,
                "Ed25519 generation requires Auto or CPU mode"
            );
            let output = output.unwrap_or_else(|| {
                PathBuf::from(format!("vanity-session-{}", uuid::Uuid::new_v4()))
            });
            let mut config = compute.config();
            let cancel = cancellation()?;
            let selected = vanity_pro::backend::calibration::resolve(
                &mut config,
                &pattern,
                None,
                compute.tuning,
                cancel.clone(),
                Arc::new(AtomicBool::new(false)),
                |s| {
                    if !compute.quiet {
                        eprintln!("{s}");
                    }
                },
            )?;
            let secret = password("Session encryption password: ", true)?;
            vanity_pro::initialize_with_strategy(&output, pattern, &secret, selected.strategy)?;
            let job_path = output.join("job.json");
            let result = if profile.key_family() == KeyFamily::Ed25519 {
                vanity_pro::search_ed25519(&job_path, &config, cancel, &secret)?
            } else {
                coordinator::search(&job_path, &config, cancel)?
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
            println!(
                "Session: {}. Use finalize --session ... --out wallet.json to export the encrypted wallet.",
                output.display()
            );
        }
        Command::Init {
            profile,
            prefix,
            suffix,
            output,
        } => {
            let pattern = Pattern::for_profile(profile.resolve()?, &prefix, &suffix)?;
            let secret = password("Seed encryption password: ", true)?;
            let job = vanity_pro::initialize(&output, pattern, &secret)?;
            println!(
                "Session {} created at {}. Difficulty: {}. Back up seed.keystore.json and job.json; losing the password or seed prevents wallet recovery.",
                job.session_id,
                output.display(),
                if job.pattern.probability().is_finite() {
                    format!(
                        "expected {:.0} trials; {}",
                        1.0 / job.pattern.probability(),
                        job.pattern.estimate()?.model
                    )
                } else {
                    "insufficient sampled matches for an estimate".into()
                }
            );
        }
        Command::Devices { self_test, json } => {
            let (mut devices, warning) = match opencl::discover() {
                Ok(devices) => (devices, None),
                Err(e) => (vec![], Some(e.to_string())),
            };
            if self_test {
                for d in &mut devices {
                    d.self_test = match vanity_pro::backend::autotune::open_automatic(
                        d.index,
                        vanity_pro::backend::autotune::default_directory().as_deref(),
                    )
                    .and_then(|mut w| w.self_test())
                    {
                        Ok(()) => "passed".into(),
                        Err(e) => format!("failed: {e:#}"),
                    };
                }
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"cpu":cpu_info(),"opencl":devices,"warning":warning})
                    )?
                );
            } else {
                println!("CPU: {:?}", cpu_info());
                if let Some(warning) = warning {
                    println!("OpenCL: {warning}");
                }
                for d in devices {
                    println!(
                        "GPU {}: {} | {} | driver {} | {} | {} | {} MiB | {} CUs | group {} | test {}",
                        d.index,
                        d.name,
                        d.vendor,
                        d.driver,
                        d.api,
                        d.language,
                        d.memory_bytes / 1_048_576,
                        d.compute_units,
                        d.max_work_group,
                        d.self_test
                    );
                }
            }
        }
        Command::Search { job, compute } => do_search(&job, compute)?,
        Command::Resume { session, compute } => do_search(&session.join("job.json"), compute)?,
        Command::Finalize { session, out } => {
            finalize_command(&session, &out, password, &mut std::io::stdout().lock())?;
        }
        Command::Verify {
            profile,
            keystore,
            prefix,
            suffix,
        } => {
            let requested = profile.resolve()?;
            ensure!(
                profile.explicit().is_none() || vanity_pro::wallet_profile(&keystore)? == requested,
                "requested chain/type differs from the wallet metadata"
            );
            let pattern = if prefix.is_empty() && suffix.is_empty() {
                None
            } else {
                Some(Pattern::for_profile(profile.resolve()?, &prefix, &suffix)?)
            };
            println!(
                "Verified wallet: {}",
                vanity_pro::verify_wallet(
                    &keystore,
                    &password("Wallet password: ", false)?,
                    pattern.as_ref()
                )?
            );
        }
        Command::Recover {
            session,
            restart: _,
        } => {
            let kind = split::session_kind(&session)?;
            coordinator::recover(&session)?;
            if kind == split::SessionKind::Worker {
                println!("Public progress reset. Resume to replay from offset zero.");
            } else {
                println!(
                    "Public progress reset; encrypted seed retained. Resume to replay from offset zero."
                );
            }
        }
        Command::Benchmark {
            prefix,
            suffix,
            search_strategy,
            #[cfg(feature = "developer-tools")]
            cpu_engine,
            #[cfg(feature = "developer-tools")]
            hash_mode,
            #[cfg(feature = "developer-tools")]
            ed_table,
            compute,
            seconds,
            warmup,
            runs,
            out,
        } => {
            compute.profile.resolve()?;
            let mut config = compute.config();
            config.benchmark_strategy = search_strategy;
            #[cfg(feature = "developer-tools")]
            {
                config.cpu_engine = cpu_engine;
                config.hash_mode = hash_mode;
                config.ed_table = ed_table;
            }
            if prefix.is_some() || suffix.is_some() {
                config.benchmark_pattern = Some(Pattern::for_profile(
                    config.profile.unwrap_or_default(),
                    prefix.as_deref().unwrap_or(""),
                    suffix.as_deref().unwrap_or(""),
                )?);
            }
            let cancel = cancellation()?;
            let calibration_pattern = if let Some(p) = &config.benchmark_pattern {
                p.clone()
            } else {
                let p = config.profile.unwrap_or_default();
                let address = p.diagnostic_address()?;
                Pattern::for_profile(p, &address, "")?
            };
            vanity_pro::backend::calibration::resolve(
                &mut config,
                &calibration_pattern,
                search_strategy,
                compute.tuning,
                cancel.clone(),
                Arc::new(AtomicBool::new(false)),
                |s| {
                    if !compute.quiet {
                        eprintln!("{s}");
                    }
                },
            )?;
            let mut report = coordinator::benchmark(&config, seconds, warmup, runs, cancel)?;
            report["calibration"] = config.calibration.clone().unwrap_or_default();
            if let Some(path) = out {
                storage::write_json(&path, &report, false)?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Tune {
            profile,
            backend,
            threads,
            devices,
            exclude_devices,
            batch_size,
            directory,
            search_strategy,
            checksum_suffix,
            quiet,
            out,
        } => {
            let profile = profile.resolve()?;
            let mut config = Config {
                mode: backend,
                profile: Some(profile),
                threads: threads.unwrap_or_else(|| Config::default().threads),
                devices,
                exclude_devices,
                batch_size,
                tuning_cache: directory.or_else(vanity_pro::backend::autotune::default_directory),
                quiet,
                ..Config::default()
            };
            let address = profile.diagnostic_address()?;
            let pattern = Pattern::for_profile(
                profile,
                if checksum_suffix { "" } else { &address },
                if checksum_suffix {
                    &address[address.len().saturating_sub(8)..]
                } else {
                    ""
                },
            )?;
            let summary = vanity_pro::backend::calibration::retune(
                &mut config,
                &pattern,
                search_strategy,
                vanity_pro::backend::calibration::TuningMode::Auto,
                cancellation()?,
                Arc::new(AtomicBool::new(false)),
                |status| {
                    if !quiet {
                        eprintln!("{status}");
                    }
                },
            )?;
            if let Some(path) = out {
                storage::write_json(&path, &summary, false)?;
            }
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        #[cfg(feature = "developer-tools")]
        Command::ProfileGpu {
            device,
            batch_size,
            repeats,
            out,
        } => {
            let report = opencl::profiling::report(device, batch_size, repeats)?;
            if let Some(path) = out {
                storage::write_json(&path, &report, true)?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "developer-tools")]
        Command::GpuTune {
            profile,
            search_strategy,
            checksum_suffix,
            device,
            directory,
            seconds,
            out,
        } => {
            let directory = directory
                .or_else(vanity_pro::backend::autotune::default_directory)
                .context("cannot locate GPU tuning directory")?;
            let resolved_profile = profile.resolve()?;
            let strategy = search_strategy.unwrap_or_else(|| {
                vanity_pro::backend::qualification::new_strategy(resolved_profile)
            });
            let report = vanity_pro::backend::autotune::tune_profile(
                device,
                &directory,
                seconds,
                cancellation()?,
                vanity_pro::backend::autotune::TuningWorkload {
                    profile: resolved_profile,
                    strategy,
                    encoded_suffix: checksum_suffix,
                },
            )?;
            if let Some(out) = out {
                storage::write_json(&out, &report, true)?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        #[cfg(feature = "developer-tools")]
        Command::CpuTune {
            compute,
            search_strategy,
            checksum_suffix,
            out,
        } => {
            let mut config = compute.config();
            config.mode = Mode::Cpu;
            let profile = compute.profile.resolve()?;
            let address = profile.diagnostic_address()?;
            let pattern = Pattern::for_profile(
                profile,
                if checksum_suffix { "" } else { &address },
                if checksum_suffix {
                    &address[address.len().saturating_sub(8)..]
                } else {
                    ""
                },
            )?;
            let summary = vanity_pro::backend::calibration::retune(
                &mut config,
                &pattern,
                search_strategy,
                vanity_pro::backend::calibration::TuningMode::Auto,
                cancellation()?,
                Arc::new(AtomicBool::new(false)),
                |s| {
                    if !compute.quiet {
                        eprintln!("{s}");
                    }
                },
            )?;
            if let Some(path) = out {
                storage::write_json(&path, &summary, false)?;
            }
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::SelfTest {
            backend,
            devices,
            baseline,
        } => {
            if !matches!(backend, TestTarget::Opencl) {
                Cpu { index: 0 }.self_test()?;
                println!("CPU known-answer tests passed");
            }
            if !matches!(backend, TestTarget::Cpu) {
                match opencl::discover() {
                    Ok(infos) => {
                        let selected = if devices.is_empty() {
                            infos.iter().map(|d| d.index).collect()
                        } else {
                            devices
                        };
                        ensure!(
                            !selected.is_empty() || matches!(backend, TestTarget::All),
                            "no OpenCL GPU found"
                        );
                        for index in selected {
                            let mut device = if baseline {
                                Opencl::new(index, false, None)?
                            } else {
                                vanity_pro::backend::autotune::open_automatic(
                                    index,
                                    vanity_pro::backend::autotune::default_directory().as_deref(),
                                )?
                            };
                            device.self_test()?;
                            println!("{} equivalence tests passed", device.name());
                        }
                    }
                    Err(e) if matches!(backend, TestTarget::All) => {
                        println!("OpenCL unavailable: {e:#}")
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Command::Cache {
            action: CacheCommand::Clear { directory },
        } => {
            coordinator::clear_cache(&directory)?;
            println!("Compiled kernel cache cleared");
        }
    }
    Ok(())
}

#[cfg(test)]
mod split_cli_tests {
    use super::*;

    fn compute(extra: &[&str]) -> ComputeArgs {
        let mut arguments = vec![
            "vanity",
            "split",
            "search",
            "--request",
            "request.json",
            "--output",
            "worker",
            "--backend",
            "cpu",
            "--threads",
            "1",
            "--batch-size",
            "32",
            "--max-candidates",
            "1024",
            "--baseline",
            "--tuning",
            "off",
            "--quiet",
        ];
        arguments.extend(extra);
        let Command::Split {
            action: SplitCommand::Search { compute, .. },
        } = Cli::try_parse_from(arguments).unwrap().command
        else {
            panic!("wrong command");
        };
        *compute
    }

    #[test]
    fn split_commands_have_separate_owner_worker_and_transfer_arguments() {
        for arguments in [
            vec![
                "vanity",
                "split",
                "create-request",
                "--session",
                "owner",
                "--out",
                "request.json",
                "--chain",
                "bitcoin",
                "--type",
                "p2wpkh",
                "--prefix",
                "bc1qa",
            ],
            vec![
                "vanity",
                "split",
                "search",
                "--request",
                "request.json",
                "--output",
                "worker",
                "--backend",
                "cpu",
                "--tuning",
                "off",
            ],
            vec![
                "vanity",
                "split",
                "export-request",
                "--session",
                "owner",
                "--out",
                "request.json",
            ],
            vec![
                "vanity",
                "split",
                "export-result",
                "--session",
                "worker",
                "--out",
                "result.json",
            ],
            vec![
                "vanity",
                "split",
                "import-result",
                "--session",
                "owner",
                "--result",
                "result.json",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
        assert!(
            Cli::try_parse_from(["vanity", "split", "create-request", "--session", "owner"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["vanity", "split", "search", "--request", "request.json"])
                .is_err()
        );
    }

    #[test]
    fn split_cli_round_trip_keeps_private_share_on_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let owner = temporary.path().join("owner");
        let worker = temporary.path().join("worker");
        let request_path = temporary.path().join("request.json");
        let result_path = temporary.path().join("result.json");
        let wallet = temporary.path().join("wallet.json");
        let mut output = vec![];
        let mut password_prompts = 0;
        split_create_request_command(
            &owner,
            &request_path,
            Pattern::new("a", "").unwrap(),
            |label, confirm| {
                password_prompts += 1;
                assert_eq!(label, "Private-share encryption password: ");
                assert!(confirm);
                Ok(Zeroizing::new("synthetic owner password".into()))
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(password_prompts, 1);
        assert_eq!(
            split::session_kind(&owner).unwrap(),
            split::SessionKind::Owner
        );
        let request = split::read_request(&request_path).unwrap();
        assert_eq!(
            request.job.strategy,
            vanity_pro::model::SearchStrategy::Linear
        );
        split_search_command(
            &request_path,
            &worker,
            compute(&[]),
            Arc::new(AtomicBool::new(false)),
            &mut output,
        )
        .unwrap();
        assert_eq!(
            split::session_kind(&worker).unwrap(),
            split::SessionKind::Worker
        );
        assert!(!worker.join("seed.keystore.json").exists());
        let worker_job: vanity_pro::model::Job =
            storage::read_json(&worker.join("job.json")).unwrap();
        assert_eq!(
            worker_job.strategy,
            vanity_pro::model::SearchStrategy::Linear
        );
        assert_eq!(worker_job.public_key, request.job.public_key);
        assert_ne!(worker_job.session_id, request.job.session_id);
        split::export_result(&worker, &result_path).unwrap();
        let result = split::read_result(&result_path).unwrap();
        split::import_result(&owner, &result).unwrap();
        let mut prompts = 0;
        finalize_command(
            &owner,
            &wallet,
            |_, _| {
                prompts += 1;
                Ok(Zeroizing::new(
                    if prompts == 1 {
                        "synthetic owner password"
                    } else {
                        "synthetic wallet password"
                    }
                    .into(),
                ))
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(prompts, 2);
        let address = vanity_pro::verify_wallet(
            &wallet,
            "synthetic wallet password",
            Some(&request.job.pattern),
        )
        .unwrap();
        assert_eq!(
            address,
            request
                .job
                .profile()
                .display_candidate(&result.candidate.address)
                .unwrap()
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Verified wallet")
        );
    }

    #[test]
    fn invalid_or_cancelled_split_search_does_not_create_worker() {
        let temporary = tempfile::tempdir().unwrap();
        let owner = temporary.path().join("owner");
        let worker = temporary.path().join("worker");
        let request_path = temporary.path().join("request.json");
        split::create_request(
            &owner,
            Pattern::new("a", "").unwrap(),
            "synthetic owner password",
        )
        .unwrap();
        split::export_request(&owner, &request_path).unwrap();
        let mut output = vec![];
        let error = split_search_command(
            &request_path,
            &worker,
            compute(&[]),
            Arc::new(AtomicBool::new(true)),
            &mut output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("stopped"));
        assert!(!worker.exists());
        assert!(
            split_search_command(
                &request_path,
                &worker,
                compute(&["--chain", "tron"]),
                Arc::new(AtomicBool::new(false)),
                &mut output
            )
            .is_err()
        );
        assert!(!worker.exists());
        assert!(
            do_search(&owner.join("job.json"), compute(&[]))
                .unwrap_err()
                .to_string()
                .contains("owner sessions cannot search")
        );
    }

    #[test]
    fn invalid_request_creation_and_worker_finalization_do_not_prompt() {
        let temporary = tempfile::tempdir().unwrap();
        let request_path = temporary.path().join("request.json");
        let owner = temporary.path().join("owner");
        let mut output = vec![];
        let pattern =
            Pattern::for_profile(Profile::new(Chain::Solana, None).unwrap(), "A", "").unwrap();
        assert!(
            split_create_request_command(
                &owner,
                &request_path,
                pattern,
                |_, _| panic!("unsupported profile must not prompt"),
                &mut output
            )
            .is_err()
        );
        assert!(!owner.exists());
        let request = split::create_request(
            &owner,
            Pattern::new("a", "").unwrap(),
            "synthetic owner password",
        )
        .unwrap();
        let worker = temporary.path().join("worker");
        split::create_worker(&worker, &request, vanity_pro::model::SearchStrategy::Linear).unwrap();
        let wallet = temporary.path().join("wallet.json");
        assert!(
            finalize_command(
                &worker,
                &wallet,
                |_, _| panic!("worker finalization must not prompt"),
                &mut output
            )
            .is_err()
        );
        assert!(!wallet.exists());
        storage::write_json(&request_path, &request, false).unwrap();
        assert!(
            split_create_request_command(
                &temporary.path().join("other-owner"),
                &request_path,
                Pattern::new("a", "").unwrap(),
                |_, _| panic!("existing output must not prompt"),
                &mut output
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod cli_surface_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn normal_tune_accepts_selected_backend_and_rejects_search_limits() {
        let cli = Cli::try_parse_from([
            "vanity",
            "tune",
            "--backend",
            "cpu",
            "--threads",
            "4",
            "--chain",
            "ethereum",
            "--search-strategy",
            "endomorphism-v1",
            "--tuning-cache",
            "cache",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Tune {
                backend: Mode::Cpu,
                threads: Some(4),
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["vanity", "tune", "--backend", "opencl", "--devices", "0"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["vanity", "tune", "--max-candidates", "1"]).is_err());
    }

    #[test]
    fn ordinary_search_retains_portable_baseline_and_resource_controls() {
        let cli = Cli::try_parse_from([
            "vanity",
            "resume",
            "--session",
            "session",
            "--backend",
            "cpu",
            "--threads",
            "2",
            "--baseline",
            "--max-seconds",
            "1",
            "--tuning",
            "off",
        ])
        .unwrap();
        let Command::Resume { compute, .. } = cli.command else {
            panic!("wrong command");
        };
        let config = compute.config();
        assert!(!config.batched);
        assert!(!config.automatic_gpu);
        assert_eq!(config.threads, 2);
        assert_eq!(config.max_seconds, Some(1.0));
    }

    #[test]
    fn developer_surface_matches_build_feature() {
        for command in ["profile-gpu", "gpu-tune", "cpu-tune"] {
            let parsed = Cli::try_parse_from(["vanity", command]);
            assert_eq!(
                parsed.is_ok(),
                cfg!(feature = "developer-tools"),
                "{command}"
            );
        }
        for flag in [
            "--gpu-manual",
            "--fast-field",
            "--gpu-wide-multiply",
            "--gpu-synchronous-dispatch",
        ] {
            let parsed = Cli::try_parse_from(["vanity", "search", "--job", "job.json", flag]);
            assert_eq!(parsed.is_ok(), cfg!(feature = "developer-tools"), "{flag}");
        }
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("tune"));
        assert_eq!(
            help.contains("profile-gpu"),
            cfg!(feature = "developer-tools")
        );
        assert_eq!(
            Cli::try_parse_from(["vanity", "benchmark", "--cpu-engine", "batched"]).is_ok(),
            cfg!(feature = "developer-tools")
        );
    }
}
