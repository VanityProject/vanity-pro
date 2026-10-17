//! Public file exchange for split-key searches. Private shares remain in KeyManager.
use crate::{
    chains::{AddressType, KeyFamily},
    crypto::Pattern,
    model::{Candidate, Checkpoint, JOB_SCHEMA, Job, Results, SearchStrategy},
    storage,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

const SCHEMA: u32 = 1;
const ROLE_FILE: &str = "split-session.json";
const REQUEST_FILE: &str = "split-request.json";
const RESULT_FILE: &str = "split-result.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionKind {
    #[default]
    Local,
    Owner,
    Worker,
}
impl SessionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Local => "Local search",
            Self::Owner => "Split-key owner",
            Self::Worker => "Split-key worker",
        }
    }
}

/// A hardware-independent owner job. Its public key is one fresh private share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitRequest {
    pub schema: u32,
    pub job: Job,
}
impl SplitRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == SCHEMA, "unsupported split request version");
        self.job.validate()?;
        ensure!(
            self.job.schema == JOB_SCHEMA
                && self.job.profile().key_family() == KeyFamily::Secp256k1
                && self.job.strategy == SearchStrategy::Linear,
            "split requests require a current Linear secp256k1 owner job"
        );
        Ok(())
    }
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

/// A public candidate and its actual execution job. No search coverage is claimed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitResult {
    pub schema: u32,
    pub request_fingerprint: String,
    pub worker_job: Job,
    pub candidate: Candidate,
}
impl SplitResult {
    pub fn validate(&self, request: &SplitRequest) -> Result<()> {
        ensure!(self.schema == SCHEMA, "unsupported split result version");
        ensure!(
            self.request_fingerprint == request.fingerprint()?,
            "result belongs to another split request"
        );
        validate_worker(request, &self.worker_job)?;
        self.candidate.verify(&self.worker_job)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRole {
    schema: u32,
    kind: SessionKind,
    job_hash: String,
    request_fingerprint: String,
}

fn validate_worker(request: &SplitRequest, job: &Job) -> Result<()> {
    request.validate()?;
    job.validate()?;
    ensure!(
        job.schema == JOB_SCHEMA
            && job.session_id != request.job.session_id
            && job.public_key == request.job.public_key
            && job.pattern == request.job.pattern,
        "worker job does not match the split request"
    );
    ensure!(
        job.profile().address_type != AddressType::P2tr || job.strategy == SearchStrategy::Linear,
        "new Taproot split searches require Linear enumeration"
    );
    Ok(())
}

pub fn read_request(path: &Path) -> Result<SplitRequest> {
    let request: SplitRequest = storage::read_json(path)?;
    request.validate()?;
    Ok(request)
}
pub fn read_result(path: &Path) -> Result<SplitResult> {
    let result: SplitResult = storage::read_json(path)?;
    ensure!(result.schema == SCHEMA, "unsupported split result version");
    // Binding and candidate validation require the owner's retained request.
    result.worker_job.validate()?;
    Ok(result)
}

fn session_record(session: &Path) -> Result<Option<(SessionRole, SplitRequest, Job)>> {
    if !storage::exists(&session.join(ROLE_FILE))? {
        ensure!(
            !storage::exists(&session.join(REQUEST_FILE))?
                && !storage::exists(&session.join(RESULT_FILE))?,
            "split session metadata is incomplete"
        );
        return Ok(None);
    }
    let role: SessionRole = storage::read_json(&session.join(ROLE_FILE))?;
    let request = read_request(&session.join(REQUEST_FILE))?;
    let job: Job = storage::read_json(&session.join("job.json"))?;
    ensure!(
        role.schema == SCHEMA
            && role.kind != SessionKind::Local
            && role.job_hash == job.fingerprint()?
            && role.request_fingerprint == request.fingerprint()?,
        "split session metadata does not match its request and job"
    );
    match role.kind {
        SessionKind::Owner => ensure!(job == request.job, "owner job has changed"),
        SessionKind::Worker => validate_worker(&request, &job)?,
        SessionKind::Local => unreachable!(),
    }
    Ok(Some((role, request, job)))
}

pub fn session_kind(session: &Path) -> Result<SessionKind> {
    Ok(session_record(session)?.map_or(SessionKind::Local, |(role, _, _)| role.kind))
}
pub fn session_request(session: &Path) -> Result<SplitRequest> {
    session_record(session)?
        .map(|(_, request, _)| request)
        .ok_or_else(|| anyhow::anyhow!("this is not a split-key session"))
}

fn write_role(session: &Path, kind: SessionKind, request: &SplitRequest, job: &Job) -> Result<()> {
    storage::write_json(&session.join(REQUEST_FILE), request, false)?;
    storage::write_json(
        &session.join(ROLE_FILE),
        &SessionRole {
            schema: SCHEMA,
            kind,
            job_hash: job.fingerprint()?,
            request_fingerprint: request.fingerprint()?,
        },
        false,
    )
}

/// Create an encrypted fresh owner share without hardware discovery or calibration.
pub fn create_request(session: &Path, pattern: Pattern, password: &str) -> Result<SplitRequest> {
    pattern.validate()?;
    ensure!(
        pattern.profile.key_family() == KeyFamily::Secp256k1,
        "split-key search is unavailable for standard Ed25519 seed wallets"
    );
    let job = crate::initialize(session, pattern, password)?;
    let _guard = storage::guard(session)?;
    let _lock = storage::lock_session(session)?;
    let request = SplitRequest {
        schema: SCHEMA,
        job,
    };
    request.validate()?;
    write_role(session, SessionKind::Owner, &request, &request.job)?;
    Ok(request)
}
pub fn export_request(session: &Path, out: &Path) -> Result<()> {
    let _guard = storage::guard(session)?;
    let _lock = storage::lock_session(session)?;
    ensure!(
        session_kind(session)? == SessionKind::Owner,
        "only an owner can save a request"
    );
    storage::write_json(out, &session_request(session)?, false)
}

/// Persist a helper job after local calibration has selected its enumeration.
pub fn create_worker(
    session: &Path,
    request: &SplitRequest,
    strategy: SearchStrategy,
) -> Result<Job> {
    request.validate()?;
    let job = Job {
        schema: JOB_SCHEMA,
        session_id: Uuid::new_v4(),
        public_key: request.job.public_key.clone(),
        pattern: request.job.pattern.clone(),
        strategy,
    };
    validate_worker(request, &job)?;
    let _guard = storage::guard(session)?;
    storage::create_directory(session, false)?;
    storage::private(session)?;
    let _lock = storage::lock_session(session)?;
    storage::write_json(&session.join("job.json"), &job, false)?;
    storage::save_checkpoint(&session.join("checkpoint.json"), &Checkpoint::new(&job)?)?;
    write_role(session, SessionKind::Worker, request, &job)?;
    Ok(job)
}

pub fn result(session: &Path) -> Result<SplitResult> {
    ensure!(
        session_kind(session)? == SessionKind::Worker,
        "only a worker can save a search result"
    );
    let request = session_request(session)?;
    let job: Job = storage::read_json(&session.join("job.json"))?;
    let checkpoint = storage::load_checkpoint(&session.join("checkpoint.json"), &job)?;
    ensure!(
        checkpoint.fault.is_none(),
        "session has a cryptographic correctness failure"
    );
    let expected = Results::from_checkpoint(&job, &checkpoint)?;
    let saved: Results = storage::read_json(&session.join("results.json"))?;
    ensure!(saved == expected, "results inconsistent with checkpoint");
    let result = SplitResult {
        schema: SCHEMA,
        request_fingerprint: request.fingerprint()?,
        worker_job: job,
        candidate: saved.candidate,
    };
    result.validate(&request)?;
    Ok(result)
}
pub fn export_result(session: &Path, out: &Path) -> Result<()> {
    let _guard = storage::guard(session)?;
    let _lock = storage::lock_session(session)?;
    storage::write_json(out, &result(session)?, false)
}

pub fn imported_result(session: &Path) -> Result<Option<SplitResult>> {
    ensure!(
        session_kind(session)? == SessionKind::Owner,
        "only an owner can import a search result"
    );
    if !storage::exists(&session.join(RESULT_FILE))? {
        return Ok(None);
    }
    let result = read_result(&session.join(RESULT_FILE))?;
    result.validate(&session_request(session)?)?;
    Ok(Some(result))
}
pub fn import_result(session: &Path, result: &SplitResult) -> Result<String> {
    let _guard = storage::guard(session)?;
    let _lock = storage::lock_session(session)?;
    ensure!(
        session_kind(session)? == SessionKind::Owner,
        "only an owner can import a search result"
    );
    let request = session_request(session)?;
    result.validate(&request)?;
    crate::key_manager::check_reservation(session, &request.job, &result.candidate)?;
    let path = session.join(RESULT_FILE);
    let replace = storage::exists(&path)?;
    storage::write_json(&path, result, replace)?;
    request
        .job
        .profile()
        .display_candidate(&result.candidate.address)
}
