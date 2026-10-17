use crate::crypto::{ORDER, Offset, Pattern, public_at};
use crate::{transforms::Transform, work::WorkIndex};
use anyhow::{Result, ensure};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SCHEMA: u32 = 1;
pub const JOB_SCHEMA: u32 = 3;
pub const RECORD_SCHEMA: u32 = 2;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum SearchStrategy {
    #[default]
    Linear,
    EndomorphismV1,
}
impl SearchStrategy {
    pub fn is_linear(&self) -> bool {
        *self == Self::Linear
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub schema: u32,
    pub session_id: Uuid,
    pub public_key: String,
    pub pattern: Pattern,
    #[serde(default, skip_serializing_if = "SearchStrategy::is_linear")]
    pub strategy: SearchStrategy,
}
impl Job {
    pub fn width(&self) -> u8 {
        if self.strategy == SearchStrategy::Linear {
            1
        } else if self.profile().address_type == crate::chains::AddressType::P2tr {
            3
        } else {
            6
        }
    }
    pub fn base_slots(&self, start: WorkIndex, completed: u32) -> Result<u32> {
        if completed == 0 {
            return Ok(0);
        }
        let (_, skip) = start.div_rem(self.width())?;
        Ok((completed + u32::from(skip)).div_ceil(u32::from(self.width())))
    }
    pub fn work_limit(&self) -> WorkIndex {
        let width = self.width();
        if width == 1 {
            return ORDER.into();
        }
        WorkIndex::from(ORDER).times(width).expect("bounded width")
    }
    pub fn record_schema(&self) -> u32 {
        if self.schema >= 3 {
            RECORD_SCHEMA
        } else {
            SCHEMA
        }
    }
    pub fn position(&self, index: WorkIndex) -> Result<(Offset, Transform)> {
        ensure!(index < self.work_limit(), "work cursor exhausted");
        let (offset, branch) = index.div_rem(self.width())?;
        Ok((offset, Transform::from_branch(branch)?))
    }
    fn validate_strategy(&self) -> Result<()> {
        ensure!(
            self.strategy == SearchStrategy::Linear
                || (self.schema == 3
                    && self.profile().key_family() == crate::chains::KeyFamily::Secp256k1),
            "unsupported job strategy"
        );
        Ok(())
    }

    pub fn profile(&self) -> crate::chains::Profile {
        self.pattern.profile
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=JOB_SCHEMA).contains(&self.schema),
            "unsupported job schema"
        );
        ensure!(
            self.schema != 1 || self.profile().is_legacy(),
            "legacy jobs are Ethereum only"
        );
        self.validate_strategy()?;
        self.pattern.validate()?;
        if self.profile().key_family() == crate::chains::KeyFamily::Ed25519 {
            let bytes: [u8; 32] = hex::decode(&self.public_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid Ed25519 public key length"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
            ensure!(!key.is_weak(), "weak Ed25519 public key");
            ensure!(
                hex::encode(bytes) == self.public_key,
                "noncanonical public key"
            );
        } else {
            self.point()?;
        }
        Ok(())
    }
    pub fn point(&self) -> Result<PublicKey> {
        ensure!(
            (1..=JOB_SCHEMA).contains(&self.schema),
            "unsupported job schema"
        );
        ensure!(
            self.schema != 1 || self.profile().is_legacy(),
            "legacy jobs are Ethereum only"
        );
        ensure!(
            self.profile().key_family() == crate::chains::KeyFamily::Secp256k1,
            "Ed25519 jobs require the trusted CPU seed engine"
        );
        self.validate_strategy()?;
        self.pattern.validate()?;
        ensure!(
            self.public_key.len() == 66,
            "job must use a compressed public key"
        );
        let point = PublicKey::from_slice(&hex::decode(&self.public_key)?)?;
        ensure!(
            hex::encode(point.serialize()) == self.public_key,
            "noncanonical public key"
        );
        Ok(point)
    }
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub start: WorkIndex,
    pub end: WorkIndex,
}
impl Interval {
    pub fn new(start: impl Into<WorkIndex>, count: u32) -> Result<Self> {
        let start = start.into();
        ensure!(count > 0, "empty batch");
        Ok(Self {
            start,
            end: start.checked_add(count as u64)?,
        })
    }
    pub fn count(&self) -> Result<u32> {
        ensure!(
            self.start < self.end && self.end <= WorkIndex::from(ORDER).times(6)?,
            "invalid canonical work interval"
        );
        Ok(self.start.distance(self.end)?.try_into()?)
    }
    pub fn contains(&self, offset: impl Into<WorkIndex>) -> bool {
        let offset = offset.into();
        self.start <= offset && offset < self.end
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub offset: Offset,
    pub address: String,
    #[serde(default, skip_serializing_if = "Transform::is_identity")]
    pub transform: Transform,
}
impl Candidate {
    pub fn work_index(&self, job: &Job) -> Result<WorkIndex> {
        self.transform.validate(job.width())?;
        WorkIndex::from(self.offset)
            .times(job.width())?
            .checked_add(self.transform.branch().into())
    }
    pub fn point(&self, job: &Job) -> Result<PublicKey> {
        self.transform.validate(job.width())?;
        let p = public_at(&job.point()?, self.offset)?
            .ok_or_else(|| anyhow::anyhow!("candidate is point at infinity"))?;
        self.transform.public(&p)
    }
    pub fn verify(&self, job: &Job) -> Result<()> {
        job.validate()?;
        self.transform.validate(job.width())?;
        if job.profile().key_family() == crate::chains::KeyFamily::Ed25519 {
            job.validate()?;
            let public = crate::chains::ed_public(job.profile(), &self.address)?;
            ensure!(
                job.pattern.compiled()?.accepts_payload(&public),
                "candidate does not match pattern"
            );
            return Ok(());
        }
        let point = self.point(job)?;
        let addr = job.profile().candidate(&point)?;
        ensure!(
            addr == self.address,
            "candidate address verification failed"
        );
        ensure!(
            job.pattern
                .compiled()?
                .accepts_payload(&job.profile().payload(&point)?),
            "candidate does not match pattern"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema: u32,
    pub job_hash: String,
    pub next: WorkIndex,
    pub completed: Vec<Interval>,
    pub pending: Vec<Interval>,
    pub candidate: Option<Candidate>,
    pub elapsed_seconds: f64,
    pub fault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated: Option<WorkIndex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<WorkIndex>,
}
impl Checkpoint {
    pub fn new(job: &Job) -> Result<Self> {
        Ok(Self {
            schema: job.record_schema(),
            job_hash: job.fingerprint()?,
            next: WorkIndex::ZERO,
            completed: vec![],
            pending: vec![],
            candidate: None,
            elapsed_seconds: 0.0,
            fault: None,
            evaluated: (job.schema >= 3).then_some(WorkIndex::ZERO),
            limit: (job.schema >= 3).then_some(job.work_limit()),
        })
    }
    pub fn validate(&self, job: &Job) -> Result<()> {
        ensure!(
            self.schema == job.record_schema() && self.job_hash == job.fingerprint()?,
            "checkpoint belongs to a different job or schema"
        );
        ensure!(
            self.next <= job.work_limit()
                && self.elapsed_seconds.is_finite()
                && self.elapsed_seconds >= 0.0,
            "invalid checkpoint metadata"
        );
        ensure!(
            self.pending.len() <= 4096 && self.completed.len() <= 8192,
            "too many intervals"
        );
        let mut intervals: Vec<_> = self.completed.iter().chain(&self.pending).collect();
        intervals.sort_by_key(|r| r.start);
        let mut cursor = WorkIndex::ZERO;
        for range in intervals {
            ensure!(
                range.start == cursor && range.end > range.start && range.end <= self.next,
                "checkpoint has overlap or missing coverage"
            );
            cursor = range.end;
        }
        ensure!(cursor == self.next, "checkpoint frontier inconsistent");
        for range in &self.pending {
            ensure!(
                range.count()? <= crate::backend::MAX_BATCH,
                "pending batch too large"
            );
        }
        ensure!(
            self.evaluated.is_some() == (job.schema >= 3)
                && self.limit == ((job.schema >= 3).then_some(job.work_limit())),
            "invalid evaluated counter schema"
        );
        if let Some(n) = self.evaluated {
            ensure!(
                n <= self.completed_count()? && (self.candidate.is_none() || n > WorkIndex::ZERO),
                "invalid evaluated count for completed slots/candidate"
            );
        }
        if let Some(candidate) = &self.candidate {
            candidate.verify(job)?;
            ensure!(
                self.completed
                    .iter()
                    .any(|r| r.contains(candidate.work_index(job).expect("verified transform"))),
                "candidate outside completed work"
            );
        }
        Ok(())
    }
    pub fn completed_count(&self) -> Result<WorkIndex> {
        self.completed.iter().try_fold(WorkIndex::ZERO, |sum, r| {
            sum.add_offset(r.start.difference(r.end)?)
        })
    }
    pub fn evaluated_count(&self) -> Result<WorkIndex> {
        Ok(self.evaluated.unwrap_or(self.completed_count()?))
    }
    pub fn trials(&self) -> f64 {
        self.evaluated_count().expect("validated coverage").as_f64()
    }
    pub fn allocate(&mut self, count: u32) -> Result<Interval> {
        ensure!(
            (1..=crate::backend::MAX_BATCH).contains(&count),
            "durable interval size is outside the supported range"
        );
        let count = if let Ok(left) = self
            .next
            .distance(self.limit.unwrap_or_else(|| ORDER.into()))
        {
            u64::from(count).min(left) as u32
        } else {
            count
        };
        let range = Interval::new(self.next, count)?;
        self.next = range.end;
        self.pending.push(range.clone());
        Ok(range)
    }
    pub fn complete(&mut self, range: &Interval, count: u32) -> Result<()> {
        self.complete_evaluated(range, count, count)
    }
    pub fn complete_evaluated(
        &mut self,
        range: &Interval,
        count: u32,
        evaluated: u32,
    ) -> Result<()> {
        ensure!(evaluated <= count, "excess evaluated candidates");
        let index = self
            .pending
            .iter()
            .position(|r| r == range)
            .ok_or_else(|| anyhow::anyhow!("unknown assigned interval"))?;
        ensure!(count <= range.count()?, "worker completed excess work");
        self.pending.remove(index);
        if let Some(n) = &mut self.evaluated {
            *n = n.checked_add(evaluated.into())?;
        }
        let end = range.start.checked_add(count as u64)?;
        if count > 0 {
            self.completed.push(Interval {
                start: range.start,
                end,
            });
        }
        if end < range.end {
            self.pending.push(Interval {
                start: end,
                end: range.end,
            });
        }
        self.completed.sort_by_key(|r| r.start);
        let mut merged: Vec<Interval> = vec![];
        for range in self.completed.drain(..) {
            if let Some(last) = merged.last_mut()
                && last.end == range.start
            {
                last.end = range.end;
                continue;
            }
            merged.push(range);
        }
        self.completed = merged;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Results {
    pub schema: u32,
    pub job_hash: String,
    pub candidate: Candidate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_cursor: Option<WorkIndex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_index: Option<WorkIndex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated: Option<WorkIndex>,
}
impl Results {
    pub fn from_checkpoint(job: &Job, checkpoint: &Checkpoint) -> Result<Self> {
        checkpoint.validate(job)?;
        let candidate = checkpoint
            .candidate
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no completed match"))?;
        Ok(Self {
            schema: job.record_schema(),
            job_hash: job.fingerprint()?,
            logical_cursor: (job.schema >= 3).then_some(checkpoint.next),
            logical_index: if job.schema >= 3 {
                Some(candidate.work_index(job)?)
            } else {
                None
            },
            evaluated: if job.schema >= 3 {
                Some(checkpoint.evaluated_count()?)
            } else {
                None
            },
            candidate,
        })
    }
}
