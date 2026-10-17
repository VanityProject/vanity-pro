use super::{BatchResult, Compute};
use crate::{
    crypto::{generator, public_at},
    model::{Candidate, Interval, Job},
    transforms::Transform,
};
use anyhow::{Result, ensure};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
pub struct Cpu {
    pub index: usize,
}
pub struct BatchedCpu {
    pub index: usize,
    pub simd: bool,
    cached: Option<(Job, secp256k1::PublicKey, crate::chains::matching::Compiled)>,
}
impl BatchedCpu {
    pub fn new(index: usize, simd: bool) -> Self {
        Self {
            index,
            simd,
            cached: None,
        }
    }
}

fn candidate(job: &Job, index: crate::work::WorkIndex) -> Result<Candidate> {
    let build = || -> Result<Candidate> {
        let (offset, transform) = job.position(index)?;
        let mut candidate = Candidate {
            offset,
            transform,
            address: String::new(),
        };
        candidate.address = job.profile().candidate(&candidate.point(job)?)?;
        candidate.verify(job)?;
        Ok(candidate)
    };
    build().map_err(|error| super::CorrectnessError(error.to_string()).into())
}

impl Compute for Cpu {
    fn name(&self) -> String {
        format!("cpu:{}", self.index)
    }
    fn diagnostics(&self) -> serde_json::Value {
        serde_json::json!({"engine":"libsecp256k1-reference","hash":"scalar-or-library-hardware"})
    }
    fn self_test(&mut self) -> Result<()> {
        super::correct(
            hex::encode(crate::crypto::address(&generator()))
                == "7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            "CPU known answer failed",
        )?;
        super::correct(
            hex::encode(crate::crypto::keccak(b""))
                == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            "CPU Keccak known answer failed",
        )?;
        Ok(())
    }
    fn run(&mut self, job: &Job, range: &Interval, cancel: &AtomicBool) -> Result<BatchResult> {
        let started = Instant::now();
        ensure!(
            range.end <= job.work_limit(),
            "CPU work exceeds job enumeration"
        );
        job.validate()?;
        let initial = job.point()?;
        let matcher = job.pattern.compiled()?;
        let count = range.count()?;
        let g = generator();
        let mut completed = 0;
        let mut evaluated = 0;
        let mut found = None;
        let mut previous = None;
        let mut point: Option<secp256k1::PublicKey> = None;
        for i in 0..count {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let index = range.start.checked_add(i.into())?;
            let (offset, transform) = job.position(index)?;
            if previous != Some(offset) {
                point = if previous
                    .is_some_and(|p: crate::crypto::Offset| p.checked_add(1).ok() == Some(offset))
                {
                    match point {
                        Some(p) => p.combine(&g).ok(),
                        None => Some(g),
                    }
                } else {
                    public_at(&initial, offset)?
                };
                previous = Some(offset);
            }
            if let Some(p) = point {
                let p = transform.public(&p)?;
                evaluated += 1;
                if found.is_none() && matcher.accepts_payload(&job.profile().payload(&p)?) {
                    found = Some(candidate(job, index)?);
                }
            }
            completed += 1;
        }
        Ok(BatchResult {
            completed,
            evaluated,
            candidate: found,
            seconds: started.elapsed().as_secs_f64(),
        })
    }
}
impl Compute for BatchedCpu {
    fn name(&self) -> String {
        format!("cpu:{}", self.index)
    }
    fn diagnostics(&self) -> serde_json::Value {
        let profile = self
            .cached
            .as_ref()
            .map_or_else(Default::default, |(job, _, _)| job.profile());
        serde_json::json!({"engine":"public-affine-montgomery","group_points":1024,"field":"k256-0.13.4-public-only","hash":super::hash_dispatch(profile,self.simd)})
    }
    fn self_test(&mut self) -> Result<()> {
        let check = || -> Result<()> {
            super::hashes::self_test()?;
            let points =
                super::public_batch::points(&generator(), crate::crypto::Offset::ZERO, 17)?;
            for (i, p) in points.into_iter().enumerate() {
                ensure!(
                    p.map(|p| p.compressed())
                        == public_at(&generator(), crate::crypto::Offset::from_u64(i as u64))?
                            .map(|p| p.serialize()),
                    "public affine self-test failed"
                );
            }
            Ok(())
        };
        check().map_err(|error| super::CorrectnessError(error.to_string()).into())
    }
    fn run(&mut self, job: &Job, range: &Interval, cancel: &AtomicBool) -> Result<BatchResult> {
        self.run_inner(job, range, || cancel.load(Ordering::Relaxed))
    }
}
impl BatchedCpu {
    fn run_inner(
        &mut self,
        job: &Job,
        range: &Interval,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<BatchResult> {
        let started = Instant::now();
        ensure!(
            range.end <= job.work_limit(),
            "CPU work exceeds job enumeration"
        );
        if self
            .cached
            .as_ref()
            .is_none_or(|(cached, _, _)| cached != job)
        {
            job.validate()?;
            self.cached = Some((job.clone(), job.point()?, job.pattern.compiled()?));
        }
        let (_, initial, matcher) = self.cached.as_ref().expect("validated job cache");
        let initial = *initial;
        let profile = job.profile();
        let count = range.count()?;
        let width = job.width();
        let mut completed = 0;
        let mut evaluated = 0;
        let mut found = None;
        let keccak = profile.is_evm() || profile.chain == crate::chains::Chain::Tron;
        let full_coordinates = keccak || profile.address_type == crate::chains::AddressType::P2tr;
        let mut compressed = Vec::with_capacity(if full_coordinates { 0 } else { 6144 });
        let mut uncompressed = Vec::with_capacity(if full_coordinates { 6144 } else { 0 });
        let mut positions = Vec::with_capacity(6144);
        let mut hashes = Vec::with_capacity(6144);
        while completed < count && !cancelled() {
            let cursor = range.start.checked_add(completed.into())?;
            let (start, branch) = cursor.div_rem(width)?;
            let remaining = count - completed;
            let n = ((remaining as usize + branch as usize).div_ceil(width as usize)).min(1024);
            let pts = super::public_batch::points(&initial, start, n).map_err(|error| {
                super::CorrectnessError(format!("public affine group: {error}"))
            })?;
            compressed.clear();
            uncompressed.clear();
            positions.clear();
            hashes.clear();
            'group: for (i, p) in pts.into_iter().enumerate() {
                for b in if i == 0 { branch } else { 0 }..width {
                    if completed == count || cancelled() {
                        break 'group;
                    }
                    if let Some(p) = p {
                        let p = p.transformed(Transform::from_branch(b)?);
                        positions.push(completed);
                        if full_coordinates {
                            uncompressed.push(p.uncompressed());
                        } else {
                            compressed.push(p.compressed());
                        }
                    }
                    completed += 1;
                }
                if completed == count {
                    break;
                }
            }
            evaluated += positions.len() as u32;
            if profile.address_type == crate::chains::AddressType::P2tr {
                for (i, coordinates) in uncompressed.iter().enumerate() {
                    // The affine engine already knows y. Parsing a compressed
                    // key would redundantly recover it with a field square root.
                    let mut bytes = [0; 65];
                    bytes[0] = 4;
                    bytes[1..].copy_from_slice(coordinates);
                    let p = secp256k1::PublicKey::from_slice(&bytes)
                        .map_err(|error| super::CorrectnessError(error.to_string()))?;
                    let payload = crate::chains::taproot_output(&p)?.0;
                    if found.is_none() && matcher.accepts_payload(&payload) {
                        found = Some(candidate(
                            job,
                            range.start.checked_add(positions[i].into())?,
                        )?);
                    }
                }
            } else {
                hashes.resize(positions.len(), [0; 20]);
                if !uncompressed.is_empty() {
                    super::hashes::keccak_many(&uncompressed, &mut hashes, self.simd);
                } else {
                    super::hashes::hash160_many(&compressed, &mut hashes, self.simd);
                }
                if found.is_none() {
                    for (i, payload) in hashes.iter().enumerate() {
                        if matcher.accepts_payload(payload) {
                            found = Some(candidate(
                                job,
                                range.start.checked_add(positions[i].into())?,
                            )?);
                            break;
                        }
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        Ok(BatchResult {
            completed,
            evaluated,
            candidate: found,
            seconds: started.elapsed().as_secs_f64(),
        })
    }
}
#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn rejected_independent_cpu_hit_is_a_cryptographic_fault() {
        let job = Job {
            schema: 3,
            strategy: crate::model::SearchStrategy::EndomorphismV1,
            session_id: uuid::Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: crate::crypto::Pattern::new(&"0".repeat(40), "").unwrap(),
        };
        let error = candidate(&job, crate::work::WorkIndex::ZERO).unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::CorrectnessError>()
                .is_some()
        );
        let mut infinity_job = job.clone();
        infinity_job.public_key = hex::encode(
            generator()
                .negate(&secp256k1::Secp256k1::verification_only())
                .serialize(),
        );
        let error = candidate(&infinity_job, crate::work::WorkIndex::from_u64(6)).unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::CorrectnessError>()
                .is_some()
        );
    }
    #[test]
    fn cancellation_can_stop_inside_a_transformation_family() {
        let job = Job {
            schema: 3,
            strategy: crate::model::SearchStrategy::EndomorphismV1,
            session_id: uuid::Uuid::nil(),
            public_key: hex::encode(generator().serialize()),
            pattern: crate::crypto::Pattern::new(&"0".repeat(40), "").unwrap(),
        };
        let mut checks = 0;
        let result = BatchedCpu::new(0, true)
            .run_inner(
                &job,
                &Interval::new(crate::crypto::Offset::ZERO, 100).unwrap(),
                || {
                    checks += 1;
                    checks >= 5
                },
            )
            .unwrap();
        assert_eq!(result.completed, 3);
        assert_eq!(result.evaluated, 3);
        assert!(result.candidate.is_none());
    }
}
