//! Specialize the shared public curve engine by typed address profile.
use super::*;
use crate::chains::{self, AddressType, Chain, Encoding, Profile};
pub const WIRE_SIZE: usize = 492;
pub fn source(tuning: &Tuning, profile: Profile) -> Result<String> {
    profile.validate()?;
    ensure!(
        !tuning.word_match || profile.is_evm(),
        "Ethereum word matching requires an EVM profile"
    );
    ensure!(
        !tuning.ternary_keccak || profile.is_evm() || profile.chain == Chain::Tron,
        "ternary Keccak requires an EVM or TRON profile"
    );
    if profile.is_evm() {
        return Ok(source_for(tuning));
    }
    ensure!(
        profile.key_family() == chains::KeyFamily::Secp256k1,
        "no private Ed25519 seed computation on OpenCL"
    );
    let mut defines = format!(
        "\n#define CH_LENGTH {}\n#define CH_HASH {}\n",
        profile.payload_len(),
        if profile.chain == Chain::Tron {
            0
        } else if profile.address_type == AddressType::P2tr {
            2
        } else {
            1
        }
    );
    match profile.encoding() {
        Encoding::WarthogHex => {
            defines += "#define CH_ENCODING 3\n#define CH_ALPHABET \"0123456789abcdef\"\n";
        }
        Encoding::Base58 { version, ripple } => {
            defines += &format!(
                "#define CH_ENCODING 0\n#define CH_VERSION {version}\n#define CH_ALPHABET \"{}\"\n",
                if ripple {
                    chains::RIPPLE_ALPHABET
                } else {
                    chains::BITCOIN_ALPHABET
                }
            )
        }
        Encoding::Bech32 { hrp, witness } => {
            defines += &format!(
                "#define CH_ENCODING 1\n#define CH_HRP \"{hrp}\"\n#define CH_HRP_LEN {}\n#define CH_SEPARATOR '1'\n#define CH_WITNESS {}\n#define CH_CHECKSUM {}U\n#define CH_ALPHABET \"{}\"\n",
                hrp.len(),
                witness.map_or(-1, i32::from),
                if witness == Some(1) { 0x2bc830a3u32 } else { 1 },
                chains::BITCOIN_ALPHABET
            )
        }
        Encoding::Cashaddr => {
            defines += &format!(
                "#define CH_ENCODING 2\n#define CH_HRP \"bitcoincash\"\n#define CH_HRP_LEN 11\n#define CH_SEPARATOR ':'\n#define CH_ALPHABET \"{}\"\n",
                chains::BITCOIN_ALPHABET
            )
        }
        _ => anyhow::bail!("unsupported OpenCL address profile"),
    }
    let mut hashes = include_str!("../../kernels/chains.cl").to_string();
    if tuning.fixed_hash
        && profile.address_type != AddressType::P2tr
        && profile.chain != Chain::Tron
    {
        hashes = hashes.replace(
            "/* TAPROOT_POWERS */",
            &format!(
                "#define CH_FIXED_HASH 1\n{}",
                include_str!("../../kernels/hash160_fixed.cl")
            ),
        );
        hashes = hashes.replace(
            "ch_sha(input,33,sha);ch_ripemd(sha,out);",
            "ch_hash160_fixed(x,y,out);",
        );
    }
    if profile.address_type == AddressType::P2tr {
        let secp = secp256k1::Secp256k1::verification_only();
        let mut xs = vec![];
        let mut ys = vec![];
        for bit in 0..256 {
            let mut bytes = [0; 32];
            bytes[31 - bit / 8] = 1 << (bit % 8);
            let scalar = secp256k1::Scalar::from_be_bytes(bytes)?;
            let point = generator()
                .mul_tweak(&secp, &scalar)?
                .serialize_uncompressed();
            for (out, part) in [(&mut xs, &point[1..33]), (&mut ys, &point[33..65])] {
                for word in part.as_chunks::<4>().0.iter().rev() {
                    out.push(u32::from_be_bytes(*word));
                }
            }
        }
        let arrays = format!(
            "constant uint CH_GX[2048]={{{}}};\nconstant uint CH_GY[2048]={{{}}};",
            xs.iter()
                .map(|v| format!("0x{v:08x}U"))
                .collect::<Vec<_>>()
                .join(","),
            ys.iter()
                .map(|v| format!("0x{v:08x}U"))
                .collect::<Vec<_>>()
                .join(",")
        );
        hashes = hashes.replace("/* TAPROOT_POWERS */", &arrays);
    }
    let mut common = source_for(tuning);
    common = common
        .replace("void eth_address(", "void legacy_eth_address(")
        .replace("int matching(", "int legacy_matching(");
    common = common
        .replace(
            "uchar addr[20];eth_address(x,y,addr);",
            "uchar addr[33];chain_address(x,y,addr);",
        )
        .replace(
            "if(matching(addr,pattern,prefix,suffix)",
            "if(chain_matching(addr,pattern,prefix,suffix)",
        );
    let position = common
        .find("kernel void search(")
        .context("missing shared search kernel")?;
    common.insert_str(position, &format!("{defines}\n{hashes}\n"));
    Ok(common)
}
pub fn wire(pattern: &Pattern) -> Result<Vec<u8>> {
    let c = pattern.compiled()?;
    if pattern.profile.is_evm() {
        let mut v: Vec<_> = pattern
            .prefix
            .bytes()
            .chain(pattern.suffix.bytes())
            .map(|b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 })
            .collect();
        if v.is_empty() {
            v.push(0);
        }
        v.resize(WIRE_SIZE, 0);
        v[64..84].copy_from_slice(&c.mask);
        v[84..104].copy_from_slice(&c.value);
        return Ok(v);
    }
    ensure!(
        c.prefix_exact && c.ranges.len() <= 8 && c.suffix.len() <= 96,
        "pattern exceeds compiled GPU matcher bounds"
    );
    let mut out = vec![0; WIRE_SIZE];
    out[0] = c.mask.len() as u8;
    out[1] = c.ranges.len() as u8;
    out[2] = c.suffix.len() as u8;
    out[4..4 + c.mask.len()].copy_from_slice(&c.mask);
    out[36..36 + c.value.len()].copy_from_slice(&c.value);
    for (i, (lo, hi)) in c.ranges.iter().enumerate() {
        out[68 + i * 40..88 + i * 40].copy_from_slice(lo);
        out[88 + i * 40..108 + i * 40].copy_from_slice(hi);
    }
    out[388..388 + c.suffix.len()].copy_from_slice(c.suffix.as_bytes());
    Ok(out)
}
pub(super) fn candidate(
    job: &Job,
    offset: impl Into<crate::work::WorkIndex>,
    actual: &[u8],
) -> Result<Candidate> {
    let offset = Offset::try_from(offset.into())?;
    let point = public_at(&job.point()?, offset)?.context("GPU selected infinity")?;
    let expected = job.profile().payload(&point)?;
    correct(
        actual == &expected[..20],
        "GPU payload disagrees with independently reconstructed public key",
    )?;
    let found = Candidate {
        transform: crate::transforms::Transform::Identity,
        offset,
        address: job.profile().candidate(&point)?,
    };
    found
        .verify(job)
        .map_err(|e| CorrectnessError(e.to_string()))?;
    Ok(found)
}
impl Opencl {
    pub(super) fn chain_self_test(&mut self) -> Result<()> {
        let started = Instant::now();
        let profile = self.chain_profile;
        // Probe complete payloads, including all 32 Taproot output-key bytes.
        let points: Vec<_> = (0..33)
            .map(|i| {
                public_at(&generator(), Offset::from_u64(i)).and_then(|p| p.context("test point"))
            })
            .collect::<Result<_>>()?;
        let mut input = Vec::with_capacity(points.len() * 64);
        for p in &points {
            input.extend_from_slice(&p.serialize_uncompressed()[1..]);
        }
        let mut output = vec![0u8; points.len() * 33];
        // SAFETY: bounded public byte arrays match chain_probe's 64-byte input and
        // 33-byte output records; blocking reads complete before buffers are dropped.
        unsafe {
            let mut ib = Buffer::<u8>::create(
                &self.context,
                CL_MEM_READ_ONLY,
                input.len(),
                ptr::null_mut(),
            )?;
            let ob = Buffer::<u8>::create(
                &self.context,
                CL_MEM_WRITE_ONLY,
                output.len(),
                ptr::null_mut(),
            )?;
            self.queue
                .enqueue_write_buffer(&mut ib, CL_BLOCKING, 0, &input, &[])?;
            let kernel = Kernel::create(&self._program, "chain_probe")?;
            let count = points.len() as u32;
            ExecuteKernel::new(&kernel)
                .set_arg(&ib)
                .set_arg(&ob)
                .set_arg(&count)
                .set_global_work_size(points.len())
                .enqueue_nd_range(&self.queue)?;
            self.queue
                .enqueue_read_buffer(&ob, CL_BLOCKING, 0, &mut output, &[])?;
        }
        for (i, p) in points.iter().enumerate() {
            let payload = profile.payload(p)?;
            correct(
                output[i * 33..i * 33 + payload.len()] == payload && output[i * 33 + 32] == 1,
                "complete GPU chain payload known-answer mismatch",
            )?;
        }
        let address = profile.address(&generator())?;
        let broad_prefix = if profile.fixed_prefix().is_empty() {
            &address[..1]
        } else {
            profile.fixed_prefix()
        };
        let patterns = [
            Pattern::for_profile(profile, broad_prefix, "")?,
            Pattern::for_profile(profile, &address, "")?,
            Pattern::for_profile(profile, "", &address[address.len() - 1..])?,
            Pattern::for_profile(profile, "", &address[address.len() - 8..])?,
        ];
        let negative = generator().negate(&secp256k1::Secp256k1::verification_only());
        for initial in [generator(), negative] {
            for start in [
                Offset::ZERO,
                Offset::from_u64(65),
                Offset::from_u64(4096),
                Offset::from_u64(4161),
                Offset::from_u64(65),
                Offset::from_u64(65).difference(crate::crypto::ORDER)?,
            ] {
                for pattern in &patterns {
                    if self.tuning.curve != Curve::Jacobian {
                        recurrence::compare(
                            self,
                            initial,
                            start,
                            65,
                            self.tuning.max_lanes.min(32),
                            pattern.clone(),
                        )?;
                    } else {
                        let job = Job {
                            strategy: crate::model::SearchStrategy::Linear,
                            schema: crate::model::JOB_SCHEMA,
                            session_id: Uuid::nil(),
                            public_key: hex::encode(initial.serialize()),
                            pattern: pattern.clone(),
                        };
                        let range = Interval::new(start, 65)?;
                        let actual = self.evaluate(&job, &range, true)?;
                        let matcher = pattern.compiled()?;
                        let mut expected =
                            vec![u32::MAX; 65usize.div_ceil(self.tuning.inversion_width)];
                        for i in 0..65 {
                            if let Some(p) =
                                public_at(&initial, range.start.checked_add(i as u64)?)?
                            {
                                let payload = profile.payload(&p)?;
                                correct(
                                    actual.addresses[i * 20..i * 20 + 20] == payload[..20],
                                    "GPU diagnostic payload mismatch",
                                )?;
                                correct(
                                    actual.points[i * 65..i * 65 + 65]
                                        == p.serialize_uncompressed(),
                                    "GPU diagnostic public point mismatch",
                                )?;
                                if matcher.accepts_payload(&payload) {
                                    let lane = i / self.tuning.inversion_width;
                                    expected[lane] = expected[lane].min(i as u32);
                                }
                            }
                        }
                        correct(actual.hits == expected, "GPU chain matching mismatch")?;
                    }
                }
            }
        }
        self.validated = true;
        self.orbit_self_test()?;
        self.self_test_seconds = started.elapsed().as_secs_f64();
        self.public_state = None;
        self.recurrence_state = None;
        Ok(())
    }
}
