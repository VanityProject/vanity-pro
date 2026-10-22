//! Trusted multi-chain key custody. Decrypted scalars and Ed25519 seeds stay here.
use super::*;
use crate::{
    chains::{self, AddressType, Chain, KeyFamily, Profile},
    crypto::Offset,
    model::{Checkpoint, JOB_SCHEMA},
};
use base64::Engine;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey};
use secp256k1::{Keypair, Message, Parity};
use sha2::Digest;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    schema: u32,
    id: Uuid,
    profile: Profile,
    role: String,
    job_hash: String,
    public_key: String,
    address: String,
    key_representation: String,
    export_format: String,
    descriptor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    metadata: Metadata,
    cipher: String,
    kdf: String,
    iterations: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}
struct Material(Zeroizing<[u8; 32]>);
impl Material {
    fn fresh() -> Result<Self> {
        Ok(Self(Zeroizing::new(random::<32>()?)))
    }
    fn secp(&self) -> Result<Secret> {
        Ok(Secret(SecretKey::from_byte_array(*self.0)?))
    }
    fn public(&self, p: Profile) -> Result<Vec<u8>> {
        Ok(match p.key_family() {
            KeyFamily::Secp256k1 => point(&self.secp()?).serialize().to_vec(),
            KeyFamily::Ed25519 => SigningKey::from_bytes(&self.0)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        })
    }
    fn address(&self, p: Profile) -> Result<String> {
        if p.key_family() == KeyFamily::Secp256k1 {
            p.address(&point(&self.secp()?))
        } else {
            p.encode(&self.public(p)?)
        }
    }
    fn proof(&self, p: Profile) -> Result<()> {
        let msg = Sha256::digest(b"Vanity Pro v0.4 offline wallet recovery proof");
        match p.key_family() {
            KeyFamily::Ed25519 => {
                let key = SigningKey::from_bytes(&self.0);
                let sig = key.sign(&msg);
                key.verifying_key().verify_strict(&msg, &sig)?;
            }
            KeyFamily::Secp256k1 => {
                let secp = Secp256k1::new();
                let key = self.secp()?;
                if p.address_type == AddressType::P2tr {
                    let mut normalized = Secret(key.0);
                    if point(&normalized).x_only_public_key().1 == Parity::Odd {
                        normalized.0 = normalized.0.negate();
                    }
                    let (output, tweak) = chains::taproot_output(&point(&key))?;
                    let tweaked = Secret(normalized.0.add_tweak(&tweak)?);
                    let pair = Keypair::from_secret_key(&secp, &tweaked.0);
                    let sig = secp.sign_schnorr_no_aux_rand(&msg, &pair);
                    secp.verify_schnorr(
                        &sig,
                        &msg,
                        &secp256k1::XOnlyPublicKey::from_byte_array(output)?,
                    )?;
                } else {
                    let msg = Message::from_digest(msg.into());
                    let sig = secp.sign_ecdsa(msg, &key.0);
                    secp.verify_ecdsa(msg, &sig, &point(&key))?;
                }
            }
        }
        Ok(())
    }
}
fn metadata(key: &Material, job: &Job, role: &str, id: Uuid) -> Result<Metadata> {
    let p = job.profile();
    let public = key.public(p)?;
    let addr = key.address(p)?;
    let descriptor = public_descriptor(p, &public)?;
    Ok(Metadata {
        schema: 1,
        id,
        profile: p,
        role: role.into(),
        job_hash: job.fingerprint()?,
        public_key: hex::encode(public),
        address: addr,
        key_representation: match p.key_family() {
            KeyFamily::Secp256k1 => "secp256k1-scalar",
            KeyFamily::Ed25519 => "ed25519-seed",
        }
        .into(),
        export_format: p.info().export.into(),
        descriptor,
    })
}
fn validate_metadata(m: &Metadata, key: &Material) -> Result<()> {
    m.profile.validate()?;
    ensure!(
        m.schema == 1
            && matches!(m.role.as_str(), "seed" | "hit" | "wallet")
            && m.job_hash.len() == 64
            && m.job_hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid wallet metadata"
    );
    ensure!(
        m.key_representation
            == if m.profile.key_family() == KeyFamily::Ed25519 {
                "ed25519-seed"
            } else {
                "secp256k1-scalar"
            },
        "key representation mismatch"
    );
    ensure!(
        m.export_format == m.profile.info().export,
        "export profile mismatch"
    );
    let public = key.public(m.profile)?;
    ensure!(
        m.public_key == hex::encode(&public) && m.address == key.address(m.profile)?,
        "wallet key/address metadata mismatch"
    );
    ensure!(
        m.descriptor == public_descriptor(m.profile, &public)?,
        "descriptor mismatch"
    );
    key.proof(m.profile)
}
fn seal_with(
    key: &Material,
    m: Metadata,
    salt_bytes: [u8; 32],
    derived: &[u8; 32],
) -> Result<Envelope> {
    let nonce = random::<24>()?;
    let aad = serde_json::to_vec(&m)?;
    let cipher = XChaCha20Poly1305::new(derived.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key.0.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok(Envelope {
        format: "vanity-pro-wallet-v1".into(),
        metadata: m,
        cipher: "xchacha20-poly1305".into(),
        kdf: "pbkdf2-hmac-sha256".into(),
        iterations: ITERATIONS,
        salt: hex::encode(salt_bytes),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}
fn seal(key: &Material, m: Metadata, password: &str) -> Result<Envelope> {
    ensure!(password.len() >= 12, "use a password of at least 12 bytes");
    let salt = random::<32>()?;
    let mut derived = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut *derived);
    seal_with(key, m, salt, &derived)
}
fn open_with(store: &Envelope, derived: &[u8; 32]) -> Result<Material> {
    let nonce = decode::<24>(&store.nonce)?;
    let ciphertext = hex::decode(&store.ciphertext)?;
    ensure!(ciphertext.len() == 48, "invalid encrypted key size");
    let aad = serde_json::to_vec(&store.metadata)?;
    let cipher = XChaCha20Poly1305::new(derived.into());
    let clear = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("incorrect password or corrupted wallet metadata"))?,
    );
    let mut bytes = Zeroizing::new([0; 32]);
    bytes.copy_from_slice(&clear);
    let key = Material(bytes);
    validate_metadata(&store.metadata, &key)?;
    Ok(key)
}
fn derive(store: &Envelope, password: &str) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        store.format == "vanity-pro-wallet-v1"
            && store.cipher == "xchacha20-poly1305"
            && store.kdf == "pbkdf2-hmac-sha256"
            && store.iterations == ITERATIONS,
        "unsupported encrypted wallet format or KDF"
    );
    let salt = decode::<32>(&store.salt)?;
    let mut derived = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, store.iterations, &mut *derived);
    Ok(derived)
}
fn open(store: &Envelope, password: &str) -> Result<Material> {
    open_with(store, &*derive(store, password)?)
}
pub(super) fn initialize_with_strategy(
    session: &Path,
    pattern: Pattern,
    password: &str,
    strategy: crate::model::SearchStrategy,
) -> Result<Job> {
    pattern.validate()?;
    ensure!(
        pattern.profile.key_family() != KeyFamily::Ed25519
            || strategy == crate::model::SearchStrategy::Linear,
        "Ed25519 requires independent seed enumeration"
    );
    ensure!(password.len() >= 12, "use a password of at least 12 bytes");
    let key = if pattern.profile.key_family() == KeyFamily::Secp256k1 {
        Material(Zeroizing::new(generate()?.0.secret_bytes()))
    } else {
        Material::fresh()?
    };
    let job = Job {
        strategy,
        schema: if pattern.profile.key_family() == KeyFamily::Ed25519 {
            2
        } else {
            JOB_SCHEMA
        },
        session_id: Uuid::new_v4(),
        public_key: hex::encode(key.public(pattern.profile)?),
        pattern,
    };
    job.validate()?;
    let store = seal(
        &key,
        metadata(&key, &job, "seed", job.session_id)?,
        password,
    )?;
    ensure!(
        open(&store, password)?.public(job.profile())? == key.public(job.profile())?,
        "encrypted seed verification failed"
    );
    storage::create_directory(session, false)
        .context("session must be a new directory with an existing parent")?;
    storage::private(session)?;
    let _lock = storage::lock_session(session)?;
    storage::write_json(&session.join("seed.keystore.json"), &store, false)?;
    storage::write_json(&session.join("job.json"), &job, false)?;
    storage::save_checkpoint(&session.join("checkpoint.json"), &Checkpoint::new(&job)?)?;
    Ok(job)
}
fn reconstruct(session: &Path, job: &Job, result: &Results, password: &str) -> Result<Material> {
    let seed: Envelope = storage::read_json(&session.join("seed.keystore.json"))?;
    ensure!(
        seed.metadata.role == "seed"
            && seed.metadata.id == job.session_id
            && seed.metadata.job_hash == job.fingerprint()?
            && seed.metadata.profile == job.profile(),
        "seed is bound to another job/profile"
    );
    let initial = open(&seed, password)?;
    ensure!(
        hex::encode(initial.public(job.profile())?) == job.public_key,
        "seed/public job mismatch"
    );
    let key = if job.profile().key_family() == KeyFamily::Secp256k1 {
        let k = reconstruct_secp(&initial.secp()?, &result.candidate)?;
        Material(Zeroizing::new(k.0.secret_bytes()))
    } else {
        let saved: EdHit = storage::read_json(&session.join("hit.keystore.json"))?;
        ensure!(
            saved.candidate == result.candidate,
            "encrypted hit candidate mismatch"
        );
        let hit = saved.envelope;
        ensure!(
            hit.metadata.role == "hit"
                && hit.metadata.job_hash == job.fingerprint()?
                && hit.metadata.profile == job.profile(),
            "hit belongs to another job"
        );
        let key = open(&hit, password)?;
        ensure!(
            hit.metadata.address == result.candidate.address,
            "encrypted hit/result mismatch"
        );
        key
    };
    let expected = job.profile().display_candidate(&result.candidate.address)?;
    ensure!(
        key.address(job.profile())? == expected,
        "private key recovery does not match the verified result"
    );
    key.proof(job.profile())?;
    Ok(key)
}
pub(super) fn validate_password(session: &Path, password: &str) -> Result<String> {
    let _lock = storage::lock_session(session)?;
    let (job, r) = finalization_inputs(session)?;
    reconstruct(session, &job, &r, password)?.address(job.profile())
}
pub(super) fn finalize(
    session: &Path,
    out: &Path,
    seed_password: &str,
    wallet_password: &str,
) -> Result<String> {
    let _lock = storage::lock_session(session)?;
    let _output_guard = storage::guard(out)?;
    let (job, r) = finalization_inputs(session)?;
    ensure!(!storage::exists(out)?, "wallet output already exists");
    let key = reconstruct(session, &job, &r, seed_password)?;
    let reserve = session.join("finalization.json");
    if !storage::exists(&reserve)? {
        storage::write_json(
            &reserve,
            &Reservation {
                schema: SCHEMA,
                job_hash: r.job_hash,
                candidate: r.candidate,
            },
            false,
        )?;
    }
    if job.profile().is_evm() {
        let mut store = encrypt(&key.secp()?, wallet_password, Uuid::new_v4())?;
        let m = metadata(&key, &job, "wallet", store.id)?;
        store.vanity_pro = Some(sign_evm(&store, m, &key.secp()?)?);
        storage::write_json(out, &store, false)?;
    } else {
        let m = metadata(&key, &job, "wallet", Uuid::new_v4())?;
        let store = seal(&key, m, wallet_password)?;
        storage::write_json(out, &store, false)?;
    }
    let addr = super::verify_wallet(out, wallet_password, Some(&job.pattern))?;
    ensure!(
        addr == key.address(job.profile())?,
        "written wallet verification failed"
    );
    Ok(addr)
}
pub(super) fn verify(path: &Path, password: &str, pattern: Option<&Pattern>) -> Result<String> {
    let store: Envelope = storage::read_json(path)?;
    ensure!(
        store.metadata.role == "wallet",
        "this is a session seed/hit, finalize it before wallet import"
    );
    let key = open(&store, password)?;
    if let Some(p) = pattern {
        ensure!(
            p.profile == store.metadata.profile,
            "wallet/pattern profile mismatch"
        );
        ensure!(
            p.compiled()?.matches_text(&key.address(p.profile)?),
            "wallet does not match pattern"
        );
    }
    key.address(store.metadata.profile)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvmBinding {
    metadata: Metadata,
    signature: String,
}
fn evm_digest(store: &Keystore, m: &Metadata) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json::to_vec(&(
        store.version,
        store.id,
        &store.address,
        &store.crypto,
        m,
    ))?)
    .into())
}
fn sign_evm(store: &Keystore, metadata: Metadata, key: &Secret) -> Result<EvmBinding> {
    let digest = evm_digest(store, &metadata)?;
    Ok(EvmBinding {
        metadata,
        signature: hex::encode(
            Secp256k1::new()
                .sign_ecdsa(Message::from_digest(digest), &key.0)
                .serialize_compact(),
        ),
    })
}
pub(super) fn verify_evm(store: &Keystore, key: &Secret) -> Result<Profile> {
    if let Some(b) = &store.vanity_pro {
        ensure!(
            b.metadata.profile.is_evm() && b.metadata.role == "wallet" && b.metadata.id == store.id,
            "invalid EVM export metadata"
        );
        let material = Material(Zeroizing::new(key.0.secret_bytes()));
        validate_metadata(&b.metadata, &material)?;
        let sig = secp256k1::ecdsa::Signature::from_compact(&decode::<64>(&b.signature)?)?;
        Secp256k1::verification_only().verify_ecdsa(
            Message::from_digest(evm_digest(store, &b.metadata)?),
            &sig,
            &point(key),
        )?;
        Ok(b.metadata.profile)
    } else {
        Ok(Profile::default())
    }
}
fn public_descriptor(p: Profile, public: &[u8]) -> Result<Option<String>> {
    if !matches!(
        p.chain,
        Chain::Bitcoin | Chain::Litecoin | Chain::Dogecoin | Chain::BitcoinCash
    ) {
        return Ok(None);
    }
    let body = if p.address_type == AddressType::P2tr {
        format!("tr({})", hex::encode(&public[1..]))
    } else {
        format!(
            "{}({})",
            if p.address_type == AddressType::P2wpkh {
                "wpkh"
            } else {
                "pkh"
            },
            hex::encode(public)
        )
    };
    Ok(Some(descriptor_checksum(&body)?))
}
// BIP380 descriptor checksum, public formatting only.
fn descriptor_checksum(body: &str) -> Result<String> {
    const INPUT: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const OUTPUT: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn step(c: u64, v: u64) -> u64 {
        let top = c >> 35;
        let mut out = ((c & 0x7ffffffff) << 5) ^ v;
        for (i, g) in [
            0xf5dee51989,
            0xa9fdca3312,
            0x1bab10e32d,
            0x3706b1677a,
            0x644d626ffd,
        ]
        .iter()
        .enumerate()
        {
            if (top >> i) & 1 != 0 {
                out ^= g;
            }
        }
        out
    }
    let mut c = 1u64;
    let mut cls = 0;
    let mut count = 0;
    for b in body.chars() {
        let pos = INPUT.find(b).context("invalid descriptor character")? as u64;
        c = step(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        count += 1;
        if count == 3 {
            c = step(c, cls);
            cls = 0;
            count = 0;
        }
    }
    if count > 0 {
        c = step(c, cls);
    }
    for _ in 0..8 {
        c = step(c, 0);
    }
    c ^= 1;
    let check: String = (0..8)
        .map(|i| OUTPUT.as_bytes()[((c >> (5 * (7 - i))) & 31) as usize] as char)
        .collect();
    Ok(format!("{body}#{check}"))
}
fn native_wif(version: u8, scalar: &[u8; 32]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(38));
    bytes.push(version);
    bytes.extend_from_slice(scalar);
    bytes.push(1);
    let first = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(&*bytes)));
    let second = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(first.as_slice())));
    bytes.extend_from_slice(&second[..4]);
    Zeroizing::new(bs58::encode(&*bytes).into_string())
}
fn native_stellar(seed: &[u8; 32]) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(35));
    bytes.push(144);
    bytes.extend_from_slice(seed);
    let mut crc = 0u16;
    for byte in bytes.iter() {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    bytes.extend_from_slice(&crc.to_le_bytes());
    Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&bytes))
}
/// Explicit plaintext export only. This API writes a private, no-clobber file and returns public data.
pub(super) fn export_native(path: &Path, password: &str, out: &Path) -> Result<String> {
    let _output_guard = storage::guard(out)?;
    ensure!(
        !storage::exists(out)?,
        "native export output already exists"
    );
    let value: serde_json::Value = storage::read_json(path)?;
    let (key, p) = if value.get("format").is_some() {
        let store: Envelope = serde_json::from_value(value)?;
        ensure!(
            store.metadata.role == "wallet",
            "finalize the session before native export"
        );
        (open(&store, password)?, store.metadata.profile)
    } else {
        let store: Keystore = serde_json::from_value(value)?;
        let k = decrypt(&store, password)?;
        let p = verify_evm(&store, &k)?;
        (Material(Zeroizing::new(k.0.secret_bytes())), p)
    };
    let public = key.public(p)?;
    let addr = key.address(p)?;
    let wart_dapp_database = out
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            ["db", "db3", "sqlite"]
                .iter()
                .any(|name| extension.eq_ignore_ascii_case(name))
        });
    if wart_dapp_database {
        ensure!(
            p.chain == Chain::Warthog,
            "Wart Dapp database export requires a Warthog wallet"
        );
        let database = super::warthog_dapp::database(&key.0, &addr, password)?;
        storage::write_bytes(out, &database, false)?;
        return Ok(addr);
    }
    let native = Zeroizing::new(match p.chain {
        Chain::Warthog => {
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct WarthogWallet<'a> {
                address: &'a str,
                private_key: &'a str,
                public_key: &'a str,
            }
            let scalar = Zeroizing::new(hex::encode(key.0.as_ref()));
            serde_json::to_vec_pretty(&WarthogWallet {
                address: &addr,
                private_key: &scalar,
                public_key: &hex::encode(&public),
            })?
        }
        Chain::Solana => {
            let mut pair = Zeroizing::new(key.0.to_vec());
            pair.extend_from_slice(&public);
            serde_json::to_vec(&*pair)?
        }
        Chain::Stellar => {
            let encoded = native_stellar(&key.0);
            encoded.as_bytes().to_vec()
        }
        Chain::Algorand => {
            let mut pair = Zeroizing::new(key.0.to_vec());
            pair.extend_from_slice(&public);
            base64::engine::general_purpose::STANDARD
                .encode(&*pair)
                .into_bytes()
        }
        Chain::Bitcoin | Chain::Litecoin | Chain::Dogecoin | Chain::BitcoinCash => {
            let wif = native_wif(
                match p.chain {
                    Chain::Litecoin => 176,
                    Chain::Dogecoin => 158,
                    _ => 128,
                },
                &key.0,
            );
            let body = Zeroizing::new(format!(
                "{}({})",
                if p.address_type == AddressType::P2tr {
                    "tr"
                } else if p.address_type == AddressType::P2wpkh {
                    "wpkh"
                } else {
                    "pkh"
                },
                wif.as_str()
            ));
            let descriptor = Zeroizing::new(descriptor_checksum(&body)?);
            #[derive(Serialize)]
            struct NativeWif<'a> {
                profile: Profile,
                address: &'a str,
                wif: &'a str,
                descriptor: &'a str,
                key_origin: &'a str,
            }
            serde_json::to_vec_pretty(&NativeWif {
                profile: p,
                address: &addr,
                wif: &wif,
                descriptor: &descriptor,
                key_origin: "independent random scalar; no mnemonic or HD derivation path",
            })?
        }
        Chain::Xrp => {
            let scalar = Zeroizing::new(hex::encode(key.0.as_ref()));
            format!("00{}", scalar.as_str()).into_bytes()
        }
        _ => hex::encode(key.0.as_ref()).into_bytes(),
    });
    storage::write_bytes(out, &native, false)?;
    Ok(addr)
}
use crate::coordinator::{Config, Mode, Progress};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdHit {
    envelope: Envelope,
    candidate: Candidate,
}
fn ed_progress(
    job: &Job,
    count: u64,
    elapsed: f64,
    candidate: Option<Candidate>,
    saved: bool,
    config: &Config,
) -> Progress {
    let (table, hash) = crate::backend::qualification::ed(config, job.profile());
    Progress {
        session_id: job.session_id.to_string(),
        prefix: job.pattern.prefix.clone(),
        suffix: job.pattern.suffix.clone(),
        candidates: count as f64,
        candidates_exact: count.to_string(),
        elapsed_seconds: elapsed,
        candidates_per_second: count as f64 / elapsed.max(1e-9),
        expected_trials: 1.0 / job.pattern.probability(),
        expected_remaining_seconds: None,
        success_probability: job.pattern.success_probability(count as f64),
        checkpoint: if saved { "saved" } else { "in memory" }.into(),
        workers: vec![crate::coordinator::WorkerStats {
            name: format!("Ed25519 CPU ({} workers)", config.threads),
            candidates: count,
            base_point_slots: 0,
            batches: 0,
            seconds: elapsed,
            peak_per_second: count as f64 / elapsed.max(1e-9),
            status: if saved { "saved" } else { "searching" }.into(),
            diagnostics: serde_json::json!({"engine":"trusted-ed25519-fixed-base", "table":table, "hash_mode":hash, "seed_microbatch":32, "search_strategy":"independent-random-seeds"}),
        }],
        errors: vec![],
        candidate,
        orchestration: None,
    }
}
/// Standard random Ed25519 seeds; no offset arithmetic and no seed material in Compute/OpenCL.
pub(super) fn search_ed(
    job_path: &Path,
    config: &Config,
    cancel: Arc<AtomicBool>,
    password: &str,
) -> Result<Progress> {
    ensure!(
        !matches!(config.mode, Mode::Opencl),
        "Ed25519 supports CPU mode only; select Auto or CPU"
    );
    ensure!(
        (1..=256).contains(&config.threads)
            && config.max_candidates != Some(0)
            && config.max_seconds.is_none_or(|s| s.is_finite() && s > 0.0),
        "invalid CPU search limits"
    );
    let session = job_path
        .parent()
        .context("job requires a session directory")?;
    let _lock = storage::lock_session(session)?;
    let job: Job = storage::read_json(job_path)?;
    job.validate()?;
    ensure!(
        job.profile().key_family() == KeyFamily::Ed25519,
        "not an Ed25519 job"
    );
    let mut cp = storage::load_checkpoint(&session.join("checkpoint.json"), &job)?;
    ensure!(
        cp.fault.is_none(),
        "session is blocked by a correctness failure"
    );
    let store: Envelope = storage::read_json(&session.join("seed.keystore.json"))?;
    ensure!(
        store.metadata.role == "seed"
            && store.metadata.job_hash == job.fingerprint()?
            && store.metadata.profile == job.profile()
            && store.metadata.id == job.session_id,
        "seed belongs to another job"
    );
    let derived = Arc::new(derive(&store, password)?);
    let initial = open_with(&store, &derived)?;
    ensure!(
        hex::encode(initial.public(job.profile())?) == job.public_key,
        "seed/public job mismatch"
    );
    drop(initial);
    // A hit is durable before public statistics/results. Recover it after an
    // interruption without generating or discarding another candidate key.
    let hit_path = session.join("hit.keystore.json");
    if storage::exists(&hit_path)? {
        let saved: EdHit = storage::read_json(&hit_path)?;
        let m = &saved.envelope.metadata;
        ensure!(
            m.role == "hit" && m.job_hash == job.fingerprint()? && m.profile == job.profile(),
            "saved hit belongs to another job"
        );
        ensure!(
            saved.envelope.salt == store.salt
                && saved.envelope.format == store.format
                && saved.envelope.cipher == store.cipher
                && saved.envelope.kdf == store.kdf
                && saved.envelope.iterations == store.iterations,
            "saved hit encryption parameters disagree with session"
        );
        let key = open_with(&saved.envelope, &derived)?;
        saved.candidate.verify(&job)?;
        ensure!(
            cp.candidate.as_ref().is_none_or(|c| c == &saved.candidate),
            "public checkpoint disagrees with authenticated hit"
        );
        ensure!(
            m.address == saved.candidate.address
                && key.address(job.profile())? == saved.candidate.address,
            "saved encrypted hit disagrees with public candidate"
        );
        let end = saved.candidate.offset.checked_add(1)?;
        cp.next = cp.next.max(end.into());
        cp.pending.clear();
        cp.completed = vec![crate::model::Interval {
            start: Offset::ZERO.into(),
            end: cp.next,
        }];
        cp.candidate = Some(saved.candidate.clone());
        cp.validate(&job)?;
        storage::save_checkpoint(&session.join("checkpoint.json"), &cp)?;
        storage::write_json(
            &session.join("results.json"),
            &Results::from_checkpoint(&job, &cp)?,
            true,
        )?;
        return Ok(ed_progress(
            &job,
            cp.trials() as u64,
            cp.elapsed_seconds,
            cp.candidate,
            true,
            config,
        ));
    }
    ensure!(
        cp.candidate.is_none(),
        "public candidate has no authenticated encrypted hit"
    );
    let previous = crate::work::WorkIndex::ZERO.distance(cp.evaluated_count()?)?;
    let started = Instant::now();
    let count = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicBool::new(false));
    let matcher = Arc::new(job.pattern.compiled()?);
    let job = Arc::new(job);
    let salt = decode::<32>(&store.salt)?;
    let (tx, rx) = mpsc::channel::<Result<EdHit>>();
    let mut handles = vec![];
    for _ in 0..config.threads {
        let (tx, derived, count, finished, found, cancel, matcher, job) = (
            tx.clone(),
            derived.clone(),
            count.clone(),
            finished.clone(),
            found.clone(),
            cancel.clone(),
            matcher.clone(),
            job.clone(),
        );
        let max = config.max_candidates;
        let seconds = config.max_seconds;
        let (table, hash) = crate::backend::qualification::ed(config, job.profile());
        handles.push(std::thread::spawn(move || {
            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                super::ed_batch::self_test(table, hash)?;
                loop {
                    if cancel.load(Ordering::Relaxed)
                        || found.load(Ordering::Relaxed)
                        || seconds.is_some_and(|s| started.elapsed().as_secs_f64() >= s)
                    {
                        break;
                    }
                    let entropy = Zeroizing::new(random::<8192>()?);
                    for group in entropy.as_chunks::<1024>().0 {
                        if cancel.load(Ordering::Relaxed)
                            || found.load(Ordering::Relaxed)
                            || seconds.is_some_and(|s| started.elapsed().as_secs_f64() >= s)
                        {
                            return Ok(());
                        }
                        let Some((ticket, size)) = super::ed_batch::reserve(&count, max) else {
                            return Ok(());
                        };
                        let mut seeds = Zeroizing::new([[0; 32]; 32]);
                        for (i, chunk) in group.as_chunks::<32>().0.iter().take(size).enumerate() {
                            seeds[i].copy_from_slice(chunk);
                        }
                        let mut public_keys = [[0; 32]; 32];
                        super::ed_batch::derive(
                            &seeds[..size],
                            &mut public_keys[..size],
                            table,
                            hash,
                        );
                        let mut matches = [false; 32];
                        for i in 0..size {
                            matches[i] = matcher.accepts_payload(&public_keys[i]);
                        }
                        finished.fetch_add(size as u64, Ordering::Relaxed);
                        for i in 0..size {
                            let mut seed = Zeroizing::new([0; 32]);
                            seed.copy_from_slice(&seeds[i]);
                            let key = Material(seed);
                            let public = public_keys[i];
                            let hit = matches[i];

                            if hit
                                && found
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                            {
                                crate::backend::correct(
                                    key.public(job.profile())?.as_slice() == public,
                                    "optimized Ed25519 public derivation mismatch",
                                )?;
                                key.proof(job.profile())?;
                                let candidate = Candidate {
                                    transform: crate::transforms::Transform::Identity,
                                    offset: Offset::from_u64(
                                        previous
                                            .checked_add(ticket)
                                            .and_then(|n| n.checked_add(i as u64))
                                            .context("counter overflow")?,
                                    ),
                                    address: job.profile().encode(&public)?,
                                };
                                candidate.verify(&job)?;
                                let envelope = seal_with(
                                    &key,
                                    metadata(&key, &job, "hit", Uuid::new_v4())?,
                                    salt,
                                    &derived,
                                )?;
                                ensure!(
                                    open_with(&envelope, &derived)?
                                        .public(job.profile())?
                                        .as_slice()
                                        == public,
                                    "encrypted hit recovery failed"
                                );
                                let _ = tx.send(Ok(EdHit {
                                    envelope,
                                    candidate,
                                }));
                                return Ok(());
                            }
                        }
                    }
                }
                Ok(())
            }))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("trusted Ed25519 worker panicked")));
            if let Err(e) = run {
                found.store(true, Ordering::Relaxed);
                let _ = tx.send(Err(e));
            }
        }));
    }
    drop(tx);
    let mut hit = None;
    let mut failure = None;
    let mut last = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(value)) => {
                match storage::write_json(&session.join("hit.keystore.json"), &value, false) {
                    Ok(()) => hit = Some(value.candidate),
                    Err(e) => {
                        cancel.store(true, Ordering::Relaxed);
                        crate::backend::retain_failure(&mut failure, e);
                    }
                }
            }
            Ok(Err(e)) => {
                crate::backend::retain_failure(&mut failure, e);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if last.elapsed() >= Duration::from_millis(500) {
            let p = ed_progress(
                &job,
                previous + finished.load(Ordering::Relaxed),
                cp.elapsed_seconds + started.elapsed().as_secs_f64(),
                hit.clone(),
                false,
                config,
            );
            if let Some(tx) = &config.progress {
                let _ = tx.try_send(p.clone());
            }
            if config.json_lines {
                if let Ok(json) = serde_json::to_string(&p) {
                    println!("{json}");
                }
            } else if !config.quiet {
                eprintln!(
                    "{} candidates | {:.0}/s | Ed25519 CPU",
                    p.candidates_exact, p.candidates_per_second
                );
            }
            last = Instant::now();
        }
    }
    for handle in handles {
        if handle.join().is_err() {
            crate::backend::retain_failure(
                &mut failure,
                anyhow::anyhow!("Ed25519 CPU worker panicked"),
            );
        }
    }
    // Attempt the existing durable writes even after a worker failed, while
    // retaining a cryptographic fault if validation or storage also fails.
    let persistence = (|| -> Result<u64> {
        let total = previous
            .checked_add(finished.load(Ordering::Relaxed))
            .context("counter overflow")?;
        cp.next = Offset::from_u64(total).into();
        cp.completed = if total > 0 {
            vec![crate::model::Interval {
                start: Offset::ZERO.into(),
                end: cp.next,
            }]
        } else {
            vec![]
        };
        cp.pending.clear();
        cp.candidate = hit;
        cp.elapsed_seconds += started.elapsed().as_secs_f64();
        if let Some(e) = &failure {
            cp.fault = Some(format!("Ed25519 CPU failure: {e}"));
        }
        cp.validate(&job)?;
        storage::save_checkpoint(&session.join("checkpoint.json"), &cp)?;
        if cp.candidate.is_some() {
            storage::write_json(
                &session.join("results.json"),
                &Results::from_checkpoint(&job, &cp)?,
                false,
            )?;
        }
        Ok(total)
    })();
    let total = finish_ed_workers(failure, persistence)?;
    Ok(ed_progress(
        &job,
        total,
        cp.elapsed_seconds,
        cp.candidate,
        true,
        config,
    ))
}

fn finish_ed_workers<T>(failure: Option<anyhow::Error>, persistence: Result<T>) -> Result<T> {
    match (failure, persistence) {
        (Some(error), Err(persistence))
            if error
                .downcast_ref::<crate::backend::CorrectnessError>()
                .is_some() =>
        {
            Err(error.context(format!("persist completed Ed25519 search: {persistence:#}")))
        }
        (_, Err(persistence)) => Err(persistence),
        (Some(error), Ok(_)) => Err(error),
        (None, Ok(value)) => Ok(value),
    }
}

/// Benchmark the actual standard-seed CPU generation path, with private seeds
/// owned and erased inside KeyManager. Only timing/counters leave this module.
pub(super) fn benchmark_ed(
    config: &Config,
    seconds: f64,
    warmup: f64,
    runs: u32,
    cancel: Arc<AtomicBool>,
) -> Result<serde_json::Value> {
    let p = config
        .profile
        .context("Ed25519 benchmark requires a profile")?;
    p.validate()?;
    ensure!(
        p.key_family() == KeyFamily::Ed25519 && !matches!(config.mode, Mode::Opencl),
        "Ed25519 benchmarks require CPU or Auto mode"
    );
    ensure!(
        (1..=256).contains(&config.threads),
        "thread count must be 1..256"
    );
    ensure!(
        config
            .benchmark_strategy
            .is_none_or(|s| s == crate::model::SearchStrategy::Linear),
        "Ed25519 does not support public-point endomorphism searches"
    );
    let pattern = if let Some(pattern) = &config.benchmark_pattern {
        ensure!(pattern.profile == p, "benchmark pattern/profile mismatch");
        pattern.validate()?;
        pattern.clone()
    } else {
        Pattern::for_profile(p, &p.diagnostic_address()?, "")?
    };
    let matcher = Arc::new(pattern.compiled()?);
    let barrier = Arc::new(std::sync::Barrier::new(config.threads));
    let mut handles = vec![];
    fn run_for(
        matcher: &chains::matching::Compiled,
        duration: f64,
        cancel: &AtomicBool,
        table: crate::backend::EdTable,
        hash: crate::backend::HashMode,
    ) -> Result<(u64, f64)> {
        let started = Instant::now();
        let mut count = 0u64;
        while started.elapsed().as_secs_f64() < duration && !cancel.load(Ordering::Relaxed) {
            let entropy = Zeroizing::new(random::<8192>()?);
            for group in entropy.as_chunks::<1024>().0 {
                if cancel.load(Ordering::Relaxed) || started.elapsed().as_secs_f64() >= duration {
                    break;
                }
                let mut seeds = Zeroizing::new([[0; 32]; 32]);
                for (i, chunk) in group.as_chunks::<32>().0.iter().enumerate() {
                    seeds[i].copy_from_slice(chunk);
                }
                let mut public = [[0; 32]; 32];
                super::ed_batch::derive(&seeds[..], &mut public, table, hash);
                for key in public {
                    std::hint::black_box(matcher.accepts_payload(&key));
                }
                count += 32;
            }
        }
        Ok((count, started.elapsed().as_secs_f64()))
    }
    let (table, hash) = crate::backend::qualification::ed(config, p);
    for i in 0..config.threads {
        let (matcher, barrier, cancel) = (matcher.clone(), barrier.clone(), cancel.clone());
        handles.push(std::thread::spawn(move||->Result<serde_json::Value>{
        let warm=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<(u64,f64)>{super::ed_batch::self_test(table,hash)?;run_for(&matcher,warmup,&cancel,table,hash)})).unwrap_or_else(|_|Err(anyhow::anyhow!("Ed25519 benchmark warmup worker panicked")));
        if warm.is_err(){cancel.store(true,Ordering::Relaxed);}
        barrier.wait();warm?;let mut measurements=vec![];
        for _ in 0..runs{let(count,elapsed)=run_for(&matcher,seconds,&cancel,table,hash)?;measurements.push(serde_json::json!({"candidates":count,"seconds":elapsed,"per_second":count as f64/elapsed.max(1e-9)}));}
        Ok(serde_json::json!({"device":format!("trusted-ed25519-cpu:{i}"),"runs":measurements}))
    }));
    }
    let mut measurements = vec![];
    let mut failure = None;
    for h in handles {
        match h.join() {
            Ok(Ok(m)) => measurements.push(m),
            Ok(Err(e)) => crate::backend::retain_failure(&mut failure, e),
            Err(_) => crate::backend::retain_failure(
                &mut failure,
                anyhow::anyhow!("Ed25519 benchmark worker panicked"),
            ),
        }
    }
    if let Some(e) = failure {
        return crate::backend::calibration::with_fault_record(
            config.calibration_record.as_deref(),
            Err(e),
        );
    }
    Ok(
        serde_json::json!({"schema":SCHEMA,"application":env!("CARGO_PKG_VERSION"),"profile":p,"workload":"OS-random standard Ed25519 seed + public derivation + chain-aware prefix matching","backend":"cpu","ed_table":table,"hash_mode":hash,"cpu":crate::backend::cpu_info(),"pattern":pattern,"warmup_seconds":warmup,"measurement_seconds":seconds,"runs":runs,"measurements":measurements}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_native_ed25519_benchmarks_use_valid_diagnostic_patterns_and_actual_counters() {
        for chain in [Chain::Solana, Chain::Stellar, Chain::Algorand] {
            let profile = Profile::new(chain, None).unwrap();
            let config = Config {
                mode: Mode::Cpu,
                profile: Some(profile),
                threads: 1,
                ed_table: crate::backend::EdTable::Reference,
                hash_mode: crate::backend::HashMode::Scalar,
                tuning_cache: None,
                quiet: true,
                ..Config::default()
            };
            let report =
                benchmark_ed(&config, 0.05, 0.0, 1, Arc::new(AtomicBool::new(false))).unwrap();
            let expected =
                Pattern::for_profile(profile, &profile.diagnostic_address().unwrap(), "").unwrap();
            assert_eq!(report["pattern"], serde_json::to_value(&expected).unwrap());
            assert_eq!(report["backend"], "cpu");
            let measurements = report["measurements"].as_array().unwrap();
            assert_eq!(measurements.len(), 1);
            let measurement = measurements[0].as_object().unwrap();
            assert_eq!(measurement.len(), 2);
            assert_eq!(measurement["device"], "trusted-ed25519-cpu:0");
            let runs = measurement["runs"].as_array().unwrap();
            assert_eq!(runs.len(), 1);
            let run = runs[0].as_object().unwrap();
            assert_eq!(run.len(), 3);
            let count = run["candidates"].as_u64().unwrap();
            let elapsed = run["seconds"].as_f64().unwrap();
            let rate = run["per_second"].as_f64().unwrap();
            assert!(count > 0 && count.is_multiple_of(32));
            assert!(elapsed.is_finite() && elapsed > 0.0);
            assert!(rate.is_finite() && rate > 0.0);
            assert_eq!(rate, count as f64 / elapsed);
        }
    }

    #[test]
    fn ed_persistence_failure_preserves_crypto_fault_for_cache_invalidation() {
        let root = tempfile::tempdir().unwrap();
        storage::private(root.path()).unwrap();
        let record = root.path().join("synthetic-calibration.json");
        storage::write_json(&record, &serde_json::json!({"schema":2}), false).unwrap();
        let error = finish_ed_workers::<()>(
            Some(
                anyhow::Error::new(crate::backend::CorrectnessError(
                    "synthetic Ed25519 mismatch".into(),
                ))
                .context("worker derivation"),
            ),
            Err(anyhow::anyhow!("synthetic checkpoint storage failure")),
        )
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::backend::CorrectnessError>()
                .is_some()
        );
        assert!(format!("{error:#}").contains("synthetic checkpoint storage failure"));
        let error = crate::backend::calibration::with_fault_record::<()>(Some(&record), Err(error))
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::backend::CorrectnessError>()
                .is_some()
        );
        let invalid: serde_json::Value = storage::read_private_json(&record).unwrap();
        assert_eq!(invalid["invalid"], true);
    }

    #[test]
    fn ed_completion_preserves_success_and_existing_ordinary_error_order() {
        assert_eq!(finish_ed_workers(None, Ok(7)).unwrap(), 7);
        assert_eq!(
            finish_ed_workers(Some(anyhow::anyhow!("ordinary worker")), Ok(7))
                .unwrap_err()
                .to_string(),
            "ordinary worker"
        );
        assert_eq!(
            finish_ed_workers::<()>(
                Some(anyhow::anyhow!("ordinary worker")),
                Err(anyhow::anyhow!("ordinary storage")),
            )
            .unwrap_err()
            .to_string(),
            "ordinary storage"
        );
    }

    #[test]
    fn warthog_native_leading_zero_key_and_metadata_binding() {
        let temp = tempfile::tempdir().unwrap();
        let profile = Profile::new(Chain::Warthog, None).unwrap();
        let key = Material(Zeroizing::new(Offset::from_u64(1).0));
        let address = key.address(profile).unwrap();
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: JOB_SCHEMA,
            session_id: Uuid::new_v4(),
            public_key: hex::encode(key.public(profile).unwrap()),
            pattern: Pattern::for_profile(profile, &address, "").unwrap(),
        };
        let store = seal(
            &key,
            metadata(&key, &job, "wallet", Uuid::new_v4()).unwrap(),
            "synthetic-warthog-password",
        )
        .unwrap();
        let encrypted = temp.path().join("encrypted.json");
        storage::write_json(&encrypted, &store, false).unwrap();
        let native = temp.path().join("wallet.json");
        export_native(&encrypted, "synthetic-warthog-password", &native).unwrap();
        let data: serde_json::Value = storage::read_json(&native).unwrap();
        assert_eq!(data["privateKey"], format!("{:064x}", 1));
        assert_eq!(data["publicKey"], job.public_key);
        assert_eq!(data["address"], address);
        let mut changed = serde_json::to_value(&store).unwrap();
        changed["metadata"]["profile"]["chain"] = serde_json::json!("cosmos");
        let tampered: Envelope = serde_json::from_value(changed).unwrap();
        assert!(open(&tampered, "synthetic-warthog-password").is_err());
    }

    #[test]
    #[ignore = "writes synthetic Warthog wallets to the explicit VANITY_WARTHOG_FIXTURES directory"]
    fn write_warthog_interop_fixtures() {
        let root = std::path::PathBuf::from(
            std::env::var_os("VANITY_WARTHOG_FIXTURES").expect("set isolated fixture directory"),
        );
        storage::create_directory(&root, true).unwrap();
        storage::private(&root).unwrap();
        let p = Profile::new(Chain::Warthog, None).unwrap();
        let password = "PUBLIC-SYNTHETIC-WARTHOG-PASSWORD";
        let high = Offset::from_u64(1)
            .difference(crate::crypto::ORDER)
            .unwrap()
            .0;
        let mut rows = vec![];
        for (index, scalar) in [Offset::from_u64(1).0, Offset::from_u64(7).0, high]
            .into_iter()
            .enumerate()
        {
            let folder = root.join(format!("case-{index}"));
            storage::create_directory(&folder, false).unwrap();
            storage::private(&folder).unwrap();
            let key = Material(Zeroizing::new(scalar));
            let address = key.address(p).unwrap();
            let public_key = hex::encode(key.public(p).unwrap());
            let job = Job {
                strategy: crate::model::SearchStrategy::Linear,
                schema: JOB_SCHEMA,
                session_id: Uuid::new_v4(),
                public_key: public_key.clone(),
                pattern: Pattern::for_profile(p, &address, "").unwrap(),
            };
            let store = seal(
                &key,
                metadata(&key, &job, "wallet", Uuid::new_v4()).unwrap(),
                password,
            )
            .unwrap();
            let encrypted = folder.join("encrypted.json");
            storage::write_json(&encrypted, &store, false).unwrap();
            export_native(&encrypted, password, &folder.join("wallet.json")).unwrap();
            export_native(&encrypted, password, &folder.join("wart-dapp.db")).unwrap();
            rows.push(serde_json::json!({"case":format!("case-{index}"),"address":address,"public_key":public_key}));
        }
        let folder = root.join("case-3");
        storage::create_directory(&folder, false).unwrap();
        storage::private(&folder).unwrap();
        let (_job, generated, address) = transformed_wallet(&folder, 3, p, password);
        let encrypted = folder.join("encrypted.json");
        storage::write_bytes(&encrypted, &storage::read_bytes(&generated).unwrap(), false).unwrap();
        export_native(&encrypted, password, &folder.join("wallet.json")).unwrap();
        export_native(&encrypted, password, &folder.join("wart-dapp.db")).unwrap();
        let store: Envelope = storage::read_json(&encrypted).unwrap();
        rows.push(serde_json::json!({"case":"case-3","address":address,"public_key":store.metadata.public_key}));
        storage::write_json(
            &root.join("manifest.json"),
            &serde_json::json!({"synthetic":true,"profile":p,"wallets":rows}),
            false,
        )
        .unwrap();
    }

    #[test]
    fn official_bip380_descriptor_checksum() {
        assert_eq!(
            descriptor_checksum("raw(deadbeef)").unwrap(),
            "raw(deadbeef)#89f8spxm"
        );
        assert!(descriptor_checksum("raw(\u{dc})").is_err());
    }
    #[test]
    fn authenticated_chain_binding_and_wallet_recovery() {
        let p = Profile::new(Chain::Bitcoin, Some(AddressType::P2tr)).unwrap();
        let key = Material(Zeroizing::new(Offset::from_u64(7).0));
        let job = Job {
            strategy: crate::model::SearchStrategy::Linear,
            schema: JOB_SCHEMA,
            session_id: Uuid::new_v4(),
            public_key: hex::encode(key.public(p).unwrap()),
            pattern: Pattern::for_profile(p, "bc1p", "").unwrap(),
        };
        let m = metadata(&key, &job, "wallet", Uuid::new_v4()).unwrap();
        let store = seal(&key, m, "synthetic-test-password").unwrap();
        assert_eq!(
            open(&store, "synthetic-test-password")
                .unwrap()
                .address(p)
                .unwrap(),
            key.address(p).unwrap()
        );
        assert!(open(&store, "wrong password").is_err());
        let mut v = serde_json::to_value(&store).unwrap();
        v["metadata"]["profile"]["chain"] = serde_json::json!("litecoin");
        let changed: Envelope = serde_json::from_value(v).unwrap();
        assert!(open(&changed, "synthetic-test-password").is_err());
        let secp = key.secp().unwrap();
        let mut evm = encrypt(&secp, "synthetic-test-password", Uuid::new_v4()).unwrap();
        let mut j = job.clone();
        j.pattern =
            Pattern::for_profile(Profile::new(Chain::Base, None).unwrap(), "a", "").unwrap();
        let m = metadata(&key, &j, "wallet", evm.id).unwrap();
        evm.vanity_pro = Some(sign_evm(&evm, m, &secp).unwrap());
        assert_eq!(verify_evm(&evm, &secp).unwrap().chain, Chain::Base);
        evm.vanity_pro.as_mut().unwrap().metadata.profile.chain = Chain::Bnb;
        assert!(verify_evm(&evm, &secp).is_err());
    }
    fn transformed_wallet(
        root: &Path,
        index: usize,
        profile: Profile,
        password: &str,
    ) -> (Job, std::path::PathBuf, String) {
        use crate::{
            backend::{CpuEngine, HashMode},
            transforms::Transform,
        };
        let initial = Material(Zeroizing::new(Offset::from_u64((index + 1) as u64).0));
        let width = if profile.address_type == AddressType::P2tr {
            3
        } else {
            6
        };
        let transform = Transform::from_branch(1 + (index as u8 % (width - 1))).unwrap();
        let mut candidate = Candidate {
            offset: Offset::from_u64(3),
            transform,
            address: String::new(),
        };
        let recovered = reconstruct_secp(&initial.secp().unwrap(), &candidate).unwrap();
        let address = profile.address(&point(&recovered)).unwrap();
        candidate.address = profile.candidate(&point(&recovered)).unwrap();
        let job = Job {
            schema: JOB_SCHEMA,
            strategy: crate::model::SearchStrategy::EndomorphismV1,
            session_id: Uuid::new_v4(),
            public_key: hex::encode(initial.public(profile).unwrap()),
            pattern: Pattern::for_profile(profile, &address, "").unwrap(),
        };
        let session = root.join(format!("transformed-{index}"));
        storage::create_directory(&session, false).unwrap();
        storage::private(&session).unwrap();
        let store = seal(
            &initial,
            metadata(&initial, &job, "seed", job.session_id).unwrap(),
            password,
        )
        .unwrap();
        storage::write_json(&session.join("seed.keystore.json"), &store, false).unwrap();
        storage::write_json(&session.join("job.json"), &job, false).unwrap();
        storage::save_checkpoint(
            &session.join("checkpoint.json"),
            &Checkpoint::new(&job).unwrap(),
        )
        .unwrap();
        let mut config = Config {
            mode: Mode::Cpu,
            threads: 3,
            batch_size: 7,
            max_candidates: Some(2),
            cpu_engine: CpuEngine::Batched,
            hash_mode: HashMode::Simd,
            quiet: true,
            ..Config::default()
        };
        let first = crate::coordinator::search(
            &session.join("job.json"),
            &config,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(first.candidate.is_none());
        assert_eq!(first.candidates_exact, "2");
        crate::coordinator::recover(&session).unwrap();
        config.max_candidates = Some(128);
        let result = crate::coordinator::search(
            &session.join("job.json"),
            &config,
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(result.candidate, Some(candidate));
        let wallet = root.join(format!("{index}-encrypted.json"));
        assert!(super::super::finalize(&session, &wallet, "incorrect-password", password).is_err());
        assert_eq!(
            super::super::finalize(&session, &wallet, password, password).unwrap(),
            address
        );
        assert!(super::super::finalize(&session, &wallet, password, password).is_err());
        assert_eq!(
            super::super::verify_wallet(&wallet, password, Some(&job.pattern)).unwrap(),
            address
        );
        assert!(super::super::verify_wallet(&wallet, "incorrect-password", None).is_err());
        (job, wallet, address)
    }
    #[test]
    fn transformed_profiles_recover_finalize_and_export() {
        let temp = tempfile::tempdir().unwrap();
        for (index, info) in chains::registry().into_iter().enumerate() {
            if info.key_family != KeyFamily::Secp256k1 {
                continue;
            }
            let (job, wallet, address) = transformed_wallet(
                temp.path(),
                index,
                info.profile,
                "PUBLIC-SYNTHETIC-TEST-PASSWORD",
            );
            let native = temp.path().join(format!("{index}-native.txt"));
            let password = "PUBLIC-SYNTHETIC-TEST-PASSWORD";
            assert_eq!(export_native(&wallet, password, &native).unwrap(), address);
            assert!(export_native(&wallet, password, &native).is_err());
            let mut tampered: serde_json::Value = storage::read_json(&wallet).unwrap();
            if job.profile().is_evm() {
                tampered["vanity_pro"]["metadata"]["role"] = "seed".into();
            } else {
                tampered["metadata"]["role"] = "seed".into();
            }
            let damaged = temp.path().join(format!("{index}-damaged.json"));
            storage::write_json(&damaged, &tampered, false).unwrap();
            assert!(super::super::verify_wallet(&damaged, password, None).is_err());
        }
    }
    #[test]
    fn ed25519_session_search_pause_resume_export() {
        let temp = tempfile::tempdir().unwrap();
        let session = temp.path().join("session");
        let profile = Profile::new(Chain::Solana, None).unwrap();
        let pattern = Pattern::for_profile(profile, "A", "").unwrap();
        let pw = "synthetic-ed-session-password";
        initialize(&session, pattern.clone(), pw).unwrap();
        let mut config = Config {
            mode: Mode::Cpu,
            threads: 2,
            max_candidates: Some(1),
            quiet: true,
            ..Config::default()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let first = search_ed(&session.join("job.json"), &config, cancel.clone(), pw).unwrap();
        assert_eq!(first.candidates, 1.0);
        if first.candidate.is_none() {
            config.max_candidates = Some(100_000);
            let second = search_ed(&session.join("job.json"), &config, cancel, pw).unwrap();
            assert!(second.candidate.is_some());
        }
        let out = temp.path().join("wallet.json");
        let addr = super::super::finalize(&session, &out, pw, "synthetic-wallet-password").unwrap();
        assert_eq!(
            super::super::verify_wallet(&out, "synthetic-wallet-password", Some(&pattern)).unwrap(),
            addr
        );
        let native = temp.path().join("solana.json");
        assert_eq!(
            export_native(&out, "synthetic-wallet-password", &native).unwrap(),
            addr
        );
        let pair: Zeroizing<Vec<u8>> =
            Zeroizing::new(serde_json::from_slice(&storage::read_bytes(&native).unwrap()).unwrap());
        assert_eq!(pair.len(), 64);
        assert!(export_native(&out, "synthetic-wallet-password", &native).is_err());
    }
    #[test]
    fn encrypted_ed_hit_recovers_after_public_result_interruption() {
        let temp = tempfile::tempdir().unwrap();
        let session = temp.path().join("interrupted");
        let p = Profile::new(Chain::Stellar, None).unwrap();
        let password = "synthetic-interruption-password";
        let job = initialize(
            &session,
            Pattern::for_profile(p, "G", "").unwrap(),
            password,
        )
        .unwrap();
        let config = Config {
            mode: Mode::Cpu,
            threads: 2,
            max_candidates: Some(10),
            quiet: true,
            ..Config::default()
        };
        let first = search_ed(
            &session.join("job.json"),
            &config,
            Arc::new(AtomicBool::new(false)),
            password,
        )
        .unwrap();
        let candidate = first.candidate.unwrap();
        let original_hit = storage::read_bytes(&session.join("hit.keystore.json")).unwrap();
        // Public backup tampering cannot endorse a different matching account,
        // with either an unrelated authentic hit or no encrypted hit at all.
        let mut forged = storage::load_checkpoint(&session.join("checkpoint.json"), &job).unwrap();
        let attacker = Material(Zeroizing::new([127; 32]));
        forged.candidate.as_mut().unwrap().address = attacker.address(p).unwrap();
        assert_ne!(
            forged.candidate.as_ref().unwrap().address,
            candidate.address
        );
        storage::save_checkpoint(&session.join("checkpoint.json"), &forged).unwrap();
        assert!(
            search_ed(
                &session.join("job.json"),
                &config,
                Arc::new(AtomicBool::new(false)),
                password
            )
            .is_err()
        );
        fs::rename(
            session.join("hit.keystore.json"),
            session.join("saved-hit.json"),
        )
        .unwrap();
        assert!(
            search_ed(
                &session.join("job.json"),
                &config,
                Arc::new(AtomicBool::new(false)),
                password
            )
            .is_err()
        );
        fs::rename(
            session.join("saved-hit.json"),
            session.join("hit.keystore.json"),
        )
        .unwrap();
        // Simulate loss of the final public writes while the encrypted hit survived.
        storage::save_checkpoint(
            &session.join("checkpoint.json"),
            &Checkpoint::new(&job).unwrap(),
        )
        .unwrap();
        fs::remove_file(session.join("results.json")).unwrap();
        assert!(
            search_ed(
                &session.join("job.json"),
                &config,
                Arc::new(AtomicBool::new(false)),
                "incorrect-password"
            )
            .is_err()
        );
        let recovered = search_ed(
            &session.join("job.json"),
            &config,
            Arc::new(AtomicBool::new(false)),
            password,
        )
        .unwrap();
        assert_eq!(recovered.candidate, Some(candidate));
        assert_eq!(
            storage::read_bytes(&session.join("hit.keystore.json")).unwrap(),
            original_hit
        );
        let out = temp.path().join("recovered-wallet.json");
        super::super::finalize(&session, &out, password, "synthetic-final-wallet-password")
            .unwrap();
    }
    #[test]
    fn bip341_tweaked_private_key_and_official_spend_signature() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/bip341-wallet.json")).unwrap();
        for group in vectors["keyPathSpending"].as_array().unwrap() {
            for v in group["inputSpending"].as_array().unwrap() {
                if !v["given"]["merkleRoot"].is_null() {
                    continue;
                }
                let original = Secret(
                    SecretKey::from_byte_array(
                        decode::<32>(v["given"]["internalPrivkey"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap(),
                );
                let public = point(&original);
                let mut normalized = Secret(original.0);
                if public.x_only_public_key().1 == Parity::Odd {
                    normalized.0 = normalized.0.negate();
                }
                let (output, tweak) = chains::taproot_output(&public).unwrap();
                let tweaked = Secret(normalized.0.add_tweak(&tweak).unwrap());
                assert_eq!(
                    hex::encode(tweaked.0.secret_bytes()),
                    v["intermediary"]["tweakedPrivkey"]
                );
                let hash = decode::<32>(v["intermediary"]["sigHash"].as_str().unwrap()).unwrap();
                let witness = hex::decode(v["expected"]["witness"][0].as_str().unwrap()).unwrap();
                let sig = secp256k1::schnorr::Signature::from_byte_array(
                    witness[..64].try_into().unwrap(),
                );
                Secp256k1::verification_only()
                    .verify_schnorr(
                        &sig,
                        &hash,
                        &secp256k1::XOnlyPublicKey::from_byte_array(output).unwrap(),
                    )
                    .unwrap();
                let pair = Keypair::from_secret_key(&Secp256k1::new(), &tweaked.0);
                let signed = Secp256k1::new().sign_schnorr_no_aux_rand(&hash, &pair);
                Secp256k1::verification_only()
                    .verify_schnorr(
                        &signed,
                        &hash,
                        &secp256k1::XOnlyPublicKey::from_byte_array(output).unwrap(),
                    )
                    .unwrap();
            }
        }
    }
    #[test]
    #[ignore = "creates synthetic encrypted/native files for independent SDK qualification"]
    fn write_native_interop_fixtures() {
        let root = std::path::PathBuf::from(
            std::env::var_os("VANITY_NATIVE_FIXTURES")
                .expect("set isolated synthetic fixture directory"),
        );
        if !root.exists() {
            fs::create_dir(&root).unwrap();
            storage::private(&root).unwrap();
        }
        let mut manifest = vec![];
        for (i, info) in chains::registry().into_iter().enumerate() {
            let key = if info.key_family == KeyFamily::Secp256k1 {
                Material(Zeroizing::new(Offset::from_u64((i + 1) as u64).0))
            } else {
                Material(Zeroizing::new(
                    Sha256::digest(
                        format!("Vanity Pro v4 PUBLIC SYNTHETIC TEST FIXTURE {i}").as_bytes(),
                    )
                    .into(),
                ))
            };
            let p = info.profile;
            let public = key.public(p).unwrap();
            let address = key.address(p).unwrap();
            let pattern =
                Pattern::for_profile(p, if p.is_evm() { "a" } else { &address }, "").unwrap();
            let job = Job {
                strategy: crate::model::SearchStrategy::Linear,
                schema: JOB_SCHEMA,
                session_id: Uuid::new_v4(),
                public_key: hex::encode(&public),
                pattern,
            };
            let (job, key, address) = if info.key_family == KeyFamily::Secp256k1 {
                let (job, wallet, address) =
                    transformed_wallet(&root, i, p, "PUBLIC-SYNTHETIC-TEST-PASSWORD");
                let result: Results =
                    storage::read_json(&root.join(format!("transformed-{i}/results.json")))
                        .unwrap();
                let initial: Envelope =
                    storage::read_json(&root.join(format!("transformed-{i}/seed.keystore.json")))
                        .unwrap();
                let material = open(&initial, "PUBLIC-SYNTHETIC-TEST-PASSWORD").unwrap();
                let recovered =
                    reconstruct_secp(&material.secp().unwrap(), &result.candidate).unwrap();
                let key = Material(Zeroizing::new(recovered.0.secret_bytes()));
                // The real finalized wallet is already present; native export below verifies it.
                assert!(wallet.exists());
                (job, key, address)
            } else {
                (job, key, address)
            };
            let public = key.public(p).unwrap();
            let m = metadata(&key, &job, "wallet", Uuid::new_v4()).unwrap();
            let file = root.join(format!("{i}-encrypted.json"));
            let native = root.join(format!("{i}-native.txt"));
            if info.key_family == KeyFamily::Secp256k1 {
                // transformed_wallet finalized this exact reconstruction above.
            } else if p.is_evm() {
                let mut store =
                    encrypt(&key.secp().unwrap(), "PUBLIC-SYNTHETIC-TEST-PASSWORD", m.id).unwrap();
                store.vanity_pro = Some(sign_evm(&store, m, &key.secp().unwrap()).unwrap());
                storage::write_json(&file, &store, false).unwrap();
            } else {
                let store = seal(&key, m, "PUBLIC-SYNTHETIC-TEST-PASSWORD").unwrap();
                storage::write_json(&file, &store, false).unwrap();
            }
            assert_eq!(
                export_native(&file, "PUBLIC-SYNTHETIC-TEST-PASSWORD", &native).unwrap(),
                address
            );
            assert_eq!(
                super::super::verify_wallet(&file, "PUBLIC-SYNTHETIC-TEST-PASSWORD", None).unwrap(),
                address
            );
            manifest.push(serde_json::json!({"profile":p,"address":address,"public_key":hex::encode(public),"wallet":file,"native":native}));
        }
        storage::write_json(&root.join("manifest.json"), &manifest, false).unwrap();
    }
}
