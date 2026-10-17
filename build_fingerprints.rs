//! Build-time implementation identities. No source text is needed by the runtime.
use sha2::{Digest, Sha256};

pub const CALIBRATION_DOMAIN: &str = "vanity-pro/calibration-implementation/v1";
pub const OPENCL_DOMAIN: &str = "vanity-pro/opencl-implementation/v1";

// Preserve the complete source coverage of the former runtime include_str! lists.
// The build logic and its new digest helper also bind the generated identities.
pub const CALIBRATION_SOURCES: &[&str] = &[
    "src/backend/calibration.rs",
    "src/backend/calibration_sampling.rs",
    "src/backend/qualification.rs",
    "src/backend/cpu.rs",
    "src/backend/hashes.rs",
    "src/backend/public_batch.rs",
    "src/transforms.rs",
    "src/chains.rs",
    "src/chains/matching.rs",
    "src/key_manager/ed_batch.rs",
    "src/key_manager/multichain.rs",
    "src/coordinator.rs",
    "src/backend/mod.rs",
    "src/crypto.rs",
    "src/model.rs",
    "src/work.rs",
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "build_fingerprints.rs",
];
pub const OPENCL_SOURCES: &[&str] = &[
    "kernels/search.cl",
    "kernels/fast_field.cl",
    "kernels/recurrence.cl",
    "kernels/chains.cl",
    "kernels/hash160_fixed.cl",
    "src/backend/chain_gpu.rs",
    "src/transforms.rs",
    "kernels/keccak_tuned.cl",
    "kernels/field_bounded.cl",
    "kernels/keccak_ternary.cl",
    "kernels/field_probe.cl",
    "kernels/lab_probes.cl",
    "src/backend/opencl.rs",
    "src/backend/recurrence.rs",
    "src/backend/autotune.rs",
    "src/backend/qualification.rs",
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "build_fingerprints.rs",
];

/// Length framing and explicit sections bind file identities and build context.
pub fn digest(domain: &str, sources: &[(&str, &[u8])], context: &[(&str, &str)]) -> String {
    fn field(hash: &mut Sha256, value: &[u8]) {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    let mut hash = Sha256::new();
    field(&mut hash, domain.as_bytes());
    field(&mut hash, b"sources");
    hash.update((sources.len() as u64).to_be_bytes());
    for (name, contents) in sources {
        field(&mut hash, name.as_bytes());
        field(&mut hash, contents);
    }
    field(&mut hash, b"context");
    hash.update((context.len() as u64).to_be_bytes());
    for (name, value) in context {
        field(&mut hash, name.as_bytes());
        field(&mut hash, value.as_bytes());
    }
    format!("{:x}", hash.finalize())
}
