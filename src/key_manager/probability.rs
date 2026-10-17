//! Public outputs for probability estimates. Temporary native-key material stays here.
//! No sample seed, scalar or signing key is returned, persisted or used for a job.
use super::Secret;
use anyhow::Result;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum Distribution {
    HashPayload,
    Ed25519,
    Taproot,
}

pub(crate) fn draw(distribution: Distribution, count: usize) -> Result<Vec<[u8; 32]>> {
    draw_with_entropy(distribution, count, |bytes| {
        getrandom::fill(bytes).map_err(|error| anyhow::anyhow!("OS entropy unavailable: {error}"))
    })
}

fn draw_with_entropy(
    distribution: Distribution,
    count: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<()>,
) -> Result<Vec<[u8; 32]>> {
    let mut public = Vec::with_capacity(count);
    match distribution {
        Distribution::HashPayload => {
            public.resize(count, [0; 32]);
            fill(public.as_mut_slice().as_flattened_mut())?;
        }
        Distribution::Ed25519 => {
            // These independent seeds exist only while the public corpus is made.
            let mut seeds = Zeroizing::new(vec![[0; 32]; count]);
            fill(seeds.as_mut_slice().as_flattened_mut())?;
            for seed in seeds.iter() {
                let key = ed25519_dalek::SigningKey::from_bytes(seed);
                public.push(key.verifying_key().to_bytes());
            }
        }
        Distribution::Taproot => {
            let context = Secp256k1::new();
            while public.len() < count {
                let mut bytes = Zeroizing::new([0; 32]);
                fill(&mut *bytes)?;
                let Ok(key) = SecretKey::from_byte_array(*bytes) else {
                    continue;
                };
                let key = Secret(key);
                let point = PublicKey::from_secret_key(&context, &key.0);
                if let Ok((output, _)) = crate::chains::taproot_output(&point) {
                    public.push(output);
                }
            }
        }
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_ed25519_public_sample_matches_rfc8032() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let public = draw_with_entropy(Distribution::Ed25519, 1, |bytes| {
            bytes.copy_from_slice(&seed);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            hex::encode(public[0]),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let signature = ed25519_dalek::Signature::from_slice(
            &hex::decode(concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ))
            .unwrap(),
        )
        .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&public[0])
            .unwrap()
            .verify_strict(b"", &signature)
            .unwrap();
    }

    #[test]
    fn taproot_rejects_invalid_scalars_and_does_not_return_partial_draws() {
        let mut one = [0; 32];
        one[31] = 1;
        let inputs = [[0; 32], crate::crypto::ORDER.0, one];
        let mut calls = 0;
        let public = draw_with_entropy(Distribution::Taproot, 1, |bytes| {
            bytes.copy_from_slice(&inputs[calls]);
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 3);
        let expected = crate::chains::taproot_output(&crate::crypto::generator())
            .unwrap()
            .0;
        assert_eq!(public, [expected]);
        let mut calls = 0;
        assert!(
            draw_with_entropy(Distribution::Taproot, 2, |bytes| {
                calls += 1;
                if calls == 2 {
                    anyhow::bail!("entropy stopped");
                }
                bytes.copy_from_slice(&one);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn samples_are_valid_public_keys_and_entropy_errors_publish_nothing() {
        for distribution in [
            Distribution::HashPayload,
            Distribution::Ed25519,
            Distribution::Taproot,
        ] {
            assert!(
                draw_with_entropy(distribution, 16, |_| anyhow::bail!("entropy unavailable"))
                    .is_err()
            );
            let values = draw(distribution, 64).unwrap();
            assert_eq!(values.len(), 64);
            assert_eq!(
                values
                    .iter()
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                64
            );
            for bytes in values {
                match distribution {
                    Distribution::Ed25519 => {
                        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
                        assert!(!key.is_weak());
                    }
                    Distribution::Taproot => {
                        secp256k1::XOnlyPublicKey::from_byte_array(bytes).unwrap();
                    }
                    Distribution::HashPayload => {}
                }
            }
        }
    }
}
