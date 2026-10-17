//! Public probability estimates. Native sample generation remains in KeyManager.
use super::{AddressType, KeyFamily, matching::Compiled};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Estimate {
    /// Suppressed for fewer than 20 sampled matches; zero observations never imply impossibility.
    pub probability: Option<f64>,
    pub lower_95: f64,
    pub upper_95: f64,
    pub samples: u32,
    pub matches: u32,
    pub exact_model: bool,
    pub model: &'static str,
}
fn sampled(matches: u32, samples: u32, model: &'static str) -> Estimate {
    let n = f64::from(samples);
    let p = f64::from(matches) / n;
    let z2 = 1.959963984540054f64.powi(2);
    let denominator = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denominator;
    let radius = (z2 * (p * (1.0 - p) / n + z2 / (4.0 * n * n))).sqrt() / denominator;
    Estimate {
        probability: (matches >= 20).then_some(p),
        lower_95: (center - radius).max(0.0),
        upper_95: (center + radius).min(1.0),
        samples,
        matches,
        exact_model: false,
        model,
    }
}
type CacheKey = (super::Profile, String, String);
pub fn estimate(c: &Compiled) -> Estimate {
    if let Some(p) = c.probability {
        return Estimate {
            probability: Some(p),
            lower_95: p,
            upper_95: p,
            samples: 0,
            matches: 0,
            exact_model: true,
            model: "uniform hash-payload model",
        };
    }
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Estimate>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (c.profile, c.prefix.clone(), c.suffix.clone());
    if let Ok(guard) = cache.lock()
        && let Some(value) = guard.get(&key)
    {
        return *value;
    }
    // Preserve the original 32,768 independent draws and confidence rule without
    // shipping three large random corpora in every executable. Each public corpus
    // is made once per process; private sample material never leaves KeyManager.
    type Samples = Result<Vec<[u8; 32]>, ()>;
    static HASH: OnceLock<Samples> = OnceLock::new();
    static ED25519: OnceLock<Samples> = OnceLock::new();
    static TAPROOT: OnceLock<Samples> = OnceLock::new();
    use crate::key_manager::probability::{Distribution, draw};
    let (samples, distribution, model) = if c.profile.key_family() == KeyFamily::Ed25519 {
        (
            &ED25519,
            Distribution::Ed25519,
            "sampled standard Ed25519 public keys",
        )
    } else if c.profile.address_type == AddressType::P2tr {
        (
            &TAPROOT,
            Distribution::Taproot,
            "sampled Taproot output keys",
        )
    } else {
        (
            &HASH,
            Distribution::HashPayload,
            "sampled uniform hash-payload model",
        )
    };
    let result = match samples.get_or_init(|| draw(distribution, 32768).map_err(|_| ())) {
        Ok(values) => {
            let count = values
                .iter()
                .filter(|bytes| c.accepts_payload(&bytes[..c.profile.payload_len()]))
                .count() as u32;
            sampled(count, values.len() as u32, model)
        }
        Err(()) => Estimate {
            probability: None,
            lower_95: 0.0,
            upper_95: 1.0,
            samples: 0,
            matches: 0,
            exact_model: false,
            model: "public sampling unavailable",
        },
    };
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= 128 {
            guard.clear();
        }
        guard.insert(key, result);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wilson_bounds_and_rare_pattern_suppression() {
        let zero = sampled(0, 32768, "test");
        assert!(zero.probability.is_none());
        assert!(zero.lower_95 < 1e-16 && zero.upper_95 > 0.0001);
        let fair = sampled(16384, 32768, "test");
        assert_eq!(fair.probability, Some(0.5));
        assert!(fair.lower_95 < 0.5 && fair.upper_95 > 0.5);
        let all = sampled(32768, 32768, "test");
        assert!(all.lower_95 < 1.0 && all.upper_95 > 0.999999);
        for chain in [
            super::super::Chain::Solana,
            super::super::Chain::Stellar,
            super::super::Chain::Algorand,
        ] {
            let profile = super::super::Profile::new(chain, None).unwrap();
            let prefix = if chain == super::super::Chain::Stellar {
                "GA"
            } else {
                "A"
            };
            let c = Compiled::new(profile, prefix, "").unwrap();
            let e = estimate(&c);
            assert!(!e.exact_model && e.samples == 32768 && e.matches >= 20);
            assert_eq!(estimate(&c).probability, e.probability);
        }
    }
}
