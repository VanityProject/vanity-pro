//! Compile public address constraints once per batch; never reduce Base58 to 58^-n.
use super::*;
use anyhow::Context;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

#[derive(Clone, Debug)]
pub struct Compiled {
    pub profile: Profile,
    pub prefix: String,
    pub suffix: String,
    pub mask: Vec<u8>,
    pub value: Vec<u8>,
    pub ranges: Vec<(Vec<u8>, Vec<u8>)>,
    pub prefix_exact: bool,
    /// Exact under a uniform hash-payload model; None for dependent checksum suffixes / Ed25519.
    pub probability: Option<f64>,
}
impl Compiled {
    pub fn new(profile: Profile, prefix: &str, suffix: &str) -> Result<Self> {
        profile.validate()?;
        ensure!(
            prefix.len() + suffix.len() > 0,
            "provide a nonempty prefix or suffix"
        );
        ensure!(
            prefix.is_ascii() && suffix.is_ascii(),
            "address patterns must be ASCII"
        );
        let mut p = prefix.to_string();
        let mut s = suffix.to_string();
        let n = profile.payload_len();
        let mut c = Self {
            profile,
            prefix: String::new(),
            suffix: String::new(),
            mask: vec![0; n],
            value: vec![0; n],
            ranges: vec![],
            prefix_exact: false,
            probability: None,
        };
        match profile.encoding() {
            Encoding::WarthogHex => {
                p.make_ascii_lowercase();
                s.make_ascii_lowercase();
                ensure!(
                    p.len() + s.len() <= 48
                        && p.bytes().chain(s.bytes()).all(|b| b.is_ascii_hexdigit()),
                    "Warthog patterns use at most 48 hex digits without 0x"
                );
                for (i, b) in p.bytes().take(40).enumerate() {
                    c.bits(i * 4, 4, b.to_digit16()?)?;
                }
                for (i, b) in s.bytes().enumerate() {
                    let position = 48 - s.len() + i;
                    if position < 40 {
                        c.bits(position * 4, 4, b.to_digit16()?)?;
                    }
                }
                // A prefix entering the checksum already fixes all 160 payload
                // bits, so validate it once rather than encoding every attempt.
                if p.len() > 40 {
                    ensure!(
                        profile.encode(&c.value)?.starts_with(&p),
                        "Warthog prefix contains an invalid checksum"
                    );
                }
                c.prefix_exact = true;
                if s.is_empty() || c.mask.iter().all(|b| *b == 255) {
                    c.probability = Some(2f64.powi(-(c.constrained_bits() as i32)));
                }
            }
            Encoding::Hex => {
                p = p
                    .strip_prefix("0x")
                    .or_else(|| p.strip_prefix("0X"))
                    .unwrap_or(&p)
                    .to_ascii_lowercase();
                s = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(&s)
                    .to_ascii_lowercase();
                ensure!(
                    p.len() + s.len() <= 40
                        && p.bytes().chain(s.bytes()).all(|b| b.is_ascii_hexdigit()),
                    "pattern must contain at most 40 hex digits"
                );
                for (i, b) in p.bytes().enumerate() {
                    c.bits(i * 4, 4, b.to_digit16()?)?;
                }
                for (i, b) in s.bytes().enumerate() {
                    c.bits((40 - s.len() + i) * 4, 4, b.to_digit16()?)?;
                }
                c.prefix_exact = true;
                c.probability = Some(16f64.powi(-((p.len() + s.len()) as i32)));
            }
            Encoding::Base58 { version, ripple } => {
                let alphabet = if ripple {
                    RIPPLE_ALPHABET
                } else {
                    BITCOIN_ALPHABET
                };
                ensure!(
                    p.len() + s.len() <= 35
                        && p.bytes()
                            .chain(s.bytes())
                            .all(|b| alphabet.as_bytes().contains(&b)),
                    "invalid Base58 pattern (0, O, I and l are not in Bitcoin Base58)"
                );
                c.ranges = base58_ranges(version, &p, ripple)?;
                ensure!(
                    !c.ranges.is_empty(),
                    "impossible prefix for this network/version"
                );
                c.prefix_exact = true;
                if s.is_empty() {
                    let count = c.ranges.iter().fold(BigUint::zero(), |sum, (l, h)| {
                        sum + BigUint::from_bytes_be(h) - BigUint::from_bytes_be(l) + BigUint::one()
                    });
                    c.probability = Some(count.to_f64().unwrap_or(0.0) / 2f64.powi(160));
                }
            }
            Encoding::Bech32 { hrp, witness } => {
                ensure!(
                    p == p.to_ascii_lowercase() && s == s.to_ascii_lowercase(),
                    "use lowercase Bech32 patterns; mixed case is invalid"
                );
                let fixed = profile.fixed_prefix();
                if !p.is_empty() && !p.starts_with(fixed) {
                    ensure!(
                        !p.contains('1'),
                        "incorrect Bech32 network or witness prefix"
                    );
                    p = format!("{fixed}{p}");
                }
                let data_start = hrp.len() + 1 + usize::from(witness.is_some());
                let data_symbols = (n * 8).div_ceil(5);
                let total = data_start + data_symbols + 6;
                ensure!(
                    p.len() + s.len() <= total,
                    "pattern exceeds the address length"
                );
                let full_fixed = profile.fixed_prefix();
                ensure!(
                    p.is_empty() || p.starts_with(full_fixed),
                    "incorrect network prefix"
                );
                let payload_prefix = if p.len() > data_start {
                    &p[data_start..]
                } else {
                    ""
                };
                ensure!(
                    payload_prefix
                        .bytes()
                        .chain(s.bytes())
                        .all(|b| BECH32_ALPHABET.as_bytes().contains(&b)),
                    "invalid Bech32 character"
                );
                for (i, b) in payload_prefix.bytes().take(data_symbols).enumerate() {
                    c.symbol(i * 5, BECH32_ALPHABET.find(b as char).unwrap() as u8)?;
                }
                // A suffix can constrain payload positions as well as checksum symbols.
                for (i, b) in s.bytes().enumerate() {
                    let pos = total - s.len() + i;
                    if pos < data_start {
                        ensure!(
                            full_fixed.as_bytes().get(pos) == Some(&b),
                            "suffix conflicts with the fixed prefix"
                        );
                    } else if pos < data_start + data_symbols {
                        c.symbol(
                            (pos - data_start) * 5,
                            BECH32_ALPHABET.find(b as char).unwrap() as u8,
                        )?;
                    }
                }
                c.prefix_exact = p.len() <= data_start + data_symbols;
                if p.len() > data_start + data_symbols {
                    ensure!(
                        profile.encode(&c.value)?.starts_with(&p),
                        "prefix contains an invalid checksum"
                    );
                    c.prefix_exact = true;
                }
                if s.is_empty() {
                    c.probability = Some(2f64.powi(-(c.constrained_bits() as i32)));
                }
            }
            Encoding::Cashaddr => {
                ensure!(
                    p == p.to_ascii_lowercase() && s == s.to_ascii_lowercase(),
                    "use lowercase CashAddr patterns"
                );
                if !p.is_empty() && !p.starts_with("bitcoincash:") {
                    ensure!(!p.contains(':'), "incorrect CashAddr network");
                    p = if p.starts_with('q') {
                        format!("bitcoincash:{p}")
                    } else {
                        format!("bitcoincash:q{p}")
                    };
                }
                ensure!(
                    p.is_empty() || p.starts_with("bitcoincash:q"),
                    "only mainnet P2PKH CashAddr is supported"
                );
                ensure!(p.len() + s.len() <= 54, "pattern exceeds CashAddr length");
                let tail = p.strip_prefix("bitcoincash:").unwrap_or("");
                ensure!(
                    tail.bytes()
                        .chain(s.bytes())
                        .all(|b| BECH32_ALPHABET.as_bytes().contains(&b)),
                    "invalid CashAddr character"
                );
                for (i, b) in tail.bytes().take(34).enumerate() {
                    let v = BECH32_ALPHABET.find(b as char).unwrap() as u8;
                    for bit in 0..5 {
                        let pos = i * 5 + bit;
                        if !(8..168).contains(&pos) {
                            ensure!(
                                (v >> (4 - bit)) & 1 == 0,
                                "incorrect CashAddr version or padding"
                            );
                        } else {
                            c.bits(pos - 8, 1, (v >> (4 - bit)) & 1)?;
                        }
                    }
                }
                c.prefix_exact = tail.len() <= 34;
                if tail.len() > 34 {
                    ensure!(
                        profile.encode(&c.value)?.starts_with(&p),
                        "prefix contains an invalid CashAddr checksum"
                    );
                    c.prefix_exact = true;
                }
                if s.is_empty() {
                    c.probability = Some(2f64.powi(-(c.constrained_bits() as i32)));
                }
            }
            Encoding::Solana => {
                ensure!(
                    p.len() + s.len() <= 44
                        && p.bytes()
                            .chain(s.bytes())
                            .all(|b| BITCOIN_ALPHABET.as_bytes().contains(&b)),
                    "invalid Solana Base58 pattern (lowercase l is not supported)"
                );
                c.ranges = raw_base58_ranges(&p)?;
                ensure!(!c.ranges.is_empty(), "impossible Solana prefix");
                c.prefix_exact = true;
            }
            Encoding::StrKey => {
                ensure!(
                    p.len() + s.len() <= 56
                        && p.bytes()
                            .chain(s.bytes())
                            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
                    "Stellar patterns use uppercase Base32"
                );
                ensure!(
                    p.is_empty() || p.starts_with('G'),
                    "Stellar account addresses must start with G"
                );
                if p.len() > 1 {
                    ensure!(
                        matches!(p.as_bytes()[1], b'A'..=b'D'),
                        "the second Stellar character must be A, B, C or D"
                    );
                }
            }
            Encoding::Algorand => {
                ensure!(
                    p.len() + s.len() <= 58
                        && p.bytes()
                            .chain(s.bytes())
                            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
                    "Algorand patterns use uppercase Base32"
                );
                if let Some(b) = s.bytes().last().or_else(|| {
                    if p.len() == 58 {
                        p.bytes().last()
                    } else {
                        None
                    }
                }) {
                    ensure!(
                        "AEIMQUY4".as_bytes().contains(&b),
                        "Algorand's final character has two zero padding bits"
                    );
                }
            }
        }
        ensure!(
            !p.is_empty() || !s.is_empty(),
            "provide a nonempty prefix or suffix"
        );
        if matches!(profile.encoding(), Encoding::StrKey | Encoding::Algorand) {
            let version_bits = if profile.encoding() == Encoding::StrKey {
                8usize
            } else {
                0
            };
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            for (i, b) in p.bytes().enumerate() {
                let value = alphabet.find(b as char).unwrap() as u8;
                for bit in 0..5 {
                    let position = i * 5 + bit;
                    let v = (value >> (4 - bit)) & 1;
                    if position < version_bits {
                        ensure!(
                            v == ((48 >> (7 - position)) & 1),
                            "incorrect Stellar version"
                        );
                    } else if position < version_bits + 256 {
                        c.bits(position - version_bits, 1, v)?;
                    } else if position
                        >= version_bits + 256 + if version_bits > 0 { 16 } else { 32 }
                    {
                        ensure!(v == 0, "noncanonical Base32 padding");
                    }
                }
            }
            c.prefix_exact = p.len() * 5 <= version_bits + 256;
            if p.len() * 5 > version_bits + 256 {
                ensure!(
                    profile.encode(&c.value)?.starts_with(&p),
                    "prefix contains an invalid checksum"
                );
                c.prefix_exact = true;
            }
        }
        c.prefix = p;
        c.suffix = s;
        if profile.key_family() == KeyFamily::Ed25519
            && c.ranges.len() == 1
            && c.ranges[0].0 == c.ranges[0].1
        {
            super::ed_public(profile, &profile.encode(&c.ranges[0].0)?)?;
        }
        if c.mask.iter().all(|b| *b == 255) {
            let text = profile.encode(&c.value)?;
            if profile.key_family() == KeyFamily::Ed25519 {
                super::ed_public(profile, &text)?;
            }
            ensure!(
                c.matches_text(&text),
                "prefix and suffix are inconsistent or checksum is invalid"
            );
        }
        Ok(c)
    }
    fn bits(&mut self, start: usize, count: usize, value: u8) -> Result<()> {
        for k in 0..count {
            let pos = start + k;
            let bit = (value >> (count - 1 - k)) & 1;
            if pos >= self.mask.len() * 8 {
                ensure!(bit == 0, "noncanonical padding in prefix");
                continue;
            }
            let m = 1 << (7 - pos % 8);
            ensure!(
                self.mask[pos / 8] & m == 0 || ((self.value[pos / 8] & m) != 0) == (bit != 0),
                "overlapping patterns conflict"
            );
            self.mask[pos / 8] |= m;
            if bit != 0 {
                self.value[pos / 8] |= m;
            }
        }
        Ok(())
    }
    fn symbol(&mut self, start: usize, value: u8) -> Result<()> {
        self.bits(start, 5, value)
    }
    fn constrained_bits(&self) -> u32 {
        self.mask.iter().map(|b| b.count_ones()).sum()
    }
    pub fn matches_text(&self, text: &str) -> bool {
        let t = if self.profile.is_evm() {
            text.strip_prefix("0x").unwrap_or(text).to_ascii_lowercase()
        } else {
            text.into()
        };
        t.starts_with(&self.prefix) && t.ends_with(&self.suffix)
    }
    pub fn accepts_payload(&self, payload: &[u8]) -> bool {
        if payload.len() != self.mask.len()
            || payload
                .iter()
                .zip(&self.mask)
                .zip(&self.value)
                .any(|((b, m), v)| b & m != *v)
        {
            return false;
        }
        if !self.ranges.is_empty()
            && !self
                .ranges
                .iter()
                .any(|(lo, hi)| payload >= lo.as_slice() && payload <= hi.as_slice())
        {
            return false;
        }
        if self.profile.is_evm() || (self.prefix_exact && self.suffix.is_empty()) {
            return true;
        }
        if self.profile.chain == Chain::Warthog {
            let checksum = Sha256::digest(payload);
            let n = self.suffix.len().min(8);
            for (i, b) in self.suffix.as_bytes()[self.suffix.len() - n..]
                .iter()
                .enumerate()
            {
                let position = 8 - n + i;
                let v = if position.is_multiple_of(2) {
                    checksum[position / 2] >> 4
                } else {
                    checksum[position / 2] & 15
                };
                if *b != b"0123456789abcdef"[v as usize] {
                    return false;
                }
            }
            return true;
        }
        self.profile
            .encode_validated(payload)
            .is_ok_and(|t| self.matches_text(&t))
    }
}
trait HexDigit {
    fn to_digit16(self) -> Result<u8>;
}
impl HexDigit for u8 {
    fn to_digit16(self) -> Result<u8> {
        (self as char)
            .to_digit(16)
            .map(|n| n as u8)
            .ok_or_else(|| anyhow::anyhow!("invalid hex digit"))
    }
}
fn fixed20(n: BigUint) -> Vec<u8> {
    let b = n.to_bytes_be();
    let mut out = vec![0; 20];
    out[20 - b.len()..].copy_from_slice(&b);
    out
}
/// Exact prefix intervals in the 160-bit payload, including checksum boundary blocks.
/// All arithmetic here is public; no private key enters this compiler.
pub fn base58_ranges(version: u8, prefix: &str, ripple: bool) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let alphabet = if ripple {
        RIPPLE_ALPHABET
    } else {
        BITCOIN_ALPHABET
    };
    let zero = alphabet.as_bytes()[0];
    let one = BigUint::one();
    let radix = BigUint::from(58u32);
    let block = &one << 32usize;
    let base = BigUint::from(version) << 160usize;
    let domain_lo = &base << 32usize;
    let domain_hi = ((&base + (&one << 160usize)) << 32usize) - &one;
    let mut ranges: Vec<(BigUint, BigUint)> = vec![];
    for z in 0usize..25 {
        if version != 0 && z != 0 || version == 0 && z == 0 {
            continue;
        }
        if prefix.bytes().take(z.min(prefix.len())).any(|b| b != zero) {
            continue;
        }
        let significant = if prefix.len() > z { &prefix[z..] } else { "" };
        if significant.as_bytes().first() == Some(&zero) {
            continue;
        }
        let byte_lo = &one << (8 * (24 - z));
        let byte_hi = (&one << (8 * (25 - z))) - &one;
        for d in 1usize..=35 {
            if significant.len() > d {
                continue;
            }
            let mut lo = radix.pow((d - 1) as u32);
            let mut hi = radix.pow(d as u32) - &one;
            if !significant.is_empty() {
                let mut n = BigUint::zero();
                for b in significant.bytes() {
                    let digit = alphabet
                        .bytes()
                        .position(|x| x == b)
                        .ok_or_else(|| anyhow::anyhow!("invalid Base58 digit"))?;
                    n = n * 58u32 + BigUint::from(digit);
                }
                let scale = radix.pow((d - significant.len()) as u32);
                lo = lo.max(&n * &scale);
                hi = hi.min((n + &one) * scale - &one);
            }
            lo = lo.max(byte_lo.clone()).max(domain_lo.clone());
            hi = hi.min(byte_hi.clone()).min(domain_hi.clone());
            if lo > hi {
                continue;
            }
            let q_lo = (&lo + &block - &one) >> 32usize;
            let q_hi = (&hi + &one) >> 32usize;
            if q_lo < q_hi {
                ranges.push((&q_lo - &base, &q_hi - &one - &base));
            }
            for q in [&lo >> 32usize, &hi >> 32usize] {
                if q < base || q >= &base + (&one << 160usize) {
                    continue;
                }
                let h = &q - &base;
                let bytes = fixed20(h.clone());
                if base58check(version, &bytes, ripple).starts_with(prefix) {
                    ranges.push((h.clone(), h));
                }
            }
        }
    }
    ranges.sort();
    let mut merged: Vec<(BigUint, BigUint)> = vec![];
    for (lo, hi) in ranges {
        if let Some(last) = merged.last_mut()
            && lo <= &last.1 + &one
        {
            last.1 = last.1.clone().max(hi);
            continue;
        }
        merged.push((lo, hi));
    }
    Ok(merged
        .into_iter()
        .map(|(lo, hi)| (fixed20(lo), fixed20(hi)))
        .collect())
}

fn raw_base58_ranges(prefix: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let one = BigUint::one();
    let radix = BigUint::from(58u32);
    let mut ranges = vec![];
    let to_bytes = |n: BigUint| {
        let b = n.to_bytes_be();
        let mut v = vec![0; 32];
        v[32 - b.len()..].copy_from_slice(&b);
        v
    };
    for z in 0usize..32 {
        if prefix.bytes().take(z.min(prefix.len())).any(|b| b != b'1') {
            continue;
        }
        let significant = if prefix.len() > z { &prefix[z..] } else { "" };
        if significant.starts_with('1') {
            continue;
        }
        let byte_lo = &one << (8 * (31 - z));
        let byte_hi = (&one << (8 * (32 - z))) - &one;
        for d in 1usize..=44 {
            if significant.len() > d {
                continue;
            }
            let mut lo = radix.pow((d - 1) as u32);
            let mut hi = radix.pow(d as u32) - &one;
            if !significant.is_empty() {
                let mut n = BigUint::zero();
                for b in significant.bytes() {
                    let digit = BITCOIN_ALPHABET
                        .bytes()
                        .position(|x| x == b)
                        .context("invalid Base58 digit")?;
                    n = n * 58u32 + BigUint::from(digit);
                }
                let scale = radix.pow((d - significant.len()) as u32);
                lo = lo.max(&n * &scale);
                hi = hi.min((n + &one) * scale - &one);
            }
            lo = lo.max(byte_lo.clone());
            hi = hi.min(byte_hi.clone());
            if lo <= hi {
                ranges.push((to_bytes(lo), to_bytes(hi)));
            }
        }
    }
    // The all-zero key is weak and cannot be emitted by our standard seed engine.
    ranges.sort();
    let mut merged: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    for (lo, hi) in ranges {
        if let Some(last) = merged.last_mut() {
            let end = BigUint::from_bytes_be(&last.1) + &one;
            if BigUint::from_bytes_be(&lo) <= end {
                if hi > last.1 {
                    last.1 = hi;
                }
                continue;
            }
        }
        merged.push((lo, hi));
    }
    Ok(merged)
}
