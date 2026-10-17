//! Public-only reference arithmetic. No private-key type is used here.
use anyhow::{Result, ensure};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

pub const ORDER: Offset = Offset([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]);
pub const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Big-endian 256-bit integer. The order itself is allowed only as an end cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Offset(pub [u8; 32]);
impl Offset {
    pub const ZERO: Self = Self([0; 32]);
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
    pub fn parse(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
            "offset must contain exactly 64 hex digits"
        );
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes)?;
        let offset = Self(bytes);
        ensure!(offset <= ORDER, "offset exceeds scalar order");
        Ok(offset)
    }
    pub fn checked_add(self, value: u64) -> Result<Self> {
        let mut out = self.0;
        let mut carry = value as u128;
        for byte in out.iter_mut().rev() {
            carry += *byte as u128;
            *byte = carry as u8;
            carry >>= 8;
        }
        ensure!(carry == 0, "offset overflow");
        let out = Self(out);
        ensure!(out <= ORDER, "scalar range exhausted");
        Ok(out)
    }
    pub fn distance(self, end: Self) -> Result<u64> {
        let diff = self.difference(end)?.0;
        ensure!(
            diff[..24].iter().all(|b| *b == 0),
            "interval too large for a batch"
        );
        Ok(u64::from_be_bytes(diff[24..].try_into()?))
    }
    pub fn difference(self, end: Self) -> Result<Self> {
        ensure!(end >= self, "reversed interval");
        let mut diff = [0; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let v = end.0[i] as i16 - self.0[i] as i16 - borrow;
            diff[i] = v as u8;
            borrow = if v < 0 { 1 } else { 0 };
        }
        Ok(Self(diff))
    }
    pub fn add_offset(self, other: Self) -> Result<Self> {
        let mut sum = [0; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            carry += u16::from(self.0[i]) + u16::from(other.0[i]);
            sum[i] = carry as u8;
            carry >>= 8;
        }
        let value = Self(sum);
        ensure!(carry == 0 && value <= ORDER, "offset sum overflow");
        Ok(value)
    }
    pub fn decimal(self) -> String {
        let mut bytes = self.0;
        let mut text = vec![];
        while bytes.iter().any(|b| *b != 0) {
            let mut remainder = 0u16;
            for byte in &mut bytes {
                let value = remainder * 256 + u16::from(*byte);
                *byte = (value / 10) as u8;
                remainder = value % 10;
            }
            text.push(b'0' + remainder as u8);
        }
        if text.is_empty() {
            return "0".into();
        }
        text.reverse();
        String::from_utf8(text).expect("decimal ASCII")
    }
    pub fn scalar(self) -> Result<Scalar> {
        ensure!(self < ORDER, "offset is not canonical");
        Scalar::from_be_bytes(self.0).map_err(Into::into)
    }
    pub fn as_f64(self) -> f64 {
        self.0.iter().fold(0.0, |n, b| n * 256.0 + *b as f64)
    }
}
impl Serialize for Offset {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}
impl<'de> Deserialize<'de> for Offset {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
pub fn keccak(input: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    let mut state = Keccak::v256();
    state.update(input);
    state.finalize(&mut hash);
    hash
}
pub fn address(point: &PublicKey) -> [u8; 20] {
    keccak(&point.serialize_uncompressed()[1..])[12..]
        .try_into()
        .expect("20 bytes")
}
pub fn checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = keccak(lower.as_bytes());
    let text: String = lower
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            let nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 15
            };
            if nibble >= 8 {
                (b as char).to_ascii_uppercase()
            } else {
                b as char
            }
        })
        .collect();
    format!("0x{text}")
}
pub fn generator() -> PublicKey {
    PublicKey::from_slice(&hex::decode(GENERATOR).expect("constant")).expect("generator")
}
pub fn public_at<T: TryInto<Offset>>(initial: &PublicKey, offset: T) -> Result<Option<PublicKey>>
where
    T::Error: Into<anyhow::Error>,
{
    let scalar = offset.try_into().map_err(Into::into)?.scalar()?;
    Ok(initial
        .add_exp_tweak(&Secp256k1::verification_only(), &scalar)
        .ok())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    pub prefix: String,
    pub suffix: String,
    #[serde(default, skip_serializing_if = "crate::chains::Profile::is_legacy")]
    pub profile: crate::chains::Profile,
}
impl Pattern {
    pub fn new(prefix: &str, suffix: &str) -> Result<Self> {
        Self::for_profile(crate::chains::Profile::default(), prefix, suffix)
    }
    pub fn for_profile(
        profile: crate::chains::Profile,
        prefix: &str,
        suffix: &str,
    ) -> Result<Self> {
        let compiled = crate::chains::matching::Compiled::new(profile, prefix, suffix)?;
        Ok(Self {
            prefix: compiled.prefix,
            suffix: compiled.suffix,
            profile,
        })
    }
    pub fn compiled(&self) -> Result<crate::chains::matching::Compiled> {
        let c = crate::chains::matching::Compiled::new(self.profile, &self.prefix, &self.suffix)?;
        ensure!(
            c.prefix == self.prefix && c.suffix == self.suffix,
            "noncanonical pattern"
        );
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        self.compiled().map(|_| ())
    }
    pub fn matches(&self, addr: &[u8; 20]) -> bool {
        if self.profile.is_evm() {
            let text = hex::encode(addr);
            text.starts_with(&self.prefix) && text.ends_with(&self.suffix)
        } else {
            self.compiled().is_ok_and(|c| c.accepts_payload(addr))
        }
    }
    pub fn estimate(&self) -> Result<crate::chains::difficulty::Estimate> {
        Ok(crate::chains::difficulty::estimate(&self.compiled()?))
    }
    pub fn probability(&self) -> f64 {
        self.estimate()
            .ok()
            .and_then(|e| e.probability)
            .unwrap_or(f64::NAN)
    }
    pub fn success_probability(&self, trials: f64) -> f64 {
        -(trials * (-self.probability()).ln_1p()).exp_m1()
    }
}
