//! Public work cursors. Scalar offsets retain their original 256-bit format.
use crate::crypto::{ORDER, Offset};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkIndex(pub [u8; 33]);
impl Default for WorkIndex {
    fn default() -> Self {
        Self::ZERO
    }
}
impl WorkIndex {
    pub const ZERO: Self = Self([0; 33]);
    pub fn from_u64(n: u64) -> Self {
        Offset::from_u64(n).into()
    }
    pub fn checked_add(self, n: u64) -> Result<Self> {
        let mut out = self.0;
        let mut carry = n as u128;
        for b in out.iter_mut().rev() {
            carry += *b as u128;
            *b = carry as u8;
            carry >>= 8;
        }
        let value = Self(out);
        ensure!(
            carry == 0 && value <= Self::from(ORDER).times(6)?,
            "work index overflow"
        );
        Ok(value)
    }
    pub fn times(self, n: u8) -> Result<Self> {
        let mut out = self.0;
        let mut carry = 0u16;
        for b in out.iter_mut().rev() {
            let v = u16::from(*b) * u16::from(n) + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        ensure!(carry == 0, "work multiplication overflow");
        Ok(Self(out))
    }
    pub fn div_rem(self, divisor: u8) -> Result<(Offset, u8)> {
        ensure!(divisor > 0, "zero work divisor");
        if divisor == 1 {
            return Ok((Offset::try_from(self)?, 0));
        }
        let mut out = [0; 33];
        let mut remainder = 0u16;
        for (i, b) in self.0.iter().enumerate() {
            let n = remainder * 256 + u16::from(*b);
            out[i] = (n / u16::from(divisor)) as u8;
            remainder = n % u16::from(divisor);
        }
        Ok((Offset::try_from(Self(out))?, remainder as u8))
    }
    pub fn difference(self, end: impl Into<Self>) -> Result<Self> {
        let end = end.into();
        ensure!(end >= self, "reversed work interval");
        let mut out = [0; 33];
        let mut borrow = 0i16;
        for i in (0..33).rev() {
            let v = i16::from(end.0[i]) - i16::from(self.0[i]) - borrow;
            out[i] = v as u8;
            borrow = i16::from(v < 0);
        }
        Ok(Self(out))
    }
    pub fn distance(self, end: impl Into<Self>) -> Result<u64> {
        let d = self.difference(end)?.0;
        ensure!(d[..25].iter().all(|b| *b == 0), "work interval too large");
        Ok(u64::from_be_bytes(d[25..].try_into()?))
    }
    pub fn add_offset(self, other: Self) -> Result<Self> {
        let mut out = [0; 33];
        let mut carry = 0u16;
        for i in (0..33).rev() {
            let v = u16::from(self.0[i]) + u16::from(other.0[i]) + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        let out = Self(out);
        ensure!(
            carry == 0 && out <= Self::from(ORDER).times(6)?,
            "work sum overflow"
        );
        Ok(out)
    }
    pub fn decimal(self) -> String {
        num_bigint::BigUint::from_bytes_be(&self.0).to_str_radix(10)
    }
    pub fn as_f64(self) -> f64 {
        self.0.iter().fold(0., |n, b| n * 256. + f64::from(*b))
    }
}
impl From<Offset> for WorkIndex {
    fn from(value: Offset) -> Self {
        let mut bytes = [0; 33];
        bytes[1..].copy_from_slice(&value.0);
        Self(bytes)
    }
}
impl TryFrom<WorkIndex> for Offset {
    type Error = anyhow::Error;
    fn try_from(value: WorkIndex) -> Result<Self> {
        ensure!(value.0[0] == 0, "work index is not a scalar offset");
        let out = Offset(value.0[1..].try_into()?);
        ensure!(out <= ORDER, "work index exceeds scalar order");
        Ok(out)
    }
}
impl PartialEq<Offset> for WorkIndex {
    fn eq(&self, other: &Offset) -> bool {
        *self == Self::from(*other)
    }
}
impl PartialOrd<Offset> for WorkIndex {
    fn partial_cmp(&self, other: &Offset) -> Option<std::cmp::Ordering> {
        self.partial_cmp(&Self::from(*other))
    }
}
impl Serialize for WorkIndex {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if *self <= ORDER {
            s.serialize_str(&hex::encode(&self.0[1..]))
        } else {
            s.serialize_str(&hex::encode(self.0))
        }
    }
}
impl<'de> Deserialize<'de> for WorkIndex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let text = String::deserialize(d)?;
        let mut bytes = [0; 33];
        match text.len() {
            64 => hex::decode_to_slice(&text, &mut bytes[1..]),
            66 => hex::decode_to_slice(&text, &mut bytes),
            _ => {
                return Err(D::Error::custom(
                    "work cursor must have 64 or 66 hex digits",
                ));
            }
        }
        .map_err(D::Error::custom)?;
        let value = Self(bytes);
        if value > Self::from(ORDER).times(6).map_err(D::Error::custom)?
            || (text.len() == 66 && value <= ORDER)
            || (text.len() == 64 && value > ORDER)
            || text != text.to_ascii_lowercase()
        {
            return Err(D::Error::custom("noncanonical work cursor"));
        }
        Ok(value)
    }
}
