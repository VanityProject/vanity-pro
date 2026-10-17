//! Public secp256k1 endomorphisms. Constants are mathematical field/scalar roots.
//! Reference: bitcoin-core/secp256k1 scalar_impl.h (MIT), lambda*G = (beta*G.x,G.y).
use crate::crypto::Offset;
use anyhow::{Result, ensure};
use secp256k1::{PublicKey, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
pub const BETA_HEX: &str = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";
pub const LAMBDA_HEX: &str = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transform {
    #[default]
    Identity,
    Endo1,
    Endo2,
    Negate,
    NegateEndo1,
    NegateEndo2,
}
impl Transform {
    pub fn is_identity(&self) -> bool {
        *self == Self::Identity
    }
    pub fn branch(self) -> u8 {
        match self {
            Self::Identity => 0,
            Self::Endo1 => 1,
            Self::Endo2 => 2,
            Self::Negate => 3,
            Self::NegateEndo1 => 4,
            Self::NegateEndo2 => 5,
        }
    }
    pub fn from_branch(n: u8) -> Result<Self> {
        Ok(match n {
            0 => Self::Identity,
            1 => Self::Endo1,
            2 => Self::Endo2,
            3 => Self::Negate,
            4 => Self::NegateEndo1,
            5 => Self::NegateEndo2,
            _ => anyhow::bail!("invalid candidate transformation"),
        })
    }
    pub fn power(self) -> u8 {
        self.branch() % 3
    }
    pub fn negative(self) -> bool {
        self.branch() >= 3
    }
    pub fn lambda() -> Scalar {
        Offset::parse(LAMBDA_HEX)
            .expect("constant scalar")
            .scalar()
            .expect("nonzero lambda")
    }
    pub fn public(self, p: &PublicKey) -> Result<PublicKey> {
        if self == Self::Identity {
            return Ok(*p);
        }
        static CONTEXT: std::sync::OnceLock<Secp256k1<secp256k1::VerifyOnly>> =
            std::sync::OnceLock::new();
        let secp = CONTEXT.get_or_init(Secp256k1::verification_only);
        let mut q = *p;
        for _ in 0..self.power() {
            q = q.mul_tweak(secp, &Self::lambda())?;
        }
        if self.negative() {
            q = q.negate(secp);
        }
        Ok(q)
    }
    pub fn validate(self, width: u8) -> Result<()> {
        ensure!(
            self.branch() < width,
            "transformation does not belong to this search strategy"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endomorphism_roots_have_order_three() {
        use num_bigint::BigUint;
        let one = BigUint::from(1u8);
        let three = BigUint::from(3u8);
        let beta = BigUint::parse_bytes(BETA_HEX.as_bytes(), 16).unwrap();
        let lambda = BigUint::parse_bytes(LAMBDA_HEX.as_bytes(), 16).unwrap();
        let prime = (BigUint::from(1u8) << 256usize)
            - (BigUint::from(1u8) << 32usize)
            - BigUint::from(977u16);
        let order = BigUint::from_bytes_be(&crate::crypto::ORDER.0);
        assert_ne!(beta, one);
        assert_ne!(lambda, one);
        assert_eq!(beta.modpow(&three, &prime), one);
        assert_eq!(lambda.modpow(&three, &order), one);
    }
}
