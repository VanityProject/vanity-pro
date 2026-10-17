//! Typed mainnet address adapters. This layer handles public data only.
use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use secp256k1::{Parity, PublicKey, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512_256};
pub mod difficulty;
pub mod matching;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Chain {
    #[default]
    Ethereum,
    Bnb,
    Polygon,
    Arbitrum,
    Optimism,
    Base,
    Avalanche,
    Tron,
    Bitcoin,
    Litecoin,
    Dogecoin,
    BitcoinCash,
    Cosmos,
    Xrp,
    Solana,
    Stellar,
    Algorand,
    Warthog,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    #[default]
    Eoa,
    P2pkh,
    P2wpkh,
    P2tr,
    Cashaddr,
    Account,
    Classic,
    Ed25519,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub chain: Chain,
    pub network: Network,
    pub address_type: AddressType,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum KeyFamily {
    Secp256k1,
    Ed25519,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    WarthogHex,
    Base58 {
        version: u8,
        ripple: bool,
    },
    Bech32 {
        hrp: &'static str,
        witness: Option<u8>,
    },
    Cashaddr,
    Solana,
    StrKey,
    Algorand,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProfileInfo {
    pub profile: Profile,
    pub name: String,
    pub key_family: KeyFamily,
    pub fixed_prefix: &'static str,
    pub cpu: bool,
    pub opencl: bool,
    pub export: &'static str,
    pub search_strategy: &'static str,
    pub address_derivation: &'static str,
    pub address_encoding: &'static str,
    pub matching_alphabet: &'static str,
    pub case_sensitive: bool,
    pub verification: &'static str,
}
impl Chain {
    pub const ALL: [Self; 18] = [
        Self::Ethereum,
        Self::Bnb,
        Self::Polygon,
        Self::Arbitrum,
        Self::Optimism,
        Self::Base,
        Self::Avalanche,
        Self::Tron,
        Self::Bitcoin,
        Self::Litecoin,
        Self::Dogecoin,
        Self::BitcoinCash,
        Self::Cosmos,
        Self::Xrp,
        Self::Solana,
        Self::Stellar,
        Self::Algorand,
        Self::Warthog,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::Bnb => "BNB Smart Chain",
            Self::Polygon => "Polygon",
            Self::Arbitrum => "Arbitrum",
            Self::Optimism => "Optimism",
            Self::Base => "Base",
            Self::Avalanche => "Avalanche C-Chain",
            Self::Tron => "TRON",
            Self::Bitcoin => "Bitcoin",
            Self::Litecoin => "Litecoin",
            Self::Dogecoin => "Dogecoin",
            Self::BitcoinCash => "Bitcoin Cash",
            Self::Cosmos => "Cosmos Hub",
            Self::Xrp => "XRP Ledger",
            Self::Solana => "Solana",
            Self::Stellar => "Stellar",
            Self::Algorand => "Algorand",
            Self::Warthog => "Warthog",
        }
    }
    pub fn types(self) -> &'static [AddressType] {
        use AddressType::*;
        match self {
            Self::Bitcoin => &[P2pkh, P2wpkh, P2tr],
            Self::Litecoin => &[P2pkh, P2wpkh],
            Self::Dogecoin => &[P2pkh],
            Self::BitcoinCash => &[Cashaddr],
            Self::Cosmos | Self::Warthog => &[Account],
            Self::Xrp => &[Classic],
            Self::Solana | Self::Stellar | Self::Algorand => &[Ed25519],
            _ => &[Eoa],
        }
    }
}
impl AddressType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Eoa => "EOA",
            Self::P2pkh => "Legacy (P2PKH, compressed)",
            Self::P2wpkh => "Native SegWit (P2WPKH)",
            Self::P2tr => "Taproot (P2TR, key path)",
            Self::Cashaddr => "CashAddr (P2PKH)",
            Self::Account => "secp256k1 account",
            Self::Classic => "Classic (raw secp256k1 keypair)",
            Self::Ed25519 => "Ed25519 account",
        }
    }
}
impl Profile {
    pub fn new(chain: Chain, address_type: Option<AddressType>) -> Result<Self> {
        let p = Self {
            chain,
            network: Network::Mainnet,
            address_type: address_type.unwrap_or(chain.types()[0]),
        };
        p.validate()?;
        Ok(p)
    }
    pub fn validate(self) -> Result<()> {
        ensure!(
            self.chain.types().contains(&self.address_type),
            "unsupported address type for {}",
            self.chain.label()
        );
        Ok(())
    }
    pub fn is_legacy(&self) -> bool {
        *self == Self::default()
    }
    pub fn is_evm(self) -> bool {
        self.address_type == AddressType::Eoa && self.chain != Chain::Tron
    }
    pub fn key_family(self) -> KeyFamily {
        if matches!(self.chain, Chain::Solana | Chain::Stellar | Chain::Algorand) {
            KeyFamily::Ed25519
        } else {
            KeyFamily::Secp256k1
        }
    }
    pub fn encoding(self) -> Encoding {
        use Chain::*;
        match (self.chain, self.address_type) {
            (Warthog, _) => Encoding::WarthogHex,
            (Tron, _) => Encoding::Base58 {
                version: 65,
                ripple: false,
            },
            (Bitcoin, AddressType::P2pkh) => Encoding::Base58 {
                version: 0,
                ripple: false,
            },
            (Litecoin, AddressType::P2pkh) => Encoding::Base58 {
                version: 48,
                ripple: false,
            },
            (Dogecoin, _) => Encoding::Base58 {
                version: 30,
                ripple: false,
            },
            (Xrp, _) => Encoding::Base58 {
                version: 0,
                ripple: true,
            },
            (Bitcoin, AddressType::P2wpkh) => Encoding::Bech32 {
                hrp: "bc",
                witness: Some(0),
            },
            (Bitcoin, AddressType::P2tr) => Encoding::Bech32 {
                hrp: "bc",
                witness: Some(1),
            },
            (Litecoin, AddressType::P2wpkh) => Encoding::Bech32 {
                hrp: "ltc",
                witness: Some(0),
            },
            (Cosmos, _) => Encoding::Bech32 {
                hrp: "cosmos",
                witness: None,
            },
            (BitcoinCash, _) => Encoding::Cashaddr,
            (Solana, _) => Encoding::Solana,
            (Stellar, _) => Encoding::StrKey,
            (Algorand, _) => Encoding::Algorand,
            _ => Encoding::Hex,
        }
    }
    pub fn fixed_prefix(self) -> &'static str {
        match self.encoding() {
            Encoding::Hex => "0x",
            Encoding::Base58 { version: 65, .. } => "T",
            Encoding::Base58 {
                version: 0,
                ripple: false,
            } => "1",
            Encoding::Base58 { version: 48, .. } => "L",
            Encoding::Base58 { version: 30, .. } => "D",
            Encoding::Base58 { ripple: true, .. } => "r",
            Encoding::Bech32 {
                hrp: "bc",
                witness: Some(0),
            } => "bc1q",
            Encoding::Bech32 {
                hrp: "bc",
                witness: Some(1),
            } => "bc1p",
            Encoding::Bech32 { hrp: "ltc", .. } => "ltc1q",
            Encoding::Bech32 { hrp: "cosmos", .. } => "cosmos1",
            Encoding::Cashaddr => "bitcoincash:q",
            Encoding::StrKey => "G",
            _ => "",
        }
    }
    pub fn info(self) -> ProfileInfo {
        ProfileInfo {
            profile: self,
            name: format!(
                "{} / {} / mainnet",
                self.chain.label(),
                self.address_type.label()
            ),
            key_family: self.key_family(),
            fixed_prefix: self.fixed_prefix(),
            search_strategy: if self.key_family() == KeyFamily::Ed25519 {
                "independent OS-random standard seeds inside KeyManager"
            } else {
                "public secp256k1 point offsets"
            },
            address_derivation: if self.key_family() == KeyFamily::Ed25519 {
                "standard Ed25519 public key"
            } else if self.is_evm() || self.chain == Chain::Tron {
                "Keccak-256(uncompressed public key without tag), low 160 bits"
            } else if self.address_type == AddressType::P2tr {
                "even-y internal x-only key + tagged TapTweak*G"
            } else {
                "RIPEMD-160(SHA-256(compressed public key))"
            },
            address_encoding: match self.encoding() {
                Encoding::Hex => "EIP-55 hexadecimal",
                Encoding::WarthogHex => "hexadecimal payload + first 4 bytes of SHA-256(payload)",
                Encoding::Base58 { .. } => "Base58Check",
                Encoding::Bech32 {
                    witness: Some(1), ..
                } => "Bech32m",
                Encoding::Bech32 { .. } => "Bech32",
                Encoding::Cashaddr => "CashAddr",
                Encoding::Solana => "raw public-key Base58",
                Encoding::StrKey => "Stellar StrKey CRC16-XModem Base32",
                Encoding::Algorand => "Algorand SHA-512/256 checksum Base32",
            },
            matching_alphabet: match self.encoding() {
                Encoding::Hex | Encoding::WarthogHex => "0123456789abcdef",
                Encoding::Base58 { ripple: true, .. } => RIPPLE_ALPHABET,
                Encoding::Base58 { .. } | Encoding::Solana => BITCOIN_ALPHABET,
                Encoding::Bech32 { .. } | Encoding::Cashaddr => BECH32_ALPHABET,
                _ => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            },
            case_sensitive: !self.is_evm() && self.chain != Chain::Warthog,
            verification: if self.key_family() == KeyFamily::Ed25519 {
                "authenticated seed recovery, exact address reconstruction, strict Ed25519 signature"
            } else if self.address_type == AddressType::P2tr {
                "private parity normalization and tweak, output-key equality, BIP340 Schnorr signature"
            } else {
                "private reconstruction, full address comparison, ECDSA signature"
            },
            cpu: true,
            opencl: self.key_family() == KeyFamily::Secp256k1,
            export: if self.is_evm() {
                "Web3 V3"
            } else {
                match self.chain {
                    Chain::Tron => "TRON raw private key",
                    Chain::Xrp => "XRPL raw keypair (no family seed)",
                    Chain::Cosmos => "Cosmos raw secp256k1 key",
                    Chain::Solana => "Solana 64-byte keypair JSON",
                    Chain::Stellar => "Stellar secret StrKey",
                    Chain::Algorand => "Algorand SDK private key (Base64)",
                    Chain::Warthog => "Warthog Core wallet JSON (raw secp256k1 keypair)",
                    _ => "compressed WIF and output descriptor",
                }
            },
        }
    }
    pub fn payload(self, point: &PublicKey) -> Result<Vec<u8>> {
        self.validate()?;
        ensure!(
            self.key_family() == KeyFamily::Secp256k1,
            "Ed25519 requires its independent seed engine"
        );
        Ok(if self.is_evm() || self.chain == Chain::Tron {
            crate::crypto::address(point).to_vec()
        } else if self.address_type == AddressType::P2tr {
            taproot_output(point)?.0.to_vec()
        } else {
            hash160(&point.serialize()).to_vec()
        })
    }
    pub fn address(self, point: &PublicKey) -> Result<String> {
        self.encode(&self.payload(point)?)
    }
    /// A valid address derived from a fixed public test vector for diagnostics.
    pub fn diagnostic_address(self) -> Result<String> {
        self.validate()?;
        match self.key_family() {
            KeyFamily::Secp256k1 => self.address(&crate::crypto::generator()),
            KeyFamily::Ed25519 => {
                // RFC 8032 Ed25519 test 1 public key. No private test seed is used.
                const PUBLIC: [u8; 32] = [
                    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9,
                    0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02,
                    0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
                ];
                self.encode(&PUBLIC)
            }
        }
    }
    /// Preserve the v0.3 lowercase hex candidate representation for EVM jobs.
    pub fn candidate(self, point: &PublicKey) -> Result<String> {
        if self.is_evm() {
            Ok(hex::encode(crate::crypto::address(point)))
        } else {
            self.address(point)
        }
    }
    pub fn display_candidate(self, text: &str) -> Result<String> {
        if self.is_evm() {
            let b: [u8; 20] = hex::decode(text)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid EVM address"))?;
            Ok(crate::crypto::checksum(&b))
        } else {
            Ok(text.into())
        }
    }
    pub fn payload_len(self) -> usize {
        if self.key_family() == KeyFamily::Ed25519 || self.address_type == AddressType::P2tr {
            32
        } else {
            20
        }
    }
    pub fn encode(self, payload: &[u8]) -> Result<String> {
        self.validate()?;
        self.encode_validated(payload)
    }
    pub(crate) fn encode_validated(self, payload: &[u8]) -> Result<String> {
        ensure!(
            payload.len() == self.payload_len(),
            "invalid address payload length"
        );
        Ok(match self.encoding() {
            Encoding::Hex => crate::crypto::checksum(payload.try_into()?),
            Encoding::WarthogHex => {
                let mut bytes = payload.to_vec();
                bytes.extend_from_slice(&Sha256::digest(payload)[..4]);
                hex::encode(bytes)
            }
            Encoding::Base58 { version, ripple } => base58check(version, payload, ripple),
            Encoding::Bech32 { hrp, witness } => {
                let h = bech32::Hrp::parse(hrp)?;
                if let Some(v) = witness {
                    bech32::segwit::encode(h, bech32::Fe32::try_from(v)?, payload)?
                } else {
                    bech32::encode::<bech32::Bech32>(h, payload)?
                }
            }
            Encoding::Cashaddr => cashaddr(payload),
            Encoding::Solana => bs58::encode(payload).into_string(),
            Encoding::StrKey => strkey(48, payload),
            Encoding::Algorand => {
                let mut b = payload.to_vec();
                b.extend_from_slice(&Sha512_256::digest(payload)[28..]);
                data_encoding::BASE32_NOPAD.encode(&b)
            }
        })
    }
}
pub fn registry() -> Vec<ProfileInfo> {
    Chain::ALL
        .into_iter()
        .flat_map(|c| {
            c.types()
                .iter()
                .map(move |t| Profile::new(c, Some(*t)).expect("static profile").info())
        })
        .collect()
}
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(Sha256::digest(bytes)).into()
}
pub fn tagged_hash(tag: &str, bytes: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(bytes);
    h.finalize().into()
}
pub fn taproot_output(point: &PublicKey) -> Result<([u8; 32], Scalar)> {
    let (internal, _) = point.x_only_public_key();
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &internal.serialize()))?;
    let (output, _) = internal.add_tweak(&Secp256k1::verification_only(), &tweak)?;
    Ok((output.serialize(), tweak))
}
pub fn even_public(point: &PublicKey) -> PublicKey {
    if point.x_only_public_key().1 == Parity::Odd {
        point.negate(&Secp256k1::verification_only())
    } else {
        *point
    }
}
pub const BITCOIN_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub const RIPPLE_ALPHABET: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
pub const BECH32_ALPHABET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub fn base58check(version: u8, payload: &[u8], ripple: bool) -> String {
    let mut b = vec![version];
    b.extend_from_slice(payload);
    let c = Sha256::digest(Sha256::digest(&b));
    b.extend_from_slice(&c[..4]);
    bs58::encode(b)
        .with_alphabet(if ripple {
            bs58::Alphabet::RIPPLE
        } else {
            bs58::Alphabet::BITCOIN
        })
        .into_string()
}
pub fn convert_bits(bytes: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>> {
    let mut out = vec![];
    let mut acc = 0u32;
    let mut bits = 0;
    let mask = (1u32 << to) - 1;
    for b in bytes {
        ensure!(u32::from(*b) >> from == 0, "invalid encoded data");
        acc = ((acc << from) | u32::from(*b)) & ((1 << (from + to - 1)) - 1);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & mask) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & mask) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & mask) != 0 {
        bail!("noncanonical padding");
    }
    Ok(out)
}
pub fn cashaddr(payload: &[u8]) -> String {
    let mut bytes = vec![0];
    bytes.extend_from_slice(payload);
    let mut data = convert_bits(&bytes, 8, 5, true).expect("byte input");
    let mut check = 1u64;
    for v in "bitcoincash"
        .bytes()
        .map(|b| b & 31)
        .chain([0])
        .chain(data.iter().copied())
        .chain([0; 8])
    {
        let top = check >> 35;
        check = ((check & 0x07ffffffff) << 5) ^ u64::from(v);
        for (i, g) in [
            0x98f2bc8e61,
            0x79b76d99e2,
            0xf33e5fb3c4,
            0xae2eabe2a8,
            0x1e4f43e470,
        ]
        .iter()
        .enumerate()
        {
            if (top >> i) & 1 != 0 {
                check ^= g;
            }
        }
    }
    check ^= 1;
    for i in (0..8).rev() {
        data.push(((check >> (5 * i)) & 31) as u8);
    }
    format!(
        "bitcoincash:{}",
        data.iter()
            .map(|b| BECH32_ALPHABET.as_bytes()[*b as usize] as char)
            .collect::<String>()
    )
}
pub fn strkey(version: u8, bytes: &[u8]) -> String {
    let mut b = vec![version];
    b.extend_from_slice(bytes);
    let mut crc = 0u16;
    for byte in &b {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    b.extend_from_slice(&crc.to_le_bytes());
    data_encoding::BASE32_NOPAD.encode(&b)
}

/// Decode only supported canonical Ed25519 account encodings, including checksums.
pub fn ed_public(profile: Profile, text: &str) -> Result<[u8; 32]> {
    ensure!(
        profile.key_family() == KeyFamily::Ed25519,
        "not an Ed25519 profile"
    );
    let bytes = match profile.encoding() {
        Encoding::Solana => bs58::decode(text).into_vec()?,
        Encoding::StrKey => {
            let b = data_encoding::BASE32_NOPAD.decode(text.as_bytes())?;
            ensure!(b.len() == 35 && b[0] == 48, "invalid Stellar account");
            b[1..33].to_vec()
        }
        Encoding::Algorand => {
            let b = data_encoding::BASE32_NOPAD.decode(text.as_bytes())?;
            ensure!(b.len() == 36, "invalid Algorand account");
            b[..32].to_vec()
        }
        _ => bail!("not an Ed25519 encoding"),
    };
    let public: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public key length"))?;
    ensure!(
        profile.encode(&public)? == text,
        "noncanonical address or invalid checksum"
    );
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public)?;
    ensure!(
        !key.is_weak() && key.to_edwards().is_torsion_free(),
        "address is not a nonzero prime-order Ed25519 signing key"
    );
    Ok(public)
}
