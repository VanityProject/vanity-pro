//! Wart Dapp's `Import existing database` format, pinned to its SQLite and Fernet importer.
//! A reviewed SQLite template has one fixed-width wallet row. Replacing only its text
//! payload bytes preserves the B-tree layout without a runtime SQLite dependency.
use super::random;
use aes::{
    Aes128,
    cipher::{Block, BlockEncrypt, KeyInit},
};
use anyhow::{Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const TEMPLATE: &[u8] = include_bytes!("warthog_dapp_template.db");
const ADDRESS_MARKER: [u8; 48] = [b'A'; 48];
const TOKEN_MARKER: [u8; 184] = [b'T'; 184];
const SALT_MARKER: [u8; 24] = [b'S'; 24];
const DAPP_ITERATIONS: u32 = 480_000;

fn replace_once(bytes: &mut [u8], marker: &[u8], value: &[u8]) -> Result<()> {
    ensure!(
        marker.len() == value.len(),
        "Wart Dapp template field length changed"
    );
    let mut positions = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(i, window)| (window == marker).then_some(i));
    let position = positions.next();
    ensure!(
        position.is_some() && positions.next().is_none(),
        "Wart Dapp template marker is invalid"
    );
    let position = position.unwrap();
    bytes[position..position + marker.len()].copy_from_slice(value);
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    debug_assert!(key.len() <= 64);
    let mut inner_pad = Zeroizing::new([0x36_u8; 64]);
    let mut outer_pad = Zeroizing::new([0x5c_u8; 64]);
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(&*inner_pad);
    hash.update(data);
    let inner = Zeroizing::new(hash.finalize().to_vec());
    let mut hash = Sha256::new();
    hash.update(&*outer_pad);
    hash.update(&*inner);
    hash.finalize().into()
}

/// Match `utils.encrypt_pk`: PBKDF2-SHA256, Fernet AES-128-CBC, then HMAC-SHA256.
fn encrypt_key(private_hex: &str, password: &str, salt: &[u8; 16]) -> Result<Zeroizing<String>> {
    let iv = Zeroizing::new(random::<16>()?);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    encrypt_key_with(private_hex, password, salt, &iv, timestamp)
}

fn encrypt_key_with(
    private_hex: &str,
    password: &str,
    salt: &[u8; 16],
    iv: &[u8; 16],
    timestamp: u64,
) -> Result<Zeroizing<String>> {
    let mut derived = Zeroizing::new([0_u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, DAPP_ITERATIONS, &mut *derived);
    let cipher = Aes128::new_from_slice(&derived[16..])?;
    let mut padded = Zeroizing::new(private_hex.as_bytes().to_vec());
    let padding = 16 - padded.len() % 16;
    padded.extend(std::iter::repeat_n(padding as u8, padding));
    let mut previous = Zeroizing::new(*iv);
    let mut token = Zeroizing::new(Vec::with_capacity(1 + 8 + 16 + padded.len() + 32));
    token.push(0x80);
    token.extend_from_slice(&timestamp.to_be_bytes());
    token.extend_from_slice(iv);
    for chunk in padded.chunks_exact(16) {
        let mut block = Zeroizing::new([0_u8; 16]);
        for i in 0..16 {
            block[i] = chunk[i] ^ previous[i];
        }
        cipher.encrypt_block(Block::<Aes128>::from_mut_slice(&mut block[..]));
        token.extend_from_slice(&*block);
        previous.copy_from_slice(&*block);
    }
    let signature = Zeroizing::new(hmac_sha256(&derived[..16], &token));
    token.extend_from_slice(&*signature);
    Ok(Zeroizing::new(URL_SAFE.encode(&*token)))
}

/// Return a single-wallet database accepted by wart-dapp's existing-database import.
pub(super) fn database(
    scalar: &[u8; 32],
    address: &str,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        address.len() == 48 && address.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid Warthog address for Wart Dapp export"
    );
    ensure!(
        (8..=1024).contains(&password.chars().count()),
        "Wart Dapp wallet password must contain 8 to 1024 characters"
    );
    let private_hex = Zeroizing::new(hex::encode(scalar));
    let salt = Zeroizing::new(random::<16>()?);
    let token = encrypt_key(&private_hex, password, &salt)?;
    let salt_text = Zeroizing::new(STANDARD.encode(&*salt));
    ensure!(
        token.len() == TOKEN_MARKER.len() && salt_text.len() == SALT_MARKER.len(),
        "Wart Dapp encrypted record length changed"
    );
    let mut output = Zeroizing::new(TEMPLATE.to_vec());
    replace_once(&mut output, &ADDRESS_MARKER, address.as_bytes())?;
    replace_once(&mut output, &TOKEN_MARKER, token.as_bytes())?;
    replace_once(&mut output, &SALT_MARKER, salt_text.as_bytes())?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_cryptography_fernet_known_answer() {
        let mut salt = [0_u8; 16];
        let mut iv = [0_u8; 16];
        for index in 0..16 {
            salt[index] = index as u8;
            iv[index] = index as u8 + 16;
        }
        let private = format!("{:064x}", 1);
        let actual = encrypt_key_with(
            &private,
            "synthetic wallet password",
            &salt,
            &iv,
            1_700_000_000,
        )
        .unwrap();
        // Independently generated by cryptography.fernet.Fernet._encrypt_from_parts.
        assert_eq!(
            actual.as_str(),
            "gAAAAABlU_EAEBESExQVFhcYGRobHB0eHzZxSI6VpLCwPJy_dkARFDBWkD4ALrk3EJTuBGgvp_Dd4SjJUVBjwZuqqg_FCWcwBpG8Xtskg2RlORbiJUQlLIQytqkO0U2NcIcRAbzcpRHY7ZGyl2qPzaif4XeraCmZ0ZZlj8sfBQMmIbrY1ZdpxYc="
        );
    }

    #[test]
    fn template_has_exact_markers_and_fernet_shape() {
        let scalar = [0_u8; 32];
        let address = "0".repeat(48);
        let database = database(&scalar, &address, "synthetic wallet password").unwrap();
        assert_eq!(&database[..16], b"SQLite format 3\0");
        assert!(
            !database
                .windows(ADDRESS_MARKER.len())
                .any(|w| w == ADDRESS_MARKER)
        );
        assert!(
            !database
                .windows(TOKEN_MARKER.len())
                .any(|w| w == TOKEN_MARKER)
        );
        assert!(
            !database
                .windows(SALT_MARKER.len())
                .any(|w| w == SALT_MARKER)
        );
        assert!(
            database
                .windows(address.len())
                .any(|w| w == address.as_bytes())
        );
    }
}
