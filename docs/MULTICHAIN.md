# Address profiles and wallet formats

## Key and address rules

New jobs store a typed chain, mainnet network and address type. Secp256k1 jobs use
schema 3. Ed25519 jobs use schema 2. Schema 1 jobs remain Ethereum-only and
preserve their original fingerprint bytes.
Explicit CLI chain overrides must match the stored profile. Settings migrate old
Ethereum preferences to schema 3. The registry uses typed adapters and constants,
not executable cryptographic scripts supplied by users.

Bitcoin-derived addresses use compressed public keys. P2WPKH is witness version 0
with Bech32; P2TR is version 1 with Bech32m. Taproot normalizes the internal public
key to even y before applying tagged TapTweak, and final signing applies the same
private-key normalization and tweak. Native export preserves the internal WIF and
checksummed tr descriptor, so importing software can derive the output key.
No HD derivation path or mnemonic recovery is claimed for a standalone vanity key.

TRON hashes the uncompressed point without its 04 tag using Keccak-256, then adds
version 41 hex and Base58Check. Cosmos Hub is an ordinary compressed secp256k1
Hash160 account with cosmos Bech32; consensus keys and other Cosmos chains are
outside this profile. XRP uses the Ripple alphabet and classic account encoding;
its standalone scalar is **not** a conventional 16-byte family seed. Use the
verified raw-keypair SDK path. X-addresses are not enabled.

Solana, Stellar and Algorand preserve standard independent 32-byte Ed25519 seeds.
They never use public-point offset searches. Solana exports the seed followed by
its public key in the usual 64-byte keypair JSON. Stellar exports the S secret
StrKey. Algorand exports the SDK's 64-byte Base64 private key; it does not label that
string as a mnemonic. Solana PDAs, Stellar muxed/contract accounts and Algorand
application escrows are not ordinary signing accounts and are not enabled.

Warthog uses compressed-public-key Hash160 plus four bytes of single SHA256 of
that payload, encoded as 48 lowercase hex characters. The checksum follows the
40 payload characters, so leading-pattern searches defer checksum work until a
candidate is reported. The Core JSON export preserves a 64-character private key
with leading zeroes and the corresponding compressed public key. The Wart Dapp
`.db` export encrypts that same key using the wallet password. See the separate
[mainnet import guide](WARTHOG.md).

## Matching and probability

Base58Check prefixes compile into exact public payload intervals, including
checksum-boundary payloads. Bech32/CashAddr compile fixed/version/padding and data
bits; full encoding and checksum comparison validate every returned hit. GPU
filters preserve all legal matches; the independent CPU verifier reconstructs
public points and the complete native address. Prefix and suffix constraints are
combined; impossible version/alphabet/case/padding/checksum combinations fail early.

The UI distinguishes fixed prefixes. Hex input is case-insensitive; Base58 and
Base32 preserve their specified case. Bech32/CashAddr use canonical lowercase.
Solana `SoL` is valid and `Sol` is invalid because lowercase l is absent in Base58.

Exact probabilities use the uniform payload model. They do not guarantee a
completion time. Other estimates use 32,768 independent public samples.
The application makes these samples on demand with OS randomness. It keeps only
public outputs in memory for that process. Native sample seeds and scalars stay
in KeyManager and are cleared after use. Samples do not supply production keys.

Sample estimates use a pointwise Wilson 95% interval. Fewer than 20 matches
suppress the probability and time estimates. Zero sampled matches do not establish
impossibility. These intervals apply to a fixed pattern. They do not provide
simultaneous or adaptive guarantees when users select patterns after inspecting
sample results.

## Primary references

- [BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki), [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki), [BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki), [BIP380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki).
- [TRON accounts](https://developers.tron.network/docs/account), [Litecoin address prefixes](https://litecoin.info/docs/key-concepts/addresses-prefixes), [Dogecoin addresses](https://lib.dogecoin.org/docs/address), [CashAddr](https://documentation.cash/protocol/blockchain/addresses.html).
- [XRPL cryptographic keys](https://xrpl.org/docs/concepts/accounts/cryptographic-keys), [XRPL accounts](https://xrpl.org/docs/concepts/accounts/addresses).
- [RFC8032](https://www.rfc-editor.org/rfc/rfc8032), [Stellar StrKey](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md), [Algorand keys](https://dev.algorand.co/concepts/accounts/keys-signing/).
