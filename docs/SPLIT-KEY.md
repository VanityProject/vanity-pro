# Split-key search

Split-key search lets a helper computer search with a public key. The owner keeps
the encrypted private share and its password. The owner combines the result on
the owner computer and saves the final encrypted wallet.

Use one helper for each request. This version exchanges files. It has no network
service or third-party split-key file import.

## Supported profiles

The feature supports all 18 secp256k1 profiles: the seven EVM networks, TRON,
Bitcoin P2PKH/P2WPKH/P2TR, Litecoin P2PKH/P2WPKH, Dogecoin, Bitcoin Cash, Cosmos Hub,
XRP classic, and Warthog. XRP uses the existing raw keypair format, without a
family seed. New Taproot searches use Linear enumeration and the existing key-path
descriptor and parity rules.

Solana, Stellar, and Algorand are unavailable for split-key search. Their standard
wallet files need Ed25519 seeds. Public-point addition does not produce a standard
seed for the resulting key. Existing local searches for these profiles remain
available.

## Windows procedure

1. On the owner computer, select **Split-key search**, then **Create request**.
2. Select the blockchain and address type. Enter the address prefix.
3. Select **Create request**. Enter the private share password twice. Select **Save private share**.
4. Make a recovery copy of the complete owner session folder. Keep its password.
5. Select **Save public request**. Transfer only this public file to the helper.
6. On the helper computer, select **Split-key search**. Select **Import search request**. Read the configuration.
7. Select **Start search**. Calibration selects settings for the helper computer.
8. After a match, select **Save search result**. Transfer this public file to the owner.
9. Open the owner session. Select **Import search result**.
10. Select **Combine and save wallet**. Enter the private share password. Select **Unlock private share**.
11. Set the wallet password and select a new encrypted wallet file.
12. Use the address only after the wallet check is correct.

CAUTION: Keep the encrypted private share and its password. The public request
and result cannot recover a wallet without the private share.

Each request has a fresh private share. A finalized owner session is reserved for
one candidate. A failed wallet save can retry that candidate with a new filename.
Keep the complete owner folder for recovery. Its finalization record prevents
another candidate from replacing a reserved wallet. Deleting that folder removes
the private share and its recovery records.

## CLI procedure

Run these commands on the specified computer. Passwords are entered at prompts.

```powershell
# Owner: make the encrypted share and the public request without calibration.
.\vanity.exe split create-request --chain ethereum --prefix 00000 --session C:\Vanity\Owner --out C:\Transfer\request.json
# Owner: save another copy of the public request if necessary.
.\vanity.exe split export-request --session C:\Vanity\Owner --out C:\Transfer\request-copy.json
# Helper: calibrate, make a public worker session, and search.
.\vanity.exe split search --request C:\Transfer\request.json --output C:\Vanity\Worker --backend auto
# Helper: continue a paused worker session with its saved strategy.
.\vanity.exe resume --session C:\Vanity\Worker --backend auto
# Helper: save the public result after a match.
.\vanity.exe split export-result --session C:\Vanity\Worker --out C:\Transfer\result.json
# Owner: import the public result and save the privately verified wallet.
.\vanity.exe split import-result --session C:\Vanity\Owner --result C:\Transfer\result.json
.\vanity.exe finalize --session C:\Vanity\Owner --out C:\Vanity\wallet.json
```

Create the parent folders first. Existing output files are not overwritten.
Use the existing `--tuning auto|off` and `--tuning-cache` options on the helper.
**Skip tuning** keeps the self-tested incumbent. **Stop** cancels calibration.
The helper never needs the private share password.

## Public file and custody contracts

`SplitRequest` version 1 contains the original Linear owner job. Its fingerprint
is SHA-256 of the validated typed serialization. `SplitResult` version 1 contains
that request fingerprint, the helper job, and the candidate offset, transformation,
and address. Import requires the same public key, profile, and pattern. The helper
job has its own session ID and its selected enumeration strategy.

The helper selects a strategy before its job is saved. Resume, device changes, and
retuning keep that strategy and its cursor. Calibration caches and hardware
settings stay on the helper. Calibration uses synthetic inputs.

`split-session.json` identifies the local role and binds the job and request.
`split-request.json` retains the public request. Owner imports use
`split-result.json`; they do not fabricate search checkpoint coverage. Worker
results still require a valid checkpoint and an independently checked candidate.
Only explicit public request/result objects are exported.

For a basic offset, workers test `P + kG`, where `P = aG` is the owner's public
share. The owner recovers `(a + k) mod n`. Optimized branches apply their recorded
negation and endomorphism to both the point and the combined scalar. The owner
authenticates the original encrypted share against its original job, reconstructs
the full address, proves private ownership, and verifies the encrypted file after
writing it. A public file checksum alone does not establish private ownership.

The additive construction follows the established
[VanitySearch split-key workflow](https://github.com/JeanLucPons/VanitySearch#generate-a-vanity-address-for-a-third-party-using-split-key).
Taproot uses [BIP 341](https://bips.dev/341/). Standard Ed25519 seed derivation is
specified by [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5).
