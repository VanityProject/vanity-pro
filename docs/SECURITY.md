# Wallet custody and recovery

Windows storage is restricted to ordinary local fixed, removable, or RAM drives.
UNC/network drives, device paths, junctions, symlinks, and cloud placeholders are
rejected. Copy recovery files to an ordinary local folder before using them.
Public GUI receipts are export history only: startup does not probe their wallet
paths, and a missing wallet remains an unverified record until explicitly checked.
Temporary private files receive their protected owner DACL atomically at creation.
Native opens reject reparse traversal at use time; handle-relative persistence
retains atomic replacement without following a changed directory path.

Use a trustworthy offline machine and vendor runtime. The key-manager boundary
keeps decrypted keys out of public search workers and GPU buffers; it does not
isolate process memory from privileged malware or a malicious native driver.
An independent external audit remains appropriate before relying on substantial
funds.

## Secret handling and encrypted formats

- OS cryptographic randomness supplies rejection-sampled secp256k1 scalars and
  independent standard Ed25519 seeds. Production entropy never comes from the
  public probability samples, a user seed, timestamps or GPU RNG.
- Only KeyManager generates, decrypts, reconstructs and exports private keys.
  secp256k1 Compute workers receive public keys, intervals and patterns. Ed25519
  CPU threads belong to KeyManager; the public Compute interface never receives seeds.
- New encrypted session keys and non-EVM wallets use XChaCha20-Poly1305, a fresh
  24-byte nonce, OS-random 32-byte salt and PBKDF2-HMAC-SHA256 with 600,000 rounds.
  AEAD authenticates the schema, profile, role, job hash, public key, address,
  key representation, export format and public descriptor.
- Final EVM wallets retain Web3 V3 AES-128-CTR and Keccak MAC compatibility with
  bounded PBKDF2/scrypt imports. New EVM exports add signed profile metadata.
  A legacy V3 wallet without that extension is interpreted as Ethereum; removing
  an extension loses its network label rather than asserting authenticated labels.
- Passwords use hidden interactive input and Zeroizing buffers. New passwords
  require confirmation and at least 12 bytes. GUI fields clear undo history.
  Passwords are never command arguments, preferences, progress or logs.
- Encrypted export is the default. **Most explicit native exports create a plaintext
  private-key import file.** Warthog `.db` exports use PBKDF2/Fernet encryption
  with the wallet password. The file is never printed and is created with
  no-clobber private permissions.
- Unix directories/files use 0700/0600. Windows uses an explicit protected owner
  DACL. Permission or ACL failures stop writing. Encrypted atomic writes flush
  before rename; Unix directory metadata is flushed too.

Secret buffers and supported library key objects receive best-effort erasure.
Compiler copies, cryptographic-library internals, swap and crash dumps prevent a
universal memory-wiping guarantee. Library callers own their input password lifetime.

## Recovery assets

For a local search, back up `seed.keystore.json` and `job.json`. Keep the session
password separately recoverable. For split-key searches, keep the complete owner
folder. The helper folder contains public data and no private share. See
[Split-key search](SPLIT-KEY.md). For secp256k1, the original scalar plus a public
candidate offset reconstructs the found key. Do not use the original and offset
wallets as independent accounts: their secret keys are publicly related. A durable
reservation prevents finalizing multiple different candidates from one session.

For Ed25519 every attempt is a new independent seed. A successful seed is encrypted
and saved immediately in **hit.keystore.json**. Once found, back up that file along
with the original seed/job and public candidate records. The original seed alone
cannot reconstruct a different randomly generated winning seed. Losing the hit
file before finalization loses that candidate's recovery path.

After finalization back up the final encrypted wallet and its password. Select
**Do wallet check** in the desktop app to check a backup. The CLI command is
`vanity verify --wallet ...`. Native import files also recover the
key; Warthog `.db` is encrypted, while the other native formats are plaintext.
Keep every import file private. Keep the applicable Bitcoin
address type and descriptor; WIF alone does not tell a wallet which script to scan.

## Interrupted work and authenticity

There are no periodic computational checkpoints. Successful hits and faults save
immediately; normal Pause/Stop saves public display statistics. secp256k1 resume
can repeat work after an abrupt termination. Ed25519 resume begins new independent
random attempts. It asks for the session password to encrypt any future hit.
No progress amount improves the odds of the next independent attempt.

The public checkpoint's SHA256 is corruption detection, not an authentication
signature. A public candidate has not established private ownership. The GUI blocks
Copy Address until successful private wallet verification in that run, including
when a previously exported session is reopened. A candidate from a copied backup
must not be treated as a funded receiving address before finalization/verification.

Ed25519 resume authenticates every existing sealed hit, checks its role/profile/job,
re-derives its address and compares the exact public candidate before returning it.
A public candidate with a missing, unrelated or modified hit fails closed. If an
interruption saved the encrypted hit but lost the final public writes, resume
repairs those writes after authentication, without replacing the hit.

Finalization reconstructs and proves control of the candidate, binds the job/seed,
checks the output address and descriptor, then independently decrypts the persisted
wallet before reporting success. Wrong passwords, forged results, invalid keys,
output collisions or disk errors prevent successful export. An interrupted export
may retain a finalization reservation; retry the same candidate with a fresh output
path, or verify an existing output. Do not restore reservation state to manufacture
related wallets. `recover --restart` resets public secp256k1 coverage only and refuses
reserved/finalized sessions; it never replaces recovery keys.

## Compiled cache

Compiled caching is disabled by default. Cache directories must already be private
and owned by the operator; changing a formerly shared directory's permissions does
not establish provenance. Cache files are opened without following symlinks and
checked through the open handle. Windows requires the exact protected owner DACL;
Unix checks effective UID and rejects group/other access.

Source/version/device/driver/options and SHA256 detect stale/corrupt cache records,
not hostile writers. Unprotected entries are never loaded. The operator account,
root/administrator and trusted native runtime remain within the trust boundary.
