//! Controlled GUI instructions. Technical terms are defined in docs/GUI-TEXT.md.
//! Keep each instruction to 20 words. Keep each description to 25 words.

pub const NEW_SEARCH: &str =
    "Make a new session for a different address. Keep the previous session for recovery.";
pub const START: &str = "Select a blockchain and an address type. Enter the address prefix.";
pub const SESSION: &str = "Use the controls below to continue the search or save the wallet.";
pub const PREFIX: &str = "Enter the first characters of the address. Use the character set for the selected address type.";
pub const PROFILE_LOCK: &str = "The blockchain, address type, and prefix cannot change in this session. Select New search to use different values.";
pub const GENERATE: &str = "Set a password for the session. The application saves the encrypted seed before the search starts.";
pub const AUTO: &str = "Use validated GPUs if available. If no GPU is available, use the CPU. Ed25519 profiles use the CPU only.";
pub const CPU: &str = "Use CPU workers for the search.";
pub const GPU: &str =
    "Use the enabled OpenCL GPUs. Stop with an error if no GPU is available for the search.";
pub const EXPECTED: &str = "This value is the mean number of search attempts. It is not a limit.";
pub const MEAN_TIME: &str = "This estimate uses the selected profile and the measured search speed. It is not a time limit.";
pub const PROBABILITY: &str = "This value is the probability of a match after this number of attempts. It does not show search completion.";
pub const PAUSE: &str =
    "Stop the search after the batch completes. Save the progress. Keep the session files.";
pub const STOP: &str =
    "Stop the search and save the progress. Keep the session so you can continue the search.";
pub const RESUME: &str = "Continue this session. For Ed25519, enter the session password. The CPU starts new random attempts.";
pub const SAVE: &str = "Unlock the session and do the key ownership check. Then select a password and a file for the encrypted wallet.";
pub const CHECK: &str = "Enter the wallet password. Decrypt the file and make sure that its address agrees with the session address.";
pub const COPY: &str = "Copy the public address. First, save the encrypted wallet and do the wallet check in this application run.";
pub const ANOTHER_COPY: &str =
    "Save the same wallet to a new encrypted file. Enter the session password first.";
pub const NATIVE: &str = "CAUTION: Do not give this file to other persons. It contains an unencrypted private key. They can control the wallet.";
pub const RECOVERY: &str = "Keep the encrypted wallet and its password. Also keep the session recovery files and the session password.";
pub const SEED_PASSWORD: &str =
    "Set a session password. This password is necessary to save the wallet after a match.";
pub const UNLOCK_PASSWORD: &str = "Enter the session password. The application calculates the wallet address and does the key ownership check.";
pub const WALLET_PASSWORD: &str =
    "Set a wallet password. You can use a different password for the wallet and the session.";
pub const CHECK_PASSWORD: &str =
    "Enter the wallet password. The application decrypts the file and does the full address check.";
pub const RESUME_PASSWORD: &str = "Enter the session password. The CPU uses this password to encrypt the seed if the search finds a match.";
pub const PASSWORD_LENGTH: &str =
    "Use 12 or more characters. Do not use this password for a different application.";
pub const DELETE: &str = "CAUTION: Make sure that you have copies of the recovery files. This operation deletes all files in the session folder.";
pub const DELETE_WAIT: &str = "Pause or stop an active search. Wait for the current operation to complete before you delete a session.";
pub const CLOSE: &str = "The application stops the search and saves progress before it closes. Wait for the operation to complete.";
pub const CLOSE_EXPORT: &str = "The application must complete the wallet operation before it closes. Wait for the encrypted file operation to complete.";
pub const THREADS: &str =
    "Set the number of CPU workers. This value has no effect on GPU searches.";
pub const BATCH: &str = "Set the maximum number of candidates in one batch. Larger batches can increase the time before a pause.";
pub const TIME_LIMIT: &str = "Pause the search after this time. The application must complete the batch before it saves progress.";
pub const DEVICES: &str = "Select the GPUs that the search can use. Automatic mode uses enabled devices after the device checks.";
pub const BENCHMARK: &str = "Measure the search speed for the selected address profile. This operation does not make a wallet.";
pub const RECALIBRATE: &str = "Measure the selected hardware with these compute preferences. Save validated settings in the local calibration cache. This operation can take several minutes.";
pub const ED25519_NO_CALIBRATION: &str =
    "The standard Ed25519 implementation is selected. Calibration is not necessary.";
pub const LOGS: &str = "Show the event log for the selected session. The log does not contain passwords or private keys.";
pub const STORAGE: &str = "Select a local folder or a removable drive. Do not select a network folder or a cloud placeholder.";
pub const SETTINGS: &str =
    "Save these preferences. The application does not save passwords in the preferences.";
pub const EVM: &str = "The same private key gives the same address on all seven EVM networks.";
pub const ED25519: &str = "This profile uses CPU workers. Each attempt uses a new random seed. The session password is necessary for Resume.";
pub const XRP: &str = "The native file contains an XRPL SDK keypair. The application does not make an XRP family seed.";
pub const WARTHOG: &str = "The address has 48 hexadecimal characters. The last eight characters are the checksum. Do not enter 0x.";
pub const WARTHOG_IMPORT: &str =
    "The native file uses the Core wallet JSON format. For Wart Dapp, import its privateKey field.";
pub const MATCH: &str = "Do not use this address. Select Save wallet to do the key ownership check and save an encrypted file.";
pub const EXPORT_RECORD: &str =
    "This is a saved export record. Select Do wallet check before you copy the address.";
pub const NO_RATE: &str = "Do a benchmark to get a time estimate.";
pub const NO_SAMPLE: &str = "The sample does not have sufficient matches for an estimate.";
pub const SAMPLE_UNAVAILABLE: &str = "Public sampling is unavailable.";
pub const ESTIMATE_UNAVAILABLE: &str = "Probability estimate unavailable.";
pub const ESTIMATE_PENDING: &str = "Probability estimate in progress.";
pub const LONG_SEARCH: &str =
    "The search time can be long. Use a shorter prefix to decrease the expected attempts.";
pub const EMPTY_SESSIONS: &str = "No sessions found. Select New search to make a session. Select Refresh to read the session folder again.";
pub const SPLIT: &str =
    "The owner keeps a private share. The helper uses a public request to find a matching address.";
pub const SPLIT_CREATE: &str = "Select the blockchain. Select the address type. Enter the address prefix. Save the encrypted private share. Give only the public request to the helper.";
pub const SPLIT_SHARE: &str = "CAUTION: Keep the private share files and their password. Do not give them to the helper. They are necessary to save the wallet.";
pub const SPLIT_SHARE_PASSWORD: &str = "Set a password for the private share. This password is necessary when you combine the search result and save the wallet.";
pub const SPLIT_REQUEST: &str = "Give only the public request file to the helper. It contains the public key, address profile, and pattern.";
pub const SPLIT_PREVIEW: &str = "Make sure that the address profile and pattern are correct. These values cannot change during the search.";
pub const SPLIT_WORKER: &str =
    "The helper does not have the private share. Save the search result. Give it to the owner.";
pub const SPLIT_WORKER_MATCH: &str = "Do not use this address. Save the search result. Give it to the owner. The owner must save the wallet.";
pub const SPLIT_OWNER_MATCH: &str =
    "Do not use this address. Select Combine and save wallet first.";
pub const SPLIT_OWNER_SESSION: &str =
    "Save the public request. Import the helper's result to combine the keys and save the wallet.";
pub const SPLIT_UNLOCK: &str = "Enter the private share password. The application combines the keys and does the key ownership check.";
pub const SPLIT_RESULT: &str = "Import the search result from the helper. The application does a check against the original request.";
pub const SPLIT_ANOTHER_COPY: &str =
    "Save the same wallet to a new encrypted file. Enter the private share password first.";
pub const SPLIT_DELETE: &str = "CAUTION: This operation deletes all files in the owner session folder. Keep copies of these files and the private share password. They are necessary to save the wallet.";
pub const SPLIT_OWNER_RECOVERY: &str = "Keep all files in the owner session folder and the private share password. This includes seed.keystore.json and the split-key metadata.";
pub const SPLIT_WORKER_RECOVERY: &str = "Keep the request and all files in the worker session folder. No private share file is necessary for this search.";
pub const HELP_STEPS: &[&str] = &[
    "Select New search.",
    "Select the blockchain and the address type.",
    "Enter the address prefix. Read the character rules below the field.",
    "Select the compute mode. Use Automatic to select the device type.",
    "Select Find address. Enter the session password twice. Select Save session and start search.",
    "To stop temporarily, select Pause. To continue, select Resume.",
    "After a match, select Save wallet. Enter the session password. Select Unlock session.",
    "Enter the wallet password twice. Select Select file and save wallet. Select a local file in the Windows dialog.",
    "If the wallet check result is correct, select Copy address.",
    "To open a saved session, select Sessions. Select the correct session.",
    "For a saved export, select Do wallet check. Enter the wallet password before you copy the address.",
];
pub const SPLIT_HELP_STEPS: &[&str] = &[
    "Owner: select Split-key search. Select Create request. Select the address profile. Enter the prefix.",
    "Select Create request. Enter the private share password twice. Select Save private share.",
    "Select Save public request. Give only that file to the helper. Keep all owner session files and the password.",
    "Helper: select Split-key search. Select Import search request. Make sure that the displayed profile and pattern are correct.",
    "Select the compute mode. Select Start search. Select Pause to stop temporarily. Select Resume to continue.",
    "After a match, select Save search result. Give that public file to the owner.",
    "Owner: open the owner session. Select Import search result.",
    "Select Combine and save wallet. Enter the private share password. Select Unlock private share.",
    "Set the wallet password. Select Select file and save wallet.",
    "If the wallet check result is correct, select Copy address.",
];

#[cfg(test)]
mod tests {
    #[test]
    fn instructions_keep_the_ste_sentence_limit() {
        // The lexical and meaning review is recorded in docs/GUI-TEXT.md.
        let source = include_str!("gui_text.rs");
        for line in source.lines().take_while(|line| *line != "#[cfg(test)]") {
            if let Some((_, value)) = line.split_once('"') {
                let value = value.split('"').next().unwrap();
                for sentence in value.split(['.', '!', '?']) {
                    assert!(sentence.split_whitespace().count() <= 20, "{sentence}");
                }
            }
        }
    }
}
