# Vanity Pro Windows interface

Extract the Windows package. Open **VanityPro.exe**. The application uses the Fluent Desk layout and native Windows file dialogs.
No terminal or network connection is necessary for wallet generation or export.

Use **Search** for a local search. Use **Split-key search** for the owner and helper workflow.
Use **Sessions** to open saved sessions. Use **Settings** for storage, appearance, and compute preferences.
Use **Diagnostics** for hardware information and speed measurements. Use **Help** for the full offline procedure.

Hover over a control to read its tooltip. Keyboard focus also opens the tooltip.
Select a question-mark button to read field help. Press Escape to close focused help.
Input rules, errors, status, and data-loss cautions remain visible.

## Find an address

1. Select **New search**. Select the blockchain. Select the address type.
2. Enter the **Address prefix**. Read the character rules below the field.
3. Select the compute mode. **Automatic** uses validated GPUs if available. If no GPU is available, it uses the CPU.
4. Select **Find address**. Enter the session password twice. Select **Save session and start search**.
5. Use **Pause** to stop temporarily. Use **Resume** to continue. **Stop** also keeps the session and its progress.
6. After a match, select **Save wallet**. Enter the session password. Select **Unlock session**.
7. Enter the wallet password twice. Select **Select file and save wallet**. Select a new local file in the Windows dialog.
8. Wait for the wallet check. If the result is correct, select **Copy address**.

The application saves the encrypted recovery files before the search starts.
Existing wallet files are not overwritten. Passwords are not saved in preferences.
Ed25519 searches use the CPU. The session password is necessary for **Resume**. This action starts new random attempts.

EVM prefixes use hexadecimal characters. Pasted `0x` is accepted. EVM matching ignores letter case.
Warthog prefixes use hexadecimal characters without `0x`. Other profiles use their own character and case rules.
The application shows these rules below the prefix field.

## Split-key search

The owner keeps the encrypted private share. The helper searches with a public request and returns a public result.
The owner imports the result and selects **Combine and save wallet**.
The password dialog uses **Private share password** and **Unlock private share** for this operation.
The helper has no **Save wallet** or **Copy address** control.

CAUTION: Keep all owner session files and the private share password. They are necessary to save the wallet.
Give only the public request to the helper. Import the search result from the helper.

See the [complete owner and helper procedure](SPLIT-KEY.md).
Imported prefix and suffix constraints remain fixed. The preview, selected session, and session history show a nonempty suffix.

## Sessions and recovery

Select a session in **Sessions** or the sidebar. The search does not start when the session opens.
The configuration closes to a compact summary. Expand **Search configuration** to read its inputs.
**Device details** shows worker measurements. **Session details and actions** contains the session ID, folder, and log control.
Select **Read session log** to open its output in **Diagnostics**.

Expand **Recovery files** to read the instructions for that session role.
Keep the complete session folder. For a local or owner session, also keep its password.
For a local Ed25519 match, also keep `hit.keystore.json`.
Owner sessions use the private share and split-key metadata for wallet recovery. Helper sessions contain public search files.
A private share is not necessary for helper operation.

To delete the selected session, select **Delete session…** beside its action controls.
To delete a past session, select **Delete session…** on its card in **Sessions**.
Pause or stop an active search first. Wait for any current operation to complete.
Read the caution and folder path. Type `DELETE`. Select **Delete session**.
Select **Keep session** to cancel. Deleting a past session keeps the selected session open.

CAUTION: Deletion removes all files in that session folder. Keep recovery copies before deletion.
The owner deletion dialog identifies the private share and its password as necessary recovery material.

## Saved wallets and native import

For a reopened export record, a wallet check is necessary before address copying.
Select **Do wallet check**. Enter the wallet password. Select **Decrypt wallet and do check**.
Use **Save new encrypted copy** to save the same wallet to a new file.

For a native import file, expand **Native import file**. Read the caution and format.
Select **Export native import file**. Enter the wallet password. Select **Select file and export private key**.

CAUTION: A native import file contains an unencrypted private key. Do not give it to other persons.
Keep the encrypted wallet as the default recovery file.
See [wallet compatibility](MULTICHAIN.md) and [recovery requirements](SECURITY.md).

## Compute preferences

The main search and request preview show the compute mode. Advanced compute preferences are in **Settings**.
These include CPU workers, maximum batch size, the optional time limit, and enabled OpenCL devices.
The application uses optimized compute paths.
Select **Save settings** to save preferences. Storage and theme preferences are in the same window.

Automatic calibration measures available implementations before the first supported search. Later searches reuse validated local settings.
Use **Skip tuning** to continue with the self-tested configuration. Use **Stop** to cancel calibration and the pending operation.
Use **Recalibrate hardware** in **Settings** to measure hardware again with the displayed compute preferences.
Recalibration does not start a search. It preserves the enumeration strategy of a selected session.
Calibration is not necessary for the standard Ed25519 implementation. The application states this in **Settings**.

Search startup does the correctness checks.
In **Diagnostics**, select **Detect hardware** to read device information. Select **Do benchmark** to measure search speed.
Benchmarking uses the saved compute preferences. The benchmark does not make a wallet.
Session and wallet locations must be ordinary local folders or removable drives.

## Estimates and progress

Probability estimates use the complete address pattern. Some profiles use a public sample and show a probability interval.
Select the question-mark button beside **Expected attempts** to read the sample count, model, and probability interval.
Keyboard focus also opens this help.
Sampling runs in a background task. You can continue to edit inputs and use controls while an estimate is in progress.
Insufficient sample matches or unavailable sampling produce no estimate. They do not establish that the pattern is impossible.

**Expected attempts** and **Mean search time** are statistical means. They are not limits.
The probability bar shows the chance after that effort. It does not show search completion.
Use a shorter prefix to decrease the expected search effort.
