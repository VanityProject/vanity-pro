# Start Vanity Pro

Extract all files before you start the program. Keep the documentation and license files with the application.

## Windows desktop package

1. Open **VanityPro.exe**.
2. Select the blockchain and address type.
3. Enter the address prefix. Read the character rules below the field.
4. Select **Find address**. Enter the session password twice.
5. Select **Save session and start search**. Use **Pause** to stop temporarily.
6. After a match, select **Save wallet**. Enter the session password, then select **Unlock session**.
7. Set the wallet password. Select **Select file and save wallet**.
8. Copy the address after the wallet check succeeds.

Keep the session files and their password until you have checked the saved wallet.
Do not use a matched address before you save and check its wallet.

For an owner or helper search, read [Split-key search](docs/SPLIT-KEY.md).
For session deletion, recovery, settings, and export, read the [desktop guide](docs/GUI.md).

## CLI package

The Windows CLI package contains **vanity.exe**. The Linux CLI package contains **vanity**.
Open a terminal in the extracted folder. Run the program with **--help**.
Read the commands and supported profiles in [README](README.md).

## Hardware

Automatic mode uses a validated GPU or falls back to CPU.
CPU mode does not need an OpenCL runtime. GPU mode needs the vendor's OpenCL driver.
See [hardware coverage](docs/COMPATIBILITY.md) for the tested combinations.
