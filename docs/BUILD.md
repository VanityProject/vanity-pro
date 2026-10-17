# Build Vanity Pro

## Requirements

- Rust 1.95 or newer with Cargo. Version 0.4.1 was validated with Rust 1.99.0.
- Windows x64: the Rust MSVC toolchain, Visual Studio Build Tools with C++ tools,
  and the Windows SDK. Use a Developer PowerShell if the compiler is not on PATH.
- Linux x64: a native C compiler and build tools, such as `build-essential` on
  Ubuntu/Debian.

Clone the source:

```sh
git clone https://github.com/VanityProject/vanity-pro.git
cd vanity-pro
```

## Windows desktop and CLI

```powershell
cargo build --release --locked
.\target\release\VanityPro.exe
.\target\release\vanity.exe --help
.\target\release\vanity.exe self-test --backend cpu
```

The desktop executable is `target/release/VanityPro.exe`. The command-line
executable is `target/release/vanity.exe`. The desktop program does not need a
CLI executable beside it. The checked-in Cargo configuration statically links
the Microsoft C runtime.

For a separate Windows CLI build without GUI dependencies:

```powershell
cargo build --release --locked --no-default-features --bin vanity --target-dir target/cli
.\target\cli\release\vanity.exe --help
```

## Linux CLI

```sh
cargo build --release --locked --no-default-features --bin vanity
./target/release/vanity --help
./target/release/vanity self-test --backend cpu
```

Linux builds produce `target/release/vanity`. The desktop UI is Windows-only.
The published Linux download was built on Ubuntu 24.04; older environments may
need to compile locally.

## GPU support

CPU searches do not require OpenCL. GPU searches need a compatible vendor driver
that supplies OpenCL. On Linux, the OpenCL loader and matching vendor ICD are
also required. No CUDA Toolkit is required to build or run the application.

Use `vanity devices --self-test` to inspect available devices and
`vanity self-test --backend all` to check the available compute backends.
See [hardware compatibility](COMPATIBILITY.md).

## Dependencies and source files

Keep `Cargo.lock` and use `--locked` to preserve dependency versions. The first
build downloads dependencies. For an offline build, populate the Cargo cache
before disconnecting, then add `--offline` to the build command. Running wallet
generation requires no network connection.

Keep `src/`, `kernels/`, `assets/`, both build helpers, and the Cargo files
together. The build computes implementation fingerprints from its source and
kernel inputs, including some files used by optional features. Removing those
inputs prevents a complete build.

Download ready-made packages from [Releases](https://github.com/VanityProject/vanity-pro/releases).
Each includes the application, user instructions, required dependency notices,
and checksums. Source code is MIT-licensed; third-party notices are in `licenses/`.
