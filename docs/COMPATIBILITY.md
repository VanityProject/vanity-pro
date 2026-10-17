# Hardware compatibility

## Standard 0.4.1 builds

The standard downloads target Windows x64 desktop and Windows/Linux x64 CLI use.
Selection uses available instructions, device limits, and cryptographic startup checks.
The program keeps scalar CPU and portable OpenCL 1.2 implementations; hardware age is not a device allowlist.
It does not assume that an OpenCL 3.x driver provides optional OpenCL 2.x features.
Khronos documents that these features remain optional and must be queried in its [OpenCL guide](https://github.com/KhronosGroup/OpenCL-Guide/blob/main/chapters/opencl_3.md).

Every production device still receives known-field, public-point, address, and hit checks.
A correctness failure stops the search. An unavailable automatic GPU can fall back to CPU.
Standard Ed25519 generation uses the library SigningKey implementation and CPU seed microbatches.
No stored job, encrypted wallet, native export, or split-key file schema changed in 0.4.1.

## Check your device

Use the CLI to list and check the available backends:

```sh
vanity devices --self-test
vanity self-test --backend cpu
vanity self-test --backend all
```

The Windows desktop application also offers hardware detection and benchmarking
in Diagnostics. Automatic mode falls back to CPU if a compatible GPU is unavailable.

Physical GPU validation has covered the NVIDIA GeForce RTX 4060 on Windows.
AMD, Intel, multiple physical GPUs, and Linux GPU runtimes require validation
on the actual device and driver. Linux CPU operation has been validated.
