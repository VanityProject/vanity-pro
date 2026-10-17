mod build_fingerprints;

fn implementation_fingerprints(compiler: &str) {
    use build_fingerprints::{
        CALIBRATION_DOMAIN, CALIBRATION_SOURCES, OPENCL_DOMAIN, OPENCL_SOURCES,
    };
    let root = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies the source directory"),
    );
    let mut context = vec![("compiler".to_owned(), compiler.to_owned())];
    for name in [
        "CARGO_PKG_VERSION",
        "TARGET",
        "HOST",
        "CARGO_CFG_TARGET_OS",
        "CARGO_CFG_TARGET_ARCH",
        "CARGO_CFG_TARGET_ENV",
        "CARGO_CFG_TARGET_VENDOR",
        "CARGO_CFG_TARGET_ABI",
        "CARGO_CFG_TARGET_POINTER_WIDTH",
        "CARGO_CFG_TARGET_ENDIAN",
        "CARGO_CFG_TARGET_FAMILY",
        "CARGO_CFG_TARGET_FEATURE",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        context.push((name.to_owned(), std::env::var(name).unwrap_or_default()));
    }
    let mut features: Vec<_> = std::env::vars()
        .filter(|(name, _)| name.starts_with("CARGO_FEATURE_"))
        .collect();
    features.sort();
    for (name, value) in features {
        println!("cargo:rerun-if-env-changed={name}");
        context.push((name, value));
    }
    let context_refs: Vec<_> = context
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut inputs =
        String::from("// Generated test inputs; source text is excluded from release binaries.\n");
    inputs.push_str("pub const BUILD_CONTEXT: &[(&str, &str)] = &[\n");
    for (name, value) in &context {
        inputs.push_str(&format!("    ({name:?}, {value:?}),\n"));
    }
    inputs.push_str("];\n");
    for (name, domain, files) in [
        ("CALIBRATION", CALIBRATION_DOMAIN, CALIBRATION_SOURCES),
        ("OPENCL", OPENCL_DOMAIN, OPENCL_SOURCES),
    ] {
        let sources: Vec<_> = files
            .iter()
            .map(|file| {
                println!("cargo:rerun-if-changed={file}");
                (
                    *file,
                    std::fs::read(root.join(file)).expect("read implementation fingerprint input"),
                )
            })
            .collect();
        let refs: Vec<_> = sources
            .iter()
            .map(|(file, bytes)| (*file, bytes.as_slice()))
            .collect();
        let digest = build_fingerprints::digest(domain, &refs, &context_refs);
        println!("cargo:rustc-env=VANITY_{name}_IMPLEMENTATION={digest}");
        inputs.push_str(&format!("pub const {name}_INPUTS: &[(&str, &[u8])] = &[\n"));
        for file in files {
            inputs.push_str(&format!(
                "    ({file:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/\", {file:?}))),\n"
            ));
        }
        inputs.push_str("];\n");
    }
    let out =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    std::fs::write(out.join("implementation-fingerprint-inputs.rs"), inputs)
        .expect("write implementation fingerprint test inputs");
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let compiler =
        std::process::Command::new(std::env::var_os("RUSTC").expect("Cargo supplies rustc"))
            .arg("--version")
            .output()
            .expect("read build compiler identity");
    assert!(compiler.status.success(), "read build compiler version");
    let compiler = String::from_utf8(compiler.stdout)
        .expect("compiler version UTF-8")
        .trim()
        .to_owned();
    println!("cargo:rustc-env=VANITY_COMPILER={}", compiler);
    implementation_fingerprints(&compiler);
    println!(
        "cargo:rustc-env=VANITY_BUILD_FLAGS={}",
        std::env::var("CARGO_ENCODED_RUSTFLAGS")
            .unwrap_or_default()
            .replace('\u{1f}', " ")
    );
    println!("cargo:rerun-if-changed=assets/vanity.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var_os("CARGO_FEATURE_GUI").is_some()
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/vanity.ico");
        resource.set("ProductName", "Vanity Pro");
        resource.set(
            "FileDescription",
            "Vanity Pro — Offline Ethereum Vanity Wallets",
        );
        resource.set("LegalCopyright", "MIT License");
        resource
            .compile()
            .expect("compile Windows application icon/version resource");
    }
}
