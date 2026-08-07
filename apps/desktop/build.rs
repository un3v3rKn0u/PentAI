use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    let target = env::var("TARGET").expect("Cargo TARGET is required");
    let extension = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let sidecar = PathBuf::from("binaries").join(format!("pentai-core-{target}{extension}"));
    println!("cargo:rerun-if-changed={}", sidecar.display());
    let bytes = fs::read(&sidecar).unwrap_or_else(|_| {
        panic!(
            "core sidecar is missing at {}; run scripts/build_core_sidecar.py",
            sidecar.display()
        )
    });
    let digest = format!("{:x}", Sha256::digest(bytes));
    println!("cargo:rustc-env=PENTAI_CORE_SIDECAR_SHA256={digest}");
    println!(
        "cargo:rustc-env=PENTAI_CORE_SIDECAR_BUILD_PATH={}",
        sidecar.display()
    );
    tauri_build::build()
}
