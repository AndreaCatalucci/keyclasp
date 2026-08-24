#![allow(clippy::panic, clippy::unwrap_used)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const XCRUN: &str = "/usr/bin/xcrun";

fn command_output(arguments: &[&str]) -> Output {
    Command::new(XCRUN)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {XCRUN}: {error}"))
}

fn successful_stdout(arguments: &[&str]) -> String {
    let output = command_output(arguments);
    if !output.status.success() {
        panic!(
            "{XCRUN} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("invalid UTF-8 from {XCRUN}: {error}"))
        .trim()
        .to_owned()
}

fn run(tool: &Path, arguments: &[&str]) {
    let output = Command::new(tool)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {}: {error}", tool.display()));
    if !output.status.success() {
        panic!(
            "{} failed: {}",
            tool.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn compile_swift(tool: &Path, target: &str, sdk: &str, source: &Path, object: &Path) {
    run(
        tool,
        &[
            "-emit-object",
            "-parse-as-library",
            "-O",
            "-warnings-as-errors",
            "-target",
            target,
            "-sdk",
            sdk,
            "-o",
            object.to_str().unwrap(),
            source.to_str().unwrap(),
        ],
    );
}

fn compile_c(tool: &Path, target: &str, sdk: &str, source: &Path, object: &Path) {
    run(
        tool,
        &[
            "-c",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-target",
            target,
            "-isysroot",
            sdk,
            "-o",
            object.to_str().unwrap(),
            source.to_str().unwrap(),
        ],
    );
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c/dynamic_code.c");
    println!("cargo:rerun-if-changed=c/metadata_crypto.c");
    println!("cargo:rerun-if-changed=c/security_backend.c");
    println!("cargo:rerun-if-changed=swift/macos_adapter.swift");
    println!("cargo:rerun-if-changed=swift/recovery_crypto.swift");
    for variable in [
        "DEVELOPER_DIR",
        "TOOLCHAINS",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "KEYCLASP_BUILD_IDENTITY",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "macos" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let source = manifest_dir.join("swift/macos_adapter.swift");
    let recovery_crypto_source = manifest_dir.join("swift/recovery_crypto.swift");
    let c_source = manifest_dir.join("c/dynamic_code.c");
    let security_source = manifest_dir.join("c/security_backend.c");
    let metadata_crypto_source = manifest_dir.join("c/metadata_crypto.c");
    let swift_object = out_dir.join("keyclasp_macos_adapter.o");
    let recovery_crypto_object = out_dir.join("keyclasp_recovery_crypto.o");
    let c_object = out_dir.join("keyclasp_dynamic_code.o");
    let security_object = out_dir.join("keyclasp_security_backend.o");
    let metadata_crypto_object = out_dir.join("keyclasp_metadata_crypto.o");
    let library = out_dir.join("libkeyclasp_macos_adapter.a");

    let sdk = successful_stdout(&["--sdk", "macosx", "--show-sdk-path"]);
    let swiftc = PathBuf::from(successful_stdout(&["--sdk", "macosx", "--find", "swiftc"]));
    let clang = PathBuf::from(successful_stdout(&["--sdk", "macosx", "--find", "clang"]));
    let ar = PathBuf::from(successful_stdout(&["--sdk", "macosx", "--find", "ar"]));
    let architecture = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_architecture = match architecture.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        unsupported => panic!("unsupported macOS architecture: {unsupported}"),
    };
    let deployment_target =
        env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "14.0".to_owned());
    let target = format!("{target_architecture}-apple-macos{deployment_target}");

    for (swift_source, object) in [
        (&source, &swift_object),
        (&recovery_crypto_source, &recovery_crypto_object),
    ] {
        compile_swift(&swiftc, &target, &sdk, swift_source, object);
    }
    for (c_source, object) in [
        (&c_source, &c_object),
        (&metadata_crypto_source, &metadata_crypto_object),
        (&security_source, &security_object),
    ] {
        compile_c(&clang, &target, &sdk, c_source, object);
    }
    run(
        &ar,
        &[
            "rcs",
            library.to_str().unwrap(),
            swift_object.to_str().unwrap(),
            recovery_crypto_object.to_str().unwrap(),
            c_object.to_str().unwrap(),
            security_object.to_str().unwrap(),
            metadata_crypto_object.to_str().unwrap(),
        ],
    );

    let toolchain_swift = swiftc
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("unexpected swiftc path: {}", swiftc.display()))
        .join("lib/swift/macosx");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=keyclasp_macos_adapter");
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!(
        "cargo:rustc-link-search=native={}",
        toolchain_swift.display()
    );
    println!("cargo:rustc-link-lib=dylib=swiftCore");
    println!("cargo:rustc-link-lib=dylib=swiftFoundation");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=Security");
}
