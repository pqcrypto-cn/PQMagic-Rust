use std::{env, path::Path};
use cmake::Config;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is NOT SET");

    let src_dir = Path::new(&manifest_dir).join("vendor/PQMagic");

    let dst = Config::new(&src_dir)
        .profile("Release")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=dylib=pqmagic_std");

    println!("cargo:rerun-if-changed={}", src_dir.display());
}
