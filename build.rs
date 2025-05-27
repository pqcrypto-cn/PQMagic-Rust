fn main() {
    let lib_path = std::env::current_dir()
        .unwrap()
        .join("vendor")
        .to_string_lossy()
        .to_string();
    
    println!("cargo:rustc-link-search=native={}", lib_path);
    println!("cargo:rustc-link-lib=dylib=pqmagic_std");
    println!("cargo:rustc-env=LD_LIBRARY_PATH={}", lib_path);
    
    println!("cargo:rerun-if-changed=vendor");
}