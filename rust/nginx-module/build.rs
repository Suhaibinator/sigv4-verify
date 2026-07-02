fn main() {
    // NGINX symbols are resolved by the nginx binary at load_module time.
    // Linux linkers allow undefined symbols in shared objects by default;
    // macOS needs to be told explicitly.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
