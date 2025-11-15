fn main() {
    println!("cargo::rustc-check-cfg=cfg(monerochan_ci_in_progress)");
    if std::env::var("MONEROCHAN_CI_IN_PROGRESS").is_ok() {
        println!("cargo::rustc-cfg=monerochan_ci_in_progress");
    }
    
    // Compile proto file for network API (only when network feature is enabled)
    // Check if tonic-build is available by checking for the feature flag via environment
    if std::env::var("CARGO_FEATURE_NETWORK").is_ok() {
        println!("cargo:rerun-if-changed=src/network/proto/api.proto");
        tonic_build::configure()
            .build_server(true)
            .compile_protos(&["src/network/proto/api.proto"], &["src/network/proto"])
            .expect("failed to compile network api proto");
    }
}
