use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let rustc = Command::new(env::var_os("RUSTC").expect("Cargo supplies RUSTC"))
        .arg("-Vv")
        .output()
        .expect("query build compiler");
    assert!(rustc.status.success(), "query build compiler");
    let metadata = format!(
        "{}\ntarget={}\nprofile={}\nopt_level={}\nrustflags={:?}\nencoded_rustflags={:?}\n",
        String::from_utf8_lossy(&rustc.stdout),
        env::var("TARGET").unwrap(),
        env::var("PROFILE").unwrap(),
        env::var("OPT_LEVEL").unwrap(),
        env::var("RUSTFLAGS").ok(),
        env::var("CARGO_ENCODED_RUSTFLAGS").ok()
    );
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("build.txt"),
        metadata,
    )
    .unwrap();
}
