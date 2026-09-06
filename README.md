# BrakeFRI

Rust implementation of the standalone coefficient-input BrakeFRI PCS, developed in milestones. M1 supplies field, hash, DFT, Merkle multiproof, transcript, and parameter primitives. PCS operations follow in M2; no benchmark measurements are available yet.

## Build

Use Rust 1.95 or newer and Cargo. Dependencies resolve from crates.io and the public Plonky3 Git repository. All `p3-*` crates use the compatible source revision recorded in `Cargo.toml` and `Cargo.lock`; the local F128 adapter uses Winterfell `winter-math` arithmetic. No local upstream checkout is required.

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Plonky3 parallelism is enabled through `p3-maybe-rayon/parallel` feature unification. `ExecutionContext` owns a local Rayon pool, shared by DFT and Merkle construction. Transcript operations and multiproof assembly are sequential. Scalar Merkle packing works with both base fields and Goldilocks quadratic leaves.

## Workspace

- `brakefri-core`: validated parameters for coefficient lengths `2^11` through `2^30`; exact integer checks of the paper's 100-bit interactive soundness bound.
- `p3-f128-adapter`: Winterfell-backed F128 with current Plonky3 traits and canonical decoding.
- `brakefri-primitives`: closed field profiles, canonical coordinate encodings, generic hash suites, natural-order DFT, checked single-matrix MMCS, and byte transcript.
- `brakefri-runtime`: local execution context; benchmark runtime integration follows in M5.

`configs/brakefri.toml` records the planned fixed protocol and benchmark settings. CLI parsing, the benchmark crate, proof codecs, and PCS assembly remain scheduled work. See [implementation status](docs/implementation-status.md).

The field/query bound is interactive. It does not include hash collision or Fiat–Shamir compilation losses.
