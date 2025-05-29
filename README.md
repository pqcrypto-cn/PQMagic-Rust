# PQMagic-Rust
The rust bindings for [PQMagic](https://github.com/pqcrypto-cn/PQMagic) , a post-quantum cryptography library .

## Features
- Complete Rust bindings for PQMagic's signature and KEM algorithms

- Type-safe API design

- Benchmarks for all supported algorithms

- Cross-platform support

## Prerequisites
- Rust Toolchain

- cmake >= 3.10 （ For PQMagic builds ）

## Building

```bash
# Clone the repository
git clone --recursive https://github.com/pqcrypto-cn/PQMagic-Rust.git
cd PQMagic-Rust

# Build and run tests
cargo build
cargo test

# Run benchmarks
cargo bench
```


## Usage
### Digital Signatures (SIG)
```rust

    // Initialize signer
    let signer = PqmagicSig::new("ML_DSA_44")?;

    // Generate keypair
    let (pk, sk) = signer.keypair()?;

    // Sign message
    let msg = b"Test message";
    let sig = signer.sign(msg, None, &sk)?;

    // Verify signature
    assert!(
        signer.verify(&sig, msg, None, &pk)?,
        "Verification failed for {}",
        signer.name()
    );
```
### Key Encapsulation Mechanism (KEM)
```rust
// Initialize KEM
let kem = PqmagicKem::new("ML_KEM_512")?;

// Generate keypair
let (pk, sk) = kem.keypair()?;

// Encapsulate (generate ciphertext and shared secret)
let (ct, ss1) = kem.encaps(&pk)?;

// Decapsulate (recover shared secret)
let ss2 = kem.decaps(&ct, &sk)?;

// Verify shared secrets match
assert_eq!(
    ss1, ss2,
    "Shared secret mismatch: encapsulated {:?}, decapsulated {:?}",
    ss1, ss2
);
```
> For detailed test examples, see [tests/pqmagic_tests.rs](./tests/pqmagic_tests.rs)

## Supported Algorithms
See the full list of supported algorithms in [src/lib](./src/lib.rs) .rs, including:

- SIG
    - ML-DSA (FIPS 204)

    - Aigis-Sig

    - Dilithium

    - SLH-DSA (FIPS 205)

    - SPHINCS-α
- KEM
    - ML-KEM (FIPS 203)

    - Aigis-Enc

    - Kyber

