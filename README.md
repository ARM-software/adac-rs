# adac-rs

This workspace contains tooling for Arm Authenticated Debug an Access Control
(ADAC) specification. It provides the core library, command-line utilities,
cryptographic provider backends, and tests needed to create, sign, and
validate ADAC certificates and attestation tokens.

[Arm ADAC specifications (DEN0101)](https://developer.arm.com/documentation/den0101/latest/) 
contain full normative definitions of ADAC data structures and processing rules.

## Workspace overview

- `adac`: Core library with ADAC data structures, certificate parsing, and signing/verification primitives.
- `adac-cli`: Command-line utility for creating, inspecting, and verifying ADAC artifacts.
- `adac-crypto-*`: Cryptographic provider backends (RustCrypto, AWS-LC, PKCS#11, Cryptoki) that plug into the core library.
- `adac-tests`: Integration and conformance harnesses. See `adac-tests/README.md` for the full matrix and environment setup.

## Prerequisites

- Rust stable toolchain (install via [`rustup`](https://rustup.rs/)); the workspace tracks the latest stable release, so `rustup update` beforehand is recommended.
- `cargo` (bundled with rustup) for building and running binaries.
- Optional: `SoftHSM2` or another PKCS#11 provider if you plan to exercise the PKCS#11 backends.

## Build and run `adac-cli`

```bash
# Build the CLI (release builds live in target/release)
cargo build -p adac-cli

# Run the CLI; pass --help to see the available subcommands
cargo run -p adac-cli -- --help

# Install the CLI into ~/.cargo/bin
cargo install --path adac-cli
```

Most CLI subcommands operate on ADAC certificates or tokens. Add the
appropriate flags (for example `display`, `sign`, `verify`, `token-sign`,
`token-offline-prepare`, and `token-offline-merge`) as documented by the
`--help` output.

Token generation uses a TOML config with token-specific fields:

```toml
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[token]
version_minor = 1
requested_permissions = "0x0000000003FFFFFFFFFFFFFF00000000"
extensions = "0x01020304"
```

Token challenges must be 32 bytes encoded as hex with a `0x` prefix. Token
files written with `--output` are raw binary for compatibility with existing
tooling. Then sign a token directly or prepare it for offline signing:

```bash
cargo run -p adac-cli -- token-sign \
  --config token.toml \
  --section token \
  --private adac-tests/resources/keys/EcdsaP384Key-0.pk8 \
  --output token.bin \
  0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

cargo run -p adac-cli -- token-offline-prepare \
  --config token.toml \
  --key-type EcdsaP384Sha384 \
  --section token \
  --output prepared-token.bin \
  --tbs prepared-token.tbs \
  --hash prepared-token.hash \
  0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

cargo run -p adac-cli -- verify \
  --path adac-tests/resources/roots/root.EcdsaP384 \
  --token token.bin \
  --challenge 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

## Testing

```bash
# Run the default workspace test suite
cargo test

# Focus on a single crate (example: the CLI)
cargo test -p adac-cli
```

Advanced and cross-environment validation lives in `adac-tests`. Refer to
[adac-tests/README.md](adac-tests/README.md) for setup instructions
(SoftHSM2, hardware tokens) and the commands needed to execute the broader
matrix.

## Current cryptographic coverage

|  CryptoSystem   |    Rust Crypto     |       AWS-LC       |      PKCS#11       |
|:---------------:|:------------------:|:------------------:|:------------------:|
| EcdsaP256Sha256 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| EcdsaP384Sha384 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| EcdsaP521Sha512 | :construction: (1) | :white_check_mark: | :white_check_mark: |
|  Ed25519Sha512  | :white_check_mark: |        :x:         | :construction: (2) |
|  Ed448Shake256  | :white_check_mark: |        :x:         | :construction: (2) |
|  MlDsa44Sha256  | :white_check_mark: | :white_check_mark: |        :x:         |
|  MlDsa65Sha384  | :white_check_mark: | :white_check_mark: |        :x:         |
|  MlDsa87Sha512  | :white_check_mark: | :white_check_mark: |        :x:         |
|  Rsa3072Sha256  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|  Rsa4096Sha256  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    SmSm2Sm3     | :white_check_mark: |        :x:         |        :x:         |

- (1): Only verification works. There is an issue with the 
  [p521](https://crates.io/crates/p521) crate for signature.
- (2): Implementation untested, `SoftHSM2` does not support `phFlag=1` option for EdDSA signature or verification.

Legend: :white_check_mark: implemented and tested, :construction: planned or
partially implemented, :x: not currently available.

## License

`adac-rs` is provided under the terms of the the BSD 3-Clause license. See [LICENSE](LICENSE) for more information.
