# adac-tests

## Setup

Rust unit and integration tests require `softhsm2`.

On Linux, the location of the token state for non-root users needs to be
configured and the value of `SOFTHSM2_CONF` be properly set. The wrapper
script (`run-tests.sh`) automates this setup, and additional information
is otherwise available in [CLI-PKCS11.md](CLI-PKCS11.md).

Other tests and scripts will require `openssl`,  and `pkcs11-tool` (the
latter is part of the `opensc` package).

## Test scripts

- `run-tests.sh`: run Rust unit and integration tests.
- `pkcs11-tests.sh`: run CLI tests for PKCS#11.
- `pkcs11-test-krypoptic.sh`: run CLI tests for PKCS#11 ML-DSA with Kryoptic.
- `offline-tests.sh`: run CLI tests for Offline signature.
