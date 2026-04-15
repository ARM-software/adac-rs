# ADAC Command Line Interface

This document describes how to use the `adac-cli` tool to generate Authenticated Debug Access Control (ADAC) certificates and tokens.

## Description

For details of the Authenticated Debug Access Control mechanism see the [ADAC specification](https://developer.arm.com/documentation/den0101/latest).

The tool supports use of a Hardware Security Module (HSM) to manage keys using the PKCS#11 API and a suitable plugin.

## Usage

The tool has a number of subcommands which perform specific actions on keys or certificate chains:
* `display` - Display certificate chain content.
* `pkcs11-keygen` - Generate keys using a PKCS#11 provider.
* `pop` - Extract the last certificate in a chain.
* `push` - Add a certificate to a chain.
* `rot-hash` - Extract the root of trust public key hash.
* `sign` - Sign a certificate.
* `offline-prepare` - Generate an unsigned certificate plus the payload that must be signed elsewhere.
* `offline-merge` - Combine an offline signature with an unsigned certificate.
* `token-sign` (alias: `token`) - Sign an authentication token.
* `token-offline-prepare` - Generate an unsigned token plus the payload that must be signed elsewhere.
* `token-offline-merge` - Combine an offline token signature with an unsigned token.
* `verify` - Verify certificate chain content.

Subsequent sections describe common or recurring option groups and each subcommand individually.

### Sign certificates using an offline system

Use the offline prepare and merge subcommands when the signing key is held in an offline system (for example, a high-security HSM) that cannot run `adac-cli` directly. This workflow separates certificate construction from signing:

1. Run `offline-prepare` to build every certificate byte except the signature. The command emits the to-be-signed (TBS) payload and its hash so they can be moved into the offline environment.
2. Sign the TBS payload using the protected private key. The offline signer should output a DER-encoded ECDSA signature matching the certificate key type.
3. Run `offline-merge` with the unsigned certificate and detached signature to produce a fully signed certificate or certificate chain, optionally prepending an issuer chain at the same time.

Offline signing supports only a subset of certificate signature algorithms. The offline signer must produce a DER-encoded signature that matches the certificate key type. For details of the DER format see the normative definition in [ITU-T Recommendation X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).

### Command line help
The following commands will provide some usage information about the tool along with a list of available subcommands:
```
adac-cli -h
adac-cli --help
adac-cli help
```
Each subcommand also has more detailed help. For example, the below will provide more information on the `sign` options:
```
adac-cli sign --help
```

### Global options

These options affect the overall program and apply to all subcommands.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-v, --verbose` | Increase log verbosity. Repeat for more verbosity. | `-vv` | |
| `--log-level` | Set log level. Options: `error`, `warn`, `info`, `debug`, `trace` | `--log-level debug` | `warn` |
| `--log-format` | Log format (text or json). | `--log-format json` | `text` |
| `--output-format` | Command output format (text or json). | `--output-format json` | `text` |
| `--log-file` | Append logs to file instead of stderr. | `--log-file log.txt` | `stderr` |
| `-h, --help` | Show help as described above. | `--help` | |
| `-V, --version` | Print version and exit. | `--version` | |

For clarity only options unique to each subcommand are detailed in the sections below.

### PKCS#11 key specifier options

These options define the PKCS#11 key used to sign a certificate or token, or specify the key being created by `pkcs11-keygen`.
Some options may be passed using shell environment variables, and some options affect which environment variables are used.

You can also sign certificates using a key from a local file. In this case, the PKCS#11 options are not required.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-m, --module` | Path to the PKCS#11 provider library. | `--module /usr/lib/pkcs11.so` | none |
| `--pin` | User PIN needed to create or access the key. | `--pin 1234` | none |
| `--pin-file` | A file containing the above user PIN. | `--pin-file secure/my_pin.txt` | none |
| `--pin-env` | The name of the environment variable containing the user PIN. | `--pin-env ALT_PIN` | `PKCS11_PIN` |
| `--slot` | Optional slot label used to find the key. | `--slot my_debug_keys` | none |

These environment variables can be used instead of the above:
* `PKCS11_MODULE` - The path to the provider library.
* `PKCS11_SLOT` - The slot label containing the needed key.
* `PKCS11_PIN` - The user PIN needed to access the key (default name).
* Custom environment variable – The user PIN, when you specify a different variable using `--pin-env`.

### display: Display certificate chain content.

Use this subcommand to display information about the certificate or certificate chain contents.

```
Usage: adac-cli display [OPTIONS] <INPUT>
```

Positional arguments:
- `<INPUT>`: Path to certificate or certificate chain.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-l, --leaf` | Show only the leaf certificate. | `--leaf` | none |
| `--print` | Output PEM of chain or leaf certificate. | `--print` | none |

Example command to print information about crt1.crt:
```
adac-cli display test/crt1.crt -l
```

### pkcs11-keygen: Generate keys using a PKCS#11 provider.

Use this subcommand to generate keys stored in a Hardware Security Module using the PKCS#11 API.

```
Usage: adac-cli pkcs11-keygen <KEY_TYPE> [OPTIONS]
```

Positional arguments:
- `<KEY_TYPE>`: Key type, see lists below.

For other flags, see the [PKCS#11 options](#pkcs11-key-specifier-options) section.

Currently the following key types are supported:
 - EcdsaP256Sha256
 - EcdsaP384Sha384
 - EcdsaP521Sha512
 - Rsa3072Sha256
 - Rsa4096Sha256

 These key types are recognised, but not yet supported:
 - Ed25519Sha512
 - Ed448Shake256
 - SmSm2Sm3
 - CmacAes
 - HmacSha256
 - MlDsa44Sha256
 - MlDsa65Sha384
 - MlDsa87Sha512

Example command to generate an ECDSA-P384 key, passing values from the environment:
```
SECRET_PIN=123456 adac-cli --output-format json pkcs11-keygen \
    EcdsaP384Sha384 --module /usr/lib/my_hsm/libhsm_pkcs11.so --slot debug_keys --pin-env SECRET_PIN
```

### pop: Extract last certificate.

Use this subcommand to extract the last certificate from a certificate chain.
If there is only one certificate in the chain, that certificate is returned.

```
Usage: adac-cli pop [OPTIONS] <INPUT>
```

Positional arguments:
- `<INPUT>`: Path to certificate or certificate chain.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-o, --output` | Output file to store the certificate in. | `--output leaf.pem` | none (stdout) |

Example command to extract the leaf certificate of crt1.crt:
```
adac-cli pop test/crt1.crt
```

### push: Add a certificate to a chain.

Use this subcommand to append a certificate or certificate chain to an existing certificate chain.
The resulting chain is written to the given output file, or printed to stdout if no output file is given.

```
Usage: adac-cli push [OPTIONS] <CHAIN> <INPUT>
```

Positional arguments:
- `<CHAIN>`: Path to the certificate or certificate chain that receives the appended certificates.
- `<INPUT>`: Path to the additional certificate or certificate chain that will be appended.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-o, --output` | Output file to store the certificate chain in. | `--output combined.crt` | none (stdout) |

Example command to add newcert.crt to the chain in test/crt1.crt and store
the result in combined.crt:
```
adac-cli push -o combined.crt test/crt1.crt newcert.crt
```

### rot-hash: Extract root of trust public key hash.

Use this subcommand to display the hash value of the Root of Trust (RoT) public key from the given certificate chain.
The Root of Trust is the key used to sign the root certificate of a chain.

```
Usage: adac-cli rot-hash [OPTIONS] <INPUT>
```

Positional arguments:
- `<INPUT>`: Path to certificate or certificate chain.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `--hash` | Hash algorithm. Options: `sha256`, `sha384`, `sha512` | `--hash sha384` | `sha256` |

Example command to show the RoT hash from crt1.crt:
```
adac-cli rot-hash test/crt1.crt --hash sha384
```

### sign: Sign a certificate.

Use this subcommand to create and sign a new certificate. This can be either a root certificate or one derived from an issuer certificate, creating a chain.

```
Usage: adac-cli sign [OPTIONS] <CONFIG> <PUBLIC_KEY>
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-i, --issuer` | Issuer certificate or certificate chain. | `--issuer my_cert.crt` | none, required for non-root certificates |
| `-k, --key-id` | The identifier of the private key, when using PKCS#11 | `--key-id abcdef012345` | - |
| `-p, --private-key` | A file containing the private key of the issuer (or RoT), when not using PKCS#11. | `--private-key my_key.pk8` | |
| `-o, --output` | Output file for the generated certificate or certificate chain. | `--output ap_team_debug.crt` | - |
| `-s, --section` | Config file section to apply. | `--section intermediate` | - |

Positional arguments:
- `<CONFIG>`: Signing configuration file [(see here)](#configuration-file-format)
- `<PUBLIC_KEY>`: Public key to incorporate into the certificate.

See the [PKCS#11 options](#pkcs11-key-specifier-options) section for information on retrieving the key using PKCS#11, including selecting the token by slot label with `--slot`.

Alternatively, the subcommand can use private keys from a [PKCS#8 format](https://datatracker.ietf.org/doc/html/rfc5208) (PK8) file given using the `--private-key` flag.

Example commands to generate certificates:
```
adac-cli sign test-config.toml EcdsaP384Key-2.pub \
    -p resources/keys/EcdsaP384Key-1.pk8 \
    -i inter.crt -s crt1 -o crt1.crt

export PKCS11_MODULE=/usr/bin/path/to/libprovider.so
export PKCS11_SLOT=debug_keys
export PKCS11_PIN=123456
adac-cli sign newchip/adac_config.toml secdbg_Alice.pub -s secdbg_team \
    -i top_soc_debug.crt \
    -o secdbg_alice.crt \
    -k 1234bcc276f40f4153659863564abba
adac-cli sign newchip/adac_config.toml dbg_Bob.pub -s nonsecdbg_team \
    -i top_soc_debug.crt \
    -o dbg_bob.crt \
    -k 1234bcc276f40f4153659863564abba
```

### offline-prepare: Stage an unsigned certificate

```
Usage: adac-cli offline-prepare [OPTIONS] <CONFIG> <PUBLIC_KEY>
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-s, --section` | Configuration section to apply. | `--section lab_leaf` | `[defaults]` |
| `-o, --output` | Write the unsigned certificate (PEM chain) to this file. | `--output unsigned.crt` | stdout |
| `-t, --tbs` | File to store the raw to-be-signed (TBS) payload. | `--tbs crt1.tbs` | stdout |
| `--hash` | File to store the hash of the TBS payload (size depends on key type). | `--hash crt1.sha384` | stdout |

Positional arguments:
- `<CONFIG>`: Signing configuration file [(same format as `sign`)](#configuration-file-format).
- `<PUBLIC_KEY>`: Public key (PEM) to incorporate into the certificate.

When you do not specify output files, the command prints the following artifacts to stdout:
* The PEM-encoded unsigned certificate chain (identical structure to a fully signed certificate but with a placeholder signature).
* `TBS=<base64>` – the byte sequence that must be signed offline.
* `Hash=<hex>` – the digest of the TBS payload (useful for audit logs or to validate the transfer).

### offline-merge: Attach the offline signature

Use this subcommand to combine an unsigned certificate with an offline signature and produce a complete certificate chain.

```
Usage: adac-cli offline-merge [OPTIONS] <INPUT> <SIGNATURE>
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-i, --issuer` | Optional issuer chain to prepend to the final output. | `--issuer inter_chain.crt` | none |
| `-o, --output` | Write the completed certificate chain to this file. | `--output crt1-final.crt` | stdout |

Positional arguments:
- `<INPUT>`: Unsigned certificate produced by `offline-prepare`.
- `<SIGNATURE>`: The DER-encoded signature over the TBS payload, created offline.

Example:
```
# Prepare unsigned certificate and TBS
adac-cli offline-prepare \
    test-config.toml \
    EcdsaP384Key-2.pub \
    -s crt1 \
    -o unsigned.crt \
    -t crt1.tbs \
    --hash crt1.sha384

# Sign crt1.tbs on the offline system and write a DER-encoded signature to crt1.sig

# Merge the signature into the certificate and add to the chain
adac-cli offline-merge \
    --issuer inter.crt \
    unsigned.crt \
    crt1.sig \
    --output crt1-final.crt
```

### token-sign: Sign an authentication token.

Use this subcommand to create and sign an authentication token. The command name `token` is available as an alias for `token-sign`.

```
Usage: adac-cli token-sign [OPTIONS] <CHALLENGE> [PERMISSIONS]
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-c, --config` | Token configuration file [(see here)](#token-configuration-file-format). | `--config token.toml` | none |
| `-k, --key-id` | The identifier of the private key, when using PKCS#11. | `--key-id abcdef012345` | none |
| `--key-type` | Key type to sign with when using `--key-id`. If provided with `--private-key`, it must match the private key. | `--key-type EcdsaP384Sha384` | inferred from private key |
| `-o, --output` | Write the resulting token to this file. | `--output token.bin` | stdout |
| `-p, --private-key` | A file containing the private key in PKCS#8 format, when not using PKCS#11. | `--private-key signer.pk8` | none |
| `-s, --section` | Config file section to apply. | `--section token` | `[defaults]` |

Positional arguments:
- `<CHALLENGE>`: Token challenge as a 32-byte `0x`-prefixed hex value.
- `[PERMISSIONS]`: Requested permissions as a 16-byte `0x`-prefixed hex value.

See the [PKCS#11 options](#pkcs11-key-specifier-options) section for information on retrieving the key using PKCS#11, including selecting the token by slot label with `--slot`.

When `--output` is omitted, the token is printed to stdout as base64. When `--output` is provided, the file contains the raw token bytes.

Example command to sign a token using a local private key:
```
adac-cli token-sign \
    0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    0xffffffffffffffffffffffffffffffff \
    --private-key resources/keys/EcdsaP384Key-2.pk8 \
    --output token.bin
```

### token-offline-prepare: Stage an unsigned token

Use this subcommand when the token signing key is held in an offline system that cannot run `adac-cli` directly.

```
Usage: adac-cli token-offline-prepare [OPTIONS] <CHALLENGE> <KEY_TYPE> [PERMISSIONS]
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-c, --config` | Token configuration file [(see here)](#token-configuration-file-format). | `--config token.toml` | none |
| `-o, --output` | Write the unsigned token to this file. | `--output unsigned-token.bin` | stdout |
| `-s, --section` | Config file section to apply. | `--section token` | `[defaults]` |
| `-t, --tbs` | File to store the raw to-be-signed (TBS) payload. | `--tbs token.tbs` | stdout |
| `--hash` | File to store the hash of the TBS payload. | `--hash token.sha384` | stdout |

Positional arguments:
- `<CHALLENGE>`: Token challenge as a 32-byte `0x`-prefixed hex value.
- `<KEY_TYPE>`: Token signature key type, for example `EcdsaP384Sha384`.
- `[PERMISSIONS]`: Requested permissions as a 16-byte `0x`-prefixed hex value.

Currently the following token signature key types are supported:
 - EcdsaP256Sha256
 - EcdsaP384Sha384
 - EcdsaP521Sha512
 - MlDsa44Sha256
 - MlDsa65Sha384
 - MlDsa87Sha512
 - Rsa3072Sha256
 - Rsa4096Sha256

When you do not specify output files, the command prints the following artifacts to stdout:
* The unsigned token as base64.
* `TBS=<base64>` – the byte sequence that must be signed offline.
* `Hash=<hex>` – the digest of the TBS payload.

Example:
```
adac-cli token-offline-prepare \
    0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    EcdsaP384Sha384 \
    0xffffffffffffffffffffffffffffffff \
    --output unsigned-token.bin \
    --tbs token.tbs \
    --hash token.sha384
```

### token-offline-merge: Attach the offline token signature

Use this subcommand to combine an unsigned token with an offline signature and produce a complete token.

```
Usage: adac-cli token-offline-merge [OPTIONS] <INPUT> <SIGNATURE>
```

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-o, --output` | Write the resulting token to this file. | `--output token.bin` | stdout |

Positional arguments:
- `<INPUT>`: Unsigned token produced by `token-offline-prepare`.
- `<SIGNATURE>`: Detached signature to merge into the token.

When `--output` is omitted, the merged token is printed to stdout as base64. When `--output` is provided, the file contains the raw token bytes.

Example:
```
# Prepare unsigned token and TBS
adac-cli token-offline-prepare \
    0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    EcdsaP384Sha384 \
    0xffffffffffffffffffffffffffffffff \
    --output unsigned-token.bin \
    --tbs token.tbs \
    --hash token.sha384

# Sign token.tbs on the offline system and write the detached signature to token.sig

# Merge the signature into the token
adac-cli token-offline-merge \
    unsigned-token.bin \
    token.sig \
    --output token.bin
```

### verify: Verify certificate chain content.

Use this subcommand to verify the integrity of a certificate or all the certificates in a chain. It can also verify an authentication token against the leaf certificate public key.

```
Usage: adac-cli verify [OPTIONS] <INPUT>
```

Positional arguments:
- `<INPUT>`: Path to certificate or certificate chain.

| Flag | Description | Example | Default |
|------|-------------|---------|---------|
| `-c, --challenge` | Challenge bytes encoded as hex for token verification. Must be provided together with `--token`. | `--challenge 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff` | none |
| `-t, --token` | Path to an authentication token to verify against the leaf certificate public key. Must be provided together with `--challenge`. | `--token token.bin` | none |

The adac-cli exit status will be non-zero if the chain or token does not verify successfully.

Example commands:
```
adac-cli verify test/crt1.crt

adac-cli verify test/crt1.crt \
    --token token.bin \
    --challenge 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

## Configuration file format

The signing configuration file is a [TOML format](https://toml.io/en/) file with a `[defaults]` section and addition
sections describing any non-default values which override the defaults.

The settings and their values are described below and in the
[ADAC specification](https://developer.arm.com/documentation/den0101/latest).

| Setting | Meaning | Description | Example Value |
|---|---|---|---|
| version_major | Certificate format (major) | Incremented only when the certificate header layout/semantics are completely redefined. | 1 |
| version_minor | Certificate format (minor) | Incremented when members are added/changed while retaining backward compatibility. | 1 |
| role | Certificate role in chain | 1=Root, 2=Intermediate, 3=Leaf (leaf signs the debug token). | 3 |
| usage | Operational usage | 0=Neutral (no special usage), 1=Standard authentication, 2=RMA lifecycle. | 0 |
| lifecycle | PSA lifecycle restriction | 0 means no restriction. Non-zero values restrict use to a specific lifecycle (e.g., 0x3000 Secured, 0x4000 Debug). | 0 |
| oem_constraint | OEM-defined constraint | Integrator/OEM bitfield to further scope authentication; compare against device’s OEM constraint value. | 0 |
| soc_class | SoC family/class | Vendor-defined identifier for a family/revision of devices; can scope the cert to a device class. | 0 |
| soc_id | Unique SoC identifier | 128‑bit device-unique ID (e.g., serial/OTP). Non-zero value locks the certificate to one device. | 0x00000000000000000000000000000000 |
| permissions_mask | Allowed debug permissions | Bit mask of logical permissions this certificate permits. Combined with other certificates and SoC masks to compute effective permissions. | 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF |
| extensions | Optional TLV extensions | Optional fields (e.g., sw_partition_id, target_identity). Empty means no extra constraints. |  |

Example configuration:
```
[defaults]
version_major = 1
version_minor = 1
role = 3
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[root]
role = 1

[intermediate]
role = 2

[crt1]
soc_id = "0x01234005678009abc00def0123456789"
permissions_mask = "0x0000000003FFFFFFFFFFFFFF00000000"

[crt2]
soc_id = "0x01234005678009abc00def0123456789"
permissions_mask = "0x8000000003FFFFFFFFFFFFFF00000000"

[crt3]
soc_id = "0x01234005678009abc00def0123456789"
usage = 2
permissions_mask = "0x00000000000000000000000000000000"
```

## Token configuration file format

The token signing configuration file is also [TOML format](https://toml.io/en/). It has a required `[defaults]` section and optional additional sections that override individual settings.

| Setting | Meaning | Description | Example Value |
|---|---|---|---|
| version_major | Token format version (major) | Must be `1`. | 1 |
| version_minor | Token format version (minor) | Currently `0` or `1`. | 1 |
| requested_permissions | Requested debug permissions | A 16-byte `0x`-prefixed hex string. | `0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF` |
| extensions | Optional TLV extensions | Raw extension bytes as a `0x`-prefixed hex string. Use an empty string when no extensions are needed. | `0x01020304` |

Example configuration:
```
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[token]
version_minor = 1
requested_permissions = "0x00000000FFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0x01020304"
```

## License

This tool is distributed under a BSD 3-Clause license, see the LICENSE file.

Copyright (c) 2019-2026, Arm Limited (or its affiliates). All rights reserved.
