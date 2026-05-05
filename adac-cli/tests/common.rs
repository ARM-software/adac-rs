// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(dead_code)]

use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac_cli::sign::certificate_sign_command;
use adac_crypto::utils::load_key;
use adac_crypto_rust::RustCryptoProvider;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, fs};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const TOKEN_CONFIG: &str = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[token]
version_minor = 1
requested_permissions = "0x00000000FFFFFFFFFFFFFFFFFFFFFFFF"
"#;

pub const TOKEN_CHALLENGE: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

pub fn make_temp_dir(prefix: &str) -> PathBuf {
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), counter));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

pub fn fixture_path(kind: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../adac-tests/resources")
        .join(kind)
        .join(name)
}

pub fn write_token_config(dir: &Path) -> PathBuf {
    let path = dir.join("token.toml");
    fs::write(&path, TOKEN_CONFIG).unwrap();
    path
}

pub fn write_public_key_from_private(dir: &Path, key_name: &str, output_name: &str) -> PathBuf {
    let (key_type, private_key) = load_key(fixture_path("keys", key_name)).unwrap();
    let mut crypto = RustCryptoProvider::default();
    let public_key = crypto
        .load_key(key_type, AdacKeyFormat::Pkcs8, private_key.as_slice())
        .unwrap();
    let pem = pem::Pem::new("PUBLIC KEY", public_key);
    let pem = pem::encode_config(
        &pem,
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );
    let path = dir.join(output_name);
    fs::write(&path, pem).unwrap();
    path
}

pub fn sign_with_private_key(key_name: &str, data: &[u8]) -> Vec<u8> {
    let (key_type, private_key) = load_key(fixture_path("keys", key_name)).unwrap();
    let mut crypto = RustCryptoProvider::default();
    crypto
        .load_key(key_type, AdacKeyFormat::Pkcs8, private_key.as_slice())
        .unwrap();
    crypto.sign(key_type, data).unwrap()
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    if value.is_empty() {
        value.push(0);
    }
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }

    let mut integer = vec![0x02, value.len().try_into().unwrap()];
    integer.extend(value);
    integer
}

pub fn ecdsa_p384_signature_to_der(signature: &[u8]) -> Vec<u8> {
    assert_eq!(signature.len(), 96);
    let r = der_integer(&signature[..48]);
    let s = der_integer(&signature[48..]);
    let mut der = vec![0x30, (r.len() + s.len()).try_into().unwrap()];
    der.extend(r);
    der.extend(s);
    der
}

pub fn write_verify_config(dir: &Path) -> PathBuf {
    let path = dir.join("verify-config.toml");
    fs::write(
        &path,
        r#"
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

[inter_usage_lifecycle]
role = 2
usage = 1
lifecycle = 0x3000

[inter_soc_class_policy]
role = 2
usage = 1
soc_class = 0x12345678
policies = 0x1

[leaf_soc_id]
usage = 1
soc_id = "0x00112233445566778899aabbccddeeff"
policies = 0x2

[leaf_conflict]
usage = 1
lifecycle = 0x4000
soc_class = 0x5678
soc_id = "0x00112233445566778899aabbccddeeff"

"#,
    )
    .unwrap();
    path
}

fn sign_certificate(
    config_path: &Path,
    issuer: Option<&Path>,
    output: &Path,
    private_key_name: &str,
    public_key: &Path,
    section: &str,
) {
    let config_path = config_path.to_path_buf();
    let issuer = issuer.map(Path::to_path_buf);
    let output = Some(output.to_path_buf());
    let private_key = Some(fixture_path("keys", private_key_name));
    let public_key = public_key.to_path_buf();
    let section = Some(section.to_string());

    certificate_sign_command(
        &config_path,
        &issuer,
        &output,
        &private_key,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &public_key,
        &section,
    )
    .unwrap();
}

pub fn write_root_certificate(dir: &Path, config_path: &Path, output_name: &str) -> PathBuf {
    let root_public = write_public_key_from_private(dir, "EcdsaP384Key-0.pk8", "root.pub");
    let root_path = dir.join(output_name);

    sign_certificate(
        config_path,
        None,
        &root_path,
        "EcdsaP384Key-0.pk8",
        &root_public,
        "root",
    );

    root_path
}

pub fn write_signed_chain(
    dir: &Path,
    inter1_section: &str,
    inter2_section: &str,
    leaf_section: &str,
    output_name: &str,
) -> PathBuf {
    let config_path = write_verify_config(dir);
    let inter1_public = write_public_key_from_private(dir, "EcdsaP384Key-1.pk8", "inter1.pub");
    let inter2_public = write_public_key_from_private(dir, "EcdsaP384Key-2.pk8", "inter2.pub");
    let leaf_public = write_public_key_from_private(dir, "EcdsaP384Key-3.pk8", "leaf.pub");
    let root_path = write_root_certificate(dir, &config_path, "root.pem");
    let inter1_path = dir.join("inter1.pem");
    let inter2_path = dir.join("inter2.pem");
    let chain_path = dir.join(output_name);

    sign_certificate(
        &config_path,
        Some(&root_path),
        &inter1_path,
        "EcdsaP384Key-0.pk8",
        &inter1_public,
        inter1_section,
    );
    sign_certificate(
        &config_path,
        Some(&inter1_path),
        &inter2_path,
        "EcdsaP384Key-1.pk8",
        &inter2_public,
        inter2_section,
    );
    sign_certificate(
        &config_path,
        Some(&inter2_path),
        &chain_path,
        "EcdsaP384Key-2.pk8",
        &leaf_public,
        leaf_section,
    );

    chain_path
}
