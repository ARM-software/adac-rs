// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac_crypto::utils::load_key;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

const CERT_CONFIG: &str = r#"
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
"#;

pub fn make_temp_dir(prefix: &str) -> PathBuf {
    let test_name = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{test_name}-{}-{suffix}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn fixture_path(kind: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../adac-tests/resources")
        .join(kind)
        .join(name)
}

pub fn write_cert_config(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("cert-config.toml");
    fs::write(&path, CERT_CONFIG).unwrap();
    path
}

pub fn write_public_key_from_private(
    dir: &std::path::Path,
    key_name: &str,
    output_name: &str,
) -> PathBuf {
    let (key_type, private_key) = load_key(fixture_path("keys", key_name)).unwrap();
    let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
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
