// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![allow(dead_code)]

use adac::CertificateRole::*;
use adac::KeyOptions::*;
use adac::{AdacVersion, CertificateHeader, KeyOptions};

mod aws_lc;
mod cryptoki;
mod cryptoki_mldsa;
mod encoding;
mod ml_dsa;
pub mod pkcs11;
mod rust_crypto;

struct TestSettings {
    /// The size of the stack of the thread that run tests.
    stack_size: usize,
}

impl Default for TestSettings {
    fn default() -> Self {
        TestSettings {
            stack_size: 8 * 1024 * 1024, // 8MB
        }
    }
}

fn run_test_with<F>(test_setting: &TestSettings, f: F)
where
    F: FnOnce(),
    F: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(test_setting.stack_size)
        .spawn(f)
        .expect("Failed to create a test thread")
        .join()
        .expect("Failed to join a test thread")
}

pub fn test_certificate_header(key_type: KeyOptions, level: usize) -> CertificateHeader {
    if level > 3 {
        panic!("level {} should be less than 3", level);
    }

    #[rustfmt::skip]
    let permissions = [
        [0xFFu8; 16],
        [
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ],
        [
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ],
        [
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ],
    ];

    let roles = [
        AdacCrtRoleRoot,
        AdacCrtRoleInt,
        AdacCrtRoleInt,
        AdacCrtRoleLeaf,
    ];

    #[rustfmt::skip]
    let soc_ids = [
        [0x00u8; 16],
        [0x00u8; 16],
        [0x00u8; 16],
        [
            0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8,
            0x08u8, 0x09u8, 0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, 0x0Eu8, 0x0Fu8
        ],
    ];
    let soc_class = [0, 0, 0x12345678u32, 0];

    let mut h = CertificateHeader::default();
    if key_type == EcdsaP384Sha384
        || key_type == MlDsa44Sha256
        || key_type == MlDsa65Sha384
        || key_type == MlDsa87Sha512
    {
        h.format_version = AdacVersion { major: 1, minor: 1 };
    }
    h.key_type = key_type;
    h.signature_type = key_type;
    h.usage = adac::CertificateUsage::AdacUsageStandard;
    h.role = roles[level];
    h.permissions_mask = permissions[level];
    h.soc_id = soc_ids[level];
    h.soc_class = soc_class[level];

    h
}

pub fn test_root_certificate_header(key_type: KeyOptions) -> (CertificateHeader, Vec<u8>) {
    #[rustfmt::skip]
    let permissions: [u8; 16]= [
        0x2Fu8, 0x2Eu8, 0x2Du8, 0x2Cu8, 0x2Bu8, 0x2Au8, 0x29u8, 0x28u8,
        0x27u8, 0x26u8, 0x25u8, 0x24u8, 0x23u8, 0x22u8, 0x21u8, 0x20u8,
    ];
    #[rustfmt::skip]
    let soc_id: [u8; 16]= [
        0x1Fu8, 0x1Eu8, 0x1Du8, 0x1Cu8, 0x1Bu8, 0x1Au8, 0x19u8, 0x18u8,
        0x17u8, 0x16u8, 0x15u8, 0x14u8, 0x13u8, 0x12u8, 0x11u8, 0x10u8,
    ];
    let role = AdacCrtRoleRoot;
    let soc_class = 0x12345678u32;
    let lifecycle = 0x3000;
    let extensions = vec![
        0x00u8, 0x00u8, 0x00u8, 0x80u8, 0x10u8, 0x00u8, 0x00u8, 0x00u8, 0x3Fu8, 0x3Eu8, 0x3Du8,
        0x3Cu8, 0x3Bu8, 0x3Au8, 0x39u8, 0x38u8, 0x37u8, 0x36u8, 0x35u8, 0x34u8, 0x33u8, 0x32u8,
        0x31u8, 0x30u8, 0x00u8, 0x00u8, 0x01u8, 0x80u8, 0x10u8, 0x00u8, 0x00u8, 0x00u8, 0x40u8,
        0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8, 0x47u8, 0x48u8, 0x49u8, 0x4Au8, 0x4Bu8,
        0x4Cu8, 0x4Du8, 0x4Eu8, 0x4Fu8,
    ];
    let extensions_bytes = extensions.len() as u32;

    let mut h = CertificateHeader::default();
    if key_type == EcdsaP384Sha384
        || key_type == MlDsa44Sha256
        || key_type == MlDsa65Sha384
        || key_type == MlDsa87Sha512
    {
        h.format_version = AdacVersion { major: 1, minor: 1 };
    }
    h.key_type = key_type;
    h.signature_type = key_type;
    h.usage = adac::CertificateUsage::AdacUsageStandard;
    h.role = role;
    h.permissions_mask = permissions;
    h.soc_id = soc_id;
    h.soc_class = soc_class;
    h.extensions_bytes = extensions_bytes;
    h.lifecycle = lifecycle;

    (h, extensions)
}
