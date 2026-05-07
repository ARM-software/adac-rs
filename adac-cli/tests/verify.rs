// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod common;

use adac_cli::CommandOutput;
use adac_cli::config::parse_adac_token_configuration;
use adac_cli::token::token_sign_command;
use adac_cli::verify::verify_command;
use adac_crypto::utils::{load_certificates, read_certificate_chain_bytes};
use std::fs;

#[test]
fn verify_command_verifies_token_and_masks_permissions() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let config_path = common::write_token_config(&dir);
    let chain_path = common::fixture_path("roots", "root.EcdsaP384");
    let private_path = common::fixture_path("keys", "EcdsaP384Key-0.pk8");
    let token_path = dir.join("token.bin");

    token_sign_command(
        common::TOKEN_CHALLENGE,
        &Some(config_path),
        &Some(token_path.clone()),
        &None,
        &Some(private_path),
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &Some("token".to_string()),
    )
    .unwrap();

    let output = verify_command(
        &chain_path,
        &Some(token_path),
        &Some(common::TOKEN_CHALLENGE.to_string()),
        false,
    )
    .unwrap();

    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 0);
    assert!(
        report
            .token
            .as_ref()
            .is_some_and(|token| token.signature_verified && token.errors.is_empty())
    );

    let chain = load_certificates(&chain_path).unwrap();
    let config =
        parse_adac_token_configuration(common::TOKEN_CONFIG, Some("token".to_string())).unwrap();
    let mut permissions = chain[0].header().permissions_mask;
    for certificate in chain.iter().skip(1) {
        for (i, permission) in permissions.iter_mut().enumerate() {
            *permission &= certificate.header().permissions_mask[i];
        }
    }
    for (i, permission) in permissions.iter_mut().enumerate() {
        *permission &= config.requested_permissions[i];
    }
    let mut effective = [0u8; 16];
    effective.copy_from_slice(u128::from_le_bytes(permissions).to_be_bytes().as_ref());
    let expected_summary = format!(
        "Effective permissions: 0x{} ({})",
        base16ct::lower::encode_string(effective.as_slice()),
        base16ct::lower::encode_string(permissions.as_slice())
    );
    assert!(report.summary.iter().any(|line| line == &expected_summary));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_command_strict_requires_token_signed_by_leaf() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let config_path = common::write_token_config(&dir);
    let chain_path = common::write_chain_ending_at_intermediate(&dir, "inter-chain.pem");
    let private_path = common::fixture_path("keys", "EcdsaP384Key-1.pk8");
    let token_path = dir.join("token.bin");

    token_sign_command(
        common::TOKEN_CHALLENGE,
        &Some(config_path),
        &Some(token_path.clone()),
        &None,
        &Some(private_path),
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &Some("token".to_string()),
    )
    .unwrap();

    let output = verify_command(
        &chain_path,
        &Some(token_path.clone()),
        &Some(common::TOKEN_CHALLENGE.to_string()),
        false,
    )
    .unwrap();
    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 0);
    assert!(
        report
            .token
            .as_ref()
            .is_some_and(|token| token.signature_verified && token.errors.is_empty())
    );

    let output = verify_command(
        &chain_path,
        &Some(token_path),
        &Some(common::TOKEN_CHALLENGE.to_string()),
        true,
    )
    .unwrap();
    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert!(report.error_count > 0);
    assert!(report.certificates.iter().any(|certificate| {
        certificate
            .errors
            .iter()
            .any(|error| error == "Last certificate does not have Leaf role")
    }));
    assert!(report.token.as_ref().is_some_and(|token| {
        token.signature_verified
            && token.errors.iter().any(|error| {
                error == "Token signature verifies, but token validation failed because the certificate chain is invalid"
            })
    }));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_command_strict_rejects_critical_certificate_extensions() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let config_path = dir.join("critical-extension.toml");
    fs::write(
        &config_path,
        r#"
[defaults]
version_major = 1
version_minor = 1
role = 1
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0100341201000000aa000000"

[root]
role = 1
"#,
    )
    .unwrap();
    let chain_path = common::write_root_certificate(&dir, &config_path, "root.pem");

    let output = verify_command(&chain_path, &None, &None, false).unwrap();
    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 0);

    let output = verify_command(&chain_path, &None, &None, true).unwrap();
    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 1);
    assert!(
        report.encoding_errors.iter().any(|error| {
            error.message == "Unknown or unprocessed critical extension type 0x1234"
        })
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_command_reports_effective() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let chain_path = common::write_signed_chain(
        &dir,
        "inter_usage_lifecycle",
        "inter_soc_class_policy",
        "leaf_soc_id",
        "restricted.pem",
    );

    let output = verify_command(&chain_path, &None, &None, false).unwrap();

    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 0);
    assert!(
        report
            .summary
            .iter()
            .any(|line| line == "Restricted to lifecycle 0x3000")
    );
    assert!(
        report
            .summary
            .iter()
            .any(|line| line == "Restricted to SoC Class: 0x12345678")
    );
    assert!(
        report.summary.iter().any(
            |line| line.starts_with("Restricted to SoC ID: 0x00112233445566778899aabbccddeeff")
        )
    );
    assert!(
        report
            .summary
            .iter()
            .any(|line| line == "Restricted to usage AdacUsageStandard")
    );
    assert!(
        report
            .summary
            .iter()
            .any(|line| line == "Effective policies: 0x3")
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_command_rejects_conflicting() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let chain_path = common::write_signed_chain(
        &dir,
        "inter_usage_lifecycle",
        "inter_soc_class_policy",
        "leaf_conflict",
        "conflict.pem",
    );

    let output = verify_command(&chain_path, &None, &None, false).unwrap();

    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 2);
    assert!(report.certificates.iter().any(|certificate| {
        certificate
            .errors
            .iter()
            .any(|error| error == "Lifecycle does not match (0x3000 != 0x4000)")
    }));
    assert!(report.certificates.iter().any(|certificate| {
        certificate
            .errors
            .iter()
            .any(|error| error == "SoC ID Class not match (0x12345678 != 0x5678)")
    }));

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn verify_command_reports_certificate_chain_encoding_errors() {
    let dir = common::make_temp_dir("adac-cli-verify-tests");
    let chain_path = common::write_signed_chain(
        &dir,
        "inter_usage_lifecycle",
        "inter_soc_class_policy",
        "leaf_soc_id",
        "bad-encoding.pem",
    );
    let contents = fs::read_to_string(&chain_path).unwrap();
    let mut bytes = read_certificate_chain_bytes(contents.as_str()).unwrap();
    bytes[1] = 1;
    let pem = pem::Pem::new("ADAC CERTIFICATE CHAIN", bytes);
    let pem = pem::encode_config(
        &pem,
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );
    fs::write(&chain_path, pem).unwrap();

    let output = verify_command(&chain_path, &None, &None, false).unwrap();

    let CommandOutput::Verify(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.error_count, 1);
    assert_eq!(report.encoding_errors.len(), 1);
    assert_eq!(
        report.encoding_errors[0].message,
        "Invalid nonzero TLV reserved field"
    );

    let _ = fs::remove_dir_all(dir);
}
