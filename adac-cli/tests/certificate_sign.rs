// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod common;

use adac_cli::CommandError;
use adac_cli::sign::certificate_sign_command;
use std::fs;

#[test]
fn certificate_sign_rejects_mismatched_self_signing_key() {
    let dir = common::make_temp_dir("adac-cli-certificate-sign-tests");
    let config_path = common::write_verify_config(&dir);
    let public_key = common::write_public_key_from_private(&dir, "EcdsaP384Key-1.pk8", "root.pub");
    let output = dir.join("root.pem");
    let private_key = Some(common::fixture_path("keys", "EcdsaP384Key-0.pk8"));

    let err = certificate_sign_command(
        &config_path,
        &None,
        &Some(output.clone()),
        &private_key,
        &None,
        &None,
        &None,
        &None,
        &None,
        &None,
        &public_key,
        &Some("root".to_string()),
    )
    .unwrap_err();

    match err {
        CommandError::AdacError { source } => {
            assert!(
                source
                    .to_string()
                    .contains("does not verify with its embedded public key")
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(!output.exists());

    let _ = fs::remove_dir_all(dir);
}
