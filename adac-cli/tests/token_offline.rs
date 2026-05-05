// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod common;

use adac::token::AdacToken;
use adac_cli::token::{load_token, token_merge_command, token_prepare_command};
use adac_cli::{CommandError, CommandOutput};
use adac_crypto::utils::{get_public_key, load_key};
use adac_crypto_rust::RustCryptoProvider;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use std::fs;

#[test]
fn token_offline_prepare_and_merge_round_trip() {
    let dir = common::make_temp_dir("adac-cli-token-offline-tests");
    let config_path = common::write_token_config(&dir);
    let prepared_path = dir.join("prepared.bin");
    let merged_path = dir.join("merged.bin");
    let tbs_path = dir.join("prepared.tbs");
    let hash_path = dir.join("prepared.hash");
    let signature_path = dir.join("signature.bin");
    let permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF".to_string();
    let key_type = "EcdsaP384Sha384".to_string();

    let output = token_prepare_command(
        &Some(config_path),
        &key_type,
        common::TOKEN_CHALLENGE,
        &Some(permissions),
        &Some("token".to_string()),
        &Some(prepared_path.clone()),
        &Some(tbs_path.clone()),
        &Some(hash_path.clone()),
    )
    .unwrap();

    let CommandOutput::TokenOfflinePrepare(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.token_path, Some(prepared_path.clone()));
    assert_eq!(report.tbs_path, Some(tbs_path.clone()));
    assert_eq!(report.hash_path, Some(hash_path.clone()));
    assert!(
        !fs::read(&prepared_path)
            .unwrap()
            .starts_with(b"-----BEGIN ADAC TOKEN-----")
    );

    let token = AdacToken::from_bytes(BASE64_STANDARD.decode(&report.token).unwrap()).unwrap();
    let requested_permissions = token.header().requested_permissions;
    assert_eq!(
        requested_permissions,
        0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
    );
    load_token(&prepared_path).unwrap();

    fs::write(
        &signature_path,
        common::sign_with_private_key(
            "EcdsaP384Key-0.pk8",
            fs::read(&tbs_path).unwrap().as_slice(),
        ),
    )
    .unwrap();

    let chain = common::fixture_path("roots", "root.EcdsaP384");
    let output = token_merge_command(
        &prepared_path,
        &signature_path,
        &Some(merged_path.clone()),
        &Some(common::TOKEN_CHALLENGE.to_string()),
        &Some(chain),
    )
    .unwrap();

    let CommandOutput::TokenOfflineMerge(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.path, Some(merged_path.clone()));

    let token = AdacToken::from_bytes(BASE64_STANDARD.decode(&report.token).unwrap()).unwrap();
    let (key_type, private_key) =
        load_key(common::fixture_path("keys", "EcdsaP384Key-0.pk8")).unwrap();
    let public_key = get_public_key(key_type, &private_key).unwrap();
    let challenge = base16ct::lower::decode_vec(common::TOKEN_CHALLENGE).unwrap();
    token
        .verify(
            public_key.as_slice(),
            challenge.as_slice(),
            &RustCryptoProvider::default(),
        )
        .unwrap();
    load_token(&merged_path).unwrap();

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn token_offline_merge_rejects_invalid_signature() {
    let dir = common::make_temp_dir("adac-cli-token-offline-tests");
    let config_path = common::write_token_config(&dir);
    let prepared_path = dir.join("prepared.bin");
    let tbs_path = dir.join("prepared.tbs");
    let signature_path = dir.join("signature.bin");
    let key_type = "EcdsaP384Sha384".to_string();

    token_prepare_command(
        &Some(config_path),
        &key_type,
        common::TOKEN_CHALLENGE,
        &None,
        &Some("token".to_string()),
        &Some(prepared_path.clone()),
        &Some(tbs_path.clone()),
        &None,
    )
    .unwrap();

    fs::write(
        &signature_path,
        common::sign_with_private_key(
            "EcdsaP384Key-1.pk8",
            fs::read(&tbs_path).unwrap().as_slice(),
        ),
    )
    .unwrap();

    let chain = common::fixture_path("roots", "root.EcdsaP384");
    let err = token_merge_command(
        &prepared_path,
        &signature_path,
        &None,
        &Some(common::TOKEN_CHALLENGE.to_string()),
        &Some(chain),
    )
    .unwrap_err();

    match err {
        CommandError::AdacError { source } => {
            assert!(
                source
                    .to_string()
                    .contains("Token does not verify against the last certificate in the chain")
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let _ = fs::remove_dir_all(dir);
}
