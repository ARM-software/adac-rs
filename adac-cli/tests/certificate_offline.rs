// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod common;

use adac_cli::offline::{certificate_merge_command, certificate_prepare_command};
use adac_cli::{CommandError, CommandOutput};
use adac_crypto::utils::{load_certificates, verify_chain};
use adac_crypto_rust::RustCryptoProvider;
use std::fs;

#[test]
fn certificate_offline_prepare_and_merge_round_trip() {
    let dir = common::make_temp_dir("adac-cli-certificate-offline-tests");
    let config_path = common::write_verify_config(&dir);
    let issuer_path = common::write_root_certificate(&dir, &config_path, "root.pem");
    let public_key = common::write_public_key_from_private(&dir, "EcdsaP384Key-1.pk8", "leaf.pub");
    let prepared_path = dir.join("prepared.pem");
    let merged_path = dir.join("merged.pem");
    let tbs_path = dir.join("prepared.tbs");
    let hash_path = dir.join("prepared.hash");
    let signature_path = dir.join("signature.der");

    let output = certificate_prepare_command(
        &config_path,
        &public_key,
        &Some("inter_soc_class_policy".to_string()),
        &Some(prepared_path.clone()),
        &Some(tbs_path.clone()),
        &Some(hash_path.clone()),
    )
    .unwrap();

    let CommandOutput::CertificateOfflinePrepare(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.crt_path, Some(prepared_path.clone()));
    assert_eq!(report.tbs_path, Some(tbs_path.clone()));
    assert_eq!(report.hash_path, Some(hash_path.clone()));

    let signature = common::sign_with_private_key(
        "EcdsaP384Key-0.pk8",
        fs::read(&tbs_path).unwrap().as_slice(),
    );
    fs::write(
        &signature_path,
        common::ecdsa_p384_signature_to_der(&signature),
    )
    .unwrap();

    let output = certificate_merge_command(
        &Some(issuer_path),
        &Some(merged_path.clone()),
        &prepared_path,
        &signature_path,
    )
    .unwrap();

    let CommandOutput::CertificateOfflineMerge(report) = output else {
        panic!("unexpected command output");
    };
    assert_eq!(report.path, Some(merged_path.clone()));

    let chain = load_certificates(&merged_path).unwrap();
    assert_eq!(chain.len(), 2);
    let policies = chain[1].header().policies;
    assert_eq!(policies, 0x1);
    verify_chain(chain, &RustCryptoProvider::default()).unwrap();

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn certificate_offline_merge_rejects_invalid_signature() {
    let dir = common::make_temp_dir("adac-cli-certificate-offline-tests");
    let config_path = common::write_verify_config(&dir);
    let issuer_path = common::write_root_certificate(&dir, &config_path, "root.pem");
    let public_key = common::write_public_key_from_private(&dir, "EcdsaP384Key-1.pk8", "leaf.pub");
    let prepared_path = dir.join("prepared.pem");
    let tbs_path = dir.join("prepared.tbs");
    let signature_path = dir.join("signature.der");

    certificate_prepare_command(
        &config_path,
        &public_key,
        &Some("inter_soc_class_policy".to_string()),
        &Some(prepared_path.clone()),
        &Some(tbs_path.clone()),
        &None,
    )
    .unwrap();

    let signature = common::sign_with_private_key(
        "EcdsaP384Key-1.pk8",
        fs::read(&tbs_path).unwrap().as_slice(),
    );
    fs::write(
        &signature_path,
        common::ecdsa_p384_signature_to_der(&signature),
    )
    .unwrap();

    let err = certificate_merge_command(&Some(issuer_path), &None, &prepared_path, &signature_path)
        .unwrap_err();

    match err {
        CommandError::AdacError { source } => {
            assert!(
                source
                    .to_string()
                    .contains("does not verify against issuer chain")
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let _ = fs::remove_dir_all(dir);
}
