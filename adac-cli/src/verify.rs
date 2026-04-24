// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, token};
use adac::{CertificateRole, CertificateUsage};
use adac_crypto::public::AdacPublicKey;
use adac_crypto::utils::load_certificates;
use serde::Serialize;
use sha2::Digest;
use sha2::digest::Update;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    certificates: Vec<CertificateVerification>,
    token: Option<TokenVerification>,
    summary: Vec<String>,
    error_count: u64,
}

impl VerificationReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for (i, crt) in self.certificates.iter().enumerate() {
            writeln!(out, "Certificate {}: Key ID {}", i, crt.key_id)?;
            for e in &crt.errors {
                writeln!(out, "Error at level {}: {}", i, e)?;
            }
        }
        if let Some(token) = &self.token {
            if token.errors.is_empty() {
                writeln!(out, "Token verified")?;
            }
            for error in &token.errors {
                writeln!(out, "Token error: {}", error)?;
            }
        }
        for s in &self.summary {
            writeln!(out, "{}", s)?;
        }
        if self.error_count > 0 {
            writeln!(out)?;
            writeln!(
                out,
                "{} error(s) found during verification",
                self.error_count
            )?;
        }

        Ok(())
    }

    pub fn error_code(&self) -> i32 {
        if self.error_count > 0 { 1 } else { 0 }
    }
}

#[derive(Debug, Serialize)]
pub struct CertificateVerification {
    key_id: String,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenVerification {
    errors: Vec<String>,
}

pub fn verify_command(
    path: &PathBuf,
    token: &Option<PathBuf>,
    challenge: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let chain = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;

    if chain.is_empty() {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Empty certificate chain"),
        });
    }

    if (token.is_some() || challenge.is_some()) && (token.is_none() || challenge.is_none()) {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --token and --challenge must be provided together."),
        });
    }

    let token = if let Some(token) = token {
        let contents = std::fs::read(token).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading token: {:?}", e),
        })?;
        Some(contents)
    } else {
        None
    };

    let challenge = if let Some(challenge) = challenge {
        Some(token::decode_challenge_parameter(challenge)?)
    } else {
        None
    };

    let mut error_count = 0;
    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    let mut pubkey = chain[0].get_public_key();
    let mut header = chain[0].header();
    let mut usage = header.usage;
    let mut soc_id = header.soc_id;
    let mut soc_class = header.soc_class;
    let mut permissions = header.permissions_mask;

    let mut certificates = vec![];

    for i in 0..chain.len() {
        let mut errors = vec![];
        let current = &chain[i];
        header = current.header();

        let public_key = AdacPublicKey::from_adac(header.key_type, current.get_public_key())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing public key at level {}: {:?}", i, e),
            })?;
        let key_id = sha2::Sha256::new().chain(public_key.get_spki()).finalize();
        let key_id = base16ct::lower::encode_string(key_id.as_slice());

        if i == 0 && header.role != CertificateRole::AdacCrtRoleRoot {
            error_count += 1;
            errors.push("First certificate does not have Root role".to_string());
        } else if header.role == CertificateRole::AdacCrtRoleRoot && i > 0 {
            error_count += 1;
            errors.push("Only first certificate can have root role".to_string());
        } else if header.role == CertificateRole::AdacCrtRoleLeaf && i != chain.len() - 1 {
            error_count += 1;
            errors.push("Only last certificate can have leaf role".to_string());
        } else {
            // if i == chain.len() - 1 && header.role != CertificateRole::AdacCrtRoleLeaf {
            //     println!("Note: Last certificate is not Leaf");
            // }
        }

        if usage == CertificateUsage::AdacUsageNeutral {
            usage = header.usage;
        } else if usage != header.usage {
            error_count += 1;
            errors.push(format!(
                "Usage mismatch was {:?} now {:?}",
                usage, header.usage
            ));
        }

        if soc_id == [0x0u8; 16] {
            soc_id = header.soc_id;
        } else if soc_id != header.soc_id {
            error_count += 1;
            errors.push(format!(
                "SoC ID does not match ({:?} != {:?})",
                soc_id, header.soc_id
            ));
        }
        if soc_class == 0 {
            soc_class = header.soc_class;
        } else if header.soc_class != 0 && soc_class != header.soc_class {
            let h_soc_class = header.soc_class;
            error_count += 1;
            errors.push(format!(
                "SoC ID Class not match (0x{:x} != 0x{:x})",
                soc_class, h_soc_class
            ));
        }
        for (i, p) in permissions.iter_mut().enumerate() {
            *p &= header.permissions_mask[i];
        }

        match current.verify(pubkey, &crypto) {
            Ok(()) => {}
            Err(e) => {
                error_count += 1;
                errors.push(format!("Signature verification failed: {:?}", e));
            }
        }
        pubkey = current.get_public_key();

        certificates.push(CertificateVerification { key_id, errors });
    }

    let token = if let (Some(token), Some(challenge)) = (token, challenge) {
        let mut errors = vec![];
        let signer = chain.last().expect("Chain can't be empty");
        let token = token::read_token(token.as_slice()).map_err(|e| {
            error_count += 1;
            CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing token: {:?}", e),
            }
        })?;
        if signer.header().key_type != token.header().signature_type {
            error_count += 1;
            errors.push("Token signature algorithm does not match.".to_string());
        } else {
            match token.verify(signer.get_public_key(), challenge.as_slice(), &crypto) {
                Ok(()) => {
                    let header = token.header();
                    for (i, p) in permissions.iter_mut().enumerate() {
                        *p &= header.requested_permissions[i];
                    }
                }
                Err(e) => {
                    error_count += 1;
                    errors.push(format!("Signature verification failed: {:?}", e));
                }
            };
        }
        Some(TokenVerification { errors })
    } else {
        None
    };

    let mut summary = vec![];
    if soc_id != [0x0u8; 16] {
        let mut id = [0x0u8; 16];
        id.copy_from_slice(u128::from_le_bytes(soc_id).to_be_bytes().as_ref());
        summary.push(format!(
            "Restricted to SoC ID: 0x{} ({})",
            base16ct::lower::encode_string(id.as_slice()),
            base16ct::lower::encode_string(soc_id.as_slice())
        ));
    }
    if soc_class != 0x0 {
        summary.push(format!("Restricted to SoC Class: 0x{:x}", soc_class));
    }

    if usage != CertificateUsage::AdacUsageNeutral {
        summary.push(format!("Restricted to usage {:?}", usage));
    }

    let mut effective = [0x00u8; 16];
    effective.copy_from_slice(u128::from_le_bytes(permissions).to_be_bytes().as_ref());
    summary.push(format!(
        "Effective permissions: 0x{} ({})",
        base16ct::lower::encode_string(effective.as_slice()),
        base16ct::lower::encode_string(permissions.as_slice())
    ));
    Ok(CommandOutput::Verify(VerificationReport {
        certificates,
        token,
        summary,
        error_count,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_adac_token_configuration;
    use crate::tests;
    use crate::token::token_sign_command;
    use std::{fs, path::Path};

    const TOKEN_CONFIG: &str = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[token]
version_minor = 1
requested_permissions = "0x00000000FFFFFFFFFFFFFFFFFFFFFFFF"
"#;
    const TOKEN_CHALLENGE: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn fixture_path(kind: &str, name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../adac-tests/resources")
            .join(kind)
            .join(name)
    }

    fn write_config(dir: &Path) -> PathBuf {
        let path = dir.join("token.toml");
        fs::write(&path, TOKEN_CONFIG).unwrap();
        path
    }

    #[test]
    fn verify_command_verifies_token_and_masks_permissions() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let config_path = write_config(&dir);
        let chain_path = fixture_path("roots", "root.EcdsaP384");
        let private_path = fixture_path("keys", "EcdsaP384Key-0.pk8");
        let token_path = dir.join("token.bin");

        token_sign_command(
            &TOKEN_CHALLENGE.to_string(),
            &Some(config_path),
            &Some(token_path.clone()),
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
            &Some(TOKEN_CHALLENGE.to_string()),
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
                .is_some_and(|token| token.errors.is_empty())
        );

        let chain = load_certificates(&chain_path).unwrap();
        let config =
            parse_adac_token_configuration(TOKEN_CONFIG, Some("token".to_string())).unwrap();
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
    fn verify_command_rejects_non_32_byte_challenge() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let config_path = write_config(&dir);
        let chain_path = fixture_path("roots", "root.EcdsaP384");
        let private_path = fixture_path("keys", "EcdsaP384Key-0.pk8");
        let token_path = dir.join("token.bin");

        token_sign_command(
            &TOKEN_CHALLENGE.to_string(),
            &Some(config_path),
            &Some(token_path.clone()),
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

        let err =
            verify_command(&chain_path, &Some(token_path), &Some("0011".to_string())).unwrap_err();

        match err {
            CommandError::InvalidParameter { parameter } => {
                assert_eq!(parameter, "--challenge");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }
}
