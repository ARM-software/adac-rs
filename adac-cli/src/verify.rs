// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, token};
use adac::CertificateUsage;
use adac_crypto::encoding::{EncodingIssue, validate_certificate_chain, validate_token};
use adac_crypto::public::AdacPublicKey;
use adac_crypto::utils::{read_certificate_chain_bytes, read_certificates};
use adac_crypto::validation::ChainValidator;
use serde::Serialize;
use sha2::Digest;
use sha2::digest::Update;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    encoding_errors: Vec<EncodingVerification>,
    certificates: Vec<CertificateVerification>,
    token: Option<TokenVerification>,
    summary: Vec<String>,
    error_count: u64,
}

impl VerificationReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for error in &self.encoding_errors {
            writeln!(
                out,
                "Encoding error at {}, offset {}: {}",
                error.context, error.offset, error.message
            )?;
        }
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
pub struct EncodingVerification {
    offset: usize,
    context: String,
    message: String,
}

impl From<EncodingIssue> for EncodingVerification {
    fn from(issue: EncodingIssue) -> Self {
        Self {
            offset: issue.offset,
            context: issue.context,
            message: issue.message,
        }
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
    let contents = std::fs::read_to_string(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error reading certificate chain: {:?}", e),
    })?;
    let certificate_chain_bytes =
        read_certificate_chain_bytes(contents.as_str()).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error decoding certificate chain: {:?}", e),
        })?;
    let mut encoding_errors = validate_certificate_chain(certificate_chain_bytes.as_slice())
        .into_iter()
        .map(EncodingVerification::from)
        .collect::<Vec<_>>();

    let chain = match read_certificates(contents) {
        Ok(chain) => chain,
        Err(e) if !encoding_errors.is_empty() => {
            return Ok(CommandOutput::Verify(VerificationReport {
                error_count: encoding_errors.len() as u64,
                encoding_errors,
                certificates: Vec::new(),
                token: None,
                summary: Vec::new(),
            }));
        }
        Err(e) => {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
            });
        }
    };

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
        encoding_errors.extend(
            validate_token(contents.as_slice())
                .into_iter()
                .map(EncodingVerification::from),
        );
        Some(contents)
    } else {
        None
    };

    let challenge = if let Some(challenge) = challenge {
        Some(token::decode_challenge_parameter(challenge)?)
    } else {
        None
    };

    let mut error_count = encoding_errors.len() as u64;
    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    let mut validator = ChainValidator::new(&crypto);

    let mut certificates = vec![];

    for (i, current) in chain.iter().enumerate() {
        let header = current.header();
        let public_key = AdacPublicKey::from_adac(header.key_type, current.get_public_key())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing public key at level {}: {:?}", i, e),
            })?;
        let key_id = sha2::Sha256::new().chain(public_key.get_spki()).finalize();
        let key_id = base16ct::lower::encode_string(key_id.as_slice());

        validator.push_certificate(current);
        certificates.push(CertificateVerification {
            key_id,
            errors: Vec::new(),
        });
    }

    let mut token_effective_permissions = None;
    let token = if let (Some(token), Some(challenge)) = (token, challenge) {
        let token = token::read_token(token.as_slice()).map_err(|e| {
            error_count += 1;
            CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing token: {:?}", e),
            }
        })?;
        let token_result = validator.validate_token(&token, challenge.as_slice());
        let errors = token_result
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        error_count += errors.len() as u64;
        token_effective_permissions = token_result.effective_permissions;
        Some(TokenVerification { errors })
    } else {
        None
    };

    let validation = validator.finish();
    error_count += validation.chain_errors.len() as u64;
    for certificate in &validation.certificates {
        let errors = certificate
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        error_count += errors.len() as u64;
        certificates[certificate.index].errors = errors;
    }

    let permissions = token_effective_permissions.unwrap_or(validation.effective.permissions);

    let mut summary = vec![];
    for error in validation.chain_errors {
        summary.push(error.to_string());
    }

    let usage = validation.effective.usage;
    let lifecycle = validation.effective.lifecycle;
    let oem_constraint = validation.effective.oem_constraint;
    let soc_id = validation.effective.soc_id;
    let soc_class = validation.effective.soc_class;
    let policies = validation.effective.policies;

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
    if lifecycle != 0 {
        summary.push(format!("Restricted to lifecycle 0x{:x}", lifecycle));
    }
    if oem_constraint != 0 {
        summary.push(format!(
            "Restricted to OEM constraint 0x{:x}",
            oem_constraint
        ));
    }

    if usage != CertificateUsage::AdacUsageNeutral {
        summary.push(format!("Restricted to usage {:?}", usage));
    }
    if policies != 0 {
        summary.push(format!("Effective policies: 0x{:x}", policies));
    }

    let mut effective = [0x00u8; 16];
    effective.copy_from_slice(u128::from_le_bytes(permissions).to_be_bytes().as_ref());
    summary.push(format!(
        "Effective permissions: 0x{} ({})",
        base16ct::lower::encode_string(effective.as_slice()),
        base16ct::lower::encode_string(permissions.as_slice())
    ));
    Ok(CommandOutput::Verify(VerificationReport {
        encoding_errors,
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
    use crate::sign::certificate_sign_command;
    use crate::tests;
    use crate::token::token_sign_command;
    use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
    use adac_crypto::utils::{load_certificates, load_key};
    use adac_crypto_rust::RustCryptoProvider;
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

    fn write_public_key_from_private(dir: &Path, key_name: &str, output_name: &str) -> PathBuf {
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

    fn write_verify_config(dir: &Path) -> PathBuf {
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

[root_conflict]
role = 1
lifecycle = 0x3000
oem_constraint = 0x1234

[root_policy]
role = 1
policies = 0x1

[leaf_restricted]
lifecycle = 0x3000
oem_constraint = 0x1234

[leaf_conflict]
lifecycle = 0x4000
oem_constraint = 0x5678

[leaf_policy]
policies = 0x2
"#,
        )
        .unwrap();
        path
    }

    fn write_signed_chain(
        dir: &Path,
        root_section: &str,
        leaf_section: &str,
        output_name: &str,
    ) -> PathBuf {
        let config_path = write_verify_config(dir);
        let root_private = fixture_path("keys", "EcdsaP384Key-0.pk8");
        let root_public = write_public_key_from_private(dir, "EcdsaP384Key-0.pk8", "root.pub");
        let leaf_public = write_public_key_from_private(dir, "EcdsaP384Key-1.pk8", "leaf.pub");
        let root_path = dir.join("root.pem");
        let chain_path = dir.join(output_name);

        certificate_sign_command(
            &config_path,
            &None,
            &Some(root_path.clone()),
            &Some(root_private.clone()),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &root_public,
            &Some(root_section.to_string()),
        )
        .unwrap();

        certificate_sign_command(
            &config_path,
            &Some(root_path),
            &Some(chain_path.clone()),
            &Some(root_private),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &leaf_public,
            &Some(leaf_section.to_string()),
        )
        .unwrap();

        chain_path
    }

    #[test]
    fn verify_command_verifies_token_and_masks_permissions() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let config_path = write_config(&dir);
        let chain_path = fixture_path("roots", "root.EcdsaP384");
        let private_path = fixture_path("keys", "EcdsaP384Key-0.pk8");
        let token_path = dir.join("token.bin");

        token_sign_command(
            TOKEN_CHALLENGE,
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
            TOKEN_CHALLENGE,
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

    #[test]
    fn verify_command_reports_effective_lifecycle_and_oem_constraint() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let chain_path = write_signed_chain(&dir, "root", "leaf_restricted", "restricted.pem");

        let output = verify_command(&chain_path, &None, &None).unwrap();

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
                .any(|line| line == "Restricted to OEM constraint 0x1234")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_command_rejects_conflicting_lifecycle_and_oem_constraint() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let chain_path = write_signed_chain(&dir, "root_conflict", "leaf_conflict", "conflict.pem");

        let output = verify_command(&chain_path, &None, &None).unwrap();

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
                .any(|error| error == "OEM constraint does not match (0x1234 != 0x5678)")
        }));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_command_reports_effective_policies() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let chain_path = write_signed_chain(&dir, "root_policy", "leaf_policy", "policy.pem");

        let output = verify_command(&chain_path, &None, &None).unwrap();

        let CommandOutput::Verify(report) = output else {
            panic!("unexpected command output");
        };
        assert_eq!(report.error_count, 0);
        assert!(
            report
                .summary
                .iter()
                .any(|line| line == "Effective policies: 0x3")
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_command_reports_certificate_chain_encoding_errors() {
        let dir = tests::make_temp_dir("adac-cli-verify-tests");
        let chain_path = write_signed_chain(&dir, "root", "leaf_restricted", "bad-encoding.pem");
        let contents = fs::read_to_string(&chain_path).unwrap();
        let mut bytes = read_certificate_chain_bytes(contents.as_str()).unwrap();
        bytes[1] = 1;
        let pem = pem::Pem::new("ADAC CERTIFICATE CHAIN", bytes);
        let pem = pem::encode_config(
            &pem,
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );
        fs::write(&chain_path, pem).unwrap();

        let output = verify_command(&chain_path, &None, &None).unwrap();

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
}
